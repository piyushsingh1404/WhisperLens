/* ================================== Setup ================================== */
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

/* ------------------------------ OpenAI (opt) ------------------------------ */
let openai = null;
try {
  const OpenAI = require("openai");
  openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
} catch (_) {}

const app = express();

/* ============================== Express Core ============================== */
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// app.set("trust proxy", 1) // if behind LB/proxy

// enable trust proxy if behind a load balancer (Render, Railway, etc.)
app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "ourLittleSecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // https only in prod
      sameSite: process.env.NODE_ENV === "production" ? "lax" : "lax",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 8, // 8 hours
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// make `user` available in all views
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

/* =============================== Rate Limits ============================== */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const writeLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
app.use("/login", authLimiter);
app.use("/register", authLimiter);
app.use("/submit", writeLimiter);
app.use("/delete", writeLimiter);
app.use("/ai", writeLimiter);

/* ========================= Mongo + Models + Passport ======================= */
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI missing in .env");
  process.exit(1);
}
mongoose.set("strictQuery", true);

/* ---- User (auth only) ---- */
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
userSchema.plugin(passportLocalMongoose);
const User = mongoose.model("User", userSchema);

/* ---- Secret (collection) ---- */
const secretSchema = new mongoose.Schema(
  {
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, required: true },
    text: { type: String, required: true },
    aiSummary: String,
    aiCategory: { type: String, index: true },
    aiSource: String,
    pseudonym: { type: String, index: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", index: true }],
  },
  { timestamps: true }
);
secretSchema.index({ createdAt: -1 });
secretSchema.index({ aiCategory: 1 });
secretSchema.index({ text: "text", aiSummary: "text" });
secretSchema.methods.likeCount = function () { return (this.likes || []).length; };

const Secret = mongoose.model("Secret", secretSchema);

/* ------------------------------ Passport ---------------------------------- */
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

/* ------------------------------- Connect ---------------------------------- */
async function connectMongo() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 12000 });
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connect error:", err?.message || err);
    process.exit(1);
  }
}

/* ================================ Helpers ================================= */
function isNonEmptyString(s) {
  return typeof s === "string" && s.trim().length > 0;
}

function randomPseudonym() {
  const animals = ["Lion","Tiger","Panda","Eagle","Shark","Wolf","Falcon","Koala","Otter","Cobra"];
  const colors  = ["Purple","Crimson","Azure","Emerald","Amber","Ivory","Onyx","Silver","Golden","Teal"];
  const a = animals[Math.floor(Math.random() * animals.length)];
  const c = colors[Math.floor(Math.random() * colors.length)];
  const n = Math.floor(10 + Math.random() * 89);
  return `${c}${a}${n}`;
}

function makeStablePseudonym(userId) {
  const colors  = ["Purple","Crimson","Azure","Emerald","Amber","Ivory","Onyx","Silver","Golden","Teal"];
  const animals = ["Lion","Tiger","Panda","Eagle","Shark","Wolf","Falcon","Koala","Otter","Cobra"];
  const hex = userId.toString().slice(-6);
  const n = parseInt(hex, 16) || Math.floor(Math.random() * 9999);
  const c = colors[n % colors.length];
  const a = animals[(n >> 3) % animals.length];
  const d = 10 + (n % 90);
  return `${c}${a}${d}`;
}

function avatarColorFromName(name = "") {
  const palette = [
    "#E57373","#F06292","#BA68C8","#9575CD","#7986CB",
    "#64B5F6","#4FC3F7","#4DD0E1","#4DB6AC","#81C784",
    "#AED581","#DCE775","#FFF176","#FFD54F","#FFB74D",
    "#A1887F","#90A4AE",
  ];
  const s = String(name);
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}

function catIcon(cat = "Other") {
  const map = {
    Work: "briefcase",
    Family: "people",
    Finance: "currency-rupee",
    Health: "heart-pulse",
    School: "book",
    Advice: "chat-dots",
    Confession: "emoji-frown",
    Other: "tag",
  };
  return map[cat] || "tag";
}

/* ------------------------------ AI helpers -------------------------------- */
function localSummarize(text) {
  const clean = (text || "").replace(/\s+/g, " ").trim();
  if (!clean) return "No content provided.";
  const firstSentence = clean.split(/([.!?])\s/)[0];
  const words = clean.split(/\s+/);
  const short = words.slice(0, 20).join(" ");
  let summary = firstSentence.length <= 140 ? firstSentence : short + (words.length > 20 ? "..." : "");
  summary = summary.charAt(0).toUpperCase() + summary.slice(1);
  if (!/[.!?]$/.test(summary)) summary += ".";
  return summary;
}
function localCategory(text) {
  const t = (text || "").toLowerCase();
  if (/(job|office|boss|salary|work|company|client)/.test(t)) return "Work";
  if (/(mom|dad|brother|sister|family|married|husband|wife)/.test(t)) return "Family";
  if (/(loan|money|debt|paid|budget|bank|rupees|rs)/.test(t)) return "Finance";
  if (/(doctor|ill|sick|health|hospital|medicine|anxiety|depressed)/.test(t)) return "Health";
  if (/(school|college|exam|study|class|teacher)/.test(t)) return "School";
  if (/(advice|suggest|tip)/.test(t)) return "Advice";
  if (/(love|crush|relationship|guilty|sorry|confess)/.test(t)) return "Confession";
  return "Other";
}

async function generateAI(text) {
  const fallback = {
    summary: localSummarize(text),
    category: localCategory(text),
    source: "local",
  };

  if (!openai || !process.env.OPENAI_API_KEY) return fallback;

  try {
    const prompt = `You will receive the user's secret.

Return exactly two lines:
1) A concise 1-sentence summary (<=20 words).
2) Category: a single word like Work/Family/Finance/Health/School/Confession/Advice/Other.

Secret:
"""${text}"""`;

    const resp = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "Be brief, safe, and respectful." },
        { role: "user", content: prompt },
      ],
      temperature: 0.4,
      max_tokens: 120,
    });

    const out = resp.choices?.[0]?.message?.content || "";
    const lines = out.split("\n").map((s) => s.trim()).filter(Boolean);
    const summary = lines[0] || fallback.summary;
    const category = (lines[1] || "").replace(/^category\s*:\s*/i, "") || fallback.category;
    return { summary, category, source: "openai" };
  } catch (err) {
    console.log("AI error (fallback used):", err.message);
    return fallback;
  }
}

/* ================================ Migration =============================== */
// Migrate old embedded secrets -> Secret docs (one-time, not AI backfill)
async function migrateEmbeddedSecretsOnce() {
  const enabled = String(process.env.MIGRATE_EMBEDDED || "true").toLowerCase() === "true";
  if (!enabled) return;

  const rawUsers = mongoose.connection.collection("users");
  const cursor = rawUsers.find({ "secrets.0": { $exists: true } }, { projection: { username: 1, secrets: 1 } });

  let created = 0, cleared = 0;
  while (await cursor.hasNext()) {
    const u = await cursor.next();
    const uid = u._id;

    if (Array.isArray(u.secrets)) {
      for (const s of u.secrets) {
        const exists = await Secret.exists({ ownerId: uid, text: s.text });
        if (exists) continue;

        await Secret.create({
          ownerId: uid,
          text: s.text || "",
          aiSummary: s.aiSummary || null,
          aiCategory: s.aiCategory || null,
          aiSource: s.aiSource || null,
          pseudonym: randomPseudonym(),
          createdAt: s.createdAt || undefined,
          updatedAt: s.updatedAt || undefined,
        });
        created++;
      }
    }

    await rawUsers.updateOne({ _id: uid }, { $unset: { secrets: "" } });
    cleared++;
  }

  console.log(`🔧 Migration done: created ${created} Secret docs, cleared embedded for ${cleared} user(s).`);
  process.env.MIGRATE_EMBEDDED = "false";
}

/* Backfill any missing pseudonyms (NOT AI) */
async function backfillMissingPseudonymsOnce() {
  try {
    const missing = await Secret.find({
      $or: [{ pseudonym: { $exists: false } }, { pseudonym: null }, { pseudonym: "" }],
    }).lean(false);

    if (!missing.length) {
      console.log("🪪 Pseudonym backfill: none needed");
      return;
    }

    let updated = 0;
    for (const s of missing) {
      s.pseudonym = makeStablePseudonym(s.ownerId);
      await s.save();
      updated++;
    }
    console.log(`🪪 Pseudonym backfill: assigned ${updated} pseudonym(s)`);
  } catch (e) {
    console.error("🪪 Pseudonym backfill error:", e?.message || e);
  }
}

/* ================================== Routes ================================= */
app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.get("/", (req, res) => res.render("home"));

/* Auth */
app.get("/register", (req, res) => res.render("register"));
app.post("/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!isNonEmptyString(username) || !isNonEmptyString(password)) return res.redirect("/register");
  User.register({ username }, password, (err) => {
    if (err) { console.log(err); return res.redirect("/register"); }
    passport.authenticate("local")(req, res, () => res.redirect("/secrets"));
  });
});

app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!isNonEmptyString(username) || !isNonEmptyString(password)) return res.redirect("/login");
  const user = new User({ username, password });
  req.login(user, (err) => {
    if (err) { console.log(err); return res.redirect("/login"); }
    passport.authenticate("local")(req, res, () => res.redirect("/secrets"));
  });
});

app.get("/logout", (req, res) => { req.logout(() => res.redirect("/")); });

/* Change Password */
app.get("/change-password", (req, res) => res.render("change-password"));
app.post("/change-password", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
  const { oldPassword, newPassword } = req.body || {};
  if (!isNonEmptyString(oldPassword) || !isNonEmptyString(newPassword)) return res.redirect("/change-password");
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.redirect("/login");
    user.changePassword(oldPassword, newPassword, (err) => {
      if (err) { console.log("change-password error:", err.message); return res.redirect("/change-password"); }
      req.logout(() => res.redirect("/login"));
    });
  } catch (e) {
    console.log("change-password error:", e.message);
    res.redirect("/change-password");
  }
});

/* Secrets Feed (server-rendered first page) */
app.get("/secrets", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");

  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "10", 10), 5), 50);
  const skip = (page - 1) * limit;
  const q = (req.query.q || "").trim();
  const cat = (req.query.cat || "").trim();

  const match = {};
  if (cat) match.aiCategory = cat;
  if (q) match.$or = [{ text: { $regex: q, $options: "i" } }, { aiSummary: { $regex: q, $options: "i" } }];

  try {
    const [rows, total] = await Promise.all([
      Secret.find(match).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Secret.countDocuments(match),
    ]);

    const secrets = rows.map(s => {
      const name = s.pseudonym || makeStablePseudonym(s.ownerId);
      return {
        userId: s.ownerId,
        username: name,
        avatarColor: avatarColorFromName(name),
        liked: (s.likes || []).some(id => String(id) === String(req.user._id)),
        likeCount: (s.likes || []).length,
        secret: s,
      };
    });

    const totalPages = Math.max(Math.ceil(total / limit), 1);

    res.render("secrets", {
      secrets,
      currentUserId: req.user._id,
      page, totalPages, q, cat, limit
    });
  } catch (e) {
    console.error(e);
    res.render("secrets", {
      secrets: [],
      currentUserId: req.user?._id || null,
      page: 1, totalPages: 1, q, cat, limit
    });
  }
});

/* JSON feed for infinite scroll */
app.get("/api/secrets", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.status(401).json({ error: "unauthenticated" });

  const page  = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "10", 10), 5), 50);
  const skip  = (page - 1) * limit;
  const q     = (req.query.q || "").trim();
  const cat   = (req.query.cat || "").trim();

  const match = {};
  if (cat) match.aiCategory = cat;
  if (q) match.$or = [{ text: { $regex: q, $options: "i" } }, { aiSummary: { $regex: q, $options: "i" } }];

  const [rows, total] = await Promise.all([
    Secret.find(match).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Secret.countDocuments(match),
  ]);
  const totalPages = Math.max(Math.ceil(total / limit), 1);

  const items = rows.map(s => {
    const name = s.pseudonym || makeStablePseudonym(s.ownerId);
    return {
      id: String(s._id),
      userId: String(s.ownerId),
      username: name,
      avatarColor: avatarColorFromName(name),
      text: s.text || "",
      aiSummary: s.aiSummary || "",
      aiCategory: s.aiCategory || "Other",
      aiSource: s.aiSource || "",
      createdAt: s.createdAt,
      liked: (s.likes || []).some(id => String(id) === String(req.user._id)),
      likeCount: (s.likes || []).length,
      icon: catIcon(s.aiCategory || "Other"),
    };
  });

  res.json({ page, totalPages, items });
});

/* Submit */
app.get("/submit", (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
  res.render("submit");
});

app.post("/submit", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
  try {
    const submittedSecret = (req.body.secret || "").trim();
    if (!submittedSecret) return res.redirect("/secrets");

    const doc = await Secret.create({
      ownerId: req.user._id,
      text: submittedSecret,
      pseudonym: randomPseudonym(),
    });

    // Background AI enrichment for THIS new secret only
    setImmediate(async () => {
      try {
        const { summary, category, source } = await generateAI(submittedSecret);
        await Secret.updateOne(
          { _id: doc._id },
          { $set: { aiSummary: summary, aiCategory: category, aiSource: source } }
        );
      } catch (err) {
        console.log("bg AI error:", err.message);
      }
    });

    res.redirect("/secrets");
  } catch (e) {
    console.log(e);
    res.redirect("/secrets");
  }
});

/* Delete */
app.post("/delete", async (req, res) => {
  try {
    if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
    const { secretId } = req.body || {};
    if (!secretId) return res.redirect("/secrets");

    await Secret.deleteOne({ _id: secretId, ownerId: req.user._id });
    return res.redirect("/secrets");
  } catch (err) {
    console.error("Delete error:", err);
    return res.redirect("/secrets");
  }
});

/* Like Toggle */
app.post("/like", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    if (req.accepts("json")) return res.status(401).json({ error: "unauthenticated" });
    return res.redirect("/login");
  }
  const { secretId } = req.body || {};
  if (!secretId) return req.accepts("json") ? res.status(400).json({ error: "missing id" }) : res.redirect("/secrets");

  const s = await Secret.findById(secretId);
  if (!s) return req.accepts("json") ? res.status(404).json({ error: "not found" }) : res.redirect("/secrets");

  const uid = String(req.user._id);
  const has = (s.likes || []).some(id => String(id) === uid);
  if (has) {
    s.likes = s.likes.filter(id => String(id) !== uid);
  } else {
    s.likes = s.likes || [];
    s.likes.push(req.user._id);
  }
  await s.save();

  if (req.accepts("json")) {
    return res.json({ liked: !has, likeCount: s.likes.length });
  }
  res.redirect("/secrets");
});

/* AI: per-secret refresh */
app.post("/ai/refresh", async (req, res) => {
  try {
    if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
    const { secretId } = req.body || {};
    if (!secretId) return res.redirect("/secrets");

    const s = await Secret.findOne({ _id: secretId, ownerId: req.user._id });
    if (!s) return res.redirect("/secrets");

    const { summary, category, source } = await generateAI(s.text || "");
    s.aiSummary = summary;
    s.aiCategory = category;
    s.aiSource   = source;
    await s.save();

    return res.redirect("/secrets");
  } catch (e) {
    console.error("ai/refresh error:", e);
    return res.redirect("/secrets");
  }
});



/* My Secrets */
app.get("/me", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");

  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "10", 10), 5), 50);
  const skip = (page - 1) * limit;

  const [rows, total] = await Promise.all([
    Secret.find({ ownerId: req.user._id }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Secret.countDocuments({ ownerId: req.user._id }),
  ]);

  const secrets = rows.map(s => {
    const name = s.pseudonym || makeStablePseudonym(s.ownerId);
    return {
      userId: s.ownerId,
      username: name,
      avatarColor: avatarColorFromName(name),
      liked: (s.likes || []).some(id => String(id) === String(req.user._id)),
      likeCount: (s.likes || []).length,
      secret: s,
    };
  });

  const totalPages = Math.max(Math.ceil(total / limit), 1);
  res.render("my-secrets", { secrets, currentUserId: req.user._id, page, totalPages, limit });
});

/* ================================== Boot ================================== */
(async () => {
  await connectMongo();
  await migrateEmbeddedSecretsOnce();       // one-time structural migration (not AI)
  await backfillMissingPseudonymsOnce();    // ensure anonymity labels exist
})();

// at the very bottom of app.js
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

