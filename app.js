/* ================================== Setup ================================== */
require("dotenv").config();

const path = require("path");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");              // session store
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
const isProd = process.env.NODE_ENV === "production";     // ✅ declare ONCE

/* ============================== Express Core ============================== */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// proxy only in prod (Render/Heroku etc.)
if (isProd) app.set("trust proxy", 1);

/* ============================ Mongo Connection ============================ */
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI missing in .env");
  process.exit(1);
}
mongoose.set("strictQuery", true);
(async () => {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 12000 });
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connect error:", err?.message || err);
    process.exit(1);
  }
})();

/* =============================== Sessions ================================= */
app.use(
  session({
    name: "secrets.sid",
    secret: process.env.SESSION_SECRET || "dev-change-me",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      collectionName: "sessions",
      ttl: 60 * 60 * 8, // 8 hours
    }),
    cookie: {
      httpOnly: true,
      secure: isProd,                         // dev=false, prod=true
      sameSite: isProd ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ================================ FLASH =================================== */
function setFlash(req, type, message) { req.session.flash = { type, message }; }
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});
function flashAndRedirect(req, res, type, message, to) {
  setFlash(req, type, message);
  req.session.save(() => res.redirect(to));
}

/* ========================= Models + Passport ============================== */
const userSchema = new mongoose.Schema({
  username: { type: String, index: true, unique: false },
});
userSchema.plugin(passportLocalMongoose);
const User = mongoose.model("User", userSchema);

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
secretSchema.index({ text: "text", aiSummary: "text" });
const Secret = mongoose.model("Secret", secretSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

/* =============================== Rate Limits ============================== */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const writeLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
app.use("/login", authLimiter);
app.use("/register", authLimiter);
app.use("/submit", writeLimiter);
app.use("/delete", writeLimiter);
app.use("/ai", writeLimiter);

/* ================================ Helpers ================================= */
function isNonEmptyString(s) { return typeof s === "string" && s.trim().length > 0; }
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
  const palette = ["#E57373","#F06292","#BA68C8","#9575CD","#7986CB","#64B5F6","#4FC3F7","#4DD0E1","#4DB6AC","#81C784","#AED581","#DCE775","#FFF176","#FFD54F","#FFB74D","#A1887F","#90A4AE"];
  const s = String(name);
  let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}
function catIcon(cat = "Other") {
  const map = { Work:"briefcase", Family:"people", Finance:"currency-rupee", Health:"heart-pulse", School:"book", Advice:"chat-dots", Confession:"emoji-frown", Other:"tag" };
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
  if (/(job|office|boss|manager|salary|work|company|colleague|coworker|client|project|deadline|meeting|meetings|team|promotion)/.test(t)) return "Work";
  if (/(mom|mother|dad|father|brother|sister|parents|parent|family|married|marriage|husband|wife|kids|children)/.test(t)) return "Family";
  if (/(loan|money|debt|paid|budget|bank|rupees|rs|expense|expenses|credit|rent|bill|bills|finance|financial)/.test(t)) return "Finance";
  if (/(doctor|ill|sick|health|hospital|medicine|anxiety|depressed|depression|therapy|panic|stress|mental|injury|diet|exercise|sleep)/.test(t)) return "Health";
  if (/(school|college|university|exam|study|studies|class|teacher|assignment|homework|semester|marks|grade|grades)/.test(t)) return "School";
  if (/(advice|suggest|tip|tips|what should i do|help me decide|how do i)/.test(t)) return "Advice";
  if (/(guilty|guilt|sorry|confess|cheated|cheating|cheat|ashamed|regret|regretting|i shouldn'?t have)/.test(t)) return "Confession";
  return "Other";
}
const ALLOWED_CATS = new Set(["Work","Family","Finance","Health","School","Advice","Confession","Other"]);
function resolveCategory(text, aiCat) {
  let cleanAI = (aiCat || "").trim().replace(/^category\s*:\s*/i, "");
  if (!ALLOWED_CATS.has(cleanAI)) cleanAI = "Other";
  const local = localCategory(text);
  const confidentLocal = ["Work","Family","Finance","Health","School","Advice"].includes(local);
  if (confidentLocal && (cleanAI === "Other" || cleanAI === "Confession")) return local;
  return cleanAI || local || "Other";
}
async function generateAI(text) {
  const fallback = { summary: localSummarize(text), category: localCategory(text), source: "local" };
  if (!openai || !process.env.OPENAI_API_KEY) return fallback;
  try {
    const prompt = `You will receive the user's secret.

Return exactly two lines:
1) A concise 1-sentence summary (<=20 words).
2) Category: a single word chosen from {Work, Family, Finance, Health, School, Confession, Advice, Other}.

Secret:
"""${text}"""`;
    const resp = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "Be brief, safe, and use only the allowed categories." },
        { role: "user", content: prompt },
      ],
      temperature: 0.2, max_tokens: 120,
    });
    const out = resp.choices?.[0]?.message?.content || "";
    const lines = out.split("\n").map((s) => s.trim()).filter(Boolean);
    const summaryFromAI = lines[0] || fallback.summary;
    const aiRawCategory  = lines[1] || "";
    const finalCategory  = resolveCategory(text, aiRawCategory);
    return { summary: summaryFromAI, category: finalCategory, source: "openai" };
  } catch (err) {
    console.log("AI error (fallback used):", err.message);
    return fallback;
  }
}

/* ================================== Routes ================================= */
app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.get("/", (_req, res) => res.render("home"));

/* ------------------------------ Auth Routes -------------------------------- */
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
      return flashAndRedirect(req, res, "danger", "Please provide username and password.", "/register");
    }
    const user = await User.register(new User({ username }), password);
    req.session.regenerate((regenErr) => {
      if (regenErr) return flashAndRedirect(req, res, "warning", "Session error. Please login.", "/login");
      req.logIn(user, (err) => {
        if (err) return flashAndRedirect(req, res, "warning", "Registered, but auto login failed. Please login.", "/login");
        setFlash(req, "success", "Registration successful! 🎉");
        req.session.save(() => res.redirect("/secrets"));
      });
    });
  } catch (err) {
    return flashAndRedirect(req, res, "danger", err.message || "Registration failed.", "/register");
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return flashAndRedirect(req, res, "danger", "Login failed. Try again.", "/login");
    if (!user) return flashAndRedirect(req, res, "danger", info?.message || "Invalid credentials.", "/login");

    req.session.regenerate((regenErr) => {
      if (regenErr) return flashAndRedirect(req, res, "danger", "Session error. Try again.", "/login");
      req.logIn(user, (loginErr) => {
        if (loginErr) return flashAndRedirect(req, res, "danger", "Login failed. Try again.", "/login");
        setFlash(req, "success", "Login successful ✅");
        req.session.save(() => res.redirect("/secrets"));
      });
    });
  })(req, res, next);
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("secrets.sid");
      res.redirect("/");
    });
  });
});

/* ------------------------------- Secrets ---------------------------------- */
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
  res.render("secrets", { secrets, currentUserId: req.user._id, page, totalPages, q, cat, limit });
});

/* JSON feed */
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

/* ============================== Dev Utilities ============================== */
if (!isProd) {
  app.get("/dev/seed", async (req, res) => {
    try {
      const exists = await User.findOne({ username: "test@local" });
      if (!exists) await User.register(new User({ username: "test@local" }), "test123");
      res.send("Seeded: username=test@local, password=test123");
    } catch (e) {
      res.status(500).send("Seed error: " + e.message);
    }
  });

  app.get("/dev/set", (req, res) => {
    req.session.testStamp = Date.now();
    req.session.save(() => res.send(`SET OK. sid=${req.sessionID}`));
  });
  app.get("/dev/get", (req, res) => {
    res.json({
      sid: req.sessionID,
      hasTestStamp: !!req.session.testStamp,
      testStamp: req.session.testStamp || null,
      cookieHeader: req.headers.cookie || null,
      authenticated: !!req.isAuthenticated?.() && !!req.user,
      user: req.user || null,
    });
  });

  app.get("/dev/whoami", (req, res) => {
    res.json({
      authenticated: !!req.isAuthenticated?.() && !!req.user,
      user: req.user ? { id: String(req.user._id), username: req.user.username } : null,
      sid: req.sessionID,
      cookieHeader: req.headers.cookie || null,
    });
  });
}

/* ================================== Boot ================================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
