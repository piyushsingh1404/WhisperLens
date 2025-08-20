/* ================================== Setup ================================== */
require("dotenv").config();

const path = require("path");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const MongoStore = require("connect-mongo"); // ✅ persistent session store

/* ------------------------------ OpenAI (opt) ------------------------------ */
let openai = null;
try {
  const OpenAI = require("openai");
  openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
} catch (_) {}

const app = express();

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

// behind proxy (for correct secure cookie handling)
app.set("trust proxy", 1);

/* ========================= Mongo / ENV sanity checks ====================== */
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI missing in .env");
  process.exit(1);
}
mongoose.set("strictQuery", true);

if (!process.env.SESSION_SECRET) {
  console.warn("⚠️ SESSION_SECRET missing. Set a long random secret in env.");
}

const isProd = process.env.NODE_ENV === "production";
/**
 * For Render/HTTPS: set FORCE_SECURE_COOKIE=true in your env.
 * That enables Secure + SameSite=None cookies. Otherwise we default to SameSite=Lax, non-secure,
 * which works in local dev and non-https paths.
 */
const USE_SECURE =
  isProd && String(process.env.FORCE_SECURE_COOKIE || "false").toLowerCase() === "true";
const SAME_SITE = USE_SECURE ? "none" : "lax";

/* ================================ Sessions ================================ */
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "ourLittleSecret",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      collectionName: "sessions",
      ttl: 60 * 60 * 24 * 7, // 7 days
      crypto: {
        secret:
          process.env.SESSION_STORE_SECRET ||
          process.env.SESSION_SECRET ||
          "storeSecret",
      },
    }),
    cookie: {
      secure: USE_SECURE,    // ✅ toggle via env
      sameSite: SAME_SITE,   // ✅ 'none' when secure
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 8, // 8 hours
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* =============================== Flash & Helpers ========================== */
function setFlash(req, type, message) {
  req.session.flash = { type, message };
}
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});
// ensure cookie is written before redirect (fixes “login lost after redirect”)
function flashAndRedirect(req, res, type, message, to) {
  setFlash(req, type, message);
  req.session.save(() => res.redirect(to));
}

/* =============================== Rate Limits ============================== */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const writeLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
app.use("/login", authLimiter);
app.use("/register", authLimiter);
app.use("/submit", writeLimiter);
app.use("/delete", writeLimiter);
app.use("/ai", writeLimiter);

/* ========================= Models + Passport ============================== */
/* ---- User (auth only) ---- */
const userSchema = new mongoose.Schema({
  username: { type: String, index: true },
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
// NOTE: you already have `aiCategory` indexed via the field option above;
// avoid adding `secretSchema.index({ aiCategory: 1 })` again to silence the duplicate warning.
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

/* ================================== Utils ================================= */
function isNonEmptyString(s) { return typeof s === "string" && s.trim().length > 0; }
function randomPseudonym() {
  const animals = ["Lion","Tiger","Panda","Eagle","Shark","Wolf","Falcon","Koala","Otter","Cobra"];
  const colors = ["Purple","Crimson","Azure","Emerald","Amber","Ivory","Onyx","Silver","Golden","Teal"];
  const a = animals[Math.floor(Math.random() * animals.length)];
  const c = colors[Math.floor(Math.random() * colors.length)];
  const n = Math.floor(10 + Math.random() * 89);
  return `${c}${a}${n}`;
}
function makeStablePseudonym(userId) {
  const colors = ["Purple","Crimson","Azure","Emerald","Amber","Ivory","Onyx","Silver","Golden","Teal"];
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
      temperature: 0.2,
      max_tokens: 120,
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

/* --------- Auth Routes --------- */
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
      return flashAndRedirect(req, res, "danger", "Please provide username and password.", "/register");
    }
    const user = await User.register(new User({ username }), password);
    req.login(user, (err) => {
      if (err) return flashAndRedirect(req, res, "warning", "Registered, but auto login failed. Please login.", "/login");
      flashAndRedirect(req, res, "success", "Registration successful! 🎉", "/secrets");
    });
  } catch (err) {
    return flashAndRedirect(req, res, "danger", err.message || "Registration failed.", "/register");
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err || !user) {
      return flashAndRedirect(req, res, "danger", info?.message || "Invalid credentials.", "/login");
    }
    // optional: mitigate fixation by regenerating before establishing session
    req.session.regenerate((regenErr) => {
      if (regenErr) return flashAndRedirect(req, res, "danger", "Session error. Try again.", "/login");
      req.login(user, (loginErr) => {
        if (loginErr) return flashAndRedirect(req, res, "danger", "Login failed. Try again.", "/login");
        req.session.save(() => flashAndRedirect(req, res, "success", "Login successful ✅", "/secrets"));
      });
    });
  })(req, res, next);
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    flashAndRedirect(req, res, "success", "Logged out. See you soon! 👋", "/");
  });
});

/* --------- Secrets Routes --------- */
app.get("/secrets", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
  const secrets = await Secret.find().sort({ createdAt: -1 }).limit(50).lean();
  res.render("secrets", { secrets, currentUserId: req.user._id });
});

app.post("/submit", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
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
    } catch (_) {}
  });
  res.redirect("/secrets");
});

app.post("/delete", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) return res.redirect("/login");
  await Secret.deleteOne({ _id: req.body.secretId, ownerId: req.user._id });
  res.redirect("/secrets");
});

/* ------------------------------ Dev helper -------------------------------- */
if (process.env.NODE_ENV !== "production") {
  app.get("/dev/whoami", (req, res) => {
    res.json({
      authenticated: !!req.isAuthenticated?.() && !!req.user,
      user: req.user ? { id: String(req.user._id), username: req.user.username } : null,
      sessionId: req.sessionID
    });
  });
}

/* ================================== Boot ================================== */
(async () => { await connectMongo(); })();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
