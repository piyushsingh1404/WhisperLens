require("dotenv").config({ path: require("path").join(__dirname, ".env"), override: true });

console.log({
  NODE_ENV: process.env.NODE_ENV,
  HAS_MONGO_URI: !!process.env.MONGO_URI,
  HAS_SESSION_SECRET: !!process.env.SESSION_SECRET,
  HAS_OPENAI: !!process.env.OPENAI_API_KEY
});
