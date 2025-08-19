require('dotenv').config();  // Load the .env file

console.log("MONGO_URI in test.js:", process.env.MONGO_URI);  // Log MONGO_URI
console.log("SECRET in test.js:", process.env.SECRET);        // Log SECRET
