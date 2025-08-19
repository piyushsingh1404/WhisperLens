
# 🔐 Secrets - Authentication Web App

This is a secure full-stack web application that allows users to register, log in, anonymously share secrets, and view secrets submitted by others — inspired by real-world authentication systems.

## 🚀 Live Demo (Optional)
You can add a Loom video link here if available.

---

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS, EJS Templating
- **Backend**: Node.js, Express.js
- **Database**: MongoDB (via MongoDB Atlas)
- **Authentication**: Express Sessions, bcrypt encryption
- **Other Tools**: dotenv, Mongoose, body-parser

---

## ✨ Features

- 📝 User Registration and Login
- 🔐 Encrypted Password Storage
- 🙈 Submit Secrets Anonymously
- 🧾 View Secrets from Other Users
- ❌ Delete Your Submitted Secrets
- 🚪 Logout functionality
- 🔒 Session-Based Authentication

---

## 📂 Folder Structure

```
Secrets-Authentication-App/
├── views/
│   ├── home.ejs
│   ├── login.ejs
│   ├── register.ejs
│   ├── secrets.ejs
│   └── submit.ejs
├── public/
│   └── css/
│       └── styles.css
├── app.js
├── package.json
├── .env.example
└── README.md
```

---

## ⚙️ Installation & Setup

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/secrets-auth-app.git
cd secrets-auth-app
```

2. **Install Dependencies**
```bash
npm install
```

3. **Configure Environment Variables**
Create a `.env` file in the root directory and add:
```
PORT=3000
MONGO_URI=your_mongodb_atlas_connection_string
SESSION_SECRET=your_session_secret
```

4. **Start the App**
```bash
node app.js
# or
nodemon app.js
```

5. **Visit**
```
http://localhost:3000
```

---

## 📸 Screenshots

### 🏠 Welcome Page
![Welcome](./screenshots/welcome.png)

### 🔐 Login Page
![Login](./screenshots/login.png)

### 🧾 Secrets Page
![Secrets](./screenshots/secrets.png)

---

## 🙋‍♂️ Author

**Piyush Singh**  
📧 piyush.singh.job@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/piyush-singh-01858123b)  
💻 [GitHub](https://github.com/piyushsingh1404)

---

## 📄 License

This project is open for educational/demo purposes only.  
Commercial use prohibited without permission.
