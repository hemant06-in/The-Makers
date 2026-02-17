const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.static("public"));

const SECRET_KEY = "makers_secret_key";

// Fake user (for now)
const USER = {
    username: "makers",
    password: "makers"
};

// LOGIN API
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    if (username === USER.username && password === USER.password) {
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ success: true, token });
    } else {
        res.status(401).json({ success: false, message: "Invalid credentials" });
    }
});

// PROTECTED ROUTE
app.get("/api/protected", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        jwt.verify(token, SECRET_KEY);
        res.json({ message: "Access granted to Makers Dashboard 🚀" });
    } catch (err) {
        res.status(403).json({ message: "Invalid token" });
    }
});

const port = process.env.port || 3000;

app.listen(3000, () => {
    console.log("Server running.....");
});