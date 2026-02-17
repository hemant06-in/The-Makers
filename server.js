const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

// ======================
// MIDDLEWARE
// ======================
app.use(express.json());
app.use(express.static("public")); // if your frontend is inside /public

// ======================
// ENV CONFIG
// ======================
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "makers_secret_key";

// ======================
// CHECK MONGO ENV
// ======================
if (!process.env.MONGO_URI) {
    console.error("❌ MONGO_URI is not defined");
    process.exit(1);
}

// ======================
// MONGODB CONNECT
// ======================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

// ======================
// USER MODEL
// ======================
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    role: { type: String, default: "member" }
});

const User = mongoose.model("User", userSchema);

// ======================
// LOGIN ROUTE
// ======================
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid username" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Wrong password" });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role },
            SECRET_KEY,
            { expiresIn: "1h" }
        );

        res.json({ success: true, token });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});
// ======================
// CREATE USER (ADMIN ONLY)
// ======================
app.post("/api/create-user", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(403).json({ message: "No token provided" });
        }

        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        // Only admin can create users
        if (decoded.role !== "admin") {
            return res.status(403).json({ message: "Access denied" });
        }

        const { username, password, role } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({
            username,
            password: hashedPassword,
            role: role || "member"
        });

        res.json({ message: "User created successfully ✅" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// ======================
// PROTECTED ROUTE EXAMPLE
// ======================
app.get("/api/protected", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        res.json({ message: "Access granted 🚀", user: decoded });
    } catch (err) {
        res.status(403).json({ message: "Invalid token" });
    }
});

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});


