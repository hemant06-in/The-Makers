const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "makers_secret_key";

// ======================
// MongoDB Connection
// ======================
if (!process.env.MONGO_URI) {
    console.error("MONGO_URI not defined");
    process.exit(1);
}

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => {
        console.error("MongoDB Error:", err);
        process.exit(1);
    });

// ======================
// User Model
// ======================
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    role: { type: String, default: "member" },
    team: { type: String, default: "general" },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// ======================
// Project Model
// ======================
const projectSchema = new mongoose.Schema({
    title: String,
    description: String,
    createdBy: String,
    createdAt: { type: Date, default: Date.now }
});

const Project = mongoose.model("Project", projectSchema);

// ======================
// LOGIN ROUTE
// ======================
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ success: false });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: "2h" }
        );

        res.json({ success: true, token });

    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ======================
// TOKEN VERIFY ROUTE
// ======================
app.get("/api/protected", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ success: false });
    }

    const token = authHeader.split(" ")[1];

    try {
        jwt.verify(token, SECRET_KEY);
        res.json({ success: true });
    } catch {
        res.status(403).json({ success: false });
    }
});

// ======================
// PUBLIC: GET PROJECTS
// ======================
app.get("/api/projects", async (req, res) => {
    try {
        const projects = await Project.find().sort({ createdAt: -1 });
        res.json(projects);
    } catch {
        res.status(500).json({ message: "Error fetching projects" });
    }
});

// ======================
// PUBLIC: GET TEAM MEMBERS
// ======================
app.get("/api/team", async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 });
        res.json(users);
    } catch {
        res.status(500).json({ message: "Error fetching team" });
    }
});

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
