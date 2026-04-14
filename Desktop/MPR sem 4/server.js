require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;

// 🔗 CONNECT MONGODB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB Error:", err));

/* =========================
   📦 USER SCHEMA (FIXED)
========================= */
const userSchema = new mongoose.Schema({
  patientId: String,
  name: String,
  password: String,
});

const User = mongoose.model("users", userSchema);

/* =========================
   📦 DOCUMENT SCHEMA
========================= */
const docSchema = new mongoose.Schema({
  patientId: String,   // ⭐ ADD THIS (IMPORTANT)
  type: String,
  folder: String,
  imageData: String,
  content: String,
  doctorName: String,
  date: String,
  name: String,
});

const Document = mongoose.model("Document", docSchema);

/* =========================
   🔒 VERIFY TOKEN MIDDLEWARE
========================= */
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
}

/* =========================
   📝 REGISTER ROUTE
========================= */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { patientId, name, password } = req.body;

    if (!patientId || !name || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    // Check for duplicate patientId
    const existing = await User.findOne({ patientId });
    if (existing) {
      return res.status(409).json({ message: "Patient ID already registered." });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user
    const newUser = new User({ patientId, name, password: hashedPassword });
    await newUser.save();

    // Issue JWT
    const token = jwt.sign(
      { id: patientId, name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: {
        id: patientId,
        name,
        initials: name.slice(0, 2).toUpperCase(),
      },
    });
  } catch (err) {
    console.log("REGISTER ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   🔐 LOGIN ROUTE (FIXED)
========================= */
app.post("/api/auth/login", async (req, res) => {
  try {
    console.log("LOGIN BODY:", req.body);

    // ✅ SAFE DESTRUCTURE (PREVENT CRASH)
    const patientId = req.body?.patientId;
    const password = req.body?.password;

    if (!patientId || !password) {
      return res.status(400).json({ message: "patientId or password missing" });
    }

    const user = await User.findOne({ patientId });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // ✅ Use bcrypt.compare instead of plain string comparison
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    // Issue JWT
    const token = jwt.sign(
      { id: user.patientId, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: {
        id: user.patientId,
        name: user.name,
        initials: user.name.slice(0, 2).toUpperCase(),
      },
    });

  } catch (err) {
    console.log("LOGIN ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   📥 GET ALL DOCS (PROTECTED)
========================= */
app.get("/docs", verifyToken, async (req, res) => {
  const { patientId } = req.query;

  const docs = await Document.find({ patientId }); // 🔥 CRITICAL

  res.json(docs);
});

/* =========================
   📤 SAVE DOC (PROTECTED)
========================= */
app.post("/save-doc", verifyToken, async (req, res) => {
  try {
    const doc = req.body;

    if (!doc.patientId) {
      return res.status(400).json({ message: "patientId missing" });
    }

    const newDoc = new Document(doc);
    await newDoc.save();

    res.json(newDoc);
  } catch (err) {
    res.status(500).json({ message: "Error saving doc" });
  }
});

/* =========================
   ❌ DELETE DOC (PROTECTED)
========================= */
app.delete("/delete-doc/:id", verifyToken, async (req, res) => {
  try {
    await Document.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting document" });
  }
});

/* =========================
   🚀 START SERVER
========================= */
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});