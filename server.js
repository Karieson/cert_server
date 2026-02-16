// ===============================
// index.js – Main Server Entry
// ===============================

import express from "express";
import session from "express-session";
import cors from "cors";
import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import fetch from "node-fetch";
import PImage from "pureimage";
import { fileURLToPath } from "url";
import { dirname } from "path";

dotenv.config();

// ===============================
// Path setup
// ===============================
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ===============================
// App init
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;

// ===============================
// Secrets
// ===============================
const JWT_SECRET = process.env.SECRET_KEY || "dev_jwt_secret";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev_session_secret";

// ===============================
// Middleware
// ===============================
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    name: "captcha.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 5 * 60 * 1000 // 5 minutes
    }
  })
);

// ===============================
// CAPTCHA CONFIG
// ===============================
const captchaConfig = {
  length: 6,
  width: 240,
  height: 90,
  fontSize: 38,
  lines: 6
};

// ===============================
// Load Font
// ===============================
const fontPath = path.join(__dirname, "fonts", "Anton-Regular.ttf");
const captchaFont = PImage.registerFont(fontPath, "Anton");
captchaFont.loadSync();

// ===============================
// CAPTCHA helpers
// ===============================
function generateCaptchaText(len = captchaConfig.length) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function createCaptchaImage(text) {
  const img = PImage.make(captchaConfig.width, captchaConfig.height);
  const ctx = img.getContext("2d");

  // background
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, captchaConfig.width, captchaConfig.height);

  // noise lines
  for (let i = 0; i < captchaConfig.lines; i++) {
    ctx.strokeStyle = `rgb(${Math.random()*255},${Math.random()*255},${Math.random()*255})`;
    ctx.beginPath();
    ctx.moveTo(Math.random()*captchaConfig.width, Math.random()*captchaConfig.height);
    ctx.lineTo(Math.random()*captchaConfig.width, Math.random()*captchaConfig.height);
    ctx.stroke();
  }

  // text
  ctx.font = `${captchaConfig.fontSize}px Anton`;
  ctx.textBaseline = "middle";

  [...text].forEach((char, i) => {
    ctx.save();
    ctx.fillStyle = `rgb(${Math.random()*255},${Math.random()*255},${Math.random()*255})`;
    ctx.translate(30 + i * 32, captchaConfig.height / 2);
    ctx.rotate((Math.random() - 0.5) * 0.4);
    ctx.fillText(char, 0, 0);
    ctx.restore();
  });

  return img;
}

// ===============================
// CAPTCHA Routes
// ===============================
app.get("/captcha-image", async (req, res) => {
  const captchaText = generateCaptchaText();
  req.session.captcha = captchaText;

  res.setHeader("Content-Type", "image/png");
  const img = createCaptchaImage(captchaText);
  await PImage.encodePNGToStream(img, res);
});

app.post("/verify-captcha", (req, res) => {
  const userText = (req.body.captcha || "").toUpperCase();
  const sessionText = (req.session.captcha || "").toUpperCase();

  if (!userText || !sessionText) {
    return res.status(400).json({ error: "Captcha missing" });
  }

  if (userText !== sessionText) {
    return res.status(400).json({ error: "Incorrect captcha" });
  }

  req.session.captcha = null;
  res.json({ success: true });
});

// ===============================
// Landing Page
// ===============================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// ===============================
// JWT Token Issuer
// ===============================
app.get("/token", (req, res) => {
  const token = jwt.sign({ access: "cert" }, JWT_SECRET, {
    expiresIn: "2m"
  });
  res.json({ token });
});

// ===============================
// JWT Middleware
// ===============================
function verifyToken(req, res, next) {
  const token = req.query.token;
  if (!token) return res.status(401).send("Token required");

  jwt.verify(token, JWT_SECRET, err => {
    if (err) return res.status(403).send("Invalid or expired token");
    next();
  });
}

// ===============================
// Protected Certificate PDF
// ===============================
app.get("/cert", verifyToken, (req, res) => {
  const file = path.join(__dirname, "certs", "my_certs.pdf");
  if (!fs.existsSync(file)) return res.status(404).send("File not found");

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "inline; filename=my_certs.pdf");
  fs.createReadStream(file).pipe(res);
});

// ===============================
// Resume Download
// ===============================
app.get("/my_resume.pdf", (req, res) => {
  const file = path.join(__dirname, "public", "my_resume.pdf");
  if (!fs.existsSync(file)) return res.status(404).send("File not found");

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=my_resume.pdf");
  fs.createReadStream(file).pipe(res);
});

// ===============================
// Server Start
// ===============================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
