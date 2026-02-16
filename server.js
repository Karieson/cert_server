// server.js (Merged: Dontev token + PureImage CAPTCHA)
import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import cors from "cors";
import fetch from "node-fetch";
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";
import PImage from "pureimage";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET_KEY || "VERY_SECRET_KEY";
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

// ===== Middleware =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
import session from 'express-session';
app.use(session({
  secret: "captcha_secret",
  resave: false,
  saveUninitialized: true
}));

// ==========================
// CAPTCHA CONFIG
// ==========================
const captchaConfigPath = path.join(__dirname,"captcha_config.json");
const captchaConfig = fs.existsSync(captchaConfigPath) 
  ? JSON.parse(fs.readFileSync(captchaConfigPath)) 
  : { length:6, width:240, height:90, font:"Anton", fontSize:36, lines:8, expirySeconds:60 };

const fontsPath = path.join(__dirname, "fonts", "Anton-Regular.ttf");
const captchaFont = PImage.registerFont(fontsPath, 'Anton');
captchaFont.loadSync();

// ===== Generate CAPTCHA text =====
function generateCaptchaText(length = captchaConfig.length) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let text = '';
  for (let i = 0; i < length; i++) text += chars.charAt(Math.floor(Math.random() * chars.length));
  return text;
}

// ===== Create CAPTCHA image =====
function createCaptchaImage(text) {
  const img = PImage.make(captchaConfig.width, captchaConfig.height);
  const ctx = img.getContext('2d');

  // Background
  ctx.fillStyle = "black";
  ctx.fillRect(0, 0, captchaConfig.width, captchaConfig.height);

  // Random lines
  for (let i = 0; i < captchaConfig.lines; i++) {
    ctx.strokeStyle = `rgb(${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)})`;
    ctx.beginPath();
    ctx.moveTo(Math.random()*captchaConfig.width, Math.random()*captchaConfig.height);
    ctx.lineTo(Math.random()*captchaConfig.width, Math.random()*captchaConfig.height);
    ctx.stroke();
  }

  // Text
  const xStart = 20;
  const yStart = captchaConfig.height/1.5;
  for (let i = 0; i < text.length; i++) {
    const letter = text[i];
    ctx.fillStyle = `rgb(${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)})`;
    ctx.save();
    const angle = (Math.random() - 0.5) * 0.5;
    ctx.translate(xStart + i*30, yStart);
    ctx.rotate(angle);
    ctx.fillText(letter, 0, 0);
    ctx.restore();
  }

  return img;
}

// ===== CAPTCHA Routes =====
app.get("/captcha-image", (req, res)=>{
  const captchaText = generateCaptchaText();
  req.session.captcha = captchaText;
  const img = createCaptchaImage(captchaText);
  res.setHeader("Content-Type","image/png");
  PImage.encodePNGToStream(img,res);
});

app.post("/verify-captcha", (req,res)=>{
  const { captcha } = req.body;
  if(!captcha || captcha.toUpperCase() !== (req.session.captcha||'').toUpperCase()){
    return res.status(400).json({ error: "Incorrect CAPTCHA" });
  }
  req.session.captcha = null;
  res.json({ success:true });
});

// ==========================
// Landing Page
// ==========================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// ==========================
// Optional: Google reCAPTCHA verification
// ==========================
app.post("/verify", async (req, res) => {
  const token = req.body["g-recaptcha-response"];
  if (!token) return res.status(400).send("CAPTCHA token missing");
  try {
    const response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`,
      { method: "POST" }
    );
    const data = await response.json();
    if (data.success) res.send("CAPTCHA passed");
    else res.status(403).send("CAPTCHA failed");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error verifying CAPTCHA");
  }
});

// ==========================
// Issue short-lived token for secure PDF
// ==========================
app.get("/token", (req, res) => {
  const token = jwt.sign({ access: "cert" }, SECRET, { expiresIn: "2m" });
  res.json({ token });
});

// ==========================
// Middleware to verify token
// ==========================
function verifyToken(req, res, next) {
  const token = req.query.token;
  if (!token) return res.status(401).send("Token required");
  jwt.verify(token, SECRET, (err) => {
    if (err) return res.status(403).send("Invalid or expired token");
    next();
  });
}

// ==========================
// Secure Certificates PDF
// ==========================
app.get("/cert", verifyToken, (req, res) => {
  const filePath = path.join(__dirname, "certs", "my_certs.pdf");
  if (!fs.existsSync(filePath)) return res.status(404).send("PDF not found");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "inline; filename=my_certs.pdf");
  fs.createReadStream(filePath).pipe(res);
});

// ==========================
// Direct Resume Download
// ==========================
app.get("/my_resume.pdf", (req, res) => {
  const filePath = path.join(__dirname, "public", "my_resume.pdf");
  if (!fs.existsSync(filePath)) return res.status(404).send("Resume not found");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=my_resume.pdf");
  fs.createReadStream(filePath).pipe(res);
});

// ==========================
// Start server
// ==========================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
