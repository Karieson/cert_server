// server.js
import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import cors from "cors";
import fetch from "node-fetch"; 
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";

dotenv.config(); // load .env variables

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET_KEY || "VERY_SECRET_KEY"; // JWT secret
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY; // loaded from Render env

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"))); 

// ==========================
// Landing Page
// ==========================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// ==========================
// Optional: reCAPTCHA verification for server-side forms
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

    if (data.success) {
      res.send("CAPTCHA passed");
    } else {
      res.status(403).send("CAPTCHA failed");
    }
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
