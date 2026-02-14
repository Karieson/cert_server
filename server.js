import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import cors from "cors";
import fetch from "node-fetch"; // For server-side reCAPTCHA verification
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";

dotenv.config(); // Load .env variables

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = "VERY_SECRET_KEY"; // Change in production!
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form POST
app.use(express.static(path.join(__dirname, "public"))); // Serve front-end files

// ==========================
// 🔐 Landing page with reCAPTCHA verification
// ==========================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// Handle reCAPTCHA form submission
app.post("/verify", async (req, res) => {
  const token = req.body["g-recaptcha-response"];

  if (!token) return res.send("CAPTCHA token missing. Please try again.");

  try {
    const response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`,
      { method: "POST" }
    );
    const data = await response.json();

    if (data.success) {
      // reCAPTCHA passed → redirect to token route or main page
      res.redirect("/token"); // or /main if you have another page
    } else {
      res.send("CAPTCHA failed. Please try again.");
    }
  } catch (err) {
    console.error(err);
    res.send("Error verifying CAPTCHA");
  }
});

// ==========================
// 🔐 Issue short-lived token
// ==========================
app.get("/token", (req, res) => {
  const token = jwt.sign({ access: "cert" }, SECRET, { expiresIn: "2m" });
  res.json({ token });
});

// ==========================
// 🛡️ Middleware to verify token
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
// 📄 Secure PDF endpoint with inline display
// ==========================
app.get("/cert", verifyToken, (req, res) => {
  const filePath = path.join(__dirname, "certs", "my_certs.pdf");

  if (!fs.existsSync(filePath)) return res.status(404).send("PDF not found");

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "inline; filename=my_certs.pdf");
  fs.createReadStream(filePath).pipe(res);
});

// ==========================
// Start server
// ==========================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
