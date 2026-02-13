import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import cors from "cors";

import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000; // Render will set this automatically
const SECRET = "VERY_SECRET_KEY"; // Change in production!

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // Serve front-end files

// 🔐 Issue short-lived token
app.get("/token", (req, res) => {
  const token = jwt.sign({ access: "cert" }, SECRET, { expiresIn: "2m" });
  res.json({ token });
});

// 🛡️ Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.query.token;
  if (!token) return res.status(401).send("Token required");

  jwt.verify(token, SECRET, (err) => {
    if (err) return res.status(403).send("Invalid or expired token");
    next();
  });
}

// 📄 Secure PDF endpoint with inline display
app.get("/cert", verifyToken, (req, res) => {
  const filePath = path.join(__dirname, "certs", "my_certs.pdf");

  if (!fs.existsSync(filePath)) return res.status(404).send("PDF not found");

  // Serve PDF inline in the browser
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "inline; filename=my_certs.pdf");
  fs.createReadStream(filePath).pipe(res);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

