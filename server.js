import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import pg from "pg";

const { Pool } = pg;
const required = ["DATABASE_URL", "JWT_SECRET", "APP_URL"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Missing environment variable: ${name}`);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS expenses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    month TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    amount NUMERIC(12, 2) NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL,
    spent_on TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  );
  CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE (user_id, name)
  );
`);

const app = express();
app.use(cors({ origin: process.env.APP_URL }));
app.use(express.json({ limit: "20kb" }));

const transporter = process.env.SMTP_USER && process.env.SMTP_PASSWORD
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
    })
  : null;

function issueToken(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const value = req.headers.authorization || "";
  const token = value.startsWith("Bearer ") ? value.slice(7) : "";
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Sesiunea a expirat. Conectează-te din nou." });
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");
    if (!name || !email || password.length < 8) {
      return res.status(400).json({ error: "Completează datele; parola trebuie să aibă cel puțin 8 caractere." });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hash]
    );
    const user = result.rows[0];
    res.status(201).json({ token: issueToken(user), user });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Acest email are deja un cont." });
    next(error);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = cleanEmail(req.body.email);
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.password_hash))) {
      return res.status(401).json({ error: "Emailul sau parola sunt incorecte." });
    }
    res.json({ token: issueToken(user), user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) { next(error); }
});

app.get("/api/me", auth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT id, name, email FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows[0]) return res.status(401).json({ error: "Contul nu mai există." });
    res.json({ user: result.rows[0] });
  } catch (error) { next(error); }
});

app.post("/api/auth/request-reset", async (req, res, next) => {
  try {
    const email = cleanEmail(req.body.email);
    const result = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (result.rows[0] && transporter) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
      await pool.query("DELETE FROM password_resets WHERE user_id = $1", [result.rows[0].id]);
      await pool.query(
        "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 minutes')",
        [tokenHash, result.rows[0].id]
      );
      const link = `${process.env.APP_URL}?resetToken=${rawToken}`;
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: "Resetare parolă - My Budget",
        text: `Apasă pe acest link pentru a seta o parolă nouă: ${link}`
      });
    }
    res.json({ message: "Dacă emailul există, vei primi un link de resetare." });
  } catch (error) { next(error); }
});

app.post("/api/auth/reset", async (req, res, next) => {
  try {
    const rawToken = String(req.body.token || "");
    const password = String(req.body.password || "");
    if (password.length < 8) return res.status(400).json({ error: "Parola trebuie să aibă cel puțin 8 caractere." });
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const found = await pool.query(
      "SELECT user_id FROM password_resets WHERE token_hash = $1 AND expires_at > NOW()",
      [tokenHash]
    );
    if (!found.rows[0]) return res.status(400).json({ error: "Linkul este invalid sau a expirat." });
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [await bcrypt.hash(password, 12), found.rows[0].user_id]);
    await pool.query("DELETE FROM password_resets WHERE token_hash = $1", [tokenHash]);
    res.json({ message: "Parola a fost schimbată. Te poți conecta." });
  } catch (error) { next(error); }
});

app.post("/api/auth/change-password", auth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows[0] || !(await bcrypt.compare(String(req.body.oldPassword || ""), result.rows[0].password_hash))) {
      return res.status(400).json({ error: "Parola actuală nu este corectă." });
    }
    const password = String(req.body.newPassword || "");
    if (password.length < 8) return res.status(400).json({ error: "Parola trebuie să aibă cel puțin 8 caractere." });
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [await bcrypt.hash(password, 12), req.user.id]);
    res.json({ message: "Parola a fost actualizată." });
  } catch (error) { next(error); }
});

app.get("/api/categories", auth, async (req, res, next) => {
  try {
    const defaults = [
      "Mâncare", "Ieșiri în oraș", "Shopping & Beauty",
      "Transport", "Casă & Facturi", "Altele"
    ];
    await pool.query(
      "INSERT INTO categories (user_id, name) SELECT $1, name FROM unnest($2::text[]) AS name ON CONFLICT DO NOTHING",
      [req.user.id, defaults]
    );
    const result = await pool.query(
      "SELECT name FROM categories WHERE user_id = $1 ORDER BY id",
      [req.user.id]
    );
    res.json({ categories: result.rows.map(row => row.name) });
  } catch (error) { next(error); }
});

app.post("/api/categories", auth, async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name || name.length > 30) {
      return res.status(400).json({ error: "Introdu o categorie cu cel mult 30 de caractere." });
    }
    await pool.query(
      "INSERT INTO categories (user_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [req.user.id, name]
    );
    const result = await pool.query(
      "SELECT name FROM categories WHERE user_id = $1 ORDER BY id",
      [req.user.id]
    );
    res.status(201).json({ categories: result.rows.map(row => row.name) });
  } catch (error) { next(error); }
});

app.get("/api/expenses", auth, async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT id, month, category, description AS desc, amount, currency, spent_on AS date FROM expenses WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    const data = {};
    for (const item of result.rows) (data[item.month] ||= []).push({ ...item, amount: Number(item.amount) });
    res.json({ data });
  } catch (error) { next(error); }
});

app.post("/api/expenses", auth, async (req, res, next) => {
  try {
    const { month, category, desc, amount, currency, date } = req.body;
    if (!month || !category || !desc || !Number.isFinite(Number(amount)) || Number(amount) <= 0 || !currency) {
      return res.status(400).json({ error: "Datele cheltuielii sunt invalide." });
    }
    const result = await pool.query(
      "INSERT INTO expenses (user_id, month, category, description, amount, currency, spent_on) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, month, category, description AS desc, amount, currency, spent_on AS date",
      [req.user.id, month, category, String(desc).trim(), Number(amount), currency, date || new Date().toLocaleDateString("ro-RO")]
    );
    res.status(201).json({ expense: { ...result.rows[0], amount: Number(result.rows[0].amount) } });
  } catch (error) { next(error); }
});

app.delete("/api/expenses/:id", auth, async (req, res, next) => {
  try {
    await pool.query("DELETE FROM expenses WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    res.status(204).end();
  } catch (error) { next(error); }
});

app.use(express.static(process.cwd()));
app.get("*", (_req, res) => res.sendFile("index.html", { root: process.cwd() }));

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: "A apărut o eroare pe server." });
});

app.listen(process.env.PORT || 3000, () => console.log("My Budget API is running"));
