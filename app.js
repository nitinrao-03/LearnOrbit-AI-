
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin: (process.env.ALLOWED_ORIGINS || "*")
    .split(",")
    .map(value => value.trim())
}));
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// Database
const db = new Database(
  process.env.DB_PATH || path.join(__dirname, "learnorbit.sqlite")
);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const findUser = db.prepare(
  "SELECT id, user_id, password_hash FROM users WHERE user_id = ?"
);

const insertUser = db.prepare(
  "INSERT INTO users (user_id, password_hash) VALUES (?, ?)"
);

const updateId = db.prepare(
  "UPDATE users SET user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
);

const updatePassword = db.prepare(
  "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
);

// Validation
function validId(value) {
  return typeof value === "string" &&
    /^[a-zA-Z0-9_]{3,24}$/.test(value.trim());
}

function validPassword(value) {
  return typeof value === "string" &&
    value.length >= 8 &&
    value.length <= 128;
}

// JWT token
function createToken(user) {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET is not configured correctly.");
  }

  return jwt.sign(
    { sub: String(user.id), userId: user.user_id },
    secret,
    { expiresIn: "2h", issuer: "learn-orbit-ai" }
  );
}

// Authentication middleware
function authenticate(req, res, next) {
  const match = (req.get("authorization") || "")
    .match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: "Please log in." });
  }

  try {
    const secret = process.env.JWT_SECRET;

    if (!secret || secret.length < 32) {
      throw new Error("JWT secret missing");
    }

    req.auth = jwt.verify(match[1], secret, {
      issuer: "learn-orbit-ai"
    });

    next();
  } catch {
    return res.status(401).json({
      error: "Session expired or invalid. Please log in again."
    });
  }
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "Learn Orbit AI" });
});

// SIGNUP
app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const userId = typeof req.body?.userId === "string"
    ? req.body.userId.trim()
    : "";

  const { password, confirmPassword } = req.body || {};

  if (!validId(userId)) {
    return res.status(400).json({
      error: "User ID must be 3–24 characters using letters, numbers, or underscore."
    });
  }

  if (!validPassword(password)) {
    return res.status(400).json({
      error: "Password must be 8–128 characters."
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: "Passwords do not match."
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = insertUser.run(userId, passwordHash);

    const user = {
      id: Number(result.lastInsertRowid),
      user_id: userId
    };

    return res.status(201).json({
      message: "Account created successfully.",
      user: { userId },
      token: createToken(user)
    });
  } catch (error) {
    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "This User ID is already taken."
      });
    }

    console.error("Signup error:", error.message);
    return res.status(500).json({
      error: "Could not create account. Check server configuration."
    });
  }
});

// LOGIN
app.post("/api/auth/login", authLimiter, async (req, res) => {
  const userId = typeof req.body?.userId === "string"
    ? req.body.userId.trim()
    : "";

  const { password } = req.body || {};

  if (!validId(userId) ||
      typeof password !== "string" ||
      password.length > 128) {
    return res.status(400).json({
      error: "Enter a valid User ID and password."
    });
  }

  try {
    const user = findUser.get(userId);
    const matched = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!matched) {
      return res.status(401).json({
        error: "Incorrect User ID or password."
      });
    }

    return res.json({
      message: "Login successful.",
      user: { userId: user.user_id },
      token: createToken(user)
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({
      error: "Could not log in. Check server configuration."
    });
  }
});

// CHANGE USER ID
app.patch(
  "/api/auth/user-id",
  authLimiter,
  authenticate,
  (req, res) => {
    const newUserId = typeof req.body?.newUserId === "string"
      ? req.body.newUserId.trim()
      : "";

    if (!validId(newUserId)) {
      return res.status(400).json({
        error: "New User ID must be 3–24 characters."
      });
    }

    try {
      const result = updateId.run(
        newUserId,
        Number(req.auth.sub)
      );

      if (!result.changes) {
        return res.status(404).json({
          error: "Account not found."
        });
      }

      return res.json({
        message: "User ID changed. Please log in again.",
        user: { userId: newUserId }
      });
    } catch (error) {
      if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
        return res.status(409).json({
          error: "This User ID is already taken."
        });
      }

      console.error("Change ID error:", error.message);
      return res.status(500).json({
        error: "Could not change User ID."
      });
    }
  }
);

// CHANGE PASSWORD
app.patch(
  "/api/auth/password",
  authLimiter,
  authenticate,
  async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};

    if (
      typeof currentPassword !== "string" ||
      !validPassword(newPassword)
    ) {
      return res.status(400).json({
        error: "Enter your current password and a new password of 8–128 characters."
      });
    }

    try {
      const user = db.prepare(
        "SELECT id, password_hash FROM users WHERE id = ?"
      ).get(Number(req.auth.sub));

      if (
        !user ||
        !(await bcrypt.compare(currentPassword, user.password_hash))
      ) {
        return res.status(401).json({
          error: "Current password is incorrect."
        });
      }

      const hash = await bcrypt.hash(newPassword, 12);
      updatePassword.run(hash, user.id);

      return res.json({
        message: "Password changed. Please log in again."
      });
    } catch (error) {
      console.error("Change password error:", error.message);
      return res.status(500).json({
        error: "Could not change password."
      });
    }
  }
);

// Error handler
app.use((err, req, res, next) => {
  console.error("Request error:", err.message);
  res.status(500).json({
    error: "Unexpected server error."
  });
});

module.exports = app;
