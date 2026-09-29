const express = require("express");
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const session = require("express-session");

const app = express();
const db = new Database("auth.db");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    secret: "my-secret-key-change-this",
    resave: false,
    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 30 * 60 * 1000
    }
}));

app.use(express.static("public"));

// Create users table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
`);

// Signup
app.post("/signup", async (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: "Email and password are required."
        });
    }

    if (password.length < 12) {
        return res.status(400).json({
            error: "Password must be at least 12 characters."
        });
    }

    try {

        // Hash password using Argon2
        const passwordHash = await argon2.hash(password);

        // Parameterized SQL query
        const statement = db.prepare(`
            INSERT INTO users (email, password_hash)
            VALUES (?, ?)
        `);

        statement.run(email, passwordHash);

        res.json({
            message: "Account created successfully!"
        });

    } catch (error) {

        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(400).json({
                error: "Unable to create account."
            });
        }

        console.error(error);

        res.status(500).json({
            error: "Something went wrong."
        });
    }
});


// Login
app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: "Email and password are required."
        });
    }

    try {

        // Parameterized query prevents SQL Injection
        const user = db.prepare(`
            SELECT id, email, password_hash
            FROM users
            WHERE email = ?
        `).get(email);

        if (!user) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        // Verify hashed password
        const validPassword = await argon2.verify(
            user.password_hash,
            password
        );

        if (!validPassword) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        // Create login session
        req.session.userId = user.id;

        res.json({
            message: "Login successful!"
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Something went wrong."
        });
    }
});


// Protected Dashboard
app.get("/dashboard", (req, res) => {

    if (!req.session.userId) {
        return res.status(401).json({
            error: "You must login first."
        });
    }

    res.json({
        message: "Welcome! You are authenticated."
    });
});


// Logout
app.post("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            return res.status(500).json({
                error: "Logout failed."
            });
        }

        res.json({
            message: "Logged out successfully."
        });
    });
});


// Start server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
