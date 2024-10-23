const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');


const app = express();
app.use(bodyParser.json());

const SECRET_KEY = 'your_jwt_secret_key'; // Replace with a secure secret in production


const db = new sqlite3.Database('./db/finance.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the SQLite database.');
});


db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('income', 'expense'))
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
            category INTEGER NOT NULL,
            amount REAL NOT NULL,
            date TEXT NOT NULL,
            description TEXT,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(category) REFERENCES categories(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
});

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized, no token provided' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user; // Attach user info to the request
        next();
    });
};


app.post('/register', [
    body('username').notEmpty(),
    body('password').isLength({ min: 6 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, hashedPassword], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'User registered successfully' });
    });
});

app.post('/login', [
    body('username').notEmpty(),
    body('password').notEmpty()
], (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});


app.post('/transactions', authenticateToken, [
    body('type').isIn(['income', 'expense']),
    body('category').isInt(),
    body('amount').isFloat({ gt: 0 }),
    body('date').isISO8601(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { type, category, amount, date, description } = req.body;
    const query = `INSERT INTO transactions (type, category, amount, date, description, user_id) VALUES (?, ?, ?, ?, ?, ?)`;
    db.run(query, [type, category, amount, date, description, req.user.id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID });
    });
});


app.get('/transactions', authenticateToken, (req, res) => {
    const query = `SELECT * FROM transactions WHERE user_id = ?`;
    db.all(query, [req.user.id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});


app.get('/transactions/:id', authenticateToken, (req, res) => {
    const query = `SELECT * FROM transactions WHERE id = ? AND user_id = ?`;
    db.get(query, [req.params.id, req.user.id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ message: 'Transaction not found' });
        }
        res.json(row);
    });
});


app.put('/transactions/:id', authenticateToken, [
    body('type').isIn(['income', 'expense']),
    body('category').isInt(),
    body('amount').isFloat({ gt: 0 }),
    body('date').isISO8601(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { type, category, amount, date, description } = req.body;
    const query = `UPDATE transactions SET type = ?, category = ?, amount = ?, date = ?, description = ? WHERE id = ? AND user_id = ?`;
    db.run(query, [type, category, amount, date, description, req.params.id, req.user.id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Transaction not found' });
        }
        res.json({ message: 'Transaction updated successfully' });
    });
});


app.delete('/transactions/:id', authenticateToken, (req, res) => {
    const query = `DELETE FROM transactions WHERE id = ? AND user_id = ?`;
    db.run(query, [req.params.id, req.user.id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Transaction not found' });
        }
        res.json({ message: 'Transaction deleted successfully' });
    });
});


app.get('/summary', authenticateToken, (req, res) => {
    const { from, to, category } = req.query;
    let query = `SELECT type, SUM(amount) as total FROM transactions WHERE user_id = ?`;
    let params = [req.user.id];

    if (from && to) {
        query += ` AND date BETWEEN ? AND ?`;
        params.push(from, to);
    }

    if (category) {
        query += ` AND category = ?`;
        params.push(category);
    }

    query += ` GROUP BY type`;

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        let income = 0;
        let expense = 0;

        rows.forEach(row => {
            if (row.type === 'income') {
                income = row.total;
            } else if (row.type === 'expense') {
                expense = row.total;
            }
        });

        const balance = income - expense;
        res.json({
            totalIncome: income || 0,
            totalExpense: expense || 0,
            balance: balance || 0
        });
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
