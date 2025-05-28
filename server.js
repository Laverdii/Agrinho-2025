const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors({ origin: 'http://localhost:5173' })); // Allow requests from Vite's default port
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        console.error('Could not connect to database', err);
        process.exit(1);
    } else {
        console.log('Connected to SQLite database');
    }
});

// Create users table
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`, (err) => {
    if (err) {
        console.error('Could not create users table', err);
    } else {
        console.log('Users table created or already exists');
    }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    console.log('Register attempt:', { email, password }); // Debug log

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword],
            function (err) {
                if (err) {
                    console.error('Database error:', err); // Debug error
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ message: 'Email already exists' });
                    }
                    return res.status(500).json({ message: 'Error registering user' });
                }
                console.log('User registered:', email); // Debug success
                res.status(201).json({ message: 'User registered successfully' });
            }
        );
    } catch (error) {
        console.error('Error hashing password:', error); // Debug error
        res.status(500).json({ message: 'Error hashing password' });
    }
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', { email }); // Debug log

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Database error:', err); // Debug error
            return res.status(500).json({ message: 'Error accessing database' });
        }
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid password' });
            }
            console.log('Login successful:', email); // Debug success
            res.status(200).json({ message: 'Login successful' });
        } catch (error) {
            console.error('Error comparing password:', error); // Debug error
            res.status(500).json({ message: 'Error during login' });
        }
    });
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});