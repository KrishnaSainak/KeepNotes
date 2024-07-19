const express = require('express');
const app = express();
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

app.use(express.static('public'));

const JWT_SECRET = 'your_jwt_secret_abcd';

app.use(express.json());
app.use(cookieParser());

const db = new sqlite3.Database('./Users.sqlite');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    `);
});

app.get('/',authenticateToken,(req, res) => {
    res.sendFile(__dirname + '/public/keepNotes.html');
});
app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/public/keepSignup.html');
});
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/keepLogin.html');
});

// Signup endpoint
app.post('/signup', (req, res) => {
    const { username, password } = req.body
    signup(username, password, (err, user) => {
        if (err) {
            return res.status(400).json({ error: err });
        }
        res.json({ message: 'User signed up successfully', user });
    });
});

function signup(username, password, callback){
    // Hash password using bcryptjs
    const bcrypt = require('bcryptjs');
    const saltRounds = 10; // Number of salt rounds for hashing
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return callback(err);
            }
            // Insert user into 'users' table
            const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
            db.run(sql, [username, hashedPassword], function(err) {
                if (err) {
                    console.error('Error inserting user:');
                    return callback(err);
                }
                console.log(`User ${username} created with ID ${this.lastID}`);
                callback(null, { id: this.lastID, username });
            });
        });
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Call login function passing database connection and callback function
    login(username, password, (err, user, error) => {
        if (err) {
            console.error('Login error:');
            return res.status(400).json({ error: 'Internal server error' });
        }
        if (!user) {
            return res.status(401).json({ error: error.message });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        res.cookie('jwt', token, { httpOnly: true, maxAge: 3600000 }); // maxAge is in milliseconds (1 hour)

        // Send token as response
        res.json({ message: 'Login successful', token });
    });
});

function login(username, password, callback){
    // Retrieve user from 'users' table
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) {
            console.error('Error retrieving user:', err);
            return callback(err);
        }
        if (!user) {
            return callback(null, null, { message: 'User not found' });
        }
        // Compare hashed password with input password
        const bcrypt = require('bcryptjs');
        bcrypt.compare(password, user.password, (bcryptErr, result) => {
            if (bcryptErr || !result) {
                return callback(null, null, { message: 'Invalid username or password' });
            }
            callback(null, { id: user.id, username });
        });
    });
};

function authenticateToken(req, res, next) {
    const token = req.cookies.jwt;

    if (!token) {
        // Redirect to login page if token is not found
        return res.redirect('/login');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next(); // Pass the execution to the next middleware
    });
}

app.listen(3000, () => {
    console.log(`Server is running on http://localhost:${3000}`);
});