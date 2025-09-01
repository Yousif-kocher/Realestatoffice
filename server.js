// =========================
// Import required modules
// =========================
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path'); // Node.js module for file paths
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');
const cookieParser = require('cookie-parser');
require('dotenv').config();

// =========================
// Initialize Express
// =========================
const app = express();
const PORT = process.env.PORT || 4000;

// =========================
// Middleware
// =========================

// Enable CORS (Cross-Origin Resource Sharing) so frontend can call backend
app.use(cors({
  
  credentials: true
}));

// Parse cookies for session handling
app.use(cookieParser());

// Parse incoming request bodies
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configure sessions for authentication
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // change to true if running HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// =========================
// Authentication middleware
// =========================

// Require user to be logged in
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Authentication required' });
  }
}

// Require user to be admin
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Admin access required' });
  }
}

// =========================
// Serve static frontend files
// =========================
app.use(express.static(path.join(__dirname, 'frontend')));

// Protect all HTML pages except login/register
app.get(/.*/, (req, res, next) => {
  // Only process .html files
  if (!req.path.endsWith('.html')) {
    return next();
  }

  const requestPath = req.path;

  // Allow login/register without authentication
  if (requestPath.endsWith('login.html') || requestPath.endsWith('register.html')) {
    return next();
  }

  // Redirect to login if user not authenticated
  if (!req.session.user) {
    return res.redirect('/login.html');
  }

  next();
});

// =========================
// Configure file uploads (multer)
// =========================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = 'frontend/uploads/profiles';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// =========================
// Database (MySQL) setup
// =========================
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'myrealestate'
});

// Connect and create tables
db.connect((err) => {
  if (err) {
    console.error('Database connection failed: ' + err.stack);
    return;
  }
  console.log('Connected to database as id ' + db.threadId);

  // Users table
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      name VARCHAR(100) NOT NULL,
      phone VARCHAR(20),
      profile_image VARCHAR(255),
      approved TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;
  db.execute(createTableQuery);

  // Map markers table
  const createMarkersTableQuery = `
    CREATE TABLE IF NOT EXISTS map_markers (
      id INT AUTO_INCREMENT PRIMARY KEY,
      x_coordinate DOUBLE NOT NULL,
      y_coordinate DOUBLE NOT NULL,
      color VARCHAR(20) NOT NULL,
      note TEXT,
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;
  db.execute(createMarkersTableQuery);
});

// =========================
// Authentication routes
// =========================

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check admin from .env file
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const userData = { id: 0, username, name: 'Administrator', isAdmin: true };
    req.session.user = userData;
    return req.session.save(() => res.json({ success: true, user: userData }));
  }

  // Check database user
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.execute(sql, [username], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });

    if (results.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const user = results[0];

    // Must be approved
    if (user.approved !== 1) {
      return res.status(401).json({ success: false, message: 'Your account is pending admin approval.' });
    }

    // Compare password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ success: false, message: 'Server error' });
      if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      const userData = {
        id: user.id,
        username: user.username,
        name: user.name,
        phone: user.phone,
        profile_image: user.profile_image,
        isAdmin: false
      };
      req.session.user = userData;
      req.session.save(() => res.json({ success: true, user: userData }));
    });
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logout successful' });
  });
});

// Current session
app.get('/api/session', (req, res) => {
  if (req.session.user) {
    res.json({ success: true, user: req.session.user });
  } else {
    res.json({ success: false, message: 'No active session' });
  }
});

// =========================
// User management routes (Admin only)
// =========================

// Get all users
app.get('/users', requireAdmin, (req, res) => {
  const sql = 'SELECT id, username, name, phone, profile_image, approved, created_at FROM users ORDER BY created_at DESC';
  db.execute(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, users: results });
  });
});

// Approve user
app.post('/users/:id/approve', requireAdmin, (req, res) => {
  const sql = 'UPDATE users SET approved = 1 WHERE id = ?';
  db.execute(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (results.affectedRows === 0) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: 'User approved successfully' });
  });
});

// Delete user
app.delete('/users/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;
  const getSql = 'SELECT profile_image FROM users WHERE id = ?';

  db.execute(getSql, [userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ success: false, message: 'User not found' });

    // Delete image if exists
    const user = results[0];
    if (user.profile_image) {
      const imagePath = path.join(__dirname, 'frontend', user.profile_image);
      if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
    }

    // Delete user
    const deleteSql = 'DELETE FROM users WHERE id = ?';
    db.execute(deleteSql, [userId], (err) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });
      res.json({ success: true, message: 'User deleted successfully' });
    });
  });
});

// =========================
// Registration
// =========================
app.post('/register', upload.single('profile_image'), (req, res) => {
  const { username, password, name, phone } = req.body;
  const profile_image = req.file ? 'uploads/profiles/' + req.file.filename : null;

  const checkSql = 'SELECT id FROM users WHERE username = ?';
  db.execute(checkSql, [username], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (results.length > 0) return res.status(400).json({ success: false, message: 'Username already exists' });

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ success: false, message: 'Error hashing password' });

      const insertSql = 'INSERT INTO users (username, password, name, phone, profile_image, approved) VALUES (?, ?, ?, ?, ?, ?)';
      db.execute(insertSql, [username, hashedPassword, name, phone, profile_image, 0], (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Error creating user' });
        res.json({ success: true, message: 'Registration successful. Please wait for admin approval.' });
      });
    });
  });
});

// =========================
// Map markers API (Protected)
// =========================

// Get all markers
app.get('/api/markers', requireAuth, (req, res) => {
  const sql = 'SELECT * FROM map_markers ORDER BY created_at DESC';
  db.execute(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, markers: results });
  });
});

// Add marker
app.post('/api/markers', requireAuth, (req, res) => {
  const { x, y, color, note } = req.body;
  const userId = req.session.user.id;

  if (!x || !y || !color) {
    return res.status(400).json({ 
      success: false, 
      message: 'Missing required fields: x, y, color' 
    });
  }

  // التحقق أولاً من وجود المستخدم
  const checkUserSql = 'SELECT id FROM users WHERE id = ?';
  db.execute(checkUserSql, [userId], (err, userResults) => {
    if (err || userResults.length === 0) {
      console.error('User not found:', err);
      return res.status(400).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // إذا وجد المستخدم، نضيف العلامة
    const sql = 'INSERT INTO map_markers (x_coordinate, y_coordinate, color, note, created_by) VALUES (?, ?, ?, ?, ?)';
    
    db.execute(sql, [x, y, color, note, userId], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error: ' + err.message 
        });
      }

      // Return newly created marker
      const getSql = 'SELECT * FROM map_markers WHERE id = ?';
      db.execute(getSql, [results.insertId], (err, markerResults) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + err.message 
          });
        }
        
        res.json({ 
          success: true, 
          marker: markerResults[0] 
        });
      });
    });
  });
});

// Delete one marker
app.delete('/api/markers/:id', requireAuth, (req, res) => {
  const sql = 'DELETE FROM map_markers WHERE id = ?';
  db.execute(sql, [req.params.id], (err) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, message: 'Marker deleted successfully' });
  });
});

// Delete all markers
app.delete('/api/markers', requireAuth, (req, res) => {
  const sql = 'DELETE FROM map_markers';
  db.execute(sql, (err) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, message: 'All markers deleted successfully' });
  });
});

// Count markers
app.get('/api/markers/count', requireAuth, (req, res) => {
  let sql = 'SELECT COUNT(*) as count FROM map_markers';
  let params = [];
  if (req.query.color) {
    sql += ' WHERE color = ?';
    params.push(req.query.color);
  }
  db.execute(sql, params, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, count: results[0].count });
  });
});

// Count users (Admin only)
app.get('/api/users/count', requireAdmin, (req, res) => {
  let sql = 'SELECT COUNT(*) as count FROM users';
  let params = [];
  if (req.query.approved !== undefined) {
    sql += ' WHERE approved = ?';
    params.push(req.query.approved === 'true' ? 1 : 0);
  }
  db.execute(sql, params, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    res.json({ success: true, count: results[0].count });
  });
});

// =========================
// Root endpoint
// =========================
app.get('/', (req, res) => {
  res.send('Server is running! Go to <a href="/login.html">login page</a>');
});

// =========================
// Start server
// =========================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access the application at: http://localhost:${PORT}`);
  console.log(`Admin username: ${process.env.ADMIN_USERNAME || 'admin'}`);
});


