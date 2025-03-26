require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const app = express();
const PizZip = require('pizzip');
const Docxtemplater = require('docxtemplater');
const JSZipUtils = require('jszip-utils');
const cloudinary = require('cloudinary').v2;
// Configuration
const MAX_USER_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;
const USER_LOCK_DURATION = 15 * 60 * 1000; // 15 minutes
const IP_BLOCK_DURATION = 60 * 60 * 1000;  // 1 hour

const RedisStore = require('connect-redis').default;
const redis = require('redis');
const redisClient = redis.createClient({
  url: `redis://default:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
});

redisClient.on('error', err => console.error('Redis Client Error:', err));
redisClient.connect().then(() => console.log('Connected to Redis'));

// Encode the password to handle special characters like @

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
}));
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET || 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 86400000, httpOnly: true, sameSite: 'lax' }
}));

// Ensure Redis is ready before routes
app.use((req, res, next) => {
  if (!redisClient.isOpen) {
    return res.status(503).json({ error: 'Redis not connected' });
  }
  next();
});

const rateLimit = require('express-rate-limit');
app.use('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 50 }));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use((req, res, next) => {
  console.log('--- Request Start ---');
  console.log('URL:', req.url);
  console.log('Method:', req.method);
  console.log('Headers:', req.headers);
  console.log('Cookies:', req.headers.cookie);
  console.log('Session ID:', req.sessionID);
  console.log('Session Data:', req.session);
  console.log('---');
  next();
});

console.log('Registering routes...');

// Database connection with foreign keys enabled
const db = new sqlite3.Database(process.env.DB_PATH, (err) => {
  if (err) console.error('Database error:', err);
  else {
    console.log('Connected to SQLite database');
    db.run('PRAGMA foreign_keys = ON', (err) => {
      if (err) console.error('Error enabling foreign keys:', err);
      else console.log('Foreign keys enabled');
    });
  }
});

// File upload setup
const uploadDir = process.env.UPLOAD_PATH;
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const { CloudinaryStorage } = require('multer-storage-cloudinary');
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
console.log('Cloudinary config:', cloudinary.config());

const dangerousExtensions = ['exe', 'bat', 'sh', 'cmd', 'dll', 'js', 'vbs', 'ps1'];
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { 
    folder: 'case_files', 
    public_id: (req, file) => `${req.params.id}/${file.originalname.split('.')[0]}-${Date.now()}`,
    resource_type: (req, file) => {
      const fileExt = file.originalname.split('.').pop().toLowerCase();
      if (dangerousExtensions.includes(fileExt)) {
        throw new Error(`File type .${fileExt} is not allowed`);
      }
      return ['docx', 'doc', 'pdf', 'txt', 'zip'].includes(fileExt) ? 'raw' : 'auto';
    }
  }
});
const upload = multer({ storage });

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Database schema initialization
async function setupDatabase() {
  let db;
  try {
    db = await initDb();

    // Create tables
    await db.run(`
      CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        dateOccurrence TEXT,
        type TEXT,
        status TEXT,
        user TEXT,
        officerAdvisedOfReferral TEXT,
        section24ReplyToRA TEXT
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS case_officers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        caseId TEXT,
        officer TEXT,
        staffNo TEXT,
        summary TEXT,
        dateOccurrence TEXT,
        type TEXT,
        status TEXT,
        breachOfStandards TEXT,
        investigator TEXT,
        severity TEXT,
        section17Date TEXT,
        policeFriend TEXT,
        section18Date TEXT,
        interviewDate TEXT,
        ioReportDate TEXT,
        raAssessment TEXT,
        officerAdvisedOfReferral TEXT,
        section24ReplyToRA TEXT
        misconductMeetingDate TEXT,
        misconductOutcome TEXT,
        grossMisconductHearingDate TEXT,
        hearingOutcome TEXT,
        appealMade TEXT,
        appealLetterDate TEXT,
        appealHearingDate TEXT,
        appealOutcome TEXT,
        comments TEXT,
        FOREIGN KEY (caseId) REFERENCES cases(id) ON DELETE CASCADE
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT,
        oneTimePassword TEXT,
        email TEXT
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS case_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        caseId TEXT,
        filePath TEXT,
        originalName TEXT,
        uploadDate TEXT DEFAULT CURRENT_TIMESTAMP,
        uploadedBy TEXT,
        FOREIGN KEY (caseId) REFERENCES cases(id) ON DELETE CASCADE
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        error_description TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS officers (
        staffNo TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        photoPath TEXT,
        joiningDate TEXT,
        rank TEXT,
        dateOfBirth TEXT,
        createdDate TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.run(`
      INSERT INTO case_officers (caseId)
      SELECT id FROM cases 
      WHERE NOT EXISTS (SELECT 1 FROM case_officers WHERE case_officers.caseId = cases.id)
    `).catch(err => console.error('Migration error (minimal):', err));

    await db.run(`
      CREATE TABLE IF NOT EXISTS user_case_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        caseId TEXT NOT NULL,
        canView BOOLEAN DEFAULT 1,
        canEdit BOOLEAN DEFAULT 0,
        assignedBy TEXT NOT NULL,
        assignedDate TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
        FOREIGN KEY (caseId) REFERENCES cases(id) ON DELETE CASCADE,
        UNIQUE(username, caseId)
      )
    `);

    // Initial data setup
    const caseCount = await db.get('SELECT COUNT(*) as count FROM cases');
    if (caseCount.count === 0) {
      await db.run(
        'INSERT INTO cases (id, dateOccurrence, type, status, user) VALUES (?, ?, ?, ?, ?)',
        ['PSD/CASE-001', '2025-01-01', 'Misconduct', 'Open', 'admin']
      ).catch(err => console.error('Error inserting initial case:', err));

      await db.run(
        'INSERT INTO case_officers (caseId, officer, staffNo) VALUES (?, ?, ?)',
        ['PSD/CASE-001', 'John Doe', '12345']
      ).catch(err => console.error('Error inserting initial case officer:', err));
    }

    const officerCount = await db.get('SELECT COUNT(*) as count FROM officers');
    if (officerCount.count === 0) {
      await db.run(
        'INSERT INTO officers (staffNo, name) VALUES (?, ?)',
        ['12345', 'John Doe']
      ).catch(err => console.error('Error inserting initial officer:', err));
    }

    const userCount = await db.get('SELECT COUNT(*) as count FROM users');
    if (userCount.count === 0) {
      const adminHash = await bcrypt.hash('password123', 10).catch(err => {
        console.error('Hash error (admin):', err);
        throw err;
      });
      await db.run(
        'INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
        ['admin', adminHash, 'admin', 'admin@example.com']
      ).catch(err => console.error('Error inserting admin user:', err));

      const user1Hash = await bcrypt.hash('pass456', 10).catch(err => {
        console.error('Hash error (user1):', err);
        throw err;
      });
      await db.run(
        'INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
        ['user1', user1Hash, 'psd admin', 'user1@example.com']
      ).catch(err => console.error('Error inserting user1:', err));
    }

    console.log('Database setup complete');
  } catch (err) {
    console.error('Database setup error:', err);
  } finally {
    if (db) await db.close().catch(err => console.error('DB close error:', err));
  }
}

// Export for use in main server file
module.exports = { initDb, setupDatabase };

// Authentication middleware

function isAuthenticated(req, res, next) {
  console.log('isAuthenticated - Session ID:', req.sessionID, 'User:', req.session.user, 'Session Data:', req.session);
  if (req.session && req.session.user) {
    console.log('User authenticated:', req.session.user);
    return next();
  }
  console.log('Authentication failed - No user in session');
  res.status(401).json({ error: 'Not authenticated' });
}

function restrictToAdminOrPSDAdmin(req, res, next) {
  console.log('restrictToAdminOrPSDAdmin Check - User:', req.session.user, 'Role:', req.session.role);
  if (req.session.role === 'admin' || req.session.role === 'psd admin') {
    next();
  } else {
    console.log('Access denied - Insufficient permissions:', req.session.user, 'Role:', req.session.role);
    res.status(403).json({ error: 'Permission denied: Admin or PSD Admin access required' });
  }
}

function restrictToStatsViewers(req, res, next) {
  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(403).json({ error: 'User not found' });
    const allowedRoles = ['admin', 'psd admin', 'auditor'];
    if (!allowedRoles.includes(row.role.toLowerCase())) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  });
}

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'File upload error', details: err.message });
  } else if (err.message.includes('File type')) {
    return res.status(400).json({ error: 'Unsupported file type', details: err.message });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.get('/cases/:id', isAuthenticated, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const user = req.session.user;
  console.log('GET /cases/:id - ID:', id, 'Inquisitor:', user);

  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  let db;
  try {
    db = await initDb();
    const rows = await db.all(`
      SELECT c.id AS caseId, c.user, co.*, cf.id AS fileId, cf.filePath, cf.originalName, cf.uploadDate, cf.uploadedBy
      FROM cases c
      LEFT JOIN case_officers co ON c.id = co.caseId
      LEFT JOIN case_files cf ON c.id = cf.caseId
      WHERE c.id = ?
    `, [id]);

    if (!rows.length) {
      console.log('Case not found:', id);
      return res.status(404).json({ error: 'Case not found' });
    }

    const caseData = { id: rows[0].caseId, user: rows[0].user, officers: [], files: [] };
    const officerMap = new Map(); // Deduplicate officers by id
    const fileMap = new Map();    // Deduplicate files by filePath

    for (const row of rows) {
      if (row.officer && !officerMap.has(row.id)) {
        officerMap.set(row.id, {
          id: row.id,
          caseId: row.caseId,
          officer: row.officer,
          summary: row.summary,
          breachOfStandards: row.breachOfStandards,
          investigator: row.investigator,
          severity: row.severity,
          section17Date: row.section17Date,
          policeFriend: row.policeFriend,
          section18Date: row.section18Date,
          interviewDate: row.interviewDate,
          ioReportDate: row.ioReportDate,
          raAssessment: row.raAssessment,
          misconductMeetingDate: row.misconductMeetingDate,
          misconductOutcome: row.misconductOutcome,
          grossMisconductHearingDate: row.grossMisconductHearingDate,
          hearingOutcome: row.hearingOutcome,
          appealMade: row.appealMade,
          appealLetterDate: row.appealLetterDate,
          appealHearingDate: row.appealHearingDate,
          appealOutcome: row.appealOutcome,
          comments: row.comments,
          staffNo: row.staffNo,
          type: row.type,
          status: row.status,
          officerAdvisedOfReferral: row.officerAdvisedOfReferral,
          section24ReplyToRA: row.section24ReplyToRA,
          dateOccurrence: row.dateOccurrence
        });
      }
      if (row.fileId && !fileMap.has(row.filePath)) {
        fileMap.set(row.filePath, {
          id: row.fileId,
          caseId: row.caseId,
          filePath: row.filePath,
          originalName: row.originalName,
          uploadDate: row.uploadDate,
          uploadedBy: row.uploadedBy
        });
      }
    }
    caseData.officers = [...officerMap.values()];
    caseData.files = [...fileMap.values()];
    console.log('Sending case data:', JSON.stringify(caseData, null, 2));
    
    // Add audit logging
    await logAction(user, 'View Case', `Viewed case ${id}`);
    
    res.json(caseData);
  } catch (error) {
    console.error('GET error:', error.stack);
    res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
    if (db) await db.close().catch(err => console.error('DB close error:', err.stack));
  }
});

function isAdmin(req, res, next) {
  console.log('isAdmin Check - Session ID:', req.sessionID, 'User:', req.session.user, 'Role:', req.session.role);
  if (req.session.role === 'admin') {
    console.log('Admin Authorized:', req.session.user);
    next();
  } else {
    console.log('Admin Check Failed:', req.session.user, 'Role:', req.session.role);
    res.status(403).json({ error: 'Admin access required' });
  }
}

function restrictToPSDOrHigher(req, res, next) {
  console.log('restrictToPSDOrHigher Check - User:', req.session.user, 'Role:', req.session.role);
  if (req.session.role === 'admin' || req.session.role === 'psd admin') {
    return next();
  }
  if (req.session.role === 'psd') {
    const caseId = req.params.id ? decodeURIComponent(req.params.id) : null;
    if (!caseId && req.method === 'POST') {
      return next(); // Allow PSD users to create new cases
    }
    if (caseId) {
      db.get(`
        SELECT canEdit FROM user_case_permissions
        WHERE username = ? AND caseId = ?
      `, [req.session.user, caseId], (err, perm) => {
        if (err) return res.status(500).json({ error: 'Database error: Unable to check permissions' });
        if (!perm) {
          db.get('SELECT user FROM cases WHERE id = ?', [caseId], (err, caseRow) => {
            if (err) return res.status(500).json({ error: 'Database error: Unable to check case ownership' });
            if (caseRow && caseRow.user === req.session.user) return next(); // Original owner
            return res.status(403).json({ error: 'Permission denied: No access to this case' });
          });
        } else if (req.method === 'PUT' && !perm.canEdit) {
          return res.status(403).json({ error: 'Permission denied: No edit access to this case' });
        } else {
          return next();
        }
      });
    } else {
      return next(); // Allow listing cases; we'll filter in the GET route
    }
  } else {
    return res.status(403).json({ error: 'PSD, PSD Admin, or Admin access required' });
  }
}

function isPSDAdmin(req, res, next) {
  console.log('isPSDAdmin Check - Session ID:', req.sessionID, 'User:', req.session.user, 'Role:', req.session.role);
  if (req.session.role === 'admin' || req.session.role === 'psd admin') {
    next();
  } else {
    res.status(403).json({ error: 'PSD Admin or Admin access required' });
  }
}

// Helper to get client IP
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

async function logAction(user, action, details) {
  let db;
  try {
    db = await initDb();
    const result = await db.run(
      'INSERT INTO audit_logs (user, action, details) VALUES (?, ?, ?)',
      [user || 'unknown', action, details || '']
    );
    console.log(`Audit logged - ID: ${result.lastID}, User: ${user}, Action: ${action}, Details: ${details}`);
  } catch (error) {
    console.error('Audit log error:', error.stack);
    throw error; // For debugging
  } finally {
    if (db) await db.close();
  }
}

app.delete('/officers/:caseId/:officerId', isAuthenticated, async (req, res) => {
  const { caseId, officerId } = req.params;
  console.log(`DELETE /officers/${caseId}/${officerId} by user:`, req.session.user);
  let db;
  try {
    db = await initDb();
    const result = await db.run('DELETE FROM case_officers WHERE caseId = ? AND id = ?', [caseId, officerId]);
    console.log(`Officer ${officerId} deleted from case ${caseId}, Rows affected:`, result.changes);
    if (result.changes === 0) return res.status(404).json({ error: 'Officer not found' });
    
    const officerCount = await db.get('SELECT COUNT(*) as count FROM case_officers WHERE caseId = ?', [caseId]);
    if (officerCount.count === 0) {
      await db.run('DELETE FROM cases WHERE id = ?', [caseId]);
      await logAction(req.session.user, 'Delete Case', `Auto-deleted case ${caseId} (no officers remaining)`);
      return res.json({ message: 'Officer and case deleted successfully' });
    }
    
    await logAction(req.session.user, 'Delete Officer', `Deleted officer ${officerId} from case ${caseId}`);
    res.status(200).json({ message: 'Officer deleted successfully' });
  } catch (err) {
    console.error('Error deleting officer:', err);
    res.status(500).json({ error: 'Database error: Unable to delete officer' });
  } finally {
    if (db) await db.close();
  }
});


console.log('Routes registered.');

// List all cases (keep this from your original)
app.get('/cases', isAuthenticated, (req, res) => {
  console.log('GET /cases reached by:', req.session.user);
  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to verify user role' });
    if (!row) return res.status(403).json({ error: 'User not found' });

    const userRole = row.role;
    let query = 'SELECT id, user FROM cases';
    let params = [];
    if (userRole === 'psd') {
      query = `
        SELECT c.id, c.user, ucp.canView, ucp.canEdit
        FROM cases c
        LEFT JOIN user_case_permissions ucp ON c.id = ucp.caseId AND ucp.username = ?
        WHERE c.user = ? OR ucp.canView = 1
      `;
      params = [req.session.user, req.session.user];
    }

    db.all(query, params, (err, caseRows) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to fetch cases' });
      if (!caseRows.length) return res.json([]);

      const casesWithDetails = caseRows.map(row => ({
        id: row.id,
        user: row.user,
        files: [],
        officers: [],
        ...(userRole === 'psd' ? {
          canView: row.canView != null ? row.canView : (row.user === req.session.user ? 1 : 0),
          canEdit: row.canEdit != null ? row.canEdit : (row.user === req.session.user ? 1 : 0)
        } : {})
      }));

      let completed = 0;
      const total = caseRows.length;

      caseRows.forEach((caseItem, index) => {
        db.all('SELECT caseId, filePath, originalName, uploadDate, uploadedBy FROM case_files WHERE caseId = ?', [caseItem.id], (err, files) => {
          if (err) console.error('Error fetching files for', caseItem.id, ':', err);
          else casesWithDetails[index].files = files || [];
          db.all('SELECT * FROM case_officers WHERE caseId = ?', [caseItem.id], (err, officers) => {
            if (err) console.error('Error fetching officers for', caseItem.id, ':', err);
            else casesWithDetails[index].officers = officers || [];
            completed++;
            if (completed === total) {
              console.log('Sending cases:', casesWithDetails);
              res.json(casesWithDetails.sort((a, b) => a.id.localeCompare(b.id)));
            }
          });
        });
      });
    });
  });
});

console.log('Routes registered.');

// Remaining routes
app.post('/audit/view-case', isAuthenticated, async (req, res) => {
  const { caseId, officerId, allOfficers } = req.body;
  const details = `Viewed case ${caseId}${officerId ? `, Officer ID: ${officerId}` : ''}${allOfficers ? ' (all officers)' : ''}`;
  console.log('Audit view-case - User:', req.session.user, 'Details:', details);
  await logAction(req.session.user, 'View Case', details);
  res.json({ message: 'Case view logged' });
});

app.post('/audit/search-staff', isAuthenticated, (req, res) => {
  const { staffNo } = req.body;
  logAction(req.session.user, 'Search Staff', `Searched for staff number ${staffNo}`);
  res.json({ message: 'Staff search logged' });
});

app.post('/audit/view-file', isAuthenticated, (req, res) => {
  const { filePath, fileName } = req.body;
  logAction(req.session.user, 'View File', `Viewed file ${fileName} at ${filePath}`);
  res.json({ message: 'File view logged' });
});

app.post('/audit/extract', isAuthenticated, (req, res) => {
  const { type, identifier } = req.body;
  logAction(req.session.user, 'Extract', `Extracted ${type} ${identifier}`);
  res.json({ message: 'Extraction logged' });
});

app.post('/report-error', isAuthenticated, (req, res) => {
  const { errorDescription } = req.body;
  const user = req.session.user;

  db.run('INSERT INTO error_logs (user, error_description) VALUES (?, ?)', [user, errorDescription], (err) => {
    if (err) {
      console.error('Error logging to database:', err);
      return res.status(500).json({ error: 'Failed to log error' });
    }
    db.get('SELECT email FROM users WHERE role = "admin" LIMIT 1', (err, row) => {
      if (err || !row) {
        console.error('Error fetching admin email:', err);
        return res.status(500).json({ error: 'Failed to send error report email' });
      }
      const adminEmail = row.email;
      const mailOptions = {
        from: 'nathanvictory84@gmail.com',
        to: adminEmail,
        subject: 'POLARIS RMS Error Report',
        text: `User ${user} reported an error:\n\n${errorDescription}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Email sending error:', error);
          return res.status(500).json({ error: 'Failed to send error report email' });
        }
        console.log('Error report email sent:', info.response);
        res.json({ message: 'Error reported successfully' });
      });
    });
  });
});

app.get('/error-logs', isAdmin, (req, res) => {
  db.all('SELECT * FROM error_logs ORDER BY timestamp DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch error logs' });
    res.json(rows);
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);
  console.log('Login attempt:', { username, password: '[hidden]', ip });

  let db;
  try {
    db = await initDb();
    console.log('Database opened');

    let ipRow = await db.get('SELECT * FROM ip_blocks WHERE ip = ?', [ip]);
    console.log('IP block check:', ipRow || 'No block found');

    const now = Date.now();
    if (ipRow && ipRow.blocked) {
      const timeLeft = ipRow.block_time + IP_BLOCK_DURATION - now;
      if (timeLeft > 0) {
        console.log('IP blocked, time left:', timeLeft);
        return res.status(403).json({ error: 'ip_blocked', blockRemaining: timeLeft });
      }
      await db.run('UPDATE ip_blocks SET blocked = FALSE, failed_attempts = 0, block_time = NULL WHERE ip = ?', [ip]);
      console.log('IP block cleared');
    }

    let user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    console.log('User fetched:', user ? { username: user.username, oneTimePassword: user.oneTimePassword } : 'Not found');
    if (!user) {
      await db.run('INSERT OR REPLACE INTO ip_blocks (ip, failed_attempts, blocked, block_time) VALUES (?, COALESCE((SELECT failed_attempts FROM ip_blocks WHERE ip = ?) + 1, 1), ?, ?)',
        [ip, ip, false, null]);
      console.log('IP attempts incremented');
      checkIPBlock(ip, res);
      console.log('User not found, returning 401');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.locked) {
      const timeLeft = user.lock_time + USER_LOCK_DURATION - now;
      if (timeLeft > 0) {
        console.log('User locked, time left:', timeLeft);
        return res.status(403).json({ error: 'user_locked', lockRemaining: timeLeft });
      }
      await db.run('UPDATE users SET locked = FALSE, failed_attempts = 0, lock_time = NULL WHERE username = ?', [username]);
      console.log('User lock cleared');
      user.locked = false;
      user.failed_attempts = 0;
      user.lock_time = null;
    }

    const match = await bcrypt.compare(password, user.password);
    console.log('Password match:', match, 'Stored hash:', user.password);

    if (!match) {
      console.log('Password mismatch, incrementing attempts');
      incrementAttempts(username, ip, res);
      return;
    }

    // Handle oneTimePassword as string or number
    if (user.oneTimePassword == '1' || user.oneTimePassword === 1) { // Loose equality or explicit string check
      console.log('Login success with temp password');
      await new Promise((resolve, reject) => resetAttempts(username, ip, err => err ? reject(err) : resolve()));
      req.session.user = username;
      req.session.role = user.role || 'default';
      req.session.name = user.name || 'Unknown';
      req.session.needsPasswordReset = true;
      await req.session.save();
      console.log('Login Success (Temp Password):', username, 'Session ID:', req.sessionID);
      logAction(username, 'Login', 'Logged in with temporary password');
      const response = { loggedIn: true, needsReset: true, role: user.role, name: user.name };
      console.log('Sending response:', response);
      return res.json(response);
    }

    console.log('Login success with regular password');
    await new Promise((resolve, reject) => resetAttempts(username, ip, err => err ? reject(err) : resolve()));
    req.session.user = username;
    req.session.role = user.role || 'default';
    req.session.name = user.name || 'Unknown';
    req.session.needsPasswordReset = false;
    await req.session.save();
    console.log('Login Success (Password):', username, 'Session ID:', req.sessionID);
    logAction(username, 'Login', 'User agreed to disclaimer and logged in');
    const response = { loggedIn: true, needsReset: false, role: user.role, name: user.name };
    console.log('Sending response:', response);
    res.json(response);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    if (db) await db.close();
    console.log('Database closed');
  }
});

app.post('/change-password', async (req, res) => {
  const { username, newPassword } = req.body;
  if (!req.session.user || req.session.user !== username) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  let db;
  try {
    db = await initDb();
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password = ?, oneTimePassword = 0 WHERE username = ?', [hashedPassword, username]);
    console.log('Password changed for:', username);
    logAction(username, 'Password Change', 'User changed password after temporary login');
    req.session.needsPasswordReset = false;
    await req.session.save();
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    if (db) await db.close();
  }
});

// Helper to increment attempts and check thresholds
function incrementAttempts(username, ip, res) {
  db.run('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?', [username], (err) => {
    if (err) console.error('Increment user attempts error:', err);
    db.run('INSERT OR REPLACE INTO ip_blocks (ip, failed_attempts, blocked, block_time) VALUES (?, COALESCE((SELECT failed_attempts FROM ip_blocks WHERE ip = ?) + 1, 1), ?, ?)',
      [ip, ip, false, null], (err) => {
        if (err) console.error('Increment IP attempts error:', err);
        checkIPBlock(ip, res);
      });
    res.status(401).json({ error: 'Invalid credentials' });
  });
}

// Helper to reset attempts on success
function resetAttempts(username, ip, callback) {
  db.run('UPDATE users SET failed_attempts = 0, locked = FALSE, lock_time = NULL WHERE username = ?', [username], (err) => {
    if (err) {
      console.error('Reset user attempts error:', err);
      return callback(err);
    }
    db.run('UPDATE ip_blocks SET failed_attempts = CASE WHEN failed_attempts > 0 THEN failed_attempts - 1 ELSE 0 END, blocked = FALSE, block_time = NULL WHERE ip = ?', [ip], (err) => {
      if (err) {
        console.error('Reset IP attempts error:', err);
        return callback(err);
      }
      callback(null);
    });
  });
}

// Helper to check IP block threshold
function checkIPBlock(ip, res) {
  db.get('SELECT failed_attempts FROM ip_blocks WHERE ip = ?', [ip], (err, row) => {
    if (err) console.error('Check IP block error:', err);
    if (row && row.failed_attempts >= MAX_IP_ATTEMPTS) {
      db.run('UPDATE ip_blocks SET blocked = TRUE, block_time = ? WHERE ip = ?', [Date.now(), ip]);
      res.status(403).json({ error: 'ip_blocked', blockRemaining: IP_BLOCK_DURATION });
    }
  });
}

app.get('/session-check', (req, res) => {
  res.json({ sessionID: req.sessionID, user: req.session.user });
});

app.post('/reset-password', isAuthenticated, (req, res) => {
  const { newPassword } = req.body;
  if (!req.session.needsPasswordReset) {
    return res.status(403).json({ error: 'No password reset required' });
  }
  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Password hashing error' });
    db.run('UPDATE users SET password = ?, oneTimePassword = NULL WHERE username = ?', [hash, req.session.user], (err) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to reset password' });
      req.session.needsPasswordReset = false;
      logAction(req.session.user, 'Password Reset', 'Set new password');
      res.json({ message: 'Password reset successful' });
    });
  });
});

app.post('/request-password-reset', (req, res) => {
  const { username, email } = req.body;

  db.get('SELECT * FROM users WHERE username = ? AND email = ?', [username, email], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to process reset request' });
    if (!user) return res.status(404).json({ error: 'User not found or email does not match' });

    const oneTimePassword = Math.random().toString(36).slice(-8);
    bcrypt.hash(oneTimePassword, 10, (err, hashedTempPassword) => {
      if (err) return res.status(500).json({ error: 'Error hashing password' });

      db.run(
        'UPDATE users SET password = ?, oneTimePassword = ? WHERE username = ?',
        [hashedTempPassword, '1', username],
        (err) => {
          if (err) return res.status(500).json({ error: 'Database error: Unable to update password' });

          const mailOptions = {
            from: 'nathanvictory84@gmail.com',
            to: email,
            subject: 'POLARIS RMS Password Reset',
            text: `Your temporary password is: ${oneTimePassword}\n\nPlease use this to log in and reset your password.`
          };

          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Email sending error:', error);
              return res.status(500).json({ error: 'Failed to send temporary password email' });
            }
            console.log('Email sent:', info.response);
            logAction(username, 'Password Reset Request', `Temporary password sent to ${email}`);
            res.json({ message: 'A temporary password has been sent to your email' });
          });
        }
      );
    });
  });
});

app.post('/logout', (req, res) => {
  logAction(req.session.user, 'Logout', 'User logged out');
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

app.post('/cases', restrictToPSDOrHigher, upload.array('files'), async (req, res) => {
  const {
    id, dateOccurrence, type, status, staffNo, officer, summary, breachOfStandards, investigator, severity,
    section17Date, policeFriend, section18Date, interviewDate, ioReportDate, raAssessment,
    misconductMeetingDate, misconductOutcome, grossMisconductHearingDate, hearingOutcome,
    appealMade, appealLetterDate, appealHearingDate, appealOutcome, comments,
    officerAdvisedOfReferral, section24ReplyToRA
  } = req.body;
  const user = req.session.user;

  if (!id || !staffNo || !officer) {
    return res.status(400).json({ error: 'Case ID, Staff No., and Officer are required' });
  }

  let db;
  try {
    db = await initDb();

    // Check for duplicate case ID
    const existingCase = await db.get('SELECT id FROM cases WHERE id = ?', [id]);
    if (existingCase) {
      return res.status(400).json({ error: `Case ID ${id} already exists` });
    }

    // Begin transaction
    await db.run('BEGIN TRANSACTION');

    // Check/create officer
    const officerRow = await db.get('SELECT * FROM officers WHERE staffNo = ?', [staffNo]);
    if (!officerRow) {
      await db.run('INSERT INTO officers (staffNo, name) VALUES (?, ?)', [staffNo, officer]);
    }

    // Insert case (minimal fields)
    await db.run(`
      INSERT INTO cases (
        id, user
      ) VALUES (?, ?)
    `, [id, user]);

    // Insert case_officers (all 27 fields)
    await db.run(`
      INSERT INTO case_officers (
        caseId, officer, staffNo, summary, breachOfStandards, investigator, severity, section17Date, policeFriend,
        section18Date, interviewDate, ioReportDate, raAssessment, misconductMeetingDate, misconductOutcome,
        grossMisconductHearingDate, hearingOutcome, appealMade, appealLetterDate, appealHearingDate,
        appealOutcome, comments, dateOccurrence, type, status, officerAdvisedOfReferral, section24ReplyToRA
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id, officer || '', staffNo || '', summary || '', breachOfStandards || '[]', investigator || '',
      severity || '', section17Date || '', policeFriend || '', section18Date || '', interviewDate || '',
      ioReportDate || '', raAssessment || '', misconductMeetingDate || '', misconductOutcome || '',
      grossMisconductHearingDate || '', hearingOutcome || '', appealMade || '', appealLetterDate || '',
      appealHearingDate || '', appealOutcome || '', comments || '', dateOccurrence || '', type || '',
      status || '', officerAdvisedOfReferral || '', section24ReplyToRA || ''
    ]);

    // Handle file uploads
    if (req.files && req.files.length > 0) {
      const fileInserts = req.files.map(file => [id, file.url, file.originalname, user]);
      await db.run(
        'INSERT INTO case_files (caseId, filePath, originalName, uploadedBy) VALUES ' +
        fileInserts.map(() => '(?, ?, ?, ?)').join(','),
        fileInserts.flat()
      );
    }

    // Commit transaction
    await db.run('COMMIT');
    await logAction(user, 'Create Case', `Created case ${id} with officer ${staffNo}`);
    res.status(201).json({ message: 'Case added successfully', id });
  } catch (error) {
    console.error('Create case error:', error.stack);
    if (db) await db.run('ROLLBACK').catch(err => console.error('Rollback error:', err));
    res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
    if (db) await db.close();
  }
});

app.post('/cases/:id/officers', restrictToPSDOrHigher, async (req, res) => {
  const { id: encodedId } = req.params;
  const id = decodeURIComponent(encodedId);
  console.log('Raw request body:', req.body);
  const {
    officer, staffNo, summary, breachOfStandards, investigator, severity, section17Date, policeFriend,
    section18Date, interviewDate, ioReportDate, raAssessment, misconductMeetingDate, misconductOutcome,
    grossMisconductHearingDate, hearingOutcome, appealMade, appealLetterDate, appealHearingDate,
    appealOutcome, comments, dateOccurrence, type, status, officerAdvisedOfReferral, section24ReplyToRA
  } = req.body;
  const user = req.session.user;

  console.log('Parsed officer:', officer);
  console.log('Parsed staffNo:', staffNo);
  console.log('Decoded Case ID:', id);
  if (!officer) return res.status(400).json({ error: 'Officer name is required' });
  if (!staffNo) return res.status(400).json({ error: 'Staff No. is required' });

  let db;
  try {
    db = await initDb();

    const caseRow = await db.get('SELECT user FROM cases WHERE id = ?', [id]);
    if (!caseRow) return res.status(404).json({ error: 'Case not found' });

    const userRow = await db.get('SELECT role FROM users WHERE username = ?', [user]);
    if (!userRow) return res.status(500).json({ error: 'Database error: Unable to verify user role' });
    if (userRow.role === 'psd' && caseRow.user !== user) {
      return res.status(403).json({ error: 'Permission denied: PSD users can only modify their own cases' });
    }

    // Check if officer exists in officers table, create if not
    const officerRow = await db.get('SELECT * FROM officers WHERE staffNo = ?', [staffNo]);
    if (!officerRow) {
      await db.run('INSERT INTO officers (staffNo, name) VALUES (?, ?)', [staffNo, officer]);
      console.log(`Created officer profile for ${staffNo}: ${officer}`);
    }

    // Insert into case_officers
    await db.run(`
      INSERT INTO case_officers (
        caseId, officer, staffNo, summary, breachOfStandards, investigator, severity, section17Date, policeFriend,
        section18Date, interviewDate, ioReportDate, raAssessment, misconductMeetingDate, misconductOutcome,
        grossMisconductHearingDate, hearingOutcome, appealMade, appealLetterDate, appealHearingDate,
        appealOutcome, comments, dateOccurrence, type, status, officerAdvisedOfReferral, section24ReplyToRA
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id, officer || '', staffNo || '', summary || '', breachOfStandards || '[]', investigator || '',
      severity || '', section17Date || '', policeFriend || '', section18Date || '', interviewDate || '',
      ioReportDate || '', raAssessment || '', misconductMeetingDate || '', misconductOutcome || '',
      grossMisconductHearingDate || '', hearingOutcome || '', appealMade || '', appealLetterDate || '',
      appealHearingDate || '', appealOutcome || '', comments || '', dateOccurrence || '', type || '',
      status || '', officerAdvisedOfReferral || '', section24ReplyToRA || ''
    ]);

    await logAction(user, 'Add Officer', `Added officer ${officer} with staffNo ${staffNo} to case ${id}`);
    res.status(201).json({ message: 'Officer added successfully', caseId: id });
  } catch (error) {
    console.error('Add officer error:', error.stack);
    res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
    if (db) await db.close();
  }
});


app.get('/session-status', (req, res) => {
  if (req.session.user) {
    db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to check session' });
      res.json({
        loggedIn: true,
        role: row ? row.role : 'unknown',
        username: req.session.user,
        name: req.session.name // Add name
      });
    });
  } else {
    res.json({ loggedIn: false });
  }
});

async function initDb() {
  const dbPath = process.env.DB_PATH || './cases.db';
  console.log('Opening database at:', dbPath);
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });
  await db.run('PRAGMA foreign_keys = ON');
  // Ensure audit_logs exists
  await db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  return db;
}

app.put('/cases/:id', restrictToPSDOrHigher, upload.array('files'), async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const user = req.session.user;
  const files = req.files || [];
  const officerData = { ...req.body };
  console.log('PUT /cases/:id - ID:', id, 'User:', user, 'Files:', files.length, 'File Details:', files.map(f => ({ name: f.originalname, url: f.url, public_id: f.public_id })), 'Body:', officerData);

  if (!officerData.officerId) {
    console.log('Missing officerId');
    return res.status(400).json({ error: 'Officer ID required' });
  }

  let db;
  let transactionActive = false;
  try {
    db = await initDb();

    const [caseRow, userRow, permissionRow] = await Promise.all([
      db.get('SELECT user FROM cases WHERE id = ?', [id]),
      db.get('SELECT role FROM users WHERE username = ?', [user]),
      db.get('SELECT canEdit FROM user_case_permissions WHERE caseId = ? AND username = ?', [id, user]) // Fixed table name
    ]);

    if (!caseRow) {
      console.log('Case not found:', id);
      return res.status(404).json({ error: 'Case not found' });
    }

    const hasOwnership = caseRow.user === user;
    const hasEditPermission = permissionRow && permissionRow.canEdit === 1;

    if (userRow.role === 'psd' && !hasOwnership && !hasEditPermission) {
      console.log('Permission denied for:', user, 'on case:', id);
      return res.status(403).json({ error: 'Permission denied: PSD users can only modify their own cases or cases they have edit permissions for' });
    }

    const officerRow = await db.get('SELECT * FROM case_officers WHERE caseId = ? AND id = ?', [id, officerData.officerId]);
    if (!officerRow) {
      console.log('Officer not found:', officerData.officerId);
      return res.status(404).json({ error: 'Officer not found' });
    }

    await db.run('BEGIN TRANSACTION');
    transactionActive = true;

    const normalize = val => val === '' ? null : val;
    const params = [
      normalize(officerData.officer) ?? officerRow.officer, normalize(officerData.staffNo) ?? officerRow.staffNo,
      normalize(officerData.dateOccurrence) ?? officerRow.dateOccurrence, normalize(officerData.type) ?? officerRow.type,
      normalize(officerData.status) ?? officerRow.status, normalize(officerData.summary) ?? officerRow.summary,
      normalize(officerData.breachOfStandards) ?? officerRow.breachOfStandards ?? '[]',
      normalize(officerData.investigator) ?? officerRow.investigator, normalize(officerData.severity) ?? officerRow.severity,
      normalize(officerData.section17Date) ?? officerRow.section17Date, normalize(officerData.policeFriend) ?? officerRow.policeFriend,
      normalize(officerData.section18Date) ?? officerRow.section18Date, normalize(officerData.interviewDate) ?? officerRow.interviewDate,
      normalize(officerData.ioReportDate) ?? officerRow.ioReportDate, normalize(officerData.raAssessment) ?? officerRow.raAssessment,
      normalize(officerData.officerAdvisedOfReferral) ?? officerRow.officerAdvisedOfReferral,
      normalize(officerData.section24ReplyToRA) ?? officerRow.section24ReplyToRA,
      normalize(officerData.misconductMeetingDate) ?? officerRow.misconductMeetingDate,
      normalize(officerData.misconductOutcome) ?? officerRow.misconductOutcome,
      normalize(officerData.grossMisconductHearingDate) ?? officerRow.grossMisconductHearingDate,
      normalize(officerData.hearingOutcome) ?? officerRow.hearingOutcome, normalize(officerData.appealMade) ?? officerRow.appealMade,
      normalize(officerData.appealLetterDate) ?? officerRow.appealLetterDate, normalize(officerData.appealHearingDate) ?? officerRow.appealHearingDate,
      normalize(officerData.appealOutcome) ?? officerRow.appealOutcome, normalize(officerData.comments) ?? officerRow.comments,
      id, officerData.officerId
    ];

    const updateResult = await db.run(`
      UPDATE case_officers SET officer=?,staffNo=?,dateOccurrence=?,type=?,status=?,summary=?,breachOfStandards=?,
      investigator=?,severity=?,section17Date=?,policeFriend=?,section18Date=?,interviewDate=?,ioReportDate=?,
      raAssessment=?,officerAdvisedOfReferral=?,section24ReplyToRA=?,misconductMeetingDate=?,misconductOutcome=?,
      grossMisconductHearingDate=?,hearingOutcome=?,appealMade=?,appealLetterDate=?,appealHearingDate=?,
      appealOutcome=?,comments=? WHERE caseId=? AND id=?
    `, params);

    const changes = updateResult.changes || 0;
    console.log('Rows updated:', changes);

    if (!changes && !files.length) {
      await db.run('COMMIT');
      transactionActive = false;
      console.log('No changes to officer data or files');
      return res.status(200).json({ message: 'No updates needed', id, officerId: officerData.officerId });
    }

    if (files.length) {
      console.log('Processing uploaded files...');
      const fileValues = files.map(file => [
        id,
        file.url,
        file.originalname,
        user,
        new Date().toISOString()
      ]);
      await db.run(
        `INSERT INTO case_files (caseId, filePath, originalName, uploadedBy, uploadDate) VALUES ${files.map(() => '(?,?,?,?,?)').join(',')}`,
        fileValues.flat()
      );
      console.log('Files inserted:', files.map(f => f.originalname));
    }

    await db.run('COMMIT');
    transactionActive = false;
    const changesLog = logChanges(officerRow, officerData);
    const updateMessage = changesLog ? 'Officer details updated' : (files.length ? 'Files uploaded' : 'No officer details changed');
    await logAction(user, 'Update Case Officer', changesLog || `Updated case ${id} officer ${officerData.officerId} with ${files.length ? `${files.length} file(s)` : 'no field changes'}`);
    res.json({ 
      message: updateMessage, 
      id, 
      officerId: officerData.officerId, 
      updatedFields: changesLog || null, 
      filesUploaded: files.length ? files.map(f => f.originalname) : null 
    });
  } catch (error) {
    console.error('PUT error:', error.stack);
    if (transactionActive) {
      await db.run('ROLLBACK').catch(err => console.error('Rollback failed:', err.stack));
    }
    res.status(500).json({ error: 'Internal server error', details: error.message });
  } finally {
    if (db) await db.close().catch(err => console.error('DB close error:', err.stack));
  }
});

// Helper to log changes
function logChanges(oldData, newData) {
  const changes = [];
  for (const key in newData) {
    // Skip if not a meaningful change
    if (key === 'officerId' || key === 'id') continue;
    const oldVal = oldData[key] === null || oldData[key] === undefined ? '' : oldData[key];
    const newVal = newData[key] === null || newData[key] === undefined ? '' : newData[key];
    if (oldVal !== newVal) {
      changes.push(`${key} from '${oldVal}' to '${newVal}'`);
    }
  }
  return changes.join(', ');
}

function restrictToStatsUsers(req, res, next) {
  const allowedRoles = ['admin', 'psd admin', 'auditor'];
  if (!req.session.user || !allowedRoles.includes(req.session.role)) {
    console.log('Access denied to stats - Inquisitor:', req.session.user, 'Role:', req.session.role);
    return res.status(403).json({ error: 'Permission denied' });
  }
  console.log('Stats access granted - Inquisitor:', req.session.user, 'Role:', req.session.role);
  next();
}

app.get('/detailed-stats', restrictToStatsViewers, (req, res) => {
  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to verify user role' });
    if (!row) return res.status(403).json({ error: 'User not found' });

    // Base query for breaches (unchanged)
    let baseQuery = `
      SELECT SUBSTR(dateOccurrence, 1, 4) as year, breachOfStandards 
      FROM case_officers 
      WHERE breachOfStandards IS NOT NULL AND breachOfStandards != 'N/A' AND breachOfStandards != '' 
      AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != ''`;
    let params = [];
    if (row.role === 'psd') {
      baseQuery += ' AND caseId IN (SELECT id FROM cases WHERE user = ?)';
      params.push(req.session.user);
    }

    db.all(baseQuery, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to fetch breaches' });

      const breachCounts = {};
      rows.forEach(row => {
        let breaches;
        try {
          breaches = row.breachOfStandards ? JSON.parse(row.breachOfStandards) : [];
          if (!Array.isArray(breaches)) breaches = [breaches];
        } catch (e) {
          breaches = row.breachOfStandards ? [row.breachOfStandards] : [];
        }
        breaches.forEach(breach => {
          if (breach && breach !== 'N/A' && breach !== '') {
            const key = `${row.year}-${breach}`;
            breachCounts[key] = (breachCounts[key] || 0) + 1;
          }
        });
      });

      const breachesOfStandards = Object.entries(breachCounts).map(([key, count]) => {
        const [year, breachOfStandards] = key.split('-', 2);
        return { year, breachOfStandards, count };
      });

      const userFilter = row.role === 'psd' ? ' AND caseId IN (SELECT id FROM cases WHERE user = ?)' : '';
      const userParams = row.role === 'psd' ? [req.session.user] : [];

      // Updated queries object
      const queries = {
        casesPerYear: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, COUNT(*) as count 
          FROM case_officers 
          WHERE dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year`,
        severity: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, severity, COUNT(*) as count 
          FROM case_officers 
          WHERE severity IS NOT NULL AND severity != 'N/A' AND severity != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, severity`,
        raAssessment: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, raAssessment, COUNT(*) as count 
          FROM case_officers 
          WHERE raAssessment IS NOT NULL AND raAssessment != 'N/A' AND raAssessment != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, raAssessment`,
        misconductOutcome: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, misconductOutcome, COUNT(*) as count 
          FROM case_officers 
          WHERE misconductOutcome IS NOT NULL AND misconductOutcome != 'N/A' AND misconductOutcome != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, misconductOutcome`,
        hearingOutcome: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, hearingOutcome, COUNT(*) as count 
          FROM case_officers 
          WHERE hearingOutcome IS NOT NULL AND hearingOutcome != 'N/A' AND hearingOutcome != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, hearingOutcome`,
        appealsPerYear: `
          SELECT SUBSTR(appealLetterDate, 1, 4) as year, COUNT(*) as count 
          FROM case_officers 
          WHERE appealLetterDate IS NOT NULL AND appealLetterDate != 'N/A' AND appealLetterDate != '' 
          GROUP BY year`,
        appealOutcome: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, appealOutcome, COUNT(*) as count 
          FROM case_officers 
          WHERE appealOutcome IS NOT NULL AND appealOutcome != 'N/A' AND appealOutcome != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, appealOutcome`,
        caseStatus: `
          SELECT SUBSTR(dateOccurrence, 1, 4) as year, status, COUNT(*) as count 
          FROM case_officers 
          WHERE status IS NOT NULL AND status != 'N/A' AND status != '' 
          AND dateOccurrence IS NOT NULL AND dateOccurrence != 'N/A' AND dateOccurrence != '' 
          GROUP BY year, status`,
        // Officer Age at Incident (total count, no year)
        officerAgeAtIncident: `
          SELECT 
            ROUND((julianday(co.dateOccurrence) - julianday(o.dateOfBirth)) / 365.25) as age, 
            COUNT(*) as count 
          FROM case_officers co 
          JOIN officers o ON co.staffNo = o.staffNo 
          WHERE co.dateOccurrence IS NOT NULL AND co.dateOccurrence != 'N/A' AND co.dateOccurrence != '' 
          AND o.dateOfBirth IS NOT NULL AND o.dateOfBirth != 'N/A' AND o.dateOfBirth != '' 
          GROUP BY age 
          ORDER BY age`,
        // Years of Service at Incident (total count, no year)
        serviceLengthAtIncident: `
          SELECT 
            ROUND((julianday(co.dateOccurrence) - julianday(o.joiningDate)) / 365.25) as years, 
            COUNT(*) as count 
          FROM case_officers co 
          JOIN officers o ON co.staffNo = o.staffNo 
          WHERE co.dateOccurrence IS NOT NULL AND co.dateOccurrence != 'N/A' AND co.dateOccurrence != '' 
          AND o.joiningDate IS NOT NULL AND o.joiningDate != 'N/A' AND o.joiningDate != '' 
          GROUP BY years 
          ORDER BY years`
      };

      Promise.all([
        new Promise((resolve, reject) => {
          db.all(queries.casesPerYear + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.severity + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.raAssessment + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.misconductOutcome + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.hearingOutcome + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.appealsPerYear + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.appealOutcome + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.caseStatus + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.officerAgeAtIncident + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        }),
        new Promise((resolve, reject) => {
          db.all(queries.serviceLengthAtIncident + userFilter, userParams, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
          });
        })
      ])
        .then(([casesPerYear, severity, raAssessment, misconductOutcome, hearingOutcome, appealsPerYear, appealOutcome, caseStatus, officerAgeAtIncident, serviceLengthAtIncident]) => {
          const stats = {
            casesPerYear,
            severity,
            raAssessment,
            misconductOutcome,
            hearingOutcome,
            appealsPerYear,
            appealOutcome,
            caseStatus,
            breachesOfStandards,
            officerAgeAtIncident,
            serviceLengthAtIncident // Renamed to match frontend
          };
          console.log('Stats data sent:', stats);
          res.json(stats);
        })
        .catch(err => {
          console.error('Stats fetch error:', err);
          res.status(500).json({ error: 'Database error: Unable to fetch stats' });
        });
    });
  });
});

app.get('/cases-by-officer', isAuthenticated, (req, res) => {
  const { staffNo } = req.query;
  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to verify user role' });
    if (!row) return res.status(403).json({ error: 'User not found' });

    let query = `
      SELECT 
        c.id AS caseId,
        co.dateOccurrence,
        co.type,
        co.status,
        c.user,
        co.officerAdvisedOfReferral,
        co.section24ReplyToRA,
        co.id AS officerId,
        co.staffNo,
        co.officer,
        co.summary,
        co.breachOfStandards,
        co.investigator,
        co.severity,
        co.section17Date,
        co.policeFriend,
        co.section18Date,
        co.interviewDate,
        co.ioReportDate,
        co.raAssessment,
        co.misconductMeetingDate,
        co.misconductOutcome,
        co.grossMisconductHearingDate,
        co.hearingOutcome,
        co.appealMade,
        co.appealLetterDate,
        co.appealHearingDate,
        co.appealOutcome,
        co.comments
      FROM cases c
      JOIN case_officers co ON c.id = co.caseId
      WHERE co.staffNo = ?
    `;
    let params = [staffNo];
    if (row.role === 'psd') {
      query += ' AND c.user = ?';
      params.push(req.session.user);
    }

    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to fetch cases' });
      if (!rows.length) return res.json([]);

      db.all('SELECT caseId, filePath, originalName, uploadDate, uploadedBy FROM case_files', (err, files) => {
        if (err) return res.status(500).json({ error: 'Database error: Unable to fetch case files' });

        const casesWithDetails = [];
        rows.forEach(row => {
          let caseEntry = casesWithDetails.find(c => c.caseId === row.caseId);
          if (!caseEntry) {
            caseEntry = {
              caseId: row.caseId,
              user: row.user,
              files: files.filter(f => f.caseId === row.caseId).map(f => f.filePath),
              officers: []
            };
            casesWithDetails.push(caseEntry);
          }
          caseEntry.officers.push({
            id: row.officerId,
            staffNo: row.staffNo,
            officer: row.officer,
            summary: row.summary,
            dateOccurrence: row.dateOccurrence,
            type: row.type,
            status: row.status,
            breachOfStandards: row.breachOfStandards,
            investigator: row.investigator,
            severity: row.severity,
            section17Date: row.section17Date,
            policeFriend: row.policeFriend,
            section18Date: row.section18Date,
            interviewDate: row.interviewDate,
            ioReportDate: row.ioReportDate,
            raAssessment: row.raAssessment,
            officerAdvisedOfReferral: row.officerAdvisedOfReferral,
            section24ReplyToRA: row.section24ReplyToRA,
            misconductMeetingDate: row.misconductMeetingDate,
            misconductOutcome: row.misconductOutcome,
            grossMisconductHearingDate: row.grossMisconductHearingDate,
            hearingOutcome: row.hearingOutcome,
            appealMade: row.appealMade,
            appealLetterDate: row.appealLetterDate,
            appealHearingDate: row.appealHearingDate,
            appealOutcome: row.appealOutcome,
            comments: row.comments
          });
        });
        console.log('Cases by officer retrieved:', casesWithDetails); // Debug log
        res.json(casesWithDetails);
      });
    });
  });
});

app.post('/admin/users', isPSDAdmin, async (req, res) => {
  const { username, role, email, name } = req.body;
  const oneTimePassword = Math.random().toString(36).slice(-8); // e.g., 'abc123xy'
  let db;

  try {
    db = await initDb();

    // Check current user's role
    const userRow = await db.get('SELECT role FROM users WHERE username = ?', [req.session.user]);
    if (!userRow) return res.status(500).json({ error: 'Database error: Unable to verify user role' });
    if (userRow.role === 'psd admin' && (role === 'psd admin' || role === 'admin')) {
      return res.status(403).json({ error: 'PSD Admin cannot create PSD Admin or Admin users' });
    }

    // Check if username exists
    const existingUser = await db.get('SELECT username FROM users WHERE username = ?', [username]);
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    // Hash the temporary password
    const hashedPassword = await bcrypt.hash(oneTimePassword, 10);

    // Insert user with hashed password and oneTimePassword as '1'
    await db.run(
      'INSERT INTO users (username, role, password, oneTimePassword, email, name) VALUES (?, ?, ?, ?, ?, ?)',
      [username, role, hashedPassword, '1', email, name || null]
    );

    await logAction(req.session.user, 'Create User', `Created user ${username} with role ${role}, email: ${email}, name: ${name || 'not set'}`);
    res.status(201).json({ message: 'User created successfully', username, oneTimePassword });
  } catch (error) {
    console.error('User creation error:', error.stack);
    res.status(500).json({ error: 'Database error: Unable to create user' });
  } finally {
    if (db) await db.close();
  }
});

app.get('/admin/users', isPSDAdmin, (req, res) => {
  db.all('SELECT username, role, email, name FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch users' });
    res.json(rows);
  });
});

app.get('/admin/permissions', restrictToAdminOrPSDAdmin, async (req, res) => {
  let db;
  try {
    db = await initDb();
    const permissions = await db.all('SELECT * FROM user_case_permissions');
    console.log('Sending permissions:', permissions);
    res.json(permissions);
  } catch (err) {
    console.error('Get permissions error:', err);
    res.status(500).json({ error: 'Failed to fetch permissions' });
  } finally {
    if (db) await db.close();
  }
});

app.put('/admin/users/:username', isPSDAdmin, (req, res) => {
  const { username } = req.params;
  const { newUsername, role, email, name } = req.body; // Added name

  if (!newUsername || !role || !email) {
    return res.status(400).json({ error: 'Username, role, and email are required' });
  }

  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, requesterRow) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch requester role' });

    db.get('SELECT role FROM users WHERE username = ?', [username], (err, targetRow) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to fetch target user' });
      if (!targetRow) return res.status(404).json({ error: 'User not found' });

      if (requesterRow.role === 'psd admin' && (targetRow.role === 'psd admin' || targetRow.role === 'admin' || role === 'psd admin' || role === 'admin')) {
        return res.status(403).json({ error: 'PSD Admin cannot modify PSD Admin or Admin users or set role to PSD Admin or Admin' });
      }

      db.get('SELECT username FROM users WHERE username = ? AND username != ?', [newUsername, username], (err, row) => {
        if (err) {
          console.error('Database error (check username):', err);
          return res.status(500).json({ error: 'Database error: Unable to check username' });
        }
        if (row) return res.status(400).json({ error: 'Username already taken' });

        db.run('UPDATE users SET username = ?, role = ?, email = ?, name = ? WHERE username = ?', [newUsername, role, email, name, username], (err) => {
          if (err) {
            console.error('Database error (UPDATE users):', err);
            return res.status(500).json({ error: 'Database error: Unable to update user' });
          }
          if (this.changes === 0) return res.status(404).json({ error: 'User not found' });

          db.run('UPDATE cases SET user = ? WHERE user = ?', [newUsername, username], (err) => {
            if (err) console.error('Failed to update case ownership:', err);
          });

          logAction(req.session.user, 'Update User', `Updated user ${username} to ${newUsername}, role: ${role}, email: ${email}, name: ${name || 'unchanged'}`);
          res.json({ message: 'User updated successfully', username: newUsername, role, email, name }); // Added name to response
        });
      });
    });
  });
});

app.post('/admin/permissions', restrictToAdminOrPSDAdmin, (req, res) => {
  console.log('POST /admin/permissions hit');
  const { username, caseId, canView, canEdit } = req.body;
  const assignedBy = req.session.user;
  console.log('Update permissions request:', { username, caseId, canView, canEdit, assignedBy });

  if (!username || !caseId) {
    console.log('Missing required fields');
    return res.status(400).json({ error: 'Username and caseId are required' });
  }

  db.get('SELECT role FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('User check error:', err);
      return res.status(500).json({ error: 'Database error: Unable to verify user' });
    }
    if (!row || row.role !== 'psd') {
      console.log('Invalid user role:', row ? row.role : 'User not found');
      return res.status(400).json({ error: 'User must be a PSD role user' });
    }

    db.get('SELECT id FROM cases WHERE id = ?', [caseId], (err, caseRow) => {
      if (err) {
        console.error('Case check error:', err);
        return res.status(500).json({ error: 'Database error: Unable to verify case' });
      }
      if (!caseRow) {
        console.log('Case not found:', caseId);
        return res.status(404).json({ error: 'Case not found' });
      }

      db.run(`
        INSERT INTO user_case_permissions (username, caseId, canView, canEdit, assignedBy)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(username, caseId) DO UPDATE SET
          canView = excluded.canView,
          canEdit = excluded.canEdit,
          assignedBy = excluded.assignedBy,
          assignedDate = CURRENT_TIMESTAMP
      `, [username, caseId, canView ? 1 : 0, canEdit ? 1 : 0, assignedBy], (err) => {
        if (err) {
          console.error('Permission update error:', err);
          return res.status(500).json({ error: 'Database error: Unable to assign/update permission' });
        }
        console.log('Permission updated successfully:', { username, caseId });
        logAction(assignedBy, 'Assign Permission', `Assigned/Updated permission for ${username} on case ${caseId}: view=${canView}, edit=${canEdit}`);
        res.status(201).json({ message: 'Permission assigned/updated successfully' });
      });
    });
  });
});

app.post('/admin/reset-password/:username', isPSDAdmin, async (req, res) => {
  const { username } = req.params;
  let db;
  try {
    db = await initDb();

    // Fetch user details
    const user = await db.get('SELECT email, username FROM users WHERE username = ?', [username]);
    if (!user || !user.email) {
      return res.status(404).json({ error: 'User not found or no email registered' });
    }

    // Generate temporary password
    const tempPassword = Math.random().toString(36).slice(-8); // e.g., "6w1tvwcx"
    const hashedTempPassword = await bcrypt.hash(tempPassword, 10);

    // Update user in database
    await db.run(
      'UPDATE users SET password = ?, oneTimePassword = 1 WHERE username = ?', 
      [hashedTempPassword, username]
    );

    // Send email to user
    const mailOptions = {
      from: 'your-email@gmail.com',
      to: user.email,
      subject: 'Your Temporary Password',
      text: `Your temporary password is: ${tempPassword}\n\nPlease log in and change your password immediately.`
    };

    await transporter.sendMail(mailOptions);
    console.log(`Temporary password email sent to ${user.email}`);

    // Log action without exposing the password
    await logAction(req.session.user, 'Admin Password Reset', `Reset password for ${username} - email sent`);

    // Respond to admin without the password
    res.json({ message: 'Password reset email sent to the user' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  } finally {
    if (db) await db.close();
  }
});

app.delete('/admin/users/:username', isPSDAdmin, (req, res) => {
  const { username } = req.params;

  db.get('SELECT role FROM users WHERE username = ?', [req.session.user], (err, requesterRow) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch requester role' });

    db.get('SELECT role FROM users WHERE username = ?', [username], (err, targetRow) => {
      if (err) return res.status(500).json({ error: 'Database error: Unable to fetch user' });
      if (!targetRow) return res.status(404).json({ error: 'User not found' });

      if (requesterRow.role === 'psd admin' && (targetRow.role === 'psd admin' || targetRow.role === 'admin')) {
        return res.status(403).json({ error: 'PSD Admin cannot delete PSD Admin or Admin users' });
      }

      console.log(`Attempting to delete user: ${username} by ${req.session.user}`);
      db.run('DELETE FROM users WHERE username = ?', [username], (err) => {
        if (err) {
          console.error('Database error (DELETE users):', err);
          return res.status(500).json({ error: 'Database error: Unable to delete user' });
        }
        if (this.changes === 0) {
          console.log(`User ${username} not found`);
          return res.status(404).json({ error: 'User not found' });
        }
        logAction(req.session.user, 'Delete User', `Deleted user ${username}`);
        console.log(`User ${username} deleted successfully`);
        res.json({ message: 'User deleted successfully', username });
      });
    });
  });
});

app.delete('/admin/permissions/:id', restrictToAdminOrPSDAdmin, (req, res) => {
  const { id } = req.params;
  const user = req.session.user;

  db.get('SELECT username, caseId FROM user_case_permissions WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch permission' });
    if (!row) return res.status(404).json({ error: 'Permission not found' });

    db.run('DELETE FROM user_case_permissions WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'Database error: Unable to remove permission' });
      if (this.changes === 0) return res.status(404).json({ error: 'Permission not found' });
      logAction(user, 'Remove Permission', `Removed permission for ${row.username} on case ${row.caseId}`);
      res.json({ message: 'Permission removed successfully' });
    });
  });
});

app.get('/audit', isPSDAdmin, (req, res) => {
  db.all('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch audit logs' });
    res.json(rows);
  });
});

app.get('/officers', isAuthenticated, (req, res) => {
  db.all('SELECT * FROM officers', (err, officers) => {
    if (err) return res.status(500).json({ error: 'Database error: Unable to fetch officers' });

    const promises = officers.map(officer => {
      return new Promise((resolve, reject) => {
        db.all('SELECT caseId, id as officerId FROM case_officers WHERE staffNo = ?', [officer.staffNo], (err, cases) => {
          if (err) reject(err);
          resolve({ ...officer, psdHistory: cases });
        });
      });
    });

    Promise.all(promises)
      .then(officersWithHistory => res.json(officersWithHistory))
      .catch(err => res.status(500).json({ error: 'Database error: Unable to fetch PSD history' }));
  });
});

app.get('/officers/:staffNo', restrictToAdminOrPSDAdmin, async (req, res) => {
  const { staffNo } = req.params;
  const user = req.session.user;
  let db;
  try {
    db = await initDb();
    const officer = await db.get('SELECT * FROM officers WHERE staffNo = ?', [staffNo]);
    if (!officer) return res.status(404).json({ error: 'Officer not found' });

    const cases = await db.all('SELECT caseId, id as officerId FROM case_officers WHERE staffNo = ?', [staffNo]);
    await logAction(user, 'View Officer Profile', `Viewed officer profile ${staffNo}`);
    res.json({ ...officer, psdHistory: cases });
  } catch (error) {
    console.error('GET officer error:', error.stack);
    res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
    if (db) await db.close();
  }
});

app.put('/officers/:staffNo', isPSDAdmin, (req, res) => {
  const { staffNo } = req.params;
  const { joiningDate, rank, dateOfBirth } = req.body;
  const user = req.session.user;

  db.run(
    'UPDATE officers SET joiningDate = ?, rank = ?, dateOfBirth = ? WHERE staffNo = ?',
    [joiningDate || null, rank || null, dateOfBirth || null, staffNo],
    function(err) {
      if (err) {
        console.error('Update officer error:', err);
        return res.status(500).json({ error: 'Database error: Unable to update officer' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'Officer not found' });
      logAction(user, 'Update Officer', `Updated officer ${staffNo}: joiningDate=${joiningDate}, rank=${rank}, dateOfBirth=${dateOfBirth}`);
      res.json({ message: 'Officer updated successfully' });
    }
  );
});

app.delete('/officers/:staffNo', isPSDAdmin, async (req, res) => {
  const { staffNo } = req.params;
  const user = req.session.user;

  let db;
  try {
    db = await initDb();

    // Check if officer is linked to any cases
    const caseOfficerRow = await db.get('SELECT staffNo FROM case_officers WHERE staffNo = ?', [staffNo]);
    if (caseOfficerRow) {
      return res.status(400).json({ error: 'Cannot delete officer: Officer is linked to one or more cases' });
    }

    // Delete officer profile
    const result = await db.run('DELETE FROM officers WHERE staffNo = ?', [staffNo]);
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Officer not found' });
    }

    await logAction(user, 'Delete Officer', `Deleted officer ${staffNo}`);
    res.json({ message: 'Officer deleted successfully' });
  } catch (error) {
    console.error('Delete officer error:', error.stack);
    res.status(500).json({ error: 'Database error', details: error.message });
  } finally {
    if (db) await db.close();
  }
});

// Database Backup Functionality
const backupDir = path.join(__dirname, 'backups');
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir);
}

function backupDatabase() {
  const source = path.join(__dirname, 'cases.db');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const destination = path.join(backupDir, `cases_backup_${timestamp}.db`);

  fs.copyFile(source, destination, (err) => {
    if (err) {
      console.error('Database backup failed:', err);
    } else {
      console.log(`Database backed up successfully to ${destination}`);
    }
  });
}

setInterval(backupDatabase, 24 * 60 * 60 * 1000);
backupDatabase();

// Discipline Disclosure Report Endpoint
app.post('/generate-disclosure-report', isAuthenticated, restrictToAdminOrPSDAdmin, async (req, res) => {
  try {
    const { rciNo, rgpNo, rtoNo, obNo, caseName, oicName, section, officers } = req.body;

    async function getPsdHistory(staffId) {
      const outcomes = [
        'Management Advice', 'Warning', 'Final Written Warning',
        'Reduction in Rank', 'Dismissal with Notice', 'Dismissal Without Notice'
      ];
      return new Promise((resolve, reject) => {
        db.all(`
          SELECT 
            misconductMeetingDate AS date,
            misconductOutcome,
            NULL AS hearingOutcome,
            breachOfStandards
          FROM case_officers 
          WHERE staffNo = ? AND misconductOutcome IN (${outcomes.map(() => '?').join(',')})
          UNION ALL
          SELECT 
            grossMisconductHearingDate AS date,
            NULL AS misconductOutcome,
            hearingOutcome,
            breachOfStandards
          FROM case_officers 
          WHERE staffNo = ? AND hearingOutcome IN (${outcomes.map(() => '?').join(',')})
        `, [staffId, ...outcomes, staffId, ...outcomes], (err, rows) => {
          if (err) {
            console.error('Database error fetching PSD history:', err);
            reject(err);
          } else {
            resolve(rows.map(row => {
              const date = row.date ? new Date(row.date).toLocaleDateString('en-GB') : 'N/A';
              return {
                date: date,
                outcome: row.misconductOutcome || row.hearingOutcome,
                breaches: row.breachOfStandards || 'N/A'
              };
            }));
          }
        });
      });
    }

    // Initialize docData with all fields empty
    const docData = {
      rciNo: rciNo || '',
      rgpNo: rgpNo || '',
      rtoNo: rtoNo || '',
      obNo: obNo || '',
      caseName: caseName || '',
      oicName: oicName || '',
      section: section || '',
      dateSubmitted: new Date().toLocaleDateString('en-GB'), // Already dd/mm/yyyy
      producedBy: req.session.name || 'Unknown'
    };
    for (let i = 1; i <= 8; i++) {
      docData[`officerName${i}`] = '';
      docData[`rankCollar${i}`] = '';
      docData[`remarks${i}`] = '';
    }

    // Populate only provided officers
    const officerData = await Promise.all(officers.map(async (officer, index) => {
      const history = await getPsdHistory(officer.staffId);
      const remarks = history.length > 0 
        ? history.map(h => {
            const breaches = h.breaches !== 'N/A' ? JSON.parse(h.breaches).join(', ') : '';
            return `Date: ${h.date}, Outcome: ${h.outcome}, Breaches of Standards: ${breaches}`;
          }).join('\n')
        : 'NO TRACE';
      return {
        [`officerName${index + 1}`]: officer.name || '',
        [`rankCollar${index + 1}`]: officer.rankCollar || '',
        [`remarks${index + 1}`]: remarks
      };
    }));

    // Merge officer data into docData
    Object.assign(docData, ...officerData);

    const templatePath = path.resolve(__dirname, 'Officers Disciplinary Report.docx');
    if (!fs.existsSync(templatePath)) {
      throw new Error('Template file not found');
    }
    const content = fs.readFileSync(templatePath, 'binary');
    const zip = new PizZip(content);
    const doc = new Docxtemplater(zip, { paragraphLoop: true, linebreaks: true });

    doc.render(docData);

    const buf = doc.getZip().generate({ type: 'nodebuffer' });
    res.setHeader('Content-Disposition', `attachment; filename=Discipline_Disclosure_${caseName.replace(/\s+/g, '_') || 'Report'}.docx`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    logAction(req.session.user, 'Generate Disclosure Report', `Generated report for case ${caseName}`);
    res.send(buf);
  } catch (error) {
    console.error('Error generating disclosure report:', error);
    res.status(500).send('Error generating report');
  }
});

// Error and 404 handlers (moved to the end)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  console.log('404 - Method:', req.method, 'URL:', req.url);
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`POLARIS RMS Version 1 Server running on http://${HOST}:${PORT}`);
});

process.on('SIGINT', () => {
  db.close();
  process.exit();
});