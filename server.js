const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const multer = require('multer');

const app = express();
const port = 8080;
const http = require('http');
const socketIo = require('socket.io');

const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static('uploads'));


// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Poorne@10_04',
  database: process.env.DB_NAME || 'food_waste_management'
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});
// Reset Password Route
app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  // Check if the token is valid and not expired
  const query = 'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?';
  db.query(query, [token, Date.now()], async (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    const user = results[0];

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token
    const updateQuery = 'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?';
    db.query(updateQuery, [hashedPassword, user.user_id], (err, result) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ error: 'Database error.' });
      }

      res.json({ message: 'Password reset successfully.' });
    });
  });
});

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail', // Use your email service (e.g., Gmail, Outlook)
  auth: {
    user: process.env.EMAIL_USER || 'pavithra2744@gmail.com', // Your email
    pass: process.env.EMAIL_PASSWORD || 'kzrq blhi cprf sukt' // Your email password
  }
});
// Serve frontend static files
app.use(express.static(path.join(__dirname, 'public'))); // Change 'public' to your actual frontend folder

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle 404 Errors
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', 'error.html'));
});

// Socket.IO connection
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Subscribe to notifications for a specific user (donor or recipient)
  socket.on('subscribe', (userId) => {
    socket.join(userId); // Join a room for the user
    console.log(`User ${userId} subscribed to notifications`);
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
  });
});

// API Routes
const api = express.Router();

/* ==================== NOTIFICATIONS ==================== */

// ✅ Add Notification
function addNotification(userId, message) {
  const query = 'INSERT INTO notifications (user_id, message) VALUES (?, ?)';
  db.query(query, [userId, message], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return;
    }
    // Emit notification to the user in real-time
    io.to(userId.toString()).emit('notification', { message });
  });
}

// ✅ Get Notifications for a User
api.get('/notifications', verifyToken, (req, res) => {
  const userId = req.user.userId;

  const query = 'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Mark Notification as Read
api.put('/notifications/:id/read', verifyToken, (req, res) => {
  const notificationId = req.params.id;

  const query = 'UPDATE notifications SET is_read = TRUE WHERE notification_id = ?';
  db.query(query, [notificationId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json({ message: 'Notification marked as read.' });
  });
});

/* ==================== FORGOT PASSWORD ==================== */

// ✅ Forgot Password - Send Reset Link
api.post('/auth/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  // Check if the email exists in the database
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = results[0];

    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    // Save the reset token and expiry in the database
    const updateQuery = 'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE user_id = ?';
    db.query(updateQuery, [resetToken, resetTokenExpiry, user.user_id], (err, result) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ error: 'Database error.' });
      }
      //create reusable transporter object using default Smtp 
      let transporter =nodemailer.createTransport({
        service:"gmail",
        port:8080,
        secure:true,
        logger:true,
        secureconnection:false,
        auth:{
          user:'pavithra2744@gmail.com',
          pass:"kzrq blhi cprf sukt"
        }
      });

      // Send the reset link via email
      const resetLink = `http://localhost:8080/reset-password?token=${resetToken}`;
      const mailOptions = {
        from: process.env.EMAIL_USER || 'pavithra2744@gmail.com',
        to:email,
        subject: 'Password Reset Request',
        html: `
          <p>welcome to zero waste kitchen ! 
          You requested a password reset. Click the link below to reset your password:</p>
          <a href="${resetLink}">Reset Password</a>
          <p>This link will expire in 1 hour.</p>
        `
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          console.error('Email Error:', err);
          return res.status(500).json({ error: 'Failed to send email.' });
        }

        res.json({ message: 'Password reset link sent to your email.' });
      });
    });
  });
});

/* ==================== RESET PASSWORD ==================== */

// ✅ Reset Password - Update Password
api.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  // Check if the token is valid and not expired
  const query = 'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?';
  db.query(query, [token, Date.now()], async (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    const user = results[0];

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token
    const updateQuery = 'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?';
    db.query(updateQuery, [hashedPassword, user.user_id], (err, result) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ error: 'Database error.' });
      }

      res.json({ message: 'Password reset successfully.' });
    });
  });
});

/* ==================== AUTHENTICATION ==================== */

// ✅ User Registration
api.post('/auth/register', async (req, res) => {
  const { username, password, user_type, email } = req.body;

  if (!username || !password || !user_type || !email) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, password, user_type, email) VALUES (?, ?, ?, ?)';
    db.query(query, [username, hashedPassword, user_type, email], (err, result) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ error: 'Database error.' });
      }
      res.status(201).json({ message: 'User registered successfully!' });
    });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ✅ User Login
api.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const user = results[0];

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.user_id, role: user.user_type },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ message: 'Login successful!', token });
  });
});

/* ==================== MIDDLEWARE ==================== */

// ✅ Middleware to Verify Token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Token is required.' });
  }

  const tokenWithoutBearer = token.split(' ')[1];

  jwt.verify(tokenWithoutBearer, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token Error:', err);
      return res.status(401).json({ error: 'Invalid token.' });
    }

    req.user = decoded; // Attach decoded payload to the request object
    next();
  });
}
/* ==================== USERS ==================== */

// ✅ Get All Users
api.get('/users', verifyToken, (req, res) => {
  const query = 'SELECT * FROM users';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single User by ID
api.get('/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  const query = 'SELECT * FROM users WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a User by ID
api.put('/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  const query = 'UPDATE users SET username = ? WHERE user_id = ?';
  db.query(query, [username, userId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ message: 'User updated successfully!' });
  });
});

// ✅ Delete a User by ID
api.delete('/users/:id', verifyToken, (req, res) => {
  const userId = req.params.id;

  const query = 'DELETE FROM users WHERE user_id = ?';
  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ message: 'User deleted successfully!' });
  });
});

/* ==================== DONORS ==================== */

// ✅ Add a Donor
api.post('/donors', verifyToken, (req, res) => {
  const { user_id, organization_name, contact_person, email, phone, address } = req.body;

  if (!user_id || !organization_name || !contact_person || !email || !phone || !address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO donors 
      (user_id, organization_name, contact_person, email, phone, address) 
    VALUES 
      (?, ?, ?, ?, ?, ?)
  `;

  db.query(query, [user_id, organization_name, contact_person, email, phone, address], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Donor added successfully!' });
  });
});

// ✅ Get All Donors
api.get('/donors', verifyToken, (req, res) => {
  const query = 'SELECT * FROM donors';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single Donor by ID
api.get('/donors/:id', verifyToken, (req, res) => {
  const donorId = req.params.id;

  const query = 'SELECT * FROM donors WHERE donor_id = ?';
  db.query(query, [donorId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Donor not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a Donor by ID
api.put('/donors/:id', verifyToken, (req, res) => {
  const donorId = req.params.id;
  const { organization_name, contact_person, email, phone, address } = req.body;

  if (!organization_name || !contact_person || !email || !phone || !address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    UPDATE donors 
    SET organization_name = ?, contact_person = ?, email = ?, phone = ?, address = ?
    WHERE donor_id = ?
  `;

  db.query(query, [organization_name, contact_person, email, phone, address, donorId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Donor not found.' });
    }

    res.json({ message: 'Donor updated successfully!' });
  });
});

// ✅ Delete a Donor by ID
api.delete('/donors/:id', verifyToken, (req, res) => {
  const donorId = req.params.id;

  const query = 'DELETE FROM donors WHERE donor_id = ?';
  db.query(query, [donorId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Donor not found.' });
    }

    res.json({ message: 'Donor deleted successfully!' });
  });
});

/* ==================== RECIPIENTS ==================== */

// ✅ Add a Recipient
api.post('/recipients', verifyToken, (req, res) => {
  const { user_id, organization_name, contact_person, email, phone, address } = req.body;

  if (!user_id || !organization_name || !contact_person || !email || !phone || !address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO recipients 
      (user_id, organization_name, contact_person, email, phone, address) 
    VALUES 
      (?, ?, ?, ?, ?, ?)
  `;

  db.query(query, [user_id, organization_name, contact_person, email, phone, address], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Recipient added successfully!' });
  });
});

// ✅ Get All Recipients
api.get('/recipients', verifyToken, (req, res) => {
  const query = 'SELECT * FROM recipients';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single Recipient by ID
api.get('/recipients/:id', verifyToken, (req, res) => {
  const recipientId = req.params.id;

  const query = 'SELECT * FROM recipients WHERE recipient_id = ?';
  db.query(query, [recipientId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Recipient not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a Recipient by ID
api.put('/recipients/:id', verifyToken, (req, res) => {
  const recipientId = req.params.id;
  const { organization_name, contact_person, email, phone, address } = req.body;

  if (!organization_name || !contact_person || !email || !phone || !address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    UPDATE recipients 
    SET organization_name = ?, contact_person = ?, email = ?, phone = ?, address = ?
    WHERE recipient_id = ?
  `;

  db.query(query, [organization_name, contact_person, email, phone, address, recipientId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Recipient not found.' });
    }

    res.json({ message: 'Recipient updated successfully!' });
  });
});

// ✅ Delete a Recipient by ID
api.delete('/recipients/:id', verifyToken, (req, res) => {
  const recipientId = req.params.id;

  const query = 'DELETE FROM recipients WHERE recipient_id = ?';
  db.query(query, [recipientId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Recipient not found.' });
    }

    res.json({ message: 'Recipient deleted successfully!' });
  });
});

/* ==================== FOOD DONATIONS ==================== */

// Set up storage for uploaded images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Save files in 'uploads' folder
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

// Multer upload middleware
const upload = multer({ storage: storage });

// ✅ Add a Food Donation
/*api.post('/food_donations', verifyToken, (req, res) => {
  const { donor_id, food_name, food_description, quantity, food_image } = req.body;

  if (!donor_id || !food_name || !food_description || !quantity || !food_image) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO food_donations 
      (donor_id, food_name, food_description, quantity, food_image) 
    VALUES 
      (?, ?, ?, ?, ?)
  `;

  db.query(query, [donor_id, food_name, food_description, quantity, food_image], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Donation created successfully!' });
  });
});*/

// Old: app.post('/api/food_donations', verifyToken, (req, res) => { 
// New:
api.post('/food_donations', verifyToken, upload.single('food_image'), (req, res) => {
  const { donor_id, food_name, food_description, quantity } = req.body;
  const food_image = req.file ? req.file.filename : null;

  if (!donor_id || !food_name || !food_description || !quantity || !food_image) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO food_donations 
      (donor_id, food_name, food_description, quantity, food_image) 
    VALUES 
      (?, ?, ?, ?, ?)
  `;

  db.query(query, [donor_id, food_name, food_description, quantity, food_image], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Donation created successfully!' });
  });
});


// ✅ Get All Food Donations
api.get('/food_donations', verifyToken, (req, res) => {
  const query = 'SELECT * FROM food_donations';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single Food Donation by ID
api.get('/food_donations/:id', verifyToken, (req, res) => {
  const donationId = req.params.id;

  const query = 'SELECT * FROM food_donations WHERE donation_id = ?';
  db.query(query, [donationId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Food donation not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a Food Donation by ID
api.put('/food_donations/:id', verifyToken, (req, res) => {
  const donationId = req.params.id;
  const { food_name, food_description, quantity, food_image } = req.body;

  if (!food_name || !food_description || !quantity || !food_image) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    UPDATE food_donations 
    SET food_name = ?, food_description = ?, quantity = ?, food_image = ?
    WHERE donation_id = ?
  `;

  db.query(query, [food_name, food_description, quantity, food_image, donationId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food donation not found.' });
    }

    res.json({ message: 'Food donation updated successfully!' });
  });
});

// ✅ Delete a Food Donation by ID
api.delete('/food_donations/:id', verifyToken, (req, res) => {
  const donationId = req.params.id;

  const query = 'DELETE FROM food_donations WHERE donation_id = ?';
  db.query(query, [donationId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food donation not found.' });
    }

    res.json({ message: 'Food donation deleted successfully!' });
  });
});

/* ==================== FOOD ORDERS ==================== */

// ✅ Add a Food Order
api.post('/food_orders', verifyToken, (req, res) => {
  const { donation_id, recipient_id } = req.body;

  if (!donation_id || !recipient_id) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO food_orders 
      (donation_id, recipient_id) 
    VALUES 
      (?, ?)
  `;

  db.query(query, [donation_id, recipient_id], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Food order placed successfully!' });
  });
});

// ✅ Get All Food Orders
api.get('/food_orders', verifyToken, (req, res) => {
  const query = 'SELECT * FROM food_orders';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single Food Order by ID
api.get('/food_orders/:id', verifyToken, (req, res) => {
  const orderId = req.params.id;

  const query = 'SELECT * FROM food_orders WHERE order_id = ?';
  db.query(query, [orderId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Food order not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a Food Order by ID
api.put('/food_orders/:id', verifyToken, (req, res) => {
  const orderId = req.params.id;
  const { donation_id, recipient_id } = req.body;

  if (!donation_id || !recipient_id) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    UPDATE food_orders 
    SET donation_id = ?, recipient_id = ?
    WHERE order_id = ?
  `;

  db.query(query, [donation_id, recipient_id, orderId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food order not found.' });
    }

    res.json({ message: 'Food order updated successfully!' });
  });
});

// ✅ Delete a Food Order by ID
api.delete('/food_orders/:id', verifyToken, (req, res) => {
  const orderId = req.params.id;

  const query = 'DELETE FROM food_orders WHERE order_id = ?';
  db.query(query, [orderId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Food order not found.' });
    }

    res.json({ message: 'Food order deleted successfully!' });
  });
});

/* ==================== CERTIFICATIONS ==================== */

// ✅ Add a Certification
api.post('/certifications', verifyToken, (req, res) => {
  const { donor_id, total_donations, certificate_name, issued_date } = req.body;

  if (!donor_id || !total_donations || !certificate_name || !issued_date) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    INSERT INTO certifications 
      (donor_id, total_donations, certificate_name, issued_date) 
    VALUES 
      (?, ?, ?, ?)
  `;

  db.query(query, [donor_id, total_donations, certificate_name, issued_date], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.status(201).json({ message: 'Certification added successfully!' });
  });
});

// ✅ Get All Certifications
api.get('/certifications', verifyToken, (req, res) => {
  const query = 'SELECT * FROM certifications';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    res.json(results);
  });
});

// ✅ Get a Single Certification by ID
api.get('/certifications/:id', verifyToken, (req, res) => {
  const certificationId = req.params.id;

  const query = 'SELECT * FROM certifications WHERE certification_id = ?';
  db.query(query, [certificationId], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Certification not found.' });
    }

    res.json(results[0]);
  });
});

// ✅ Update a Certification by ID
api.put('/certifications/:id', verifyToken, (req, res) => {
  const certificationId = req.params.id;
  const { total_donations, certificate_name, issued_date } = req.body;

  if (!total_donations || !certificate_name || !issued_date) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const query = `
    UPDATE certifications 
    SET total_donations = ?, certificate_name = ?, issued_date = ?
    WHERE certification_id = ?
  `;

  db.query(query, [total_donations, certificate_name, issued_date, certificationId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Certification not found.' });
    }

    res.json({ message: 'Certification updated successfully!' });
  });
});

// ✅ Delete a Certification by ID
api.delete('/certifications/:id', verifyToken, (req, res) => {
  const certificationId = req.params.id;

  const query = 'DELETE FROM certifications WHERE certification_id = ?';
  db.query(query, [certificationId], (err, result) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Certification not found.' });
    }

    res.json({ message: 'Certification deleted successfully!' });
  });
});

// ✅ Download Certificate as PDF
api.get('/certifications/download/:id', verifyToken, (req, res) => {
  const { id } = req.params;

  const query = 'SELECT * FROM certifications WHERE certification_id = ?';
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Certification not found.' });
    }

    const certification = results[0];

    // Create a PDF document
    const doc = new PDFDocument();
    const filePath = path.join(__dirname, 'certificates', `certificate_${id}.pdf`);

    // Pipe the PDF to a file and send it as a response
    doc.pipe(fs.createWriteStream(filePath));
    doc.pipe(res);

    // Add content to the PDF
    doc.fontSize(25).text('Certificate of Appreciation', { align: 'center' });
    doc.moveDown();
    doc.fontSize(18).text(`This certificate is awarded to ${certification.certificate_name}`, { align: 'center' });
    doc.moveDown();
    doc.fontSize(16).text(`For donating ${certification.total_donations} times.`, { align: 'center' });
    doc.moveDown();
    doc.fontSize(14).text(`Issued on: ${new Date(certification.issued_date).toLocaleDateString()}`, { align: 'center' });

    // Finalize the PDF
    doc.end();

    // Set response headers for file download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=certificate_${id}.pdf`);
  });
});

/* ==================== MIDDLEWARE ==================== */

// ✅ Middleware to Verify Token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Token is required.' });
  }

  // Remove "Bearer " from the token string
  const tokenWithoutBearer = token.split(' ')[1];

  jwt.verify(tokenWithoutBearer, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token Error:', err);
      return res.status(401).json({ error: 'Invalid token.' });
    }

    req.user = decoded; // Attach decoded payload to the request object
    next();
  });
}

/* ==================== START SERVER ==================== */

// Use API Routes
app.use('/api', api);

// Start the Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});