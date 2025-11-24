// ============================
// KryptoConnect - COMPLETELY FIXED Server.js
// ============================
require('dotenv').config();
const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
app.set('trust proxy', 1);

// Enhanced CORS configuration
app.use(cors({
  origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

const io = new Server(server, {
  cors: { 
    origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"],
    methods: ['GET', 'POST'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate Limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many attempts, please try again later.'
});

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: 'Too many OTP requests, please try again later.'
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/send-otp', otpLimiter);
app.use('/api/resend-otp', otpLimiter);

// Other Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'kryptoconnect-backup-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ============================
// MongoDB Connection
// ============================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kryptoconnect';

const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  retryWrites: true,
  w: 'majority'
};

mongoose.connect(MONGODB_URI, mongooseOptions)
  .then(() => {
    console.log('✅ MongoDB Connected Successfully!');
    console.log('📍 Database:', mongoose.connection.name);
    console.log('📍 Host:', mongoose.connection.host);
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.log('🔄 Starting server without database connection...');
  });

// Enhanced connection event handlers
mongoose.connection.on('connected', () => {
  console.log('📊 MongoDB event connected');
});

mongoose.connection.on('error', (err) => {
  console.error('📊 MongoDB event error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('📊 MongoDB event disconnected');
});



// ============================
// Email Configuration
// ============================

// ============================
// SendGrid Email Configuration (FIXED)
// ============================

// ============================
// SendGrid Email Configuration (DIRECT API)
// ============================

// ============================
// SendGrid Email Configuration (FINAL FIX)
// ============================

const sgMail = require('@sendgrid/mail');
// ============================
// Twilio SMS OTP Setup
// ============================
const twilio = require("twilio");

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Send OTP via SMS
async function sendOTPSMS(phone, otpType) {
  try {
    const formattedPhone = phone.startsWith("+") ? phone : `+91${phone}`;

    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({
        to: formattedPhone,
        channel: "sms"
      });

    console.log("📩 SMS OTP sent to:", formattedPhone);
    return true;
  } catch (err) {
    console.error("❌ SMS OTP Error:", err.message);
    return false;
  }
}

// Verify SMS OTP using Twilio
async function verifyOTPSMS(phone, code) {
  try {
    const formattedPhone = phone.startsWith("+") ? phone : `+91${phone}`;

    const result = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({
        to: formattedPhone,
        code
      });

    return result.status === "approved";
  } catch (err) {
    console.error("❌ OTP Verify Error:", err.message);
    return false;
  }
}

// DEBUG: Check API Key
console.log('📧 SendGrid API Key length:', process.env.EMAIL_PASS ? process.env.EMAIL_PASS.length : 'MISSING');
console.log('📧 SendGrid API Key starts with:', process.env.EMAIL_PASS ? process.env.EMAIL_PASS.substring(0, 5) : 'MISSING');

// Set API Key properly
if (process.env.EMAIL_PASS && process.env.EMAIL_PASS.startsWith('SG.')) {
  sgMail.setApiKey(process.env.EMAIL_PASS.trim());
  console.log('📧 SendGrid API configured successfully');
} else {
  console.log('❌ Invalid SendGrid API Key');
}

// Email sending function (SendGrid API)
async function sendOTPEmail(email, otp, type) {
  try {
    // Check if API key is properly set
    if (!process.env.EMAIL_PASS || !process.env.EMAIL_PASS.startsWith('SG.')) {
      console.log('❌ SendGrid API Key not configured properly');
      return false;
    }

    const typeText = type === 'signup' ? 'Account Verification' : 
                    type === 'reset' ? 'Password Reset' : 'Login Verification';

    const msg = {
      to: email,
      from: '202401080009@mitaoe.ac.in',
      subject: `KryptoConnect Verification - ${otp}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #00ffcc, #00ccff); padding: 20px; text-align: center; color: white;">
            <h1>KryptoConnect</h1>
            <p>Secure Crypto Chat</p>
          </div>
          <div style="padding: 20px; background: white;">
            <h2>${typeText}</h2>
            <p>Your verification code is:</p>
            <div style="font-size: 32px; font-weight: bold; color: #00ffcc; text-align: center; margin: 20px 0; letter-spacing: 5px;">
              ${otp}
            </div>
            <p>This code will expire in 10 minutes.</p>
          </div>
        </div>
      `
    };

    console.log(`📧 Attempting to send OTP via SendGrid API to: ${email}`);
    
    // Send email
    const result = await sgMail.send(msg);
    console.log(`✅ OTP email sent via SendGrid API to: ${email}`);
    console.log(`✅ SendGrid Response:`, result[0]?.statusCode);
    
    return true;
    
  } catch (error) {
    console.error('❌ SendGrid API failed:', error.message);
    if (error.response) {
      console.error('❌ SendGrid Response Body:', error.response.body);
      console.error('❌ SendGrid Response Headers:', error.response.headers);
    }
    return false;
  }
}
// ============================
// Enhanced Schemas
// ============================

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: { 
    type: String, 
    sparse: true,
    validate: {
      validator: function(v) {
        return !v || /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
      },
      message: 'Please enter a valid email'
    }
  },
  phone: { 
    type: String, 
    sparse: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  joined: { 
    type: Date, 
    default: Date.now 
  },
  lastSeen: { 
    type: Date, 
    default: Date.now 
  },
  profilePicture: { 
    type: String, 
    default: null 
  }
});

const messageSchema = new mongoose.Schema({
  from: { 
    type: String, 
    required: true 
  },
  to: { 
    type: String, 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  },
  isFile: { 
    type: Boolean, 
    default: false 
  },
  fileData: { 
    type: Object, 
    default: null 
  },
  read: { 
    type: Boolean, 
    default: false 
  },
  messageId: { 
    type: String, 
    unique: true,
    sparse: true
  }
});

const friendRequestSchema = new mongoose.Schema({
  from: { 
    type: String, 
    required: true 
  },
  to: { 
    type: String, 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'accepted', 'rejected'], 
    default: 'pending' 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

const friendSchema = new mongoose.Schema({
  user1: { 
    type: String, 
    required: true 
  },
  user2: { 
    type: String, 
    required: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

const otpSchema = new mongoose.Schema({
  emailPhone: { 
    type: String, 
    required: true 
  },
  otp: { 
    type: String, 
    required: true 
  },
  type: { 
    type: String, 
    enum: ['signup', 'login', 'reset'], 
    required: true 
  },
  expiresAt: { 
    type: Date, 
    required: true 
  },
  attempts: { 
    type: Number, 
    default: 0 
  }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friend = mongoose.model('Friend', friendSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Create Indexes for Performance
async function createIndexes() {
  try {
    await User.createIndexes();
    await Message.createIndexes();
    await FriendRequest.createIndexes();
    await Friend.createIndexes();
    await OTP.createIndexes();
    
    await Message.collection.createIndex({ from: 1, to: 1, timestamp: -1 });
    await Message.collection.createIndex({ messageId: 1 }, { unique: true, sparse: true });
    await Friend.collection.createIndex({ user1: 1, user2: 1 });
    await FriendRequest.collection.createIndex({ from: 1, to: 1 });
    await OTP.collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 600 });
    console.log('✅ Database indexes created successfully');
  } catch (error) {
    console.log('⚠️ Index creation warning:', error.message);
  }
}

// Delay index creation to ensure DB connection
setTimeout(() => {
  if (mongoose.connection.readyState === 1) {
    createIndexes().catch(console.error);
  }
}, 5000);

// ============================
// File Upload Configuration
// ============================

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('✅ Uploads directory created');
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf', 'text/plain',
    'video/mp4', 'audio/mpeg',
    'application/zip', 'application/x-rar-compressed'
  ];
  
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} not allowed`), false);
  }
};

const upload = multer({ 
  storage, 
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter 
});

// ============================
// Passport Configuration
// ============================

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        username: profile.displayName.replace(/\s+/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
        email,
        password: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
        isVerified: true
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// Facebook OAuth
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "/auth/facebook/callback",
  profileFields: ['id', 'displayName', 'emails']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        username: profile.displayName.replace(/\s+/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
        email,
        password: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
        isVerified: true
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// ============================
// Utility Functions
// ============================

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePhone(phone) {
  const re = /^[\+]?[1-9][\d]{0,15}$/;
  return re.test(phone.replace(/\D/g, ''));
}

function validateEmailOrPhone(input) {
  return validateEmail(input) || validatePhone(input);
}

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ============================
// Basic Routes
// ============================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'Server is running!',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    environment: process.env.NODE_ENV || 'development',
    onlineUsers: Object.keys(onlineUsers).length
  });
});

// OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    req.session.userId = req.user._id;
    res.redirect('/');
  }
);

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    req.session.userId = req.user._id;
    res.redirect('/');
  }
);

// ============================
// OTP - Send OTP (COMPLETE FIXED BLOCK)
// ============================

app.post('/api/send-otp', asyncHandler(async (req, res) => {
  const { emailPhone, type } = req.body;

  // 1. Required fields
  if (!emailPhone || !type) {
    return res.status(400).json({ error: 'Email/phone and type are required' });
  }

  // 2. Validate email or phone
  if (!validateEmail(emailPhone) && !validatePhone(emailPhone)) {
    return res.status(400).json({ error: 'Please enter a valid email or phone number' });
  }

  // 3. Check user existence (SIGNUP)
  if (type === 'signup') {
    const existingUser = await User.findOne({
      $or: [{ email: emailPhone }, { phone: emailPhone }]
    });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email/phone' });
    }
  }

  // 4. Check user existence (LOGIN/RESET)
  if (type === 'login' || type === 'reset') {
    const user = await User.findOne({
      $or: [{ email: emailPhone }, { phone: emailPhone }]
    });
    if (!user) {
      return res.status(404).json({ error: 'No account found with this email/phone' });
    }
  }

  // 5. Delete previous OTP
  await OTP.deleteMany({ emailPhone });

  // 6. Generate OTP
  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // 7. Save OTP
  const otpRecord = new OTP({
    emailPhone,
    otp,
    type,
    expiresAt
  });
  await otpRecord.save();

  // 8. Send OTP via Email or SMS
  let sent = false;

  if (validateEmail(emailPhone)) {
    sent = await sendOTPEmail(emailPhone, otp, type);
  } else {
    sent = await sendOTPSMS(emailPhone, type);
  }

  console.log(`📩 OTP for ${emailPhone}: ${otp}`);

  // 9. Response
  res.json({
    success: sent,
    message: sent ? 'Verification code sent successfully' : 'Failed to send verification code',
    debugOtp: process.env.NODE_ENV === 'production' ? undefined : otp,
    method: validateEmail(emailPhone) ? 'email' : 'sms'
  });
}));

app.post('/api/verify-otp-signup', asyncHandler(async (req, res) => {
  const { emailPhone, otp, username, password } = req.body;

  if (!emailPhone || !otp || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Verify OTP first
  const otpRecord = await OTP.findOne({ emailPhone, type: 'signup' });
  
  if (!otpRecord) {
    return res.status(400).json({ error: 'Invalid or expired verification code' });
  }

  if (otpRecord.expiresAt < new Date()) {
    await OTP.deleteOne({ _id: otpRecord._id });
    return res.status(400).json({ error: 'Verification code expired' });
  }

if (validateEmail(emailPhone)) {
    if (otpRecord.otp !== otp)
        return res.status(400).json({ error: 'Invalid verification code' });
} else {
    const verified = await verifyOTPSMS(emailPhone, otp);
    if (!verified)
        return res.status(400).json({ error: 'Invalid verification code' });
}

  }
  else if (otpRecord.otp !== otp) {
    otpRecord.attempts += 1;
    await otpRecord.save();
    
    if (otpRecord.attempts >= 3) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ error: 'Too many failed attempts. Please request a new code.' });
    }
    
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Check if username already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  // Create user
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const userData = {
    username: username.trim(),
    password: hashedPassword,
    isVerified: true
  };

  if (validateEmail(emailPhone)) {
    userData.email = emailPhone;
  } else {
    userData.phone = emailPhone;
  }

  const newUser = new User(userData);
  await newUser.save();

  // Clean up OTP
  await OTP.deleteOne({ _id: otpRecord._id });

  res.json({ 
    success: true,
    message: 'Account created successfully',
    user: { 
      username: newUser.username,
      email: newUser.email,
      phone: newUser.phone
    }
  });
}));

app.post('/api/verify-otp', asyncHandler(async (req, res) => {
  const { emailPhone, otp, type } = req.body;

  if (!emailPhone || !otp || !type) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const otpRecord = await OTP.findOne({ emailPhone, type });
  
  if (!otpRecord) {
    return res.status(400).json({ error: 'Invalid or expired verification code' });
  }

  if (otpRecord.expiresAt < new Date()) {
    await OTP.deleteOne({ _id: otpRecord._id });
    return res.status(400).json({ error: 'Verification code expired' });
  }

  // SMS OTP verification for phone numbers
  if (validatePhone(emailPhone)) {
    const verified = await verifyOTPSMS(emailPhone, otp);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }
  }
  else if (otpRecord.otp !== otp) {
    otpRecord.attempts += 1;
    await otpRecord.save();
    
    if (otpRecord.attempts >= 3) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ error: 'Too many failed attempts. Please request a new code.' });
    }
    
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // OTP verified successfully
  await OTP.deleteOne({ _id: otpRecord._id });

  res.json({ 
    success: true,
    message: 'Verification successful',
    verified: true
  });
}));

app.post('/api/resend-otp', asyncHandler(async (req, res) => {
  const { emailPhone, type } = req.body;

  if (!emailPhone || !type) {
    return res.status(400).json({ error: 'Email/phone and type are required' });
  }

  // Delete previous OTP
  await OTP.deleteMany({ emailPhone, type });

  // Generate new OTP
  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const otpRecord = new OTP({
    emailPhone,
    otp,
    type,
    expiresAt
  });

  await otpRecord.save();

  // ✅ NEW: Send OTP via email or SMS
  let sent = false;

if (validateEmail(emailPhone)) {
    sent = await sendOTPEmail(emailPhone, otp, type);
} else {
    sent = await sendOTPSMS(emailPhone, type);
}


  console.log(`📧 New OTP for ${emailPhone} (${type}): ${otp}`);

  // ✅ UPDATED: Return status
  res.json({ 
    success: sent,
    message: sent ? 'Verification code sent successfully' : 'Failed to send verification code',
    debugOtp: process.env.NODE_ENV === 'production' ? undefined : otp,
    method: validateEmail(emailPhone) ? 'email' : 'sms'
  });
}));

// ============================
// File Upload & Download APIs
// ============================

app.post('/api/upload', upload.single('file'), asyncHandler(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // Additional file type validation
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.mp4', '.mp3', '.zip', '.rar'];
  const fileExtension = path.extname(req.file.originalname).toLowerCase();

  if (!allowedExtensions.includes(fileExtension)) {
    fs.unlinkSync(req.file.path); // Delete uploaded file
    return res.status(400).json({ error: 'File type not allowed' });
  }

  const fileData = {
    fileName: req.file.originalname,
    fileSize: req.file.size,
    fileType: req.file.mimetype,
    filePath: `/uploads/${req.file.filename}`,
    fileUrl: `/api/download/${req.file.filename}`,
    timestamp: Date.now()
  };

  res.json({
    success: true,
    ...fileData
  });
}));

app.get('/api/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.download(filePath);
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============================
// Auth & User APIs
// ============================

app.post('/api/register', asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({
    username: username.trim(),
    password: hashedPassword
  });

  await newUser.save();

  res.json({ 
    success: true,
    message: 'Registration successful', 
    user: { username: newUser.username } 
  });
}));

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  user.lastSeen = new Date();
  await user.save();

  req.session.userId = user._id;
  req.session.username = user.username;

  res.json({ 
    success: true,
    message: 'Login successful', 
    user: { 
      username: user.username,
      email: user.email,
      phone: user.phone
    } 
  });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logout successful' });
  });
});

app.get('/api/users', asyncHandler(async (req, res) => {
  const users = await User.find({}, 'username lastSeen isVerified');
  const usersWithOnlineStatus = users.map(user => ({
    username: user.username,
    lastSeen: user.lastSeen,
    isOnline: Object.values(onlineUsers).includes(user.username),
    isVerified: user.isVerified
  }));
  res.json(usersWithOnlineStatus);
}));

app.get('/api/user/:username', asyncHandler(async (req, res) => {
  const user = await User.findOne({ username: req.params.username }, 'username joined lastSeen isVerified');
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
}));

// ============================
// Friend System APIs
// ============================

app.get('/api/friend-requests/:username', asyncHandler(async (req, res) => {
  const requests = await FriendRequest.find({ 
    to: req.params.username, 
    status: 'pending' 
  });
  res.json(requests);
}));

app.get('/api/friends/:username', asyncHandler(async (req, res) => {
  const friends = await Friend.find({
    $or: [
      { user1: req.params.username },
      { user2: req.params.username }
    ]
  });

  const allFriends = friends.map(f => 
    f.user1 === req.params.username ? f.user2 : f.user1
  );
  
  res.json(allFriends);
}));

app.get('/api/messages/:user1/:user2', asyncHandler(async (req, res) => {
  const { user1, user2 } = req.params;
  const limit = parseInt(req.query.limit) || 50;
  const before = req.query.before ? new Date(req.query.before) : new Date();
  
  const messages = await Message.find({
    $or: [
      { from: user1, to: user2 },
      { from: user2, to: user1 }
    ],
    timestamp: { $lt: before }
  })
  .sort({ timestamp: -1 })
  .limit(limit);
  
  res.json(messages.reverse());
}));

// ============================
// Socket.IO Real-Time Chat (COMPLETELY FIXED)
// ============================

const onlineUsers = {};
const messageDeliveryTracker = new Map();

// Socket authentication middleware
io.use((socket, next) => {
  const username = socket.handshake.auth.username;
  if (username && username.trim() !== '') {
    socket.username = username.trim();
    next();
  } else {
    next(new Error('Authentication required'));
  }
});

io.on('connection', (socket) => {
  console.log('✅ User connected:', socket.username, socket.id);

  onlineUsers[socket.id] = socket.username;

  // Notify others about user coming online
  socket.broadcast.emit('userOnline', socket.username);

  // Send current online users to the connected user
  const currentOnlineUsers = [...new Set(Object.values(onlineUsers))];
  socket.emit('onlineUsers', currentOnlineUsers);

  // Send pending friend requests
  socket.on('getPendingRequests', async () => {
    try {
      const requests = await FriendRequest.find({ 
        to: socket.username, 
        status: 'pending' 
      });
      socket.emit('pendingRequests', requests);
    } catch (error) {
      console.error('Error getting pending requests:', error);
      socket.emit('error', { message: 'Failed to load pending requests' });
    }
  });

  // User login event
  socket.on('userLogin', (username) => {
    console.log('👤 User logged in:', username);
    onlineUsers[socket.id] = username;
    socket.broadcast.emit('userOnline', username);
  });

  // FIXED: Chat messages - NO DOUBLE MESSAGES
  socket.on('chatMessage', async (data) => {
    try {
      const { from, to, message, timestamp, messageId } = data;

      console.log('Processing message:', { from, to, message, messageId });

      if (!from || !to || !message) {
        socket.emit('error', { message: 'Invalid message data' });
        return;
      }

      // Trim and validate message
      const trimmedMessage = message.trim();
      if (trimmedMessage.length === 0) {
        socket.emit('error', { message: 'Message cannot be empty' });
        return;
      }

      // Check for duplicate messages using messageId
      if (messageId) {
        const existingMessage = await Message.findOne({ messageId });
        if (existingMessage) {
          console.log('⚠️ Duplicate message prevented (messageId):', messageId);
          
          // Still deliver to recipient if not received
          const recipientSocket = getSocketByUsername(to);
          if (recipientSocket) {
            io.to(recipientSocket).emit('chatMessage', {
              from,
              to,
              message: trimmedMessage,
              timestamp: existingMessage.timestamp,
              messageId: messageId
            });
          }
          return;
        }
      }

      // Check for duplicate messages in database (within 2 seconds)
      const duplicateMessage = await Message.findOne({
        from: from,
        to: to,
        message: trimmedMessage,
        timestamp: {
          $gte: new Date(timestamp - 2000),
          $lte: new Date(timestamp + 2000)
        }
      });

      if (duplicateMessage) {
        console.log('⚠️ Duplicate message prevented in database');
        return;
      }

      // Create new message
      const newMessage = new Message({
        from,
        to,
        message: trimmedMessage,
        timestamp: new Date(timestamp),
        messageId: messageId
      });

      await newMessage.save();

      console.log(`✅ Message saved to database: ${from} → ${to}: ${trimmedMessage}`);

      // Prepare response data
      const responseData = {
        from,
        to,
        message: trimmedMessage,
        timestamp: newMessage.timestamp,
        messageId: messageId || newMessage._id.toString()
      };

      // Send to recipient
      const recipientSocket = getSocketByUsername(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('chatMessage', responseData);
        console.log(`📤 Message sent to recipient: ${to}`);
      }

      // Send confirmation back to sender (only if not duplicate)
      socket.emit('chatMessage', responseData);
      console.log(`📤 Confirmation sent to sender: ${from}`);

    } catch (error) {
      console.error('❌ Chat message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Typing indicators
  socket.on('typingStart', (data) => {
    const recipientSocket = getSocketByUsername(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStart', { from: data.from });
    }
  });

  socket.on('typingStop', (data) => {
    const recipientSocket = getSocketByUsername(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStop', { from: data.from });
    }
  });

  // FIXED: Friend requests - NO DOUBLE FRIEND REQUESTS
  socket.on('friendRequest', async (data) => {
    try {
      const { from, to } = data;

      console.log('Processing friend request:', { from, to });

      // Check if users exist
      const fromUser = await User.findOne({ username: from });
      const toUser = await User.findOne({ username: to });
      
      if (!fromUser || !toUser) {
        socket.emit('friendRequestError', { error: 'User not found' });
        return;
      }

      if (from === to) {
        socket.emit('friendRequestError', { error: 'Cannot send friend request to yourself' });
        return;
      }

      // Check if already friends
      const existingFriendship = await Friend.findOne({
        $or: [
          { user1: from, user2: to },
          { user1: to, user2: from }
        ]
      });

      if (existingFriendship) {
        socket.emit('friendRequestError', { error: 'Already friends with this user' });
        return;
      }

      // Check if pending request already exists
      const existingRequest = await FriendRequest.findOne({
        $or: [
          { from: from, to: to, status: 'pending' },
          { from: to, to: from, status: 'pending' }
        ]
      });

      if (existingRequest) {
        socket.emit('friendRequestError', { error: 'Friend request already sent or pending' });
        return;
      }

      // Create friend request
      const friendRequest = new FriendRequest({
        from: from,
        to: to,
        status: 'pending'
      });

      await friendRequest.save();

      // Notify recipient
      const toSocket = getSocketByUsername(to);
      if (toSocket) {
        io.to(toSocket).emit('friendRequest', {
          from: from,
          to: to,
          timestamp: new Date().toISOString()
        });
      }

      // Send success to sender
      socket.emit('friendRequestSent', { to: to });

      console.log(`✅ Friend request created from ${from} to ${to}`);

    } catch (error) {
      console.error('Friend request error:', error);
      socket.emit('friendRequestError', { error: 'Failed to send friend request' });
    }
  });

  // FIXED: File upload via socket - NO DUPLICATES
  socket.on('fileUpload', async (fileData) => {
    try {
      if (!fileData.fileName || !fileData.from || !fileData.to) {
        socket.emit('fileUploadError', { error: 'Invalid file data' });
        return;
      }

      // Check for duplicate file using fileId
      if (fileData.fileId) {
        const existingFile = await Message.findOne({ 
          messageId: fileData.fileId,
          isFile: true 
        });
        if (existingFile) {
          console.log('⚠️ Duplicate file prevented:', fileData.fileId);
          
          // Still deliver to recipient if not received
          const recipientSocket = getSocketByUsername(fileData.to);
          if (recipientSocket) {
            io.to(recipientSocket).emit('fileUpload', {
              ...fileData,
              id: existingFile._id
            });
          }
          return;
        }
      }

      const fileMessage = new Message({
        from: fileData.from,
        to: fileData.to,
        message: `[FILE] ${fileData.fileName}`,
        timestamp: new Date(fileData.timestamp),
        isFile: true,
        fileData: fileData,
        messageId: fileData.fileId
      });

      await fileMessage.save();

      // Send to recipient
      const recipientSocket = getSocketByUsername(fileData.to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('fileUpload', {
          ...fileData,
          id: fileMessage._id
        });
      }

      // Also send back to sender (only if not duplicate)
      socket.emit('fileUpload', {
        ...fileData,
        id: fileMessage._id
      });

      console.log(`📁 File uploaded from ${fileData.from} to ${fileData.to}: ${fileData.fileName}`);

    } catch (error) {
      console.error('File upload error:', error);
      socket.emit('fileUploadError', { error: 'File upload failed' });
    }
  });

  // Friend request responses - IMPROVED
  socket.on('acceptFriendRequest', async (data) => {
    try {
      const { from, to } = data;

      console.log('Accepting friend request:', { from, to });

      // Update friend request status
      const updatedRequest = await FriendRequest.findOneAndUpdate(
        { from: from, to: to, status: 'pending' },
        { status: 'accepted' },
        { new: true }
      );

      if (!updatedRequest) {
        socket.emit('error', { message: 'Friend request not found or already processed' });
        return;
      }

      // Create friendship (both directions)
      const friendship = new Friend({
        user1: from,
        user2: to
      });

      await friendship.save();

      console.log(`✅ Friendship created between ${from} and ${to}`);

      // Notify both users
      const fromSocket = getSocketByUsername(from);
      const toSocket = getSocketByUsername(to);

      if (fromSocket) {
        io.to(fromSocket).emit('friendRequestAccepted', {
          from: to,
          to: from
        });
      }

      if (toSocket) {
        io.to(toSocket).emit('friendRequestAccepted', {
          from: from,
          to: to
        });
      }

    } catch (error) {
      console.error('Accept friend request error:', error);
      socket.emit('error', { message: 'Failed to accept friend request' });
    }
  });

  socket.on('rejectFriendRequest', async (data) => {
    try {
      const { from, to } = data;

      const updatedRequest = await FriendRequest.findOneAndUpdate(
        { from: from, to: to, status: 'pending' },
        { status: 'rejected' },
        { new: true }
      );

      if (!updatedRequest) {
        socket.emit('error', { message: 'Friend request not found' });
        return;
      }

      const fromSocket = getSocketByUsername(from);
      if (fromSocket) {
        io.to(fromSocket).emit('friendRequestRejected', {
          from: to,
          to: from
        });
      }

      console.log(`❌ Friend request rejected from ${from} to ${to}`);

    } catch (error) {
      console.error('Reject friend request error:', error);
      socket.emit('error', { message: 'Failed to reject friend request' });
    }
  });

  socket.on('removeFriend', async (data) => {
    try {
      const { from, friend } = data;

      const result = await Friend.deleteOne({
        $or: [
          { user1: from, user2: friend },
          { user1: friend, user2: from }
        ]
      });

      if (result.deletedCount === 0) {
        socket.emit('error', { message: 'Friendship not found' });
        return;
      }

      const friendSocket = getSocketByUsername(friend);
      if (friendSocket) {
        io.to(friendSocket).emit('friendRemoved', {
          from: from,
          friend: friend
        });
      }

      socket.emit('friendRemoved', {
        from: from,
        friend: friend
      });

      console.log(`🗑️ Friendship removed between ${from} and ${friend}`);

    } catch (error) {
      console.error('Remove friend error:', error);
      socket.emit('error', { message: 'Failed to remove friend' });
    }
  });

  socket.on('disconnect', (reason) => {
    const username = onlineUsers[socket.id];
    if (username) {
      delete onlineUsers[socket.id];
      socket.broadcast.emit('userOffline', username);
      
      // Update last seen in database
      User.findOneAndUpdate(
        { username: username },
        { lastSeen: new Date() }
      ).catch(console.error);
      
      console.log(`🔴 ${username} disconnected - ${Object.keys(onlineUsers).length} users online - Reason: ${reason}`);
    }
  });
});

// Helper function to get socket by username
function getSocketByUsername(username) {
  return Object.entries(onlineUsers).find(([_, uname]) => uname === username)?.[0];
}

// ============================
// Legal Pages (Required for OAuth)
// ============================

app.get("/privacy", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Privacy Policy - KryptoConnect</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #00ffcc; }
      </style>
    </head>
    <body>
      <h1>Privacy Policy</h1>
      <p>We value your privacy. KryptoConnect only uses your information to provide chat services and never shares your data with third parties.</p>
    </body>
    </html>
  `);
});

app.get("/terms", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Terms of Service - KryptoConnect</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #00ffcc; }
      </style>
    </head>
    <body>
      <h1>Terms of Service</h1>
      <p>By using KryptoConnect, you agree to follow our community guidelines and not share harmful content.</p>
    </body>
    </html>
  `);
});

app.get("/delete-data", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Data Deletion - KryptoConnect</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #00ffcc; }
      </style>
    </head>
    <body>
      <h1>Data Deletion Instructions</h1>
      <p>If you want to delete your data, please email us at support@kryptoconnect.com — we will remove it within 48 hours.</p>
    </body>
    </html>
  `);
});

// ============================
// Global Error Handler
// ============================

app.use((error, req, res, next) => {
  console.error('Unhandled Error:', error);
  
  // Multer file filter errors
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size too large. Maximum 100MB allowed.' });
    }
  }
  
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Something went wrong!' 
      : error.message 
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ============================
// Start Server
// ============================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 KryptoConnect Server Running on Port ${PORT}`);
  console.log('💬 Real-time Chat | 📁 File Sharing | 🔐 OAuth & OTP Verification');
  console.log('📍 Environment:', process.env.NODE_ENV || 'development');
  console.log('📍 MongoDB:', mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected');
  console.log('📍 Health Check: http://localhost:' + PORT + '/api/health');
  console.log('📍 Uploads Directory:', uploadsDir);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
