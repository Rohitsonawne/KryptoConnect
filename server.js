// ============================
// KryptoConnect - Enhanced Server.js (FIXED)
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

const app = express();
const server = http.createServer(app);

// Enhanced CORS configuration
app.use(cors({
  origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

const io = new Server(server, {
  cors: { 
    origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500"],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for development
  crossOriginEmbedderPolicy: false
}));

// Rate Limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Increased from 5 to 10
  message: 'Too many attempts, please try again later.'
});

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5, // Increased from 3 to 5
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
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ============================
// MongoDB Connection (IMPROVED)
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
// Enhanced Schemas (UNCHANGED)
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
    await Friend.collection.createIndex({ user1: 1, user2: 1 });
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
// File Upload Configuration (IMPROVED)
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
// Passport Configuration (UNCHANGED)
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
// Basic Routes (ENHANCED)
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
    environment: process.env.NODE_ENV || 'development'
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
// OTP APIs (FIXED)
// ============================

app.post('/api/send-otp', asyncHandler(async (req, res) => {
  const { emailPhone, type } = req.body;
  
  if (!emailPhone || !type) {
    return res.status(400).json({ error: 'Email/phone and type are required' });
  }

  if (!validateEmailOrPhone(emailPhone)) {
    return res.status(400).json({ error: 'Please enter a valid email or phone number' });
  }

  // Check if user exists (for signup)
  if (type === 'signup') {
    const existingUser = await User.findOne({ 
      $or: [
        { email: emailPhone },
        { phone: emailPhone }
      ]
    });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email/phone' });
    }
  }

  // Check if user exists (for login/reset)
  if (type === 'login' || type === 'reset') {
    const user = await User.findOne({ 
      $or: [
        { email: emailPhone },
        { phone: emailPhone }
      ]
    });
    if (!user) {
      return res.status(404).json({ error: 'No account found with this email/phone' });
    }
  }

  // Delete any existing OTP for this email/phone
  await OTP.deleteMany({ emailPhone });

  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const otpRecord = new OTP({
    emailPhone,
    otp,
    type,
    expiresAt
  });

  await otpRecord.save();

  console.log(`📧 OTP for ${emailPhone} (${type}): ${otp}`);

  res.json({ 
    success: true,
    message: 'Verification code sent successfully',
    debugOtp: process.env.NODE_ENV === 'production' ? undefined : otp
  });
}));

// FIXED: Added missing verify-otp-signup endpoint
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

  if (otpRecord.otp !== otp) {
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

  if (otpRecord.otp !== otp) {
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

  console.log(`📧 New OTP for ${emailPhone} (${type}): ${otp}`);

  res.json({ 
    success: true,
    message: 'Verification code sent successfully',
    debugOtp: process.env.NODE_ENV === 'production' ? undefined : otp
  });
}));

// ============================
// File Upload & Download APIs (FIXED)
// ============================

app.post('/api/upload', upload.single('file'), asyncHandler(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
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
// Auth & User APIs (ENHANCED)
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
  const friends1 = await Friend.find({ user1: req.params.username });
  const friends2 = await Friend.find({ user2: req.params.username });
  
  const allFriends = [
    ...friends1.map(f => f.user2),
    ...friends2.map(f => f.user1)
  ];
  
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
// Socket.IO Real-Time Chat (ENHANCED)
// ============================

const onlineUsers = {};

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

  // Chat messages
  socket.on('chatMessage', async (data) => {
    try {
      const { from, to, message, timestamp } = data;

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

      const newMessage = new Message({
        from,
        to,
        message: trimmedMessage,
        timestamp: new Date(timestamp)
      });

      await newMessage.save();

      // Send to recipient
      const recipientSocket = Object.entries(onlineUsers).find(([_, username]) => username === to)?.[0];
      if (recipientSocket) {
        io.to(recipientSocket).emit('chatMessage', {
          ...data,
          timestamp: newMessage.timestamp
        });
      }

      // Also send back to sender for confirmation
      socket.emit('chatMessage', {
        ...data,
        timestamp: newMessage.timestamp
      });

    } catch (error) {
      console.error('Chat message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Typing indicators
  socket.on('typingStart', (data) => {
    const recipientSocket = Object.entries(onlineUsers).find(([_, username]) => username === data.to)?.[0];
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStart', { from: data.from });
    }
  });

  socket.on('typingStop', (data) => {
    const recipientSocket = Object.entries(onlineUsers).find(([_, username]) => username === data.to)?.[0];
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStop', { from: data.from });
    }
  });

  // Friend requests
  socket.on('friendRequest', async (data) => {
    try {
      const { from, to } = data;

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
        socket.emit('friendRequestError', { error: 'Already friends' });
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
        socket.emit('friendRequestError', { error: 'Request already sent or pending' });
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
      const toSocket = Object.entries(onlineUsers).find(([_, username]) => username === to)?.[0];
      if (toSocket) {
        io.to(toSocket).emit('friendRequest', {
          from: from,
          to: to,
          timestamp: new Date().toISOString()
        });
      }

      socket.emit('friendRequestSent', { to: to });

    } catch (error) {
      console.error('Friend request error:', error);
      socket.emit('friendRequestError', { error: 'Failed to send friend request' });
    }
  });

  // File upload via socket
  socket.on('fileUpload', async (fileData) => {
    try {
      if (!fileData.fileName || !fileData.from || !fileData.to) {
        socket.emit('fileUploadError', { error: 'Invalid file data' });
        return;
      }

      const fileMessage = new Message({
        from: fileData.from,
        to: fileData.to,
        message: `[FILE] ${fileData.fileName}`,
        timestamp: new Date(fileData.timestamp),
        isFile: true,
        fileData: fileData
      });

      await fileMessage.save();

      // Send to recipient
      const recipientSocket = Object.entries(onlineUsers).find(([_, username]) => username === fileData.to)?.[0];
      if (recipientSocket) {
        io.to(recipientSocket).emit('fileUpload', fileData);
      }

      // Also send back to sender
      socket.emit('fileUpload', fileData);

    } catch (error) {
      console.error('File upload error:', error);
      socket.emit('fileUploadError', { error: 'File upload failed' });
    }
  });

  // Friend request responses
  socket.on('acceptFriendRequest', async (data) => {
    try {
      const { from, to } = data;

      // Update friend request status
      await FriendRequest.updateOne(
        { from: from, to: to, status: 'pending' },
        { status: 'accepted' }
      );

      // Create friendship
      const friendship = new Friend({
        user1: from,
        user2: to
      });

      await friendship.save();

      // Notify both users
      const fromSocket = Object.entries(onlineUsers).find(([_, username]) => username === from)?.[0];
      const toSocket = Object.entries(onlineUsers).find(([_, username]) => username === to)?.[0];

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

      await FriendRequest.updateOne(
        { from: from, to: to, status: 'pending' },
        { status: 'rejected' }
      );

      const fromSocket = Object.entries(onlineUsers).find(([_, username]) => username === from)?.[0];
      if (fromSocket) {
        io.to(fromSocket).emit('friendRequestRejected', {
          from: to,
          to: from
        });
      }

    } catch (error) {
      console.error('Reject friend request error:', error);
      socket.emit('error', { message: 'Failed to reject friend request' });
    }
  });

  socket.on('removeFriend', async (data) => {
    try {
      const { from, friend } = data;

      await Friend.deleteOne({
        $or: [
          { user1: from, user2: friend },
          { user1: friend, user2: from }
        ]
      });

      const friendSocket = Object.entries(onlineUsers).find(([_, username]) => username === friend)?.[0];
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
      console.log(`🔴 ${username} disconnected - ${Object.keys(onlineUsers).length} users online`);
    }
  });
});

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
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
