// ============================
// KryptoConnect - Server.js
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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === Sessions ===
app.use(session({
  secret: 'kryptoconnect_secret_key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// ============================
// MongoDB Connection
// ============================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kryptoconnect';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB Connected Successfully!'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ============================
// File Upload Config
// ============================

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ============================
// MongoDB Schemas
// ============================

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  joined: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
});
const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
  isFile: { type: Boolean, default: false },
  fileData: { type: Object, default: null }
});
const friendRequestSchema = new mongoose.Schema({
  from: String,
  to: String,
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  timestamp: { type: Date, default: Date.now }
});
const friendSchema = new mongoose.Schema({
  user1: String,
  user2: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friend = mongoose.model('Friend', friendSchema);

// ============================
// Passport Serialization
// ============================

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ============================
// Google OAuth Strategy
// ============================

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
        username: profile.displayName,
        email,
        password: await bcrypt.hash('google-login', 10)
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// ============================
// Facebook OAuth Strategy
// ============================

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
        username: profile.displayName,
        email,
        password: await bcrypt.hash('facebook-login', 10)
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// ============================
// Basic Routes
// ============================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// === Google Auth Routes ===
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => res.redirect('/')
);

// === Facebook Auth Routes ===
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login.html' }),
  (req, res) => res.redirect('/')
);

// ============================
// File Upload & Download APIs
// ============================

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const fileData = {
      fileName: req.file.originalname,
      fileSize: req.file.size,
      fileType: req.file.mimetype,
      filePath: `/uploads/${req.file.filename}`,
      fileUrl: `/api/download/${req.file.filename}`,
      timestamp: Date.now()
    };
    res.json(fileData);
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});

app.get('/api/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.download(filePath);
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============================
// Auth & User APIs
// ============================

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required' });
    if (await User.findOne({ username }))
      return res.status(400).json({ error: 'Username already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username: username.trim(), password: hashedPassword });
    await newUser.save();
    res.json({ message: 'Registration successful', user: { username: newUser.username } });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });
    user.lastSeen = new Date();
    await user.save();
    res.json({ message: 'Login successful', user: { username: user.username } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================
// Socket.IO Real-Time Chat
// ============================

const onlineUsers = {};
io.on('connection', (socket) => {
  console.log('✅ A user connected:', socket.id);

  socket.on('userLogin', async (username) => {
    onlineUsers[socket.id] = username;
    socket.broadcast.emit('userOnline', username);
  });

  socket.on('chatMessage', async (data) => {
    const { from, to, message } = data;
    const newMessage = new Message({ from, to, message, timestamp: new Date() });
    await newMessage.save();
    const recipientSocket = Object.entries(onlineUsers).find(([_, user]) => user === to)?.[0];
    if (recipientSocket) io.to(recipientSocket).emit('chatMessage', data);
  });

  socket.on('disconnect', () => {
    const username = onlineUsers[socket.id];
    delete onlineUsers[socket.id];
    socket.broadcast.emit('userOffline', username);
  });
});

// ============================
// Start Server
// ============================

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 KryptoConnect Server Running on Port ${PORT}`);
  console.log('💬 Real-time Chat, 📁 File Sharing, 🔐 OAuth Active');
});
