const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? process.env.CLIENT_URL || true : '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(express.json());

// CORS middleware for API routes
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage (for production use a database)
let users = [];
let messages = {};
let onlineUsers = {};

// Serve index.html (static middleware will also serve this)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API Routes
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  if (users.find(user => user.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const newUser = {
    id: generateId(),
    username,
    password, // NOTE: Hash passwords in production
    joined: new Date().toISOString()
  };

  users.push(newUser);
  res.json({ message: 'Registration successful', user: { username: newUser.username } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ message: 'Login successful', user: { username: user.username } });
});

app.get('/api/users', (req, res) => {
  res.json(users.map(user => ({ username: user.username })));
});

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('✅ A user connected:', socket.id);

  // User login
  socket.on('userLogin', (username) => {
    onlineUsers[socket.id] = username;
    socket.broadcast.emit('userOnline', username);
    console.log(`🟢 ${username} is online`);
  });

  // Chat messages
  socket.on('chatMessage', (data) => {
    const { from, to, message, timestamp } = data;

    // Save message
    const chatKey = [from, to].sort().join('_');
    if (!messages[chatKey]) messages[chatKey] = [];
    messages[chatKey].push({
      from,
      to,
      message,
      timestamp,
      id: generateId()
    });

    // Send to recipient if online
    const recipientSocket = findSocketByUsername(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('chatMessage', data);
    }

    // Also send to sender for confirmation
    socket.emit('chatMessage', data);
  });

  // File sharing
  socket.on('fileUpload', (fileData) => {
    socket.broadcast.emit('fileUpload', fileData);
  });

  // Typing indicators
  socket.on('typingStart', (data) => {
    const recipientSocket = findSocketByUsername(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStart', { from: data.from });
    }
  });

  socket.on('typingStop', (data) => {
    const recipientSocket = findSocketByUsername(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('typingStop', { from: data.from });
    }
  });

  // Friend requests
  socket.on('friendRequest', (data) => {
    const recipientSocket = findSocketByUsername(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friendRequest', data);
    }
  });

  // Disconnect
  socket.on('disconnect', () => {
    const username = onlineUsers[socket.id];
    if (username) {
      socket.broadcast.emit('userOffline', username);
      delete onlineUsers[socket.id];
      console.log(`🔴 ${username} disconnected`);
    }
    console.log('❌ A user disconnected:', socket.id);
  });
});

// Helper functions
function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

function findSocketByUsername(username) {
  for (let [socketId, user] of Object.entries(onlineUsers)) {
    if (user === username) return socketId;
  }
  return null;
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('💬 KryptoConnect Backend Ready!');
});