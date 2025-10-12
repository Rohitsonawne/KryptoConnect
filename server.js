const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kryptoconnect';

// ✅ DEBUG CODE ADD KARO YAHAN
console.log('🔍 DEBUG: MongoDB Connection Check');
console.log('MongoDB URI Present:', process.env.MONGODB_URI ? '✅ YES' : '❌ NO');
console.log('Using URI:', MONGODB_URI);

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB Connected Successfully!');
  console.log('Connection State:', mongoose.connection.readyState);
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  console.log('Connection State:', mongoose.connection.readyState);
});

// Connection events
mongoose.connection.on('connected', () => {
  console.log('🎯 MongoDB Event: CONNECTED');
});

mongoose.connection.on('error', (err) => {
  console.log('💥 MongoDB Event: ERROR -', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('🔴 MongoDB Event: DISCONNECTED');
});


mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  joined: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isFile: { type: Boolean, default: false },
  fileData: { type: Object, default: null }
});

const friendRequestSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  timestamp: { type: Date, default: Date.now }
});

const friendSchema = new mongoose.Schema({
  user1: { type: String, required: true },
  user2: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

// MongoDB Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friend = mongoose.model('Friend', friendSchema);

// In-memory storage for online users (temporary)
const onlineUsers = {};

// File upload constant
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API Routes
app.post('/api/register', async (req, res) => {
  try {
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

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username: username.trim(),
      password: hashedPassword
    });

    await newUser.save();
    
    console.log(`👤 New user registered: ${username}`);
    res.json({ 
      message: 'Registration successful', 
      user: { username: newUser.username } 
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last seen
    user.lastSeen = new Date();
    await user.save();

    console.log(`🔐 User logged in: ${username}`);
    res.json({ 
      message: 'Login successful', 
      user: { username: user.username } 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});
app.get('/api/connection-test', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const messagesCount = await Message.countDocuments();
    
    res.json({
      status: 'success',
      database: 'connected', 
      usersCount: usersCount,
      messagesCount: messagesCount,
      connectionState: mongoose.connection.readyState
    });
  } catch (error) {
    res.json({
      status: 'error',
      message: error.message,
      connectionState: mongoose.connection.readyState
    });
  }
});
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username lastSeen');
    const usersWithOnlineStatus = users.map(user => ({
      username: user.username,
      lastSeen: user.lastSeen,
      isOnline: Object.values(onlineUsers).includes(user.username)
    }));
    res.json(usersWithOnlineStatus);
  } catch (error) {
    console.error('Error loading users:', error);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.get('/api/friend-requests/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const requests = await FriendRequest.find({ 
      to: username, 
      status: 'pending' 
    });
    res.json(requests);
  } catch (error) {
    console.error('Error loading friend requests:', error);
    res.status(500).json({ error: 'Failed to load friend requests' });
  }
});

app.get('/api/friends/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const friends1 = await Friend.find({ user1: username });
    const friends2 = await Friend.find({ user2: username });
    
    const allFriends = [
      ...friends1.map(f => f.user2),
      ...friends2.map(f => f.user1)
    ];
    
    res.json(allFriends);
  } catch (error) {
    console.error('Error loading friends:', error);
    res.status(500).json({ error: 'Failed to load friends' });
  }
});

// Get chat history
app.get('/api/messages/:user1/:user2', async (req, res) => {
  try {
    const { user1, user2 } = req.params;
    
    const messages = await Message.find({
      $or: [
        { from: user1, to: user2 },
        { from: user2, to: user1 }
      ]
    }).sort({ timestamp: 1 });
    
    res.json(messages);
  } catch (error) {
    console.error('Error loading messages:', error);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});

// Get user stats
app.get('/api/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const onlineUsersCount = Object.keys(onlineUsers).length;
    const totalMessages = await Message.countDocuments();
    const activeChats = await Message.distinct('from');
    
    const stats = {
      totalUsers,
      onlineUsers: onlineUsersCount,
      totalMessages,
      activeChats: activeChats.length
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Error loading stats:', error);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('✅ A user connected:', socket.id);

  socket.on('userLogin', async (username) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        socket.emit('error', { message: 'User not found' });
        return;
      }

      onlineUsers[socket.id] = username;
      user.lastSeen = new Date();
      await user.save();
      
      socket.broadcast.emit('userOnline', username);
      console.log(`🟢 ${username} is online (${Object.keys(onlineUsers).length} users online)`);

      // Send pending friend requests
      const pendingRequests = await FriendRequest.find({ 
        to: username, 
        status: 'pending' 
      });
      
      if (pendingRequests.length > 0) {
        pendingRequests.forEach(request => {
          socket.emit('friendRequest', {
            from: request.from,
            to: username,
            timestamp: request.timestamp
          });
        });
      }

    } catch (error) {
      console.error('Login error:', error);
      socket.emit('error', { message: 'Login failed' });
    }
  });

  socket.on('chatMessage', async (data) => {
    try {
      const { from, to, message, timestamp } = data;

      if (!from || !to || !message) {
        socket.emit('error', { message: 'Invalid message data' });
        return;
      }

      // Save message to database
      const newMessage = new Message({
        from,
        to,
        message: message.trim(),
        timestamp: new Date(timestamp)
      });

      await newMessage.save();

      // Send to recipient
      const recipientSocket = findSocketByUsername(to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('chatMessage', data);
        console.log(`💬 Message delivered from ${from} to ${to}`);
      }

      console.log(`💬 Message from ${from} to ${to}`);

    } catch (error) {
      console.error('Chat message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

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

  socket.on('friendRequest', async (data) => {
    try {
      const { from, to } = data;
      console.log(`📩 Friend request from ${from} to ${to}`);

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
        from: from,
        to: to,
        status: 'pending'
      });

      if (existingRequest) {
        socket.emit('friendRequestError', { error: 'Request already sent' });
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
      const toSocket = findSocketByUsername(to);
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

  socket.on('fileUpload', async (fileData) => {
    try {
      console.log(`📁 File upload from ${fileData.from} to ${fileData.to}`);
      
      if (!fileData.fileName || !fileData.from || !fileData.to) {
        socket.emit('fileUploadError', { error: 'Invalid file data' });
        return;
      }
      
      if (fileData.fileSize > MAX_FILE_SIZE) {
        socket.emit('fileUploadError', { error: 'File size exceeds 100MB limit' });
        return;
      }

      // Save file message to database
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
      const recipientSocket = findSocketByUsername(fileData.to);
      if (recipientSocket) {
        io.to(recipientSocket).emit('fileUpload', fileData);
        console.log(`✅ File delivered to ${fileData.to}`);
      }

    } catch (error) {
      console.error('File upload error:', error);
      socket.emit('fileUploadError', { error: 'File upload failed' });
    }
  });

  socket.on('acceptFriendRequest', async (data) => {
    try {
      const { from, to } = data;
      console.log(`✅ ${to} accepted friend request from ${from}`);

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
      const fromSocket = findSocketByUsername(from);
      const toSocket = findSocketByUsername(to);

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
    }
  });

  socket.on('rejectFriendRequest', async (data) => {
    try {
      const { from, to } = data;
      console.log(`❌ ${to} rejected friend request from ${from}`);

      // Update friend request status
      await FriendRequest.updateOne(
        { from: from, to: to, status: 'pending' },
        { status: 'rejected' }
      );

      // Notify sender
      const fromSocket = findSocketByUsername(from);
      if (fromSocket) {
        io.to(fromSocket).emit('friendRequestRejected', {
          from: to,
          to: from
        });
      }

    } catch (error) {
      console.error('Reject friend request error:', error);
    }
  });

  socket.on('removeFriend', async (data) => {
    try {
      const { from, friend } = data;
      console.log(`🗑️ ${from} removed friend ${friend}`);

      // Remove friendship
      await Friend.deleteOne({
        $or: [
          { user1: from, user2: friend },
          { user1: friend, user2: from }
        ]
      });

      // Notify friend
      const friendSocket = findSocketByUsername(friend);
      if (friendSocket) {
        io.to(friendSocket).emit('friendRemoved', {
          from: from,
          friend: friend
        });
      }

    } catch (error) {
      console.error('Remove friend error:', error);
    }
  });

  socket.on('disconnect', (reason) => {
    const username = onlineUsers[socket.id];
    if (username) {
      socket.broadcast.emit('userOffline', username);
      delete onlineUsers[socket.id];
      console.log(`🔴 ${username} disconnected - ${Object.keys(onlineUsers).length} users online`);
    }
  });
});

// Helper Functions
function findSocketByUsername(username) {
  for (let [socketId, user] of Object.entries(onlineUsers)) {
    if (user === username) return socketId;
  }
  return null;
}

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log('🚀 KryptoConnect Server Started with MongoDB!');
  console.log(`📍 Server running on port ${PORT}`);
  console.log('💾 Database: MongoDB');
  console.log('💬 Real-time Chat: ACTIVE');
  console.log('📁 File Sharing: ACTIVE (100MB)');
});
