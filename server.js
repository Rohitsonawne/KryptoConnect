// Modern Auth System
document.addEventListener('DOMContentLoaded', function() {
    // Page elements
    const loginPage = document.getElementById('loginPage');
    const signupPage = document.getElementById('signupPage');
    const forgotPasswordPage = document.getElementById('forgotPasswordPage');
    const chatApp = document.getElementById('chatApp');
    
    // Navigation links
    const showSignup = document.getElementById('showSignup');
    const showLoginFromSignup = document.getElementById('showLoginFromSignup');
    const showForgotPassword = document.getElementById('showForgotPassword');
    const showLoginFromForgot = document.getElementById('showLoginFromForgot');
    
    // Forms
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    
    // Password toggles
    const loginPasswordToggle = document.getElementById('loginPasswordToggle');
    const signupPasswordToggle = document.getElementById('signupPasswordToggle');
    
    // Password strength
    const signupPassword = document.getElementById('signupPassword');
    const passwordStrengthFill = document.getElementById('passwordStrengthFill');
    const passwordStrengthText = document.getElementById('passwordStrengthText');

    // Navigation Functions
    function showPage(page) {
        // Hide all pages
        loginPage.style.display = 'none';
        signupPage.style.display = 'none';
        forgotPasswordPage.style.display = 'none';
        chatApp.style.display = 'none';
        
        // Show selected page
        page.style.display = 'block';
    }

    // Event Listeners for Navigation
    showSignup.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(signupPage);
    });

    showLoginFromSignup.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(loginPage);
    });

    showForgotPassword.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(forgotPasswordPage);
    });

    showLoginFromForgot.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(loginPage);
    });

    // Password Toggle Functionality
    function setupPasswordToggle(toggleBtn, passwordInput) {
        toggleBtn.addEventListener('click', () => {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            toggleBtn.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });
    }

    setupPasswordToggle(loginPasswordToggle, document.getElementById('loginPassword'));
    setupPasswordToggle(signupPasswordToggle, document.getElementById('signupPassword'));

    // Password Strength Indicator
    signupPassword.addEventListener('input', function() {
        const password = this.value;
        const strength = calculatePasswordStrength(password);
        
        passwordStrengthFill.style.width = strength.percentage + '%';
        passwordStrengthFill.style.background = strength.color;
        passwordStrengthText.textContent = strength.text;
        passwordStrengthText.style.color = strength.color;
    });

    function calculatePasswordStrength(password) {
        let score = 0;
        
        if (password.length >= 8) score += 25;
        if (password.length >= 12) score += 15;
        if (/[A-Z]/.test(password)) score += 20;
        if (/[a-z]/.test(password)) score += 20;
        if (/[0-9]/.test(password)) score += 20;
        if (/[^A-Za-z0-9]/.test(password)) score += 20;
        
        if (score >= 80) {
            return { percentage: 100, color: '#00ffcc', text: 'Strong' };
        } else if (score >= 60) {
            return { percentage: 75, color: '#ffcc00', text: 'Good' };
        } else if (score >= 40) {
            return { percentage: 50, color: '#ff9900', text: 'Fair' };
        } else {
            return { percentage: 25, color: '#ff6b6b', text: 'Weak' };
        }
    }

    // Form Submissions with Loading States
    function setButtonLoading(button, isLoading) {
        const btnText = button.querySelector('.btn-text');
        const btnLoader = button.querySelector('.btn-loader');
        
        if (isLoading) {
            btnText.style.opacity = '0';
            btnLoader.style.display = 'block';
            button.disabled = true;
        } else {
            btnText.style.opacity = '1';
            btnLoader.style.display = 'none';
            button.disabled = false;
        }
    }

    // Login Form Submission
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const loginBtn = document.getElementById('loginBtn');
        setButtonLoading(loginBtn, true);
        
        // Use your existing login logic here
        await handleLogin(); // Your existing handleLogin function
        
        setButtonLoading(loginBtn, false);
    });

    // Signup Form Submission
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const signupBtn = document.getElementById('signupBtn');
        setButtonLoading(signupBtn, true);
        
        // Add your signup logic here
        await handleSignup(); // You'll need to create this function
        
        setButtonLoading(signupBtn, false);
    });

    // Forgot Password Form Submission
    forgotPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const resetBtn = document.getElementById('resetPasswordBtn');
        setButtonLoading(resetBtn, true);
        
        // Simulate API call
        setTimeout(() => {
            document.getElementById('forgotSuccess').style.display = 'flex';
            document.getElementById('forgotError').textContent = '';
            setButtonLoading(resetBtn, false);
        }, 2000);
    });

    // Social Login Handlers (placeholder)
    document.querySelectorAll('.social-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            // Add social login integration here
            console.log('Social login clicked:', btn.textContent.trim());
        });
    });

    // Initialize - Show login page by default
    showPage(loginPage);
});

// Your existing handleLogin function will work with the new UI
// You'll need to modify it to show the chat app on successful login
async function handleLogin() {
    // Your existing login logic, but add:
    // On successful login:
    // document.getElementById('chatApp').style.display = 'block';
    // document.getElementById('loginPage').style.display = 'none';
}

// Add this function for signup
async function handleSignup() {
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    
    // Add your signup logic here
    console.log('Signup attempt:', { username, email, password, confirmPassword });
}



const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');

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
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kryptoconnect';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB Connected Successfully!');
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
});

// File Upload Configuration
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB
    }
});

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

// In-memory storage for online users
const onlineUsers = {};

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ✅ FILE UPLOAD ENDPOINT
app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        console.log('📁 File upload request received');
        
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

        console.log(`✅ File uploaded: ${fileData.fileName}`);
        res.json(fileData);

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'File upload failed' });
    }
});

// ✅ FILE DOWNLOAD ENDPOINT
app.get('/api/download/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(__dirname, 'uploads', filename);
        
        console.log(`📥 Download request for: ${filename}`);
        
        // Check if file exists
        if (!fs.existsSync(filePath)) {
            console.log('❌ File not found:', filename);
            return res.status(404).json({ error: 'File not found' });
        }

        // Get original filename from database or use stored name
        const originalName = req.query.original || filename;

        // Set headers for download
        res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
        res.setHeader('Content-Type', 'application/octet-stream');

        // Stream file to response
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);

        console.log(`✅ File download started: ${filename}`);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// Serve static files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

            // Save file message to database
            const fileMessage = new Message({
                from: fileData.from,
                to: fileData.to,
                message: `[FILE] ${fileData.fileName}`,
                timestamp: new Date(fileData.timestamp),
                isFile: true,
                fileData: {
                    fileName: fileData.fileName,
                    fileSize: fileData.fileSize,
                    fileType: fileData.fileType,
                    filePath: fileData.filePath,
                    fileUrl: fileData.fileUrl,
                    from: fileData.from,
                    to: fileData.to,
                    timestamp: fileData.timestamp
                }
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
    console.log('📂 Uploads Directory: ./uploads/');
});
