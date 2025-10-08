// Development vs Production configuration
const isDevelopment = window.location.port === '5500' || window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
const API_BASE_URL = isDevelopment ? 'http://localhost:3000' : window.location.protocol + '//' + window.location.host;
const socket = isDevelopment ? io('http://localhost:3000') : io();

// DOM Elements - KryptoConnect specific
const authSection = document.getElementById('authSection');
const chatSection = document.getElementById('chatSection');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const showRegister = document.getElementById('showRegister');
const showLogin = document.getElementById('showLogin');
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const logoutBtn = document.getElementById('logoutBtn');
const loginError = document.getElementById('loginError');
const regError = document.getElementById('regError');
const usernameDisplay = document.getElementById('usernameDisplay');
const userAvatar = document.getElementById('userAvatar');
const usersList = document.getElementById('usersList');
const friendsList = document.getElementById('friendsList');
const messagesContainer = document.getElementById('messagesContainer');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const chatWithInfo = document.getElementById('chatWithInfo');
const chatWithName = document.getElementById('chatWithName');
const noChatSelected = document.getElementById('noChatSelected');
const typingIndicator = document.getElementById('typingIndicator');
const addFriendBtn = document.getElementById('addFriendBtn');
const addFriendModal = document.getElementById('addFriendModal');
const closeModal = document.getElementById('closeModal');
const friendUsername = document.getElementById('friendUsername');
const sendFriendRequestBtn = document.getElementById('sendFriendRequestBtn');
const friendError = document.getElementById('friendError');
const clearChatBtn = document.getElementById('clearChatBtn');

// App State
let currentUser = null;
let currentChatWith = null;
let isTyping = false;
let typingTimer = null;
let allUsers = [];

// Initialize Socket Events
socket.on('connect', () => {
    console.log('✅ Connected to server');
    if (currentUser) {
        socket.emit('userLogin', currentUser);
    }
});

socket.on('disconnect', () => {
    console.log('❌ Disconnected from server');
});

socket.on('userOnline', (username) => {
    updateUserStatus(username, true);
    showNotification(`${username} is now online`, 'online');
});

socket.on('userOffline', (username) => {
    updateUserStatus(username, false);
    showNotification(`${username} is now offline`, 'offline');
});

socket.on('chatMessage', (data) => {
    if (data.from === currentChatWith) {
        addMessageToChat(data.from, data.message, data.timestamp, false);
    }
});

socket.on('typingStart', (data) => {
    if (data.from === currentChatWith) {
        typingIndicator.textContent = `${data.from} is typing...`;
    }
});

socket.on('typingStop', (data) => {
    if (data.from === currentChatWith) {
        typingIndicator.textContent = '';
    }
});

socket.on('friendRequest', (data) => {
    showFriendRequestNotification(data.from);
});

// Event Listeners
showRegister.addEventListener('click', () => {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
    loginError.textContent = '';
});

showLogin.addEventListener('click', () => {
    registerForm.style.display = 'none';
    loginForm.style.display = 'block';
    regError.textContent = '';
});

loginBtn.addEventListener('click', handleLogin);
registerBtn.addEventListener('click', handleRegister);
logoutBtn.addEventListener('click', handleLogout);
sendBtn.addEventListener('click', sendMessage);

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

messageInput.addEventListener('input', handleTyping);

// Friend system events
addFriendBtn.addEventListener('click', () => {
    addFriendModal.style.display = 'flex';
});

closeModal.addEventListener('click', () => {
    addFriendModal.style.display = 'none';
    friendError.textContent = '';
});

sendFriendRequestBtn.addEventListener('click', sendFriendRequestHandler);

clearChatBtn.addEventListener('click', clearChat);

// Functions
async function handleLogin() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!username || !password) {
        loginError.textContent = 'Please enter both username and password';
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            loginError.textContent = data.error;
            return;
        }
        
        loginError.textContent = '';
        currentUser = username;
        
        // Update UI
        usernameDisplay.textContent = currentUser;
        userAvatar.textContent = currentUser.charAt(0).toUpperCase();
        
        authSection.style.display = 'none';
        chatSection.style.display = 'flex';
        
        // Socket.io login
        socket.emit('userLogin', currentUser);
        
        // Load users and friends
        await loadAllUsers();
        loadFriendsList();
        
        localStorage.setItem('kryptoconnect_current_user', currentUser);
        
    } catch (error) {
        loginError.textContent = 'Login failed. Please try again.';
        console.error('Login error:', error);
    }
}

async function handleRegister() {
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('regConfirmPassword').value;
    
    if (!username || !password || !confirmPassword) {
        regError.textContent = 'Please fill in all fields';
        return;
    }
    
    if (password !== confirmPassword) {
        regError.textContent = 'Passwords do not match';
        return;
    }
    
    if (username.length < 3) {
        regError.textContent = 'Username must be at least 3 characters';
        return;
    }
    
    if (password.length < 6) {
        regError.textContent = 'Password must be at least 6 characters';
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            regError.textContent = data.error;
            return;
        }
        
        regError.textContent = '';
        document.getElementById('loginUsername').value = username;
        registerForm.style.display = 'none';
        loginForm.style.display = 'block';
        loginError.textContent = 'Registration successful! Please login.';
        loginError.className = 'success-message';
        
    } catch (error) {
        regError.textContent = 'Registration failed. Please try again.';
        console.error('Registration error:', error);
    }
}

function handleLogout() {
    currentUser = null;
    currentChatWith = null;
    chatSection.style.display = 'none';
    authSection.style.display = 'flex';
    messagesContainer.innerHTML = '';
    loginError.textContent = '';
    loginError.className = 'error-message';
    localStorage.removeItem('kryptoconnect_current_user');
    
    // Socket.io disconnect
    socket.disconnect();
    socket.connect();
}

async function loadAllUsers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/users`);
        allUsers = await response.json();
        renderUsersList();
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

function renderUsersList() {
    usersList.innerHTML = '';
    
    const friends = getFriends(currentUser);
    const otherUsers = allUsers.filter(user => 
        user.username !== currentUser && !friends.includes(user.username)
    );
    
    if (otherUsers.length === 0) {
        usersList.innerHTML = '<li style="padding: 20px; text-align: center; color: #a3f4e8;">No other users available</li>';
        return;
    }
    
    otherUsers.forEach(user => {
        const userElement = document.createElement('li');
        userElement.className = 'user-item';
        
        userElement.innerHTML = `
            <div class="user-info-small">
                <div class="user-status" style="background: #00ffcc"></div>
                <span>${escapeHTML(user.username)}</span>
            </div>
            <div class="friend-actions">
                <button class="friend-action-btn add-friend-action" title="Add Friend">
                    <i class="fas fa-user-plus"></i>
                </button>
            </div>
        `;
        
        // ✅ YAHIN ADD KARO - CLICK EVENT LISTENER
        userElement.addEventListener('click', () => {
            console.log('Clicked on user:', user.username);
            startChatWith(user.username);
        });
        
        userElement.querySelector('.add-friend-action').addEventListener('click', (e) => {
            e.stopPropagation();
            sendFriendRequest(currentUser, user.username);
            userElement.innerHTML = `
                <div class="user-info-small">
                    <div class="user-status" style="background: #ffcc00"></div>
                    <span>${escapeHTML(user.username)}</span>
                </div>
                <span style="font-size:0.7rem; color:#ffcc00;">Request Sent</span>
            `;
        });
        
        usersList.appendChild(userElement);
    });
}

function loadFriendsList() {
    friendsList.innerHTML = '';
    
    const friends = getFriends(currentUser);
    
    if (friends.length === 0) {
        friendsList.innerHTML = '<li style="padding: 20px; text-align: center; color: #a3f4e8;">No friends yet. Add some friends to start chatting!</li>';
        return;
    }
    
    friends.forEach(friend => {
        const friendElement = document.createElement('li');
        friendElement.className = 'user-item';
        
        friendElement.innerHTML = `
            <div class="user-info-small">
                <div class="user-status" style="background: #00ffcc"></div>
                <span>${escapeHTML(friend)}</span>
            </div>
            <div class="friend-actions">
                <button class="friend-action-btn remove-friend-action" title="Remove Friend">
                    <i class="fas fa-user-minus"></i>
                </button>
            </div>
        `;
        
        friendElement.addEventListener('click', () => {
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('active');
            });
            friendElement.classList.add('active');
            startChatWith(friend);
        });
        
        friendElement.querySelector('.remove-friend-action').addEventListener('click', (e) => {
            e.stopPropagation();
            removeFriend(currentUser, friend);
            loadFriendsList();
            renderUsersList();
        });
        
        friendsList.appendChild(friendElement);
    });
}

function startChatWith(username) {
    currentChatWith = username;
    chatWithName.textContent = username;
    chatWithInfo.style.display = 'flex';
    noChatSelected.style.display = 'none';
    messageInput.disabled = false;
    sendBtn.disabled = false;
    messageInput.placeholder = `Message ${username}...`;
    messageInput.focus();
    loadChatHistory(username);
}

function loadChatHistory(username) {
    messagesContainer.innerHTML = '';
    
    // In a real app, you would fetch chat history from the server
    const history = getChatHistory(currentUser, username);
    
    if (history.length > 0) {
        history.forEach(message => {
            addMessageToChat(message.sender, message.text, message.time, message.sender === currentUser);
        });
    } else {
        const noMessages = document.createElement('div');
        noMessages.className = 'no-chat-selected';
        noMessages.innerHTML = `
            <div>
                <i class="fas fa-comment" style="font-size: 3rem; margin-bottom: 15px; opacity: 0.5;"></i>
                <h3>Start a conversation with ${escapeHTML(username)}</h3>
                <p>No messages yet. Send the first message to start chatting!</p>
            </div>
        `;
        messagesContainer.appendChild(noMessages);
    }
    
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function addMessageToChat(sender, text, time, isSender) {
    const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
    if (noMessagesElement) {
        noMessagesElement.remove();
    }
    
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isSender ? 'sent' : 'received'}`;
    
    messageElement.innerHTML = `
        <div class="message-sender">${isSender ? 'You' : escapeHTML(sender)}</div>
        <div class="message-text">${escapeHTML(text)}</div>
        <div class="message-time">${time}</div>
    `;
    
    messagesContainer.appendChild(messageElement);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !currentChatWith) return;
    
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const timestamp = Date.now();
    
    // Send via Socket.io
    socket.emit('chatMessage', {
        from: currentUser,
        to: currentChatWith,
        message: text,
        timestamp: timestamp
    });
    
    // Add to UI immediately
    addMessageToChat(currentUser, text, time, true);
    messageInput.value = '';
    
    // Save to local storage (for persistence)
    saveChatMessage(currentUser, currentChatWith, {
        sender: currentUser,
        text: text,
        time: time,
        timestamp: timestamp
    });
}

function handleTyping() {
    if (!currentChatWith) return;
    
    if (!isTyping) {
        isTyping = true;
        socket.emit('typingStart', { from: currentUser, to: currentChatWith });
    }
    
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
        isTyping = false;
        socket.emit('typingStop', { from: currentUser, to: currentChatWith });
    }, 1000);
}

function sendFriendRequestHandler() {
    const username = friendUsername.value.trim();
    
    if (!username) {
        friendError.textContent = 'Please enter a username';
        return;
    }
    
    if (username === currentUser) {
        friendError.textContent = 'You cannot add yourself as a friend';
        return;
    }
    
    if (!allUsers.find(user => user.username === username)) {
        friendError.textContent = 'User not found';
        return;
    }
    
    const friends = getFriends(currentUser);
    if (friends.includes(username)) {
        friendError.textContent = 'This user is already your friend';
        return;
    }
    
    // Send friend request via Socket.io
    socket.emit('friendRequest', {
        from: currentUser,
        to: username
    });
    
    friendError.textContent = '';
    friendUsername.value = '';
    addFriendModal.style.display = 'none';
    
    showNotification(`Friend request sent to ${username}`, 'success');
    renderUsersList();
}

function clearChat() {
    if (!currentChatWith) return;
    
    if (confirm("Are you sure you want to clear the chat history with " + currentChatWith + "?")) {
        clearChatHistory(currentUser, currentChatWith);
        loadChatHistory(currentChatWith);
    }
}

// Helper functions
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? 'rgba(0, 255, 204, 0.2)' : type === 'online' ? 'rgba(0, 255, 0, 0.2)' : 'rgba(255, 0, 0, 0.2)'};
        border: 1px solid ${type === 'success' ? '#00ffcc' : type === 'online' ? '#00ff00' : '#ff0000'};
        border-radius: 10px;
        padding: 15px;
        z-index: 1000;
        max-width: 300px;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (document.body.contains(notification)) {
            document.body.removeChild(notification);
        }
    }, 3000);
}

function showFriendRequestNotification(fromUser) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(0, 255, 204, 0.2);
        border: 1px solid #00ffcc;
        border-radius: 10px;
        padding: 15px;
        z-index: 1000;
        max-width: 300px;
    `;
    
    notification.innerHTML = `
        <h4>Friend Request</h4>
        <p>${fromUser} wants to be your friend</p>
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button class="btn" onclick="acceptFriendRequest('${fromUser}')" style="padding: 5px 10px; font-size: 0.8rem;">Accept</button>
            <button class="btn-secondary" onclick="this.parentElement.parentElement.remove()" style="padding: 5px 10px; font-size: 0.8rem;">Ignore</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (document.body.contains(notification)) {
            document.body.removeChild(notification);
        }
    }, 10000);
}

// Friend management functions (using localStorage as fallback)
function getFriends(username) {
    const key = `friends_${username}`;
    return JSON.parse(localStorage.getItem(key)) || [];
}

function saveFriend(username, friendUsername) {
    const key = `friends_${username}`;
    const friends = getFriends(username);
    if (!friends.includes(friendUsername)) {
        friends.push(friendUsername);
        localStorage.setItem(key, JSON.stringify(friends));
        return true;
    }
    return false;
}

function removeFriend(username, friendUsername) {
    const key = `friends_${username}`;
    let friends = getFriends(username);
    friends = friends.filter(f => f !== friendUsername);
    localStorage.setItem(key, JSON.stringify(friends));
}

// Chat history functions
function getChatHistory(user1, user2) {
    const key = `chat_${[user1, user2].sort().join('_')}`;
    return JSON.parse(localStorage.getItem(key)) || [];
}

function saveChatMessage(user1, user2, message) {
    const key = `chat_${[user1, user2].sort().join('_')}`;
    const history = getChatHistory(user1, user2);
    history.push(message);
    localStorage.setItem(key, JSON.stringify(history));
}

function clearChatHistory(user1, user2) {
    const key = `chat_${[user1, user2].sort().join('_')}`;
    localStorage.setItem(key, JSON.stringify([]));
}

function updateUserStatus(username, isOnline) {
    // Update status indicator in UI
    const statusIndicators = document.querySelectorAll(`.user-item:contains('${username}') .user-status`);
    statusIndicators.forEach(indicator => {
        indicator.style.background = isOnline ? '#00ffcc' : '#ff6b6b';
    });
}

// Global functions for notifications
window.acceptFriendRequest = function(fromUser) {
    saveFriend(currentUser, fromUser);
    saveFriend(fromUser, currentUser);
    loadFriendsList();
    renderUsersList();
    
    // Remove notification
    const notifications = document.querySelectorAll('div');
    notifications.forEach(notif => {
        if (notif.innerHTML.includes('Friend Request')) {
            notif.remove();
        }
    });
    
    showNotification(`You are now friends with ${fromUser}`, 'success');
};

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    const savedUser = localStorage.getItem('kryptoconnect_current_user');
    if (savedUser) {
        currentUser = savedUser;
        usernameDisplay.textContent = currentUser;
        userAvatar.textContent = currentUser.charAt(0).toUpperCase();
        authSection.style.display = 'none';
        chatSection.style.display = 'flex';
        
        // Socket.io login
        socket.emit('userLogin', currentUser);
        
        // Load users and friends
        loadAllUsers();
        loadFriendsList();
    }
});
