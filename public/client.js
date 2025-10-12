const socket = io();

// DOM Elements
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
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const filePreview = document.getElementById('filePreview');
const filePreviewName = document.getElementById('filePreviewName');
const filePreviewSize = document.getElementById('filePreviewSize');
const filePreviewIcon = document.getElementById('filePreviewIcon');
const filePreviewImage = document.getElementById('filePreviewImage');
const fileRemoveBtn = document.getElementById('fileRemoveBtn');
const uploadProgressBar = document.getElementById('uploadProgressBar');
const attachFileBtn = document.getElementById('attachFileBtn');
const fileUploadContainer = document.getElementById('fileUploadContainer');
const uploadInfo = document.getElementById('uploadInfo');
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
let selectedFile = null;
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB in bytes

// Initialize Socket Events
socket.on('connect', () => {
    console.log('✅ Connected to server with ID:', socket.id);
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
    console.log('📨 Message received:', data);
    if (data.from === currentChatWith || data.to === currentChatWith) {
        addMessageToChat(data.from, data.message, formatTime(data.timestamp), data.from !== currentUser);
        saveChatMessage(currentUser, currentChatWith, {
            sender: data.from,
            text: data.message,
            time: formatTime(data.timestamp),
            timestamp: data.timestamp
        });
        
        // Ensure input remains visible after receiving message
        setTimeout(ensureInputVisible, 100);
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

// Friend request events
socket.on('friendRequest', (data) => {
    console.log('📩 Friend request received:', data);
    if (data.to === currentUser) {
        showFriendRequestNotification(data.from);
    }
});

socket.on('friendRequestForUser', (data) => {
    console.log('📩 Friend request for user:', data);
    if (data.to === currentUser) {
        console.log('✅ This friend request is for me!');
        showFriendRequestNotification(data.from);
    }
});

socket.on('friendRequestSent', (data) => {
    console.log('✅ Friend request sent to:', data.to);
    showNotification(`Friend request sent to ${data.to}`, 'success');
    renderUsersList();
});

socket.on('friendRequestError', (data) => {
    console.log('❌ Friend request error:', data.error);
    showNotification(data.error, 'error');
});

socket.on('friendRequestAccepted', (data) => {
    console.log('✅ Friend request accepted:', data);
    if (data.to === currentUser) {
        loadFriendsList();
        renderUsersList();
        showNotification(`${data.from} accepted your friend request!`, 'success');
    }
});

socket.on('friendRequestRejected', (data) => {
    console.log('❌ Friend request rejected by:', data.from);
    showNotification(`${data.from} rejected your friend request`, 'info');
});

socket.on('friendRemoved', (data) => {
    console.log('🗑️ Friend removed you:', data.from);
    showNotification(`${data.from} removed you from friends`, 'info');
    loadFriendsList();
    renderUsersList();
});

// File upload events
socket.on('fileUpload', (fileData) => {
    console.log('📁 File received:', fileData);
    if ((fileData.to === currentUser && fileData.from === currentChatWith) || 
        (fileData.from === currentUser && fileData.to === currentChatWith)) {
        addFileMessageToChat(fileData, fileData.from !== currentUser);
        saveChatMessage(currentUser, currentChatWith, {
            sender: fileData.from,
            text: `[FILE] ${fileData.fileName}`,
            time: formatTime(fileData.timestamp),
            timestamp: fileData.timestamp,
            isFile: true,
            fileData: fileData
        });
        
        // Ensure input remains visible after receiving file
        setTimeout(ensureInputVisible, 100);
    }
});

socket.on('fileUploadError', (data) => {
    showNotification(data.error, 'error');
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

addFriendBtn.addEventListener('click', () => {
    addFriendModal.style.display = 'flex';
});

closeModal.addEventListener('click', () => {
    addFriendModal.style.display = 'none';
    friendError.textContent = '';
});

sendFriendRequestBtn.addEventListener('click', sendFriendRequestHandler);
clearChatBtn.addEventListener('click', clearChat);

// File Upload Event Listeners
attachFileBtn.addEventListener('click', toggleFileUpload);
fileInput.addEventListener('change', handleFileSelect);
uploadBtn.addEventListener('click', uploadFile);
fileRemoveBtn.addEventListener('click', clearFileSelection);

// Functions
async function handleLogin() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!username || !password) {
        loginError.textContent = 'Please enter both username and password';
        return;
    }
    
    try {
        const response = await fetch('/api/login', {
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
        
        usernameDisplay.textContent = currentUser;
        userAvatar.textContent = currentUser.charAt(0).toUpperCase();
        
        authSection.style.display = 'none';
        chatSection.style.display = 'flex';
        
        socket.emit('userLogin', currentUser);
        
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
        const response = await fetch('/api/register', {
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
    
    socket.disconnect();
    socket.connect();
}

async function loadAllUsers() {
    try {
        const response = await fetch('/api/users');
        allUsers = await response.json();
        renderUsersList();
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

function renderUsersList() {
    usersList.innerHTML = '';
    
    const friends = getFriends(currentUser);
    const pendingRequests = getPendingRequests(currentUser);
    
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
        
        let statusHTML = '';
        if (pendingRequests.includes(user.username)) {
            statusHTML = '<span style="font-size:0.7rem; color:#ffcc00;">Request Pending</span>';
        } else {
            statusHTML = `
                <button class="friend-action-btn add-friend-action" title="Add Friend">
                    <i class="fas fa-user-plus"></i>
                </button>
            `;
        }
        
        userElement.innerHTML = `
            <div class="user-info-small">
                <div class="user-status" style="background: #00ffcc"></div>
                <span>${escapeHTML(user.username)}</span>
            </div>
            <div class="friend-actions">
                ${statusHTML}
            </div>
        `;
        
        userElement.addEventListener('click', () => {
            startChatWith(user.username);
        });
        
        const addBtn = userElement.querySelector('.add-friend-action');
        if (addBtn) {
            addBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                sendFriendRequest(currentUser, user.username);
            });
        }
        
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
            socket.emit('removeFriend', { from: currentUser, friend: friend });
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
    
    // Hide file upload section when switching chats
    fileUploadContainer.style.display = 'none';
    uploadInfo.style.display = 'none';
    clearFileSelection();
    
    loadChatHistory(username);
    
    // Ensure input is visible when starting new chat
    setTimeout(ensureInputVisible, 100);
}

function loadChatHistory(username) {
    messagesContainer.innerHTML = '';
    
    const history = getChatHistory(currentUser, username);
    
    if (history.length > 0) {
        history.forEach(message => {
            if (message.isFile) {
                addFileMessageToChat(message.fileData, message.sender === currentUser);
            } else {
                addMessageToChat(message.sender, message.text, message.time, message.sender === currentUser);
            }
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
    
    scrollToBottom();
    ensureInputVisible();
}

function addMessageToChat(sender, text, time, isSender) {
    const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
    if (noMessagesElement) {
        noMessagesElement.remove();
    }
    
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isSender ? 'sent' : 'received'}`;
    
    messageElement.innerHTML = `
        ${!isSender ? `<div class="message-sender">${escapeHTML(sender)}</div>` : '<div class="message-sender">You</div>'}
        <div class="message-text">${escapeHTML(text)}</div>
        <div class="message-time">${time}</div>
    `;
    
    messagesContainer.appendChild(messageElement);
    
    // Scroll to bottom only if user is near bottom
    if (isUserNearBottom()) {
        setTimeout(() => {
            scrollToBottom();
        }, 100);
    }
}

// UPDATED: sendMessage function with input visibility fix
function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !currentChatWith) return;
    
    const timestamp = Date.now();
    const time = formatTime(timestamp);
    
    // Send via Socket.IO
    socket.emit('chatMessage', {
        from: currentUser,
        to: currentChatWith,
        message: text,
        timestamp: timestamp
    });
    
    // Add message to UI immediately
    addMessageToChat(currentUser, text, time, true);
    
    // Save to local storage
    saveChatMessage(currentUser, currentChatWith, {
        sender: currentUser,
        text: text,
        time: time,
        timestamp: timestamp
    });
    
    // Clear input and focus
    messageInput.value = '';
    messageInput.focus();
    
    // Stop typing indicator
    clearTimeout(typingTimer);
    isTyping = false;
    socket.emit('typingStop', { from: currentUser, to: currentChatWith });
    
    // NEW: Ensure input remains visible after sending
    setTimeout(ensureInputVisible, 100);
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

// NEW: Function to ensure input remains visible
function ensureInputVisible() {
    const inputContainer = document.querySelector('.message-input-container');
    if (inputContainer) {
        inputContainer.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
}

// File Upload Functions
function toggleFileUpload() {
    if (!currentChatWith) {
        showNotification('Please select a friend to send files', 'error');
        return;
    }
    
    if (fileUploadContainer.style.display === 'none' || !fileUploadContainer.style.display) {
        fileUploadContainer.style.display = 'flex';
        uploadInfo.style.display = 'block';
    } else {
        fileUploadContainer.style.display = 'none';
        uploadInfo.style.display = 'none';
        clearFileSelection();
    }
    
    // Ensure input remains visible when toggling file upload
    setTimeout(ensureInputVisible, 100);
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;

    // File size check
    if (file.size > MAX_FILE_SIZE) {
        showNotification('File size exceeds 100MB limit', 'error');
        clearFileSelection();
        return;
    }

    selectedFile = file;
    updateFilePreview(file);
    uploadBtn.disabled = false;
    
    // Ensure input remains visible after file selection
    setTimeout(ensureInputVisible, 100);
}

function updateFilePreview(file) {
    const fileSize = (file.size / (1024 * 1024)).toFixed(2);
    
    filePreviewName.textContent = file.name;
    filePreviewSize.textContent = `${fileSize} MB`;
    filePreviewIcon.className = `fas ${setFileIcon(file.name, file.type)} file-icon`;
    
    // Show image preview for image files
    if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = function(e) {
            filePreviewImage.src = e.target.result;
            filePreviewImage.style.display = 'block';
        };
        reader.readAsDataURL(file);
    } else {
        filePreviewImage.style.display = 'none';
    }
    
    filePreview.style.display = 'block';
}

function setFileIcon(filename, fileType) {
    const extension = filename.split('.').pop().toLowerCase();
    
    if (fileType.startsWith('image/')) return 'fa-file-image';
    if (fileType.startsWith('video/')) return 'fa-file-video';
    if (fileType.startsWith('audio/')) return 'fa-file-audio';
    
    switch(extension) {
        case 'pdf': return 'fa-file-pdf';
        case 'doc': case 'docx': return 'fa-file-word';
        case 'xls': case 'xlsx': return 'fa-file-excel';
        case 'ppt': case 'pptx': return 'fa-file-powerpoint';
        case 'zip': case 'rar': return 'fa-file-archive';
        case 'txt': return 'fa-file-alt';
        default: return 'fa-file';
    }
}

function clearFileSelection() {
    fileInput.value = '';
    selectedFile = null;
    filePreview.style.display = 'none';
    uploadBtn.disabled = true;
    filePreviewImage.style.display = 'none';
    uploadProgressBar.style.width = '0%';
}

async function uploadFile() {
    if (!selectedFile || !currentChatWith) {
        showNotification('Please select a file and a friend to chat with', 'error');
        return;
    }

    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';

    // Simulate upload progress
    simulateUploadProgress();

    try {
        // For demo purposes, we'll simulate file upload
        // In real app, you would upload to server and get URL
        const fileData = {
            fileName: selectedFile.name,
            fileSize: selectedFile.size,
            fileType: selectedFile.type,
            fileUrl: URL.createObjectURL(selectedFile), // Temporary local URL
            from: currentUser,
            to: currentChatWith,
            timestamp: Date.now()
        };

        // Send file data via socket
        socket.emit('fileUpload', fileData);

        // Add file message to chat
        addFileMessageToChat(fileData, true);

        // Save to local storage
        saveChatMessage(currentUser, currentChatWith, {
            sender: currentUser,
            text: `[FILE] ${selectedFile.name}`,
            time: formatTime(fileData.timestamp),
            timestamp: fileData.timestamp,
            isFile: true,
            fileData: fileData
        });

        showNotification('File uploaded successfully', 'success');
        clearFileSelection();

    } catch (error) {
        console.error('Upload error:', error);
        showNotification('File upload failed: ' + error.message, 'error');
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload';
        
        // Ensure input remains visible after upload
        setTimeout(ensureInputVisible, 100);
    }
}

function simulateUploadProgress() {
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
        }
        uploadProgressBar.style.width = progress + '%';
    }, 200);
}

function addFileMessageToChat(fileData, isSender) {
    const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
    if (noMessagesElement) {
        noMessagesElement.remove();
    }

    const fileSize = (fileData.fileSize / (1024 * 1024)).toFixed(2);
    const fileElement = document.createElement('div');
    fileElement.className = `file-message ${isSender ? 'sent' : 'received'}`;
    
    fileElement.innerHTML = `
        ${!isSender ? `<div class="message-sender">${escapeHTML(fileData.from)}</div>` : ''}
        <div class="file-message-header">
            <i class="fas ${setFileIcon(fileData.fileName, fileData.fileType)} file-message-icon"></i>
            <div class="file-message-name">${escapeHTML(fileData.fileName)}</div>
            <div class="file-message-size">${fileSize} MB</div>
        </div>
        <div class="file-message-actions">
            <a href="${fileData.fileUrl}" class="download-btn" download="${fileData.fileName}">
                <i class="fas fa-download"></i> Download
            </a>
        </div>
        ${fileData.fileType.startsWith('image/') ? 
            `<img src="${fileData.fileUrl}" class="file-preview-image" alt="${fileData.fileName}" style="display: block; max-width: 100%; max-height: 200px; border-radius: 8px; margin-top: 8px;">` : ''
        }
    `;

    messagesContainer.appendChild(fileElement);
    
    if (isUserNearBottom()) {
        setTimeout(() => {
            scrollToBottom();
        }, 100);
    }
}

// Friend Request Functions
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
    
    socket.emit('friendRequest', {
        from: currentUser,
        to: username
    });
    
    friendError.textContent = '';
    friendUsername.value = '';
    addFriendModal.style.display = 'none';
}

function sendFriendRequest(fromUser, toUser) {
    socket.emit('friendRequest', {
        from: fromUser,
        to: toUser
    });
    
    savePendingRequest(toUser, fromUser);
    renderUsersList();
}

// Global functions for friend requests
window.acceptFriendRequest = function(fromUser) {
    socket.emit('acceptFriendRequest', {
        from: fromUser,
        to: currentUser
    });
    
    saveFriend(currentUser, fromUser);
    saveFriend(fromUser, currentUser);
    
    removePendingRequest(currentUser, fromUser);
    
    loadFriendsList();
    renderUsersList();
    
    // Remove notification
    const notifications = document.querySelectorAll('.friend-request-notification');
    notifications.forEach(notif => {
        if (notif.innerHTML.includes(fromUser)) {
            notif.remove();
        }
    });
    
    showNotification(`You are now friends with ${fromUser}`, 'success');
};

window.rejectFriendRequest = function(fromUser) {
    socket.emit('rejectFriendRequest', {
        from: fromUser,
        to: currentUser
    });
    
    removePendingRequest(currentUser, fromUser);
    
    // Remove notification
    const notifications = document.querySelectorAll('.friend-request-notification');
    notifications.forEach(notif => {
        if (notif.innerHTML.includes(fromUser)) {
            notif.remove();
        }
    });
    
    showNotification(`Friend request from ${fromUser} rejected`, 'info');
};

function clearChat() {
    if (!currentChatWith) return;
    
    if (confirm("Are you sure you want to clear the chat history with " + currentChatWith + "?")) {
        clearChatHistory(currentUser, currentChatWith);
        loadChatHistory(currentChatWith);
    }
}

// Helper Functions
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? 'rgba(0, 255, 204, 0.2)' : 
                     type === 'online' ? 'rgba(0, 255, 0, 0.2)' : 
                     type === 'error' ? 'rgba(255, 0, 0, 0.2)' : 
                     'rgba(255, 204, 0, 0.2)'};
        border: 1px solid ${type === 'success' ? '#00ffcc' : 
                           type === 'online' ? '#00ff00' : 
                           type === 'error' ? '#ff0000' : 
                           '#ffcc00'};
        border-radius: 10px;
        padding: 15px;
        z-index: 1000;
        max-width: 300px;
        backdrop-filter: blur(10px);
        color: white;
        font-weight: 600;
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
    notification.className = 'friend-request-notification';
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
        backdrop-filter: blur(10px);
    `;
    
    notification.innerHTML = `
        <h4 style="margin: 0 0 10px 0; color: #00ffcc;">Friend Request</h4>
        <p style="margin: 0 0 15px 0; color: white;">${fromUser} wants to be your friend</p>
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button class="btn-accept" onclick="acceptFriendRequest('${fromUser}')" style="padding: 8px 15px; font-size: 0.9rem; background: #00ffcc; color: #0a1929; border: none; border-radius: 5px; cursor: pointer; font-weight: 600;">Accept</button>
            <button class="btn-reject" onclick="rejectFriendRequest('${fromUser}')" style="padding: 8px 15px; font-size: 0.9rem; background: transparent; color: #ff6b6b; border: 1px solid #ff6b6b; border-radius: 5px; cursor: pointer; font-weight: 600;">Reject</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (document.body.contains(notification)) {
            document.body.removeChild(notification);
        }
    }, 10000);
}

// Scroll helper functions
function isUserNearBottom() {
    if (!messagesContainer) return true;
    
    const threshold = 150; // Increased threshold
    const distanceFromBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight;
    
    return distanceFromBottom <= threshold;
}

function scrollToBottom() {
    if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

// Local Storage Functions
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

function getPendingRequests(username) {
    const key = `pending_requests_${username}`;
    return JSON.parse(localStorage.getItem(key)) || [];
}

function savePendingRequest(toUser, fromUser) {
    const key = `pending_requests_${toUser}`;
    const requests = getPendingRequests(toUser);
    if (!requests.includes(fromUser)) {
        requests.push(fromUser);
        localStorage.setItem(key, JSON.stringify(requests));
    }
}

function removePendingRequest(username, fromUser) {
    const key = `pending_requests_${username}`;
    let requests = getPendingRequests(username);
    requests = requests.filter(req => req !== fromUser);
    localStorage.setItem(key, JSON.stringify(requests));
}

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
    const statusIndicators = document.querySelectorAll('.user-item');
    statusIndicators.forEach(item => {
        if (item.textContent.includes(username)) {
            const status = item.querySelector('.user-status');
            if (status) {
                status.style.background = isOnline ? '#00ffcc' : '#ff6b6b';
            }
        }
    });
}

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    const savedUser = localStorage.getItem('kryptoconnect_current_user');
    if (savedUser) {
        currentUser = savedUser;
        usernameDisplay.textContent = currentUser;
        userAvatar.textContent = currentUser.charAt(0).toUpperCase();
        authSection.style.display = 'none';
        chatSection.style.display = 'flex';
        
        socket.emit('userLogin', currentUser);
        
        loadAllUsers();
        loadFriendsList();
    }
});
