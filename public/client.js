/* ============================================================================
   client.js - Unified auth + chat (single file)
   - Supports: index.html (chat), login.html, signup.html, forgot.html
   - Preserves original chat/friend/file logic and adds auth handlers.
   ============================================================================ */

const socket = io();

// safe element getter
function $id(id) { return document.getElementById(id); }

// Page detection
const pathname = window.location.pathname.split('/').pop();
const isIndex = pathname === '' || pathname === 'index.html';
const isLogin = pathname === 'login.html';
const isSignup = pathname === 'signup.html';
const isForgot = pathname === 'forgot.html';

// -------------------------------
// Common helpers
// -------------------------------
function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = 'notification';
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'success' ? 'rgba(0, 255, 204, 0.18)' :
                 type === 'online' ? 'rgba(0,255,0,0.12)' :
                 type === 'error' ? 'rgba(255,0,0,0.12)' :
                 'rgba(255,204,0,0.12)'};
    border: 1px solid ${type === 'success' ? '#00ffcc' :
                       type === 'online' ? '#00ff00' :
                       type === 'error' ? '#ff0000' : '#ffcc00'};
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    z-index: 9999;
    font-weight: 700;
    max-width: 320px;
    backdrop-filter: blur(6px);
  `;
  notification.textContent = message;
  document.body.appendChild(notification);
  setTimeout(() => { if (document.body.contains(notification)) document.body.removeChild(notification); }, 3000);
}
function isElement(el) { return !!el; }

// -------------------------------
// AUTH: login / signup / forgot (if on those pages)
// -------------------------------
if (isLogin) {
  const loginForm = $id('loginForm');
  const loginError = $id('loginError');
  const togglePassword = $id('togglePassword');

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (loginError) loginError.textContent = '';
      const username = ($id('loginUsername')?.value || '').trim();
      const password = ($id('loginPassword')?.value || '').trim();

      if (!username || !password) {
        if (loginError) loginError.textContent = 'Please enter username and password';
        return;
      }

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) {
          if (loginError) loginError.textContent = data.error || 'Login failed';
          return;
        }
        // save session and redirect to index
        localStorage.setItem('kryptoconnect_current_user', username);
        window.location.href = '/';
      } catch (err) {
        console.error('Login error:', err);
        if (loginError) loginError.textContent = 'Login failed. Try again.';
      }
    });
  }

  if (togglePassword) {
    togglePassword.addEventListener('click', () => {
      const p = $id('loginPassword');
      if (!p) return;
      p.type = p.type === 'password' ? 'text' : 'password';
    });
  }
}

if (isSignup) {
  const signupForm = $id('signupForm');
  const signupError = $id('signupError');

  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (signupError) signupError.textContent = '';

      const username = ($id('signupUsername')?.value || '').trim();
      const emailOrPhone = ($id('signupEmailPhone')?.value || '').trim();
      const password = ($id('signupPassword')?.value || '').trim();
      const confirm = ($id('signupConfirmPassword')?.value || '').trim();

      if (!username || !emailOrPhone || !password || !confirm) {
        if (signupError) signupError.textContent = 'All fields are required';
        return;
      }
      if (password !== confirm) {
        if (signupError) signupError.textContent = 'Passwords do not match';
        return;
      }
      if (username.length < 3) {
        if (signupError) signupError.textContent = 'Username must be at least 3 chars';
        return;
      }
      if (password.length < 6) {
        if (signupError) signupError.textContent = 'Password must be at least 6 chars';
        return;
      }

      try {
        const res = await fetch('/api/register', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ username, password, email: emailOrPhone })
        });
        const data = await res.json();
        if (!res.ok) {
          if (signupError) signupError.textContent = data.error || 'Signup failed';
          return;
        }
        alert('Account created — please login.');
        window.location.href = 'login.html';
      } catch (err) {
        console.error('Signup error:', err);
        if (signupError) signupError.textContent = 'Registration failed. Try again.';
      }
    });
  }
}

if (isForgot) {
  const forgotForm = $id('forgotForm');
  const forgotError = $id('forgotError');

  if (forgotForm) {
    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (forgotError) forgotError.textContent = '';
      const emailPhone = ($id('forgotEmail')?.value || '').trim();

      if (!emailPhone) {
        if (forgotError) forgotError.textContent = 'Enter your registered email or phone';
        return;
      }

      // Placeholder: integrate with backend reset API later
      alert(`Password reset link (placeholder) sent to ${emailPhone}`);
      window.location.href = 'login.html';
    });
  }
}

// -------------------------------
// If on index (chat) page: load full chat client
// -------------------------------
if (isIndex) {
  // DOM Elements (many; may be null depending on markup)
  const authSection = $id('authSection');
  const chatSection = $id('chatSection');
  const loginForm = $id('loginForm');
  const registerForm = $id('registerForm');
  const showRegister = $id('showRegister');
  const showLogin = $id('showLogin');
  const loginBtn = $id('loginBtn');
  const registerBtn = $id('registerBtn');
  const logoutBtn = $id('logoutBtn');
  const loginError = $id('loginError');
  const regError = $id('regError');
  const usernameDisplay = $id('usernameDisplay');
  const userAvatar = $id('userAvatar');
  const usersList = $id('usersList');
  const friendsList = $id('friendsList');
  const messagesContainer = $id('messagesContainer');
  const messageInput = $id('messageInput');
  const sendBtn = $id('sendBtn');
  const chatWithInfo = $id('chatWithInfo');
  const chatWithName = $id('chatWithName');
  const noChatSelected = $id('noChatSelected');
  const fileInput = $id('fileInput');
  const uploadBtn = $id('uploadBtn');
  const filePreview = $id('filePreview');
  const filePreviewName = $id('filePreviewName');
  const filePreviewSize = $id('filePreviewSize');
  const filePreviewIcon = $id('filePreviewIcon');
  const filePreviewImage = $id('filePreviewImage');
  const fileRemoveBtn = $id('fileRemoveBtn');
  const uploadProgressBar = $id('uploadProgressBar');
  const attachFileBtn = $id('attachFileBtn');
  const fileUploadContainer = $id('fileUploadContainer');
  const uploadInfo = $id('uploadInfo');
  const typingIndicator = $id('typingIndicator');
  const addFriendBtn = $id('addFriendBtn');
  const addFriendModal = $id('addFriendModal');
  const closeModal = $id('closeModal');
  const friendUsername = $id('friendUsername');
  const sendFriendRequestBtn = $id('sendFriendRequestBtn');
  const friendError = $id('friendError');
  const clearChatBtn = $id('clearChatBtn');

  // App State
  let currentUser = null;
  let currentChatWith = null;
  let isTyping = false;
  let typingTimer = null;
  let allUsers = [];
  let selectedFile = null;
  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

  // -------------------------------
  // Socket events
  // -------------------------------
  socket.on('connect', () => {
    console.log('✅ Connected to server with ID:', socket.id);
    if (currentUser) socket.emit('userLogin', currentUser);
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
    showNotification(`${username} is now offline`, 'info');
  });

  socket.on('chatMessage', (data) => {
    console.log('📨 Message received:', data);
    if (data.from === currentChatWith || data.to === currentChatWith) {
      addMessageToChat(data.from, data.message, formatTime(data.timestamp), data.from === currentUser);
      saveChatMessage(currentUser, currentChatWith, {
        sender: data.from,
        text: data.message,
        time: formatTime(data.timestamp),
        timestamp: data.timestamp
      });
      setTimeout(ensureInputVisible, 100);
    }
  });

  socket.on('typingStart', (data) => {
    if (data.from === currentChatWith && typingIndicator) {
      typingIndicator.textContent = `${data.from} is typing...`;
    }
  });

  socket.on('typingStop', (data) => {
    if (data.from === currentChatWith && typingIndicator) {
      typingIndicator.textContent = '';
    }
  });

  // Friend events
  socket.on('friendRequest', (data) => {
    console.log('📩 Friend request received:', data);
    if (data.to === currentUser) showFriendRequestNotification(data.from);
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

  // File events
  socket.on('fileUpload', (fileData) => {
    console.log('📁 File received:', fileData);
    if ((fileData.to === currentUser && fileData.from === currentChatWith) ||
        (fileData.from === currentUser && fileData.to === currentChatWith)) {
      addFileMessageToChat(fileData, fileData.from === currentUser);
      saveChatMessage(currentUser, currentChatWith, {
        sender: fileData.from,
        text: `[FILE] ${fileData.fileName}`,
        time: formatTime(fileData.timestamp),
        timestamp: fileData.timestamp,
        isFile: true,
        fileData: fileData
      });
      setTimeout(ensureInputVisible, 100);
    }
  });

  socket.on('fileUploadError', (data) => {
    showNotification(data.error, 'error');
  });

  // -------------------------------
  // Event listeners (safe attach)
  // -------------------------------
  if (showRegister) showRegister.addEventListener('click', () => {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'block';
    if (loginError) loginError.textContent = '';
  });

  if (showLogin) showLogin.addEventListener('click', () => {
    if (registerForm) registerForm.style.display = 'none';
    if (loginForm) loginForm.style.display = 'block';
    if (regError) regError.textContent = '';
  });

  if (loginBtn) loginBtn.addEventListener('click', handleLogin);
  if (registerBtn) registerBtn.addEventListener('click', handleRegister);
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
  if (sendBtn) sendBtn.addEventListener('click', sendMessage);
  if (messageInput) {
    messageInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });
    messageInput.addEventListener('input', handleTyping);
  }

  if (addFriendBtn) addFriendBtn.addEventListener('click', () => { if (addFriendModal) addFriendModal.style.display = 'flex'; });
  if (closeModal) closeModal.addEventListener('click', () => { if (addFriendModal) addFriendModal.style.display = 'none'; if (friendError) friendError.textContent = ''; });
  if (sendFriendRequestBtn) sendFriendRequestBtn.addEventListener('click', sendFriendRequestHandler);
  if (clearChatBtn) clearChatBtn.addEventListener('click', clearChat);

  if (attachFileBtn) attachFileBtn.addEventListener('click', toggleFileUpload);
  if (fileInput) fileInput.addEventListener('change', handleFileSelect);
  if (uploadBtn) uploadBtn.addEventListener('click', uploadFile);
  if (fileRemoveBtn) fileRemoveBtn.addEventListener('click', clearFileSelection);

  // -------------------------------
  // Auth handlers (inline login/register on chat page)
  // -------------------------------
  async function handleLogin() {
    if (!loginForm) return;
    const username = ($id('loginUsername')?.value || '').trim();
    const password = ($id('loginPassword')?.value || '').trim();
    if (!username || !password) {
      if (loginError) loginError.textContent = 'Please enter both username and password';
      return;
    }
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (!response.ok) {
        if (loginError) loginError.textContent = data.error;
        return;
      }
      if (loginError) loginError.textContent = '';
      currentUser = username;
      if (usernameDisplay) usernameDisplay.textContent = currentUser;
      if (userAvatar) userAvatar.textContent = currentUser.charAt(0).toUpperCase();
      if (authSection) authSection.style.display = 'none';
      if (chatSection) chatSection.style.display = 'flex';
      socket.emit('userLogin', currentUser);
      await loadAllUsers();
      loadFriendsList();
      localStorage.setItem('kryptoconnect_current_user', currentUser);
    } catch (err) {
      console.error('Login error:', err);
      if (loginError) loginError.textContent = 'Login failed. Please try again.';
    }
  }

  async function handleRegister() {
    if (!registerForm) return;
    const username = ($id('regUsername')?.value || '').trim();
    const password = ($id('regPassword')?.value || '').trim();
    const confirmPassword = ($id('regConfirmPassword')?.value || '').trim();
    if (!username || !password || !confirmPassword) {
      if (regError) regError.textContent = 'Please fill in all fields';
      return;
    }
    if (password !== confirmPassword) {
      if (regError) regError.textContent = 'Passwords do not match';
      return;
    }
    if (username.length < 3) {
      if (regError) regError.textContent = 'Username must be at least 3 characters';
      return;
    }
    if (password.length < 6) {
      if (regError) regError.textContent = 'Password must be at least 6 characters';
      return;
    }
    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (!response.ok) {
        if (regError) regError.textContent = data.error;
        return;
      }
      if (regError) regError.textContent = '';
      if ($id('loginUsername')) $id('loginUsername').value = username;
      if (registerForm) registerForm.style.display = 'none';
      if (loginForm) loginForm.style.display = 'block';
      if (loginError) { loginError.textContent = 'Registration successful! Please login.'; loginError.className = 'success-message'; }
    } catch (err) {
      console.error('Registration error:', err);
      if (regError) regError.textContent = 'Registration failed. Please try again.';
    }
  }

  function handleLogout() {
    currentUser = null;
    currentChatWith = null;
    if (chatSection) chatSection.style.display = 'none';
    if (authSection) authSection.style.display = 'flex';
    if (messagesContainer) messagesContainer.innerHTML = '';
    if (loginError) { loginError.textContent = ''; loginError.className = 'error-message'; }
    localStorage.removeItem('kryptoconnect_current_user');
    socket.disconnect();
    socket.connect();
  }

  // -------------------------------
  // Users / Friends rendering
  // -------------------------------
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
    if (!usersList) return;
    usersList.innerHTML = '';
    const friends = getFriends(currentUser);
    const pendingRequests = getPendingRequests(currentUser);
    const otherUsers = allUsers.filter(user => user.username !== currentUser && !friends.includes(user.username));

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
    if (!friendsList) return;
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
        document.querySelectorAll('.user-item').forEach(item => item.classList.remove('active'));
        friendElement.classList.add('active');
        startChatWith(friend);
      });

      const removeBtn = friendElement.querySelector('.remove-friend-action');
      if (removeBtn) {
        removeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          removeFriend(currentUser, friend);
          socket.emit('removeFriend', { from: currentUser, friend: friend });
          loadFriendsList();
          renderUsersList();
        });
      }

      friendsList.appendChild(friendElement);
    });
  }

  // -------------------------------
  // Chat / history
  // -------------------------------
  function startChatWith(username) {
    currentChatWith = username;
    if (chatWithName) chatWithName.textContent = username;
    if (chatWithInfo) chatWithInfo.style.display = 'flex';
    if (noChatSelected) noChatSelected.style.display = 'none';
    if (messageInput) { messageInput.disabled = false; messageInput.placeholder = `Message ${username}...`; messageInput.focus(); }
    if (sendBtn) sendBtn.disabled = false;

    // hide file upload when switching
    if (fileUploadContainer) fileUploadContainer.style.display = 'none';
    if (uploadInfo) uploadInfo.style.display = 'none';
    clearFileSelection();

    loadChatHistory(username);
    setTimeout(ensureInputVisible, 100);
  }

  function loadChatHistory(username) {
    if (!messagesContainer) return;
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
    if (!messagesContainer) return;
    const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
    if (noMessagesElement) noMessagesElement.remove();

    const messageElement = document.createElement('div');
    messageElement.className = `message ${isSender ? 'sent' : 'received'}`;

    messageElement.innerHTML = `
      ${!isSender ? `<div class="message-sender">${escapeHTML(sender)}</div>` : '<div class="message-sender">You</div>'}
      <div class="message-text">${escapeHTML(text)}</div>
      <div class="message-time">${time}</div>
    `;

    messagesContainer.appendChild(messageElement);

    if (isUserNearBottom()) {
      setTimeout(() => scrollToBottom(), 100);
    }
  }

  function sendMessage() {
    if (!messageInput) return;
    const text = messageInput.value.trim();
    if (!text || !currentChatWith) return;

    const timestamp = Date.now();
    const time = formatTime(timestamp);

    socket.emit('chatMessage', { from: currentUser, to: currentChatWith, message: text, timestamp });
    addMessageToChat(currentUser, text, time, true);

    saveChatMessage(currentUser, currentChatWith, {
      sender: currentUser,
      text: text,
      time: time,
      timestamp: timestamp
    });

    messageInput.value = '';
    messageInput.focus();

    clearTimeout(typingTimer);
    isTyping = false;
    socket.emit('typingStop', { from: currentUser, to: currentChatWith });

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

  function ensureInputVisible() {
    const inputContainer = document.querySelector('.message-input-container');
    if (inputContainer) inputContainer.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }

  // -------------------------------
  // File Upload
  // -------------------------------
  function toggleFileUpload() {
    if (!currentChatWith) {
      showNotification('Please select a friend to send files', 'error');
      return;
    }
    if (!fileUploadContainer) return;
    if (fileUploadContainer.style.display === 'none' || !fileUploadContainer.style.display) {
      fileUploadContainer.style.display = 'flex';
      if (uploadInfo) uploadInfo.style.display = 'block';
    } else {
      fileUploadContainer.style.display = 'none';
      if (uploadInfo) uploadInfo.style.display = 'none';
      clearFileSelection();
    }
    setTimeout(ensureInputVisible, 100);
  }

  function handleFileSelect(event) {
    const file = event?.target?.files?.[0];
    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
      showNotification('File size exceeds 100MB limit', 'error');
      clearFileSelection();
      return;
    }

    selectedFile = file;
    updateFilePreview(file);
    if (uploadBtn) uploadBtn.disabled = false;
    setTimeout(ensureInputVisible, 100);
  }

  function updateFilePreview(file) {
    if (!filePreview) return;
    const fileSize = (file.size / (1024 * 1024)).toFixed(2);
    if (filePreviewName) filePreviewName.textContent = file.name;
    if (filePreviewSize) filePreviewSize.textContent = `${fileSize} MB`;
    if (filePreviewIcon) filePreviewIcon.className = `fas ${setFileIcon(file.name, file.type)} file-icon`;

    if (file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = function(e) {
        if (filePreviewImage) {
          filePreviewImage.src = e.target.result;
          filePreviewImage.style.display = 'block';
        }
      };
      reader.readAsDataURL(file);
    } else {
      if (filePreviewImage) filePreviewImage.style.display = 'none';
    }
    filePreview.style.display = 'block';
  }

  function setFileIcon(filename, fileType) {
    const extension = filename.split('.').pop().toLowerCase();
    if (fileType.startsWith('image/')) return 'fa-file-image';
    if (fileType.startsWith('video/')) return 'fa-file-video';
    if (fileType.startsWith('audio/')) return 'fa-file-audio';
    switch (extension) {
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
    if (fileInput) fileInput.value = '';
    selectedFile = null;
    if (filePreview) filePreview.style.display = 'none';
    if (uploadBtn) uploadBtn.disabled = true;
    if (filePreviewImage) filePreviewImage.style.display = 'none';
    if (uploadProgressBar) uploadProgressBar.style.width = '0%';
  }

  async function uploadFile() {
    if (!selectedFile || !currentChatWith) {
      showNotification('Please select a file and a friend to chat with', 'error');
      return;
    }
    if (!uploadBtn) return;
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';

    simulateUploadProgress();

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
      }

      const fileData = await response.json();
      fileData.from = currentUser;
      fileData.to = currentChatWith;
      fileData.timestamp = Date.now();

      socket.emit('fileUpload', fileData);

      addFileMessageToChat(fileData, true);

      saveChatMessage(currentUser, currentChatWith, {
        sender: currentUser,
        text: `[FILE] ${selectedFile.name}`,
        time: formatTime(fileData.timestamp),
        timestamp: fileData.timestamp,
        isFile: true,
        fileData: fileData
      });

      showNotification(`File "${selectedFile.name}" uploaded successfully`, 'success');
      clearFileSelection();

    } catch (error) {
      console.error('Upload error:', error);
      showNotification('File upload failed: ' + error.message, 'error');
    } finally {
      uploadBtn.disabled = false;
      uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload';
      setTimeout(ensureInputVisible, 100);
    }
  }

  function simulateUploadProgress() {
    if (!uploadProgressBar) return;
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
    if (!messagesContainer) return;
    const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
    if (noMessagesElement) noMessagesElement.remove();

    const fileSize = (fileData.fileSize / (1024 * 1024)).toFixed(2);
    const fileElement = document.createElement('div');
    fileElement.className = `file-message ${isSender ? 'sent' : 'received'}`;

    fileElement.innerHTML = `
      ${!isSender ? `<div class="message-sender">${escapeHTML(fileData.from)}</div>` : '<div class="message-sender">You</div>'}
      <div class="file-message-header">
        <i class="fas ${setFileIcon(fileData.fileName, fileData.fileType)} file-message-icon"></i>
        <div class="file-message-info">
          <div class="file-message-name">${escapeHTML(fileData.fileName)}</div>
          <div class="file-message-size">${fileSize} MB</div>
        </div>
      </div>
      <div class="file-message-actions">
        <a href="${fileData.fileUrl}" class="download-btn" download="${fileData.fileName}">
          <i class="fas fa-download"></i> Download
        </a>
        ${fileData.fileType.startsWith('image/') ? 
          `<a href="${fileData.fileUrl}" target="_blank" class="view-btn"><i class="fas fa-eye"></i> View</a>` : ''
        }
      </div>
      ${fileData.fileType.startsWith('image/') ? 
        `<img src="${fileData.fileUrl}" class="file-preview-image" alt="${fileData.fileName}" style="display:block;max-width:100%;max-height:200px;border-radius:8px;margin-top:8px;cursor:pointer;" onclick="window.open('${fileData.fileUrl}','_blank')">` : ''
      }
    `;
    messagesContainer.appendChild(fileElement);
    if (isUserNearBottom()) setTimeout(() => scrollToBottom(), 100);
  }

  // -------------------------------
  // Friend requests / accept / reject / remove
  // -------------------------------
  function sendFriendRequestHandler() {
    if (!friendUsername) return;
    const username = friendUsername.value.trim();
    if (!username) {
      if (friendError) friendError.textContent = 'Please enter a username';
      return;
    }
    if (username === currentUser) {
      if (friendError) friendError.textContent = 'You cannot add yourself as a friend';
      return;
    }
    if (!allUsers.find(user => user.username === username)) {
      if (friendError) friendError.textContent = 'User not found';
      return;
    }
    const friends = getFriends(currentUser);
    if (friends.includes(username)) {
      if (friendError) friendError.textContent = 'This user is already your friend';
      return;
    }
    socket.emit('friendRequest', { from: currentUser, to: username });
    if (friendError) friendError.textContent = '';
    if (friendUsername) friendUsername.value = '';
    if (addFriendModal) addFriendModal.style.display = 'none';
  }

  function sendFriendRequest(fromUser, toUser) {
    socket.emit('friendRequest', { from: fromUser, to: toUser });
    savePendingRequest(toUser, fromUser);
    renderUsersList();
  }

  window.acceptFriendRequest = function(fromUser) {
    socket.emit('acceptFriendRequest', { from: fromUser, to: currentUser });
    saveFriend(currentUser, fromUser);
    saveFriend(fromUser, currentUser);
    removePendingRequest(currentUser, fromUser);
    loadFriendsList();
    renderUsersList();
    const notifications = document.querySelectorAll('.friend-request-notification');
    notifications.forEach(notif => { if (notif.innerHTML.includes(fromUser)) notif.remove(); });
    showNotification(`You are now friends with ${fromUser}`, 'success');
  };

  window.rejectFriendRequest = function(fromUser) {
    socket.emit('rejectFriendRequest', { from: fromUser, to: currentUser });
    removePendingRequest(currentUser, fromUser);
    const notifications = document.querySelectorAll('.friend-request-notification');
    notifications.forEach(notif => { if (notif.innerHTML.includes(fromUser)) notif.remove(); });
    showNotification(`Friend request from ${fromUser} rejected`, 'info');
  };

  function clearChat() {
    if (!currentChatWith) return;
    if (confirm("Are you sure you want to clear the chat history with " + currentChatWith + "?")) {
      clearChatHistory(currentUser, currentChatWith);
      loadChatHistory(currentChatWith);
    }
  }

  // -------------------------------
  // UI helpers: notifications, status, scroll
  // -------------------------------
  function showFriendRequestNotification(fromUser) {
    const notification = document.createElement('div');
    notification.className = 'friend-request-notification';
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: rgba(0,255,204,0.12);
      border: 1px solid #00ffcc;
      border-radius: 10px;
      padding: 15px;
      z-index: 1000;
      max-width: 300px;
      backdrop-filter: blur(10px);
    `;
    notification.innerHTML = `
      <h4 style="margin:0 0 10px 0; color:#00ffcc;">Friend Request</h4>
      <p style="margin:0 0 15px 0; color:white;">${fromUser} wants to be your friend</p>
      <div style="display:flex;gap:10px;margin-top:10px;">
        <button onclick="acceptFriendRequest('${fromUser}')" style="padding:8px 15px;background:#00ffcc;color:#0a1929;border:none;border-radius:5px;cursor:pointer;font-weight:600;">Accept</button>
        <button onclick="rejectFriendRequest('${fromUser}')" style="padding:8px 15px;background:transparent;color:#ff6b6b;border:1px solid #ff6b6b;border-radius:5px;cursor:pointer;font-weight:600;">Reject</button>
      </div>
    `;
    document.body.appendChild(notification);
    setTimeout(() => { if (document.body.contains(notification)) document.body.removeChild(notification); }, 10000);
  }

  function isUserNearBottom() {
    if (!messagesContainer) return true;
    const threshold = 150;
    const distanceFromBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight;
    return distanceFromBottom <= threshold;
  }

  function scrollToBottom() {
    if (messagesContainer) messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function updateUserStatus(username, isOnline) {
    const statusIndicators = document.querySelectorAll('.user-item');
    statusIndicators.forEach(item => {
      if (item.textContent.includes(username)) {
        const status = item.querySelector('.user-status');
        if (status) status.style.background = isOnline ? '#00ffcc' : '#ff6b6b';
      }
    });
  }

  // -------------------------------
  // Local storage helpers: friends, pending, chats
  // -------------------------------
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

  // -------------------------------
  // Init: restore session if exists
  // -------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    const savedUser = localStorage.getItem('kryptoconnect_current_user');
    if (savedUser) {
      currentUser = savedUser;
      if (usernameDisplay) usernameDisplay.textContent = currentUser;
      if (userAvatar) userAvatar.textContent = currentUser.charAt(0).toUpperCase();
      if (authSection) authSection.style.display = 'none';
      if (chatSection) chatSection.style.display = 'flex';
      socket.emit('userLogin', currentUser);
      loadAllUsers();
      loadFriendsList();
    } else {
      // if index but not logged in, you may redirect to login page
      // window.location.href = 'login.html';
      console.log('No saved user - show login form if present.');
    }
  });

} // end isIndex
