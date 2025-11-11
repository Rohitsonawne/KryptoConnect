// ============================
// KryptoConnect - Enhanced Client.js (ALL ISSUES FIXED)
// ============================

// Improved Socket connection with better error handling
const socket = io({
  auth: {
    username: localStorage.getItem('kryptoconnect_current_user') || ''
  },
  transports: ['websocket', 'polling'],
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000
});

// Safe element getter with null checks
function $id(id) { 
  const element = document.getElementById(id);
  if (!element) {
    console.warn(`Element with id '${id}' not found`);
  }
  return element;
}

// Page detection
const pathname = window.location.pathname.split('/').pop();
const isIndex = pathname === '' || pathname === 'index.html';
const isLogin = pathname === 'login.html';
const isSignup = pathname === 'signup.html';
const isForgot = pathname === 'forgot.html';

// ============================
// Global State Management
// ============================

const APP_STATE = {
  currentUser: null,
  currentChatWith: null,
  isTyping: false,
  typingTimer: null,
  allUsers: [],
  selectedFile: null,
  onlineUsers: new Map(),
  otpTimer: null,
  otpTimeLeft: 120,
  currentEmailPhone: '',
  pendingRequests: [],
  socketConnected: false,
  isSending: false,
  sentMessageIds: new Set(),
  lastMessageTimestamp: 0
};

const CONFIG = {
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  TYPING_DELAY: 1000,
  NOTIFICATION_TIMEOUT: 3000,
  FRIEND_REQUEST_TIMEOUT: 10000,
  OTP_TIMEOUT: 120
};

// ============================
// Utility Functions
// ============================

function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString([], { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

function formatDate(timestamp) {
  return new Date(timestamp).toLocaleDateString();
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
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

function maskEmailPhone(input) {
  if (!input) return '';
  if (input.includes('@')) {
    const [name, domain] = input.split('@');
    return `${name.substring(0, 2)}***@${domain}`;
  } else {
    return input.replace(/(\d{3})\d+(\d{3})/, '$1***$2');
  }
}

function showNotification(message, type = 'info') {
  const existingNotifications = document.querySelectorAll('.notification');
  existingNotifications.forEach(notif => {
    if (notif.textContent.includes(message)) {
      notif.remove();
    }
  });

  const notification = document.createElement('div');
  notification.className = 'notification';
  
  const colors = {
    success: { bg: 'rgba(0, 255, 204, 0.18)', border: '#00ffcc' },
    error: { bg: 'rgba(255, 107, 107, 0.18)', border: '#ff6b6b' },
    warning: { bg: 'rgba(255, 204, 0, 0.18)', border: '#ffcc00' },
    info: { bg: 'rgba(0, 204, 255, 0.18)', border: '#00ccff' },
    online: { bg: 'rgba(0, 255, 0, 0.12)', border: '#00ff00' }
  };

  const color = colors[type] || colors.info;

  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${color.bg};
    border: 1px solid ${color.border};
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    z-index: 9999;
    font-weight: 700;
    max-width: 320px;
    backdrop-filter: blur(6px);
    animation: slideInRight 0.3s ease;
  `;
  
  notification.textContent = message;
  document.body.appendChild(notification);
  
  setTimeout(() => {
    if (document.body.contains(notification)) {
      notification.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => {
        if (document.body.contains(notification)) {
          document.body.removeChild(notification);
        }
      }, 300);
    }
  }, CONFIG.NOTIFICATION_TIMEOUT);
}

// ============================
// Local Storage Functions
// ============================

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
  
  if (history.length > 1000) {
    history.splice(0, history.length - 1000);
  }
  
  localStorage.setItem(key, JSON.stringify(history));
}

function clearChatHistory(user1, user2) {
  const key = `chat_${[user1, user2].sort().join('_')}`;
  localStorage.setItem(key, JSON.stringify([]));
}

// ============================
// OTP System Functions
// ============================

function startOtpTimer() {
  clearInterval(APP_STATE.otpTimer);
  APP_STATE.otpTimeLeft = CONFIG.OTP_TIMEOUT;
  updateOtpTimer();
  
  APP_STATE.otpTimer = setInterval(() => {
    APP_STATE.otpTimeLeft--;
    updateOtpTimer();
    
    if (APP_STATE.otpTimeLeft <= 0) {
      clearInterval(APP_STATE.otpTimer);
      const resendBtn = $id('resendOtpBtn');
      if (resendBtn) {
        resendBtn.disabled = false;
        resendBtn.innerHTML = 'Resend Code';
      }
    }
  }, 1000);
}

function updateOtpTimer() {
  const timerElement = $id('otpTimer');
  const resendBtn = $id('resendOtpBtn');
  
  if (timerElement) {
    const minutes = Math.floor(APP_STATE.otpTimeLeft / 60);
    const seconds = APP_STATE.otpTimeLeft % 60;
    timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  }
  
  if (resendBtn && APP_STATE.otpTimeLeft > 0) {
    resendBtn.disabled = true;
    resendBtn.innerHTML = `Resend (${APP_STATE.otpTimeLeft}s)`;
  }
}

async function handleSendOtp() {
  const username = ($id('regUsername')?.value || '').trim();
  const emailPhone = ($id('regEmailPhone')?.value || '').trim();
  const password = ($id('regPassword')?.value || '').trim();
  const confirmPassword = ($id('regConfirmPassword')?.value || '').trim();
  const regError = $id('regError');

  if (!username || !emailPhone || !password || !confirmPassword) {
    if (regError) regError.textContent = 'All fields are required';
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

  if (!validateEmailOrPhone(emailPhone)) {
    if (regError) regError.textContent = 'Please enter valid email or phone number';
    return;
  }

  try {
    const sendOtpBtn = $id('sendOtpBtn');
    if (sendOtpBtn) {
      sendOtpBtn.disabled = true;
      sendOtpBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
    }

    const response = await fetch('/api/send-otp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        emailPhone: emailPhone,
        type: 'signup'
      })
    });

    const data = await response.json();

    if (!response.ok) {
      if (regError) regError.textContent = data.error || 'Failed to send verification code';
      return;
    }

    if (data.success) {
      APP_STATE.currentEmailPhone = emailPhone;
      
      $id('signupStep1').style.display = 'none';
      $id('signupStep2').style.display = 'block';
      $id('otpSentTo').textContent = maskEmailPhone(emailPhone);
      
      if (data.debugOtp) {
        console.log('🔐 Development OTP:', data.debugOtp);
        showNotification(`OTP for testing: ${data.debugOtp}`, 'info');
      }
      
      startOtpTimer();

      if (regError) regError.textContent = '';
      showNotification('Verification code sent successfully!', 'success');
    } else {
      if (regError) regError.textContent = data.error || 'Failed to send verification code';
    }

  } catch (error) {
    console.error('Send OTP error:', error);
    if (regError) regError.textContent = 'Network error. Please check your connection.';
    showNotification('Network error. Please try again.', 'error');
  } finally {
    const sendOtpBtn = $id('sendOtpBtn');
    if (sendOtpBtn) {
      sendOtpBtn.disabled = false;
      sendOtpBtn.innerHTML = 'Send Verification Code';
    }
  }
}

async function handleVerifyOtp() {
  const otp = ($id('regOtp')?.value || '').trim();
  const username = ($id('regUsername')?.value || '').trim();
  const password = ($id('regPassword')?.value || '').trim();
  const otpError = $id('otpError');

  if (!otp || otp.length !== 6) {
    if (otpError) otpError.textContent = 'Please enter valid 6-digit code';
    return;
  }

  try {
    const verifyBtn = $id('verifyOtpBtn');
    if (verifyBtn) {
      verifyBtn.disabled = true;
      verifyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
    }

    const response = await fetch('/api/verify-otp-signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        emailPhone: APP_STATE.currentEmailPhone,
        otp: otp,
        username: username,
        password: password
      })
    });

    const data = await response.json();

    if (!response.ok) {
      if (otpError) otpError.textContent = data.error || 'Verification failed';
      return;
    }

    if (data.success) {
      if (otpError) {
        otpError.textContent = 'Account created successfully!';
        otpError.className = 'success-message';
      }

      showNotification('Account created successfully!', 'success');

      setTimeout(() => {
        localStorage.setItem('kryptoconnect_current_user', username);
        window.location.href = '/';
      }, 1500);
    } else {
      if (otpError) otpError.textContent = data.error || 'Verification failed';
    }

  } catch (error) {
    console.error('Verify OTP error:', error);
    if (otpError) otpError.textContent = 'Network error. Please try again.';
    showNotification('Network error during verification', 'error');
  } finally {
    const verifyBtn = $id('verifyOtpBtn');
    if (verifyBtn) {
      verifyBtn.disabled = false;
      verifyBtn.innerHTML = 'Verify & Create Account';
    }
  }
}

async function handleResendOtp() {
  try {
    const resendBtn = $id('resendOtpBtn');
    if (resendBtn) {
      resendBtn.disabled = true;
      resendBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Resending...';
    }

    const response = await fetch('/api/resend-otp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        emailPhone: APP_STATE.currentEmailPhone,
        type: 'signup'
      })
    });

    const data = await response.json();

    if (!response.ok) {
      showNotification(data.error || 'Failed to resend code', 'error');
      return;
    }

    if (data.success) {
      if (data.debugOtp) {
        console.log('🔐 New OTP:', data.debugOtp);
        showNotification(`New OTP: ${data.debugOtp}`, 'info');
      }

      showNotification('Verification code sent!', 'success');
      startOtpTimer();
    } else {
      showNotification(data.error || 'Failed to resend code', 'error');
    }

  } catch (error) {
    console.error('Resend OTP error:', error);
    showNotification('Network error. Please try again.', 'error');
  } finally {
    const resendBtn = $id('resendOtpBtn');
    if (resendBtn) {
      resendBtn.disabled = false;
      resendBtn.innerHTML = 'Resend Code';
    }
  }
}

// ============================
// Authentication Functions
// ============================

async function handleLogin() {
  const username = ($id('loginUsername')?.value || '').trim();
  const password = ($id('loginPassword')?.value || '').trim();
  const loginError = $id('loginError');

  if (!username || !password) {
    if (loginError) loginError.textContent = 'Please enter both username and password';
    return;
  }

  try {
    const loginBtn = $id('loginBtn');
    if (loginBtn) {
      loginBtn.disabled = true;
      loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    }

    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      if (loginError) loginError.textContent = data.error || 'Login failed';
      return;
    }

    if (data.success) {
      if (loginError) loginError.textContent = '';
      
      APP_STATE.currentUser = username;
      localStorage.setItem('kryptoconnect_current_user', username);

      socket.auth.username = username;
      socket.disconnect().connect();

      showNotification('Login successful!', 'success');

      if (isLogin || isSignup) {
        window.location.href = '/';
      } else {
        initializeChat();
      }
    } else {
      if (loginError) loginError.textContent = data.error || 'Login failed';
    }

  } catch (error) {
    console.error('Login error:', error);
    if (loginError) loginError.textContent = 'Network error. Please try again.';
    showNotification('Network error during login', 'error');
  } finally {
    const loginBtn = $id('loginBtn');
    if (loginBtn) {
      loginBtn.disabled = false;
      loginBtn.innerHTML = 'Login';
    }
  }
}

function handleLogout() {
  fetch('/api/logout', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        APP_STATE.currentUser = null;
        APP_STATE.currentChatWith = null;
        localStorage.removeItem('kryptoconnect_current_user');
        
        socket.auth.username = '';
        socket.disconnect();
        
        showNotification('Logged out successfully', 'info');
        
        setTimeout(() => {
          window.location.reload();
        }, 1000);
      } else {
        showNotification('Logout failed', 'error');
      }
    })
    .catch(error => {
      console.error('Logout error:', error);
      showNotification('Network error during logout', 'error');
    });
}

// ============================
// Chat System Functions (FIXED DOUBLE MESSAGES)
// ============================

async function loadAllUsers() {
  try {
    const response = await fetch('/api/users');
    if (!response.ok) {
      throw new Error('Failed to load users');
    }
    APP_STATE.allUsers = await response.json();
    renderUsersList();
    loadFriendRequests();
  } catch (error) {
    console.error('Error loading users:', error);
    showNotification('Failed to load users', 'error');
  }
}

function renderUsersList() {
  const usersList = $id('usersList');
  if (!usersList) return;

  usersList.innerHTML = '';
  
  const friends = getFriends(APP_STATE.currentUser);
  const pendingRequests = getPendingRequests(APP_STATE.currentUser);
  
  const otherUsers = APP_STATE.allUsers.filter(user => 
    user.username !== APP_STATE.currentUser && !friends.includes(user.username)
  );

  if (otherUsers.length === 0) {
    usersList.innerHTML = '<li class="no-users">No other users available</li>';
    return;
  }

  otherUsers.forEach(user => {
    const userElement = document.createElement('li');
    userElement.className = 'user-item';
    
    const isOnline = APP_STATE.onlineUsers.has(user.username);
    const isPending = pendingRequests.includes(user.username);

    let statusHTML = '';
    if (isPending) {
      statusHTML = '<span class="pending-badge">Request Pending</span>';
    } else {
      statusHTML = `
        <button class="friend-action-btn add-friend-action" title="Add Friend">
          <i class="fas fa-user-plus"></i>
        </button>
      `;
    }

    userElement.innerHTML = `
      <div class="user-info-small">
        <div class="user-status ${isOnline ? 'online' : 'offline'}"></div>
        <span>${escapeHTML(user.username)}</span>
        ${user.isVerified ? '<i class="fas fa-badge-check verified-badge" title="Verified"></i>' : ''}
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
        sendFriendRequest(APP_STATE.currentUser, user.username);
      });
    }

    usersList.appendChild(userElement);
  });
}

function loadFriendsList() {
  const friendsList = $id('friendsList');
  if (!friendsList) return;

  friendsList.innerHTML = '';
  
  const friends = getFriends(APP_STATE.currentUser);

  if (friends.length === 0) {
    friendsList.innerHTML = `
      <li class="no-friends">
        <i class="fas fa-users"></i>
        <p>No friends yet</p>
        <small>Add friends to start chatting!</small>
      </li>
    `;
    return;
  }

  friends.forEach(friend => {
    const friendElement = document.createElement('li');
    friendElement.className = `user-item ${APP_STATE.currentChatWith === friend ? 'active' : ''}`;
    
    const isOnline = APP_STATE.onlineUsers.has(friend);

    friendElement.innerHTML = `
      <div class="user-info-small">
        <div class="user-status ${isOnline ? 'online' : 'offline'}"></div>
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

    const removeBtn = friendElement.querySelector('.remove-friend-action');
    if (removeBtn) {
      removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (confirm(`Remove ${friend} from friends?`)) {
          removeFriend(APP_STATE.currentUser, friend);
          socket.emit('removeFriend', { from: APP_STATE.currentUser, friend: friend });
          loadFriendsList();
          renderUsersList();
        }
      });
    }

    friendsList.appendChild(friendElement);
  });
}

// FRIEND REQUEST SYSTEM (FIXED)
function loadFriendRequests() {
  const requestsList = $id('friendRequestsList');
  const requestCount = $id('requestCount');
  
  if (!requestsList) return;
  
  const pendingRequests = getPendingRequests(APP_STATE.currentUser);
  
  if (pendingRequests.length === 0) {
    requestsList.innerHTML = '<li class="no-requests">No pending requests</li>';
    if (requestCount) requestCount.textContent = '0';
    return;
  }
  
  if (requestCount) requestCount.textContent = pendingRequests.length.toString();
  
  requestsList.innerHTML = '';
  
  pendingRequests.forEach(fromUser => {
    const requestItem = document.createElement('li');
    requestItem.className = 'friend-request-item';
    
    requestItem.innerHTML = `
      <div class="request-info">
        <strong>${escapeHTML(fromUser)}</strong>
        <small>wants to be your friend</small>
      </div>
      <div class="friend-request-actions">
        <button class="btn-accept" onclick="acceptFriendRequest('${escapeHTML(fromUser)}')">
          <i class="fas fa-check"></i> Accept
        </button>
        <button class="btn-reject" onclick="rejectFriendRequest('${escapeHTML(fromUser)}')">
          <i class="fas fa-times"></i> Reject
        </button>
      </div>
    `;
    
    requestsList.appendChild(requestItem);
  });
}

// FIXED: Friend Request Function
function sendFriendRequest(fromUser, toUser) {
  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  console.log('Sending friend request:', { from: fromUser, to: toUser });

  // Check if already friends (LOCAL CHECK)
  const friends = getFriends(APP_STATE.currentUser);
  if (friends.includes(toUser)) {
    showNotification('This user is already your friend', 'info');
    return;
  }

  // Check if request already pending (LOCAL CHECK)
  const pendingRequests = getPendingRequests(toUser);
  if (pendingRequests.includes(fromUser)) {
    showNotification('Friend request already sent', 'info');
    return;
  }

  socket.emit('friendRequest', { 
    from: fromUser, 
    to: toUser 
  });
  
  // TEMPORARILY add to pending requests for UI feedback
  savePendingRequest(toUser, fromUser);
  renderUsersList();
  loadFriendRequests();
  
  showNotification(`Friend request sent to ${toUser}`, 'success');
}

// Global functions for friend requests
window.acceptFriendRequest = function(fromUser) {
  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  console.log('Accepting friend request from:', fromUser);
  
  socket.emit('acceptFriendRequest', { 
    from: fromUser, 
    to: APP_STATE.currentUser 
  });
  
  // Local storage update
  saveFriend(APP_STATE.currentUser, fromUser);
  saveFriend(fromUser, APP_STATE.currentUser);
  removePendingRequest(APP_STATE.currentUser, fromUser);
  
  // UI Update
  loadFriendRequests();
  loadFriendsList();
  renderUsersList();
  
  showNotification(`You are now friends with ${fromUser}`, 'success');
};

window.rejectFriendRequest = function(fromUser) {
  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  console.log('Rejecting friend request from:', fromUser);
  
  socket.emit('rejectFriendRequest', { 
    from: fromUser, 
    to: APP_STATE.currentUser 
  });
  
  // Local storage update
  removePendingRequest(APP_STATE.currentUser, fromUser);
  
  // UI Update
  loadFriendRequests();
  renderUsersList();
  
  showNotification(`Friend request from ${fromUser} rejected`, 'info');
};

function startChatWith(username) {
  if (!username || !APP_STATE.currentUser) {
    showNotification('Please login to start chatting', 'error');
    return;
  }

  APP_STATE.currentChatWith = username;
  
  if ($id('chatWithName')) $id('chatWithName').textContent = username;
  if ($id('chatWithInfo')) $id('chatWithInfo').style.display = 'flex';
  if ($id('noChatSelected')) $id('noChatSelected').style.display = 'none';
  
  const messageInput = $id('messageInput');
  const sendBtn = $id('sendBtn');
  
  if (messageInput) {
    messageInput.disabled = false;
    messageInput.placeholder = `Message ${username}...`;
    messageInput.focus();
  }
  
  if (sendBtn) sendBtn.disabled = false;

  // Hide file upload when switching chats
  if ($id('fileUploadContainer')) $id('fileUploadContainer').style.display = 'none';
  if ($id('uploadInfo')) $id('uploadInfo').style.display = 'none';
  clearFileSelection();

  loadChatHistory(username);
  ensureInputVisible();
}

function loadChatHistory(username) {
  const messagesContainer = $id('messagesContainer');
  if (!messagesContainer) return;

  messagesContainer.innerHTML = '';
  
  const history = getChatHistory(APP_STATE.currentUser, username);

  if (history.length > 0) {
    let lastDate = null;
    
    history.forEach(message => {
      const messageDate = formatDate(message.timestamp);
      if (messageDate !== lastDate) {
        const dateSeparator = document.createElement('div');
        dateSeparator.className = 'date-separator';
        dateSeparator.textContent = messageDate;
        messagesContainer.appendChild(dateSeparator);
        lastDate = messageDate;
      }

      if (message.isFile) {
        addFileMessageToChat(message.fileData, message.sender === APP_STATE.currentUser);
      } else {
        addMessageToChat(message.sender, message.text, formatTime(message.timestamp), message.sender === APP_STATE.currentUser);
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
}

// FIXED: Add message to chat with duplicate prevention
function addMessageToChat(sender, text, time, isSender, messageId = null) {
  const messagesContainer = $id('messagesContainer');
  if (!messagesContainer) return;
  
  const noMessagesElement = messagesContainer.querySelector('.no-chat-selected');
  if (noMessagesElement) noMessagesElement.remove();

  // Check if message already exists in DOM
  if (messageId) {
    const existingMessage = messagesContainer.querySelector(`[data-message-id="${messageId}"]`);
    if (existingMessage) {
      console.log('⚠️ Message already in DOM, skipping:', messageId);
      return;
    }
  }

  const messageElement = document.createElement('div');
  messageElement.className = `message ${isSender ? 'sent' : 'received'}`;
  
  if (messageId) {
    messageElement.setAttribute('data-message-id', messageId);
  }

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

// FIXED: Send Message Function (No Double Messages)
function sendMessage() {
  if (APP_STATE.isSending) {
    console.log('⚠️ Message already sending, skipping...');
    return;
  }

  const messageInput = $id('messageInput');
  if (!messageInput) return;
  
  const text = messageInput.value.trim();
  
  console.log('📤 Attempting to send message:', {
    text: text,
    from: APP_STATE.currentUser,
    to: APP_STATE.currentChatWith,
    connected: APP_STATE.socketConnected
  });

  if (!text || !APP_STATE.currentChatWith) {
    if (!APP_STATE.currentChatWith) {
      showNotification('Please select a friend to chat with', 'error');
    }
    return;
  }

  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  // Prevent rapid sending
  const now = Date.now();
  if (now - APP_STATE.lastMessageTimestamp < 1000) {
    showNotification('Please wait before sending another message', 'warning');
    return;
  }

  APP_STATE.isSending = true;
  APP_STATE.lastMessageTimestamp = now;
  
  const timestamp = Date.now();
  const time = formatTime(timestamp);

  // Generate unique message ID
  const messageId = `${APP_STATE.currentUser}_${APP_STATE.currentChatWith}_${timestamp}`;
  
  // Add to sent messages to prevent duplicates
  APP_STATE.sentMessageIds.add(messageId);

  try {
    // Show message locally immediately (OPTIMISTIC UI)
    addMessageToChat(APP_STATE.currentUser, text, time, true, messageId);

    // Send to server
    socket.emit('chatMessage', { 
      from: APP_STATE.currentUser, 
      to: APP_STATE.currentChatWith, 
      message: text, 
      timestamp: timestamp,
      messageId: messageId
    });

    console.log('✅ Message sent to server with ID:', messageId);

    messageInput.value = '';
    messageInput.focus();

    clearTimeout(APP_STATE.typingTimer);
    APP_STATE.isTyping = false;
    socket.emit('typingStop', { 
      from: APP_STATE.currentUser, 
      to: APP_STATE.currentChatWith 
    });

    ensureInputVisible();

  } catch (error) {
    console.error('❌ Send message error:', error);
    showNotification('Failed to send message', 'error');
    
    // Remove from sent messages if failed
    APP_STATE.sentMessageIds.delete(messageId);
  } finally {
    // Reset sending flag after a short delay
    setTimeout(() => {
      APP_STATE.isSending = false;
    }, 500);
  }
}

const debouncedTyping = debounce(() => {
  if (!APP_STATE.currentChatWith || !APP_STATE.socketConnected) return;
  
  if (!APP_STATE.isTyping) {
    APP_STATE.isTyping = true;
    socket.emit('typingStart', { 
      from: APP_STATE.currentUser, 
      to: APP_STATE.currentChatWith 
    });
  }
}, 300);

function handleTyping() {
  if (!APP_STATE.currentChatWith || !APP_STATE.socketConnected) return;
  
  debouncedTyping();
  
  clearTimeout(APP_STATE.typingTimer);
  APP_STATE.typingTimer = setTimeout(() => {
    APP_STATE.isTyping = false;
    socket.emit('typingStop', { 
      from: APP_STATE.currentUser, 
      to: APP_STATE.currentChatWith 
    });
  }, CONFIG.TYPING_DELAY);
}

// ============================
// File Upload Functions
// ============================

function toggleFileUpload() {
  if (!APP_STATE.currentChatWith) {
    showNotification('Please select a friend to send files', 'error');
    return;
  }
  
  const fileUploadContainer = $id('fileUploadContainer');
  if (!fileUploadContainer) return;
  
  if (fileUploadContainer.style.display === 'none' || !fileUploadContainer.style.display) {
    fileUploadContainer.style.display = 'flex';
    if ($id('uploadInfo')) $id('uploadInfo').style.display = 'block';
  } else {
    fileUploadContainer.style.display = 'none';
    if ($id('uploadInfo')) $id('uploadInfo').style.display = 'none';
    clearFileSelection();
  }
  
  ensureInputVisible();
}

function handleFileSelect(event) {
  const file = event?.target?.files?.[0];
  if (!file) return;

  if (file.size > CONFIG.MAX_FILE_SIZE) {
    showNotification('File size exceeds 100MB limit', 'error');
    clearFileSelection();
    return;
  }

  APP_STATE.selectedFile = file;
  updateFilePreview(file);
  
  if ($id('uploadBtn')) $id('uploadBtn').disabled = false;
  ensureInputVisible();
}

function updateFilePreview(file) {
  const filePreview = $id('filePreview');
  if (!filePreview) return;
  
  const fileSize = (file.size / (1024 * 1024)).toFixed(2);
  
  if ($id('filePreviewName')) $id('filePreviewName').textContent = file.name;
  if ($id('filePreviewSize')) $id('filePreviewSize').textContent = `${fileSize} MB`;
  if ($id('filePreviewIcon')) {
    $id('filePreviewIcon').className = `fas ${setFileIcon(file.name, file.type)} file-icon`;
  }

  if (file.type.startsWith('image/')) {
    const reader = new FileReader();
    reader.onload = function(e) {
      if ($id('filePreviewImage')) {
        $id('filePreviewImage').src = e.target.result;
        $id('filePreviewImage').style.display = 'block';
      }
    };
    reader.readAsDataURL(file);
  } else {
    if ($id('filePreviewImage')) $id('filePreviewImage').style.display = 'none';
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
  if ($id('fileInput')) $id('fileInput').value = '';
  APP_STATE.selectedFile = null;
  
  if ($id('filePreview')) $id('filePreview').style.display = 'none';
  if ($id('uploadBtn')) $id('uploadBtn').disabled = true;
  if ($id('filePreviewImage')) $id('filePreviewImage').style.display = 'none';
  if ($id('uploadProgressBar')) $id('uploadProgressBar').style.width = '0%';
}

async function uploadFile() {
  if (!APP_STATE.selectedFile || !APP_STATE.currentChatWith) {
    showNotification('Please select a file and a friend to chat with', 'error');
    return;
  }

  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  const uploadBtn = $id('uploadBtn');
  if (!uploadBtn) return;
  
  uploadBtn.disabled = true;
  uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';

  simulateUploadProgress();

  try {
    const formData = new FormData();
    formData.append('file', APP_STATE.selectedFile);

    const response = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Upload failed');
    }

    const fileData = await response.json();
    
    if (fileData.success) {
      fileData.from = APP_STATE.currentUser;
      fileData.to = APP_STATE.currentChatWith;
      fileData.timestamp = Date.now();

      socket.emit('fileUpload', fileData);

      addFileMessageToChat(fileData, true);

      saveChatMessage(APP_STATE.currentUser, APP_STATE.currentChatWith, {
        sender: APP_STATE.currentUser,
        text: `[FILE] ${APP_STATE.selectedFile.name}`,
        time: formatTime(fileData.timestamp),
        timestamp: fileData.timestamp,
        isFile: true,
        fileData: fileData
      });

      showNotification(`File "${APP_STATE.selectedFile.name}" uploaded successfully`, 'success');
      clearFileSelection();
    } else {
      throw new Error(fileData.error || 'Upload failed');
    }

  } catch (error) {
    console.error('Upload error:', error);
    showNotification('File upload failed: ' + error.message, 'error');
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload';
    ensureInputVisible();
  }
}

function simulateUploadProgress() {
  const uploadProgressBar = $id('uploadProgressBar');
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
  const messagesContainer = $id('messagesContainer');
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
        `<a href="${fileData.fileUrl}" target="_blank" class="view-btn">
          <i class="fas fa-eye"></i> View
        </a>` : ''
      }
    </div>
    ${fileData.fileType.startsWith('image/') ? 
      `<img src="${fileData.fileUrl}" class="file-preview-image" alt="${fileData.fileName}" 
           onclick="window.open('${fileData.fileUrl}', '_blank')">` : ''
    }
  `;
  
  messagesContainer.appendChild(fileElement);
  
  if (isUserNearBottom()) {
    setTimeout(() => scrollToBottom(), 100);
  }
}

// ============================
// Friend System Functions
// ============================

function sendFriendRequestHandler() {
  const friendUsername = $id('friendUsername');
  const friendError = $id('friendError');
  
  if (!friendUsername) return;
  
  const username = friendUsername.value.trim();
  if (!username) {
    if (friendError) friendError.textContent = 'Please enter a username';
    return;
  }

  if (username === APP_STATE.currentUser) {
    if (friendError) friendError.textContent = 'You cannot add yourself as a friend';
    return;
  }

  if (!APP_STATE.allUsers.find(user => user.username === username)) {
    if (friendError) friendError.textContent = 'User not found';
    return;
  }

  const friends = getFriends(APP_STATE.currentUser);
  if (friends.includes(username)) {
    if (friendError) friendError.textContent = 'This user is already your friend';
    return;
  }

  if (!APP_STATE.socketConnected) {
    showNotification('Connection lost. Please try again.', 'error');
    return;
  }

  socket.emit('friendRequest', { 
    from: APP_STATE.currentUser, 
    to: username 
  });
  
  if (friendError) friendError.textContent = '';
  if (friendUsername) friendUsername.value = '';
  if ($id('addFriendModal')) $id('addFriendModal').style.display = 'none';
}

function clearChat() {
  if (!APP_STATE.currentChatWith) return;
  
  if (confirm(`Are you sure you want to clear the chat history with ${APP_STATE.currentChatWith}?`)) {
    clearChatHistory(APP_STATE.currentUser, APP_STATE.currentChatWith);
    loadChatHistory(APP_STATE.currentChatWith);
    showNotification('Chat history cleared', 'info');
  }
}

// ============================
// UI Helper Functions
// ============================

function isUserNearBottom() {
  const messagesContainer = $id('messagesContainer');
  if (!messagesContainer) return true;
  
  const threshold = 150;
  const distanceFromBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight;
  return distanceFromBottom <= threshold;
}

function scrollToBottom() {
  const messagesContainer = $id('messagesContainer');
  if (messagesContainer) {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }
}

function ensureInputVisible() {
  const inputContainer = document.querySelector('.message-input-container');
  if (inputContainer) {
    inputContainer.scrollIntoView({ 
      behavior: 'smooth', 
      block: 'end' 
    });
  }
}

function updateUserStatus(username, isOnline) {
  if (isOnline) {
    APP_STATE.onlineUsers.set(username, true);
  } else {
    APP_STATE.onlineUsers.delete(username);
  }
  
  const statusIndicators = document.querySelectorAll('.user-item');
  statusIndicators.forEach(item => {
    if (item.textContent.includes(username)) {
      const status = item.querySelector('.user-status');
      if (status) {
        status.className = `user-status ${isOnline ? 'online' : 'offline'}`;
      }
    }
  });
}

// ============================
// Socket Event Handlers (ENHANCED)
// ============================

socket.on('connect', () => {
  console.log('✅ Connected to server with ID:', socket.id);
  APP_STATE.socketConnected = true;
  showNotification('Connected to chat server', 'success');
  
  if (APP_STATE.currentUser) {
    socket.emit('userLogin', APP_STATE.currentUser);
    socket.emit('getPendingRequests');
  }
});

socket.on('disconnect', () => {
  console.log('❌ Disconnected from server');
  APP_STATE.socketConnected = false;
  showNotification('Disconnected from server', 'error');
});

socket.on('connect_error', (error) => {
  console.error('Socket connection error:', error);
  APP_STATE.socketConnected = false;
  showNotification('Connection failed. Trying to reconnect...', 'error');
});

socket.on('reconnect_attempt', () => {
  console.log('🔄 Attempting to reconnect...');
});

socket.on('reconnect', () => {
  console.log('✅ Reconnected to server');
  APP_STATE.socketConnected = true;
  showNotification('Reconnected to chat server', 'success');
});

socket.on('onlineUsers', (users) => {
  console.log('Online users:', users);
  users.forEach(username => {
    if (username !== APP_STATE.currentUser) {
      APP_STATE.onlineUsers.set(username, true);
    }
  });
  loadFriendsList();
  renderUsersList();
});

socket.on('userOnline', (username) => {
  updateUserStatus(username, true);
  showNotification(`${username} is now online`, 'online');
});

socket.on('userOffline', (username) => {
  updateUserStatus(username, false);
  showNotification(`${username} is now offline`, 'info');
});

// FIXED: Message receive with duplicate prevention
socket.on('chatMessage', (data) => {
  console.log('📥 Received message from server:', data);
  
  // Check if this is for current chat
  if ((data.from === APP_STATE.currentChatWith && data.to === APP_STATE.currentUser) ||
      (data.from === APP_STATE.currentUser && data.to === APP_STATE.currentChatWith)) {
    
    // Generate message ID for comparison
    const receivedMessageId = data.messageId || `${data.from}_${data.to}_${data.timestamp}`;
    
    // Check if message already exists (DUPLICATE PREVENTION)
    if (APP_STATE.sentMessageIds.has(receivedMessageId)) {
      console.log('⚠️ Duplicate message ignored (already sent):', receivedMessageId);
      APP_STATE.sentMessageIds.delete(receivedMessageId); // Clean up
      return;
    }

    // Check local storage for duplicates
    const existingMessages = getChatHistory(APP_STATE.currentUser, APP_STATE.currentChatWith);
    const isDuplicate = existingMessages.some(msg => 
      Math.abs(msg.timestamp - data.timestamp) < 1000 && msg.text === data.message
    );

    if (isDuplicate) {
      console.log('⚠️ Duplicate message ignored (in history):', data.message);
      return;
    }

    console.log('✅ Adding new message to chat:', data.message);
    
    // Add message to UI
    addMessageToChat(data.from, data.message, formatTime(data.timestamp), data.from === APP_STATE.currentUser, receivedMessageId);
    
    // Save to local storage
    saveChatMessage(APP_STATE.currentUser, APP_STATE.currentChatWith, {
      sender: data.from,
      text: data.message,
      time: formatTime(data.timestamp),
      timestamp: data.timestamp,
      messageId: receivedMessageId
    });
    
    ensureInputVisible();
  }
});

socket.on('typingStart', (data) => {
  if (data.from === APP_STATE.currentChatWith && $id('typingIndicator')) {
    $id('typingIndicator').textContent = `${data.from} is typing...`;
  }
});

socket.on('typingStop', (data) => {
  if (data.from === APP_STATE.currentChatWith && $id('typingIndicator')) {
    $id('typingIndicator').textContent = '';
  }
});

// Friend events - ADD THESE NEW EVENTS
socket.on('friendRequest', (data) => {
  if (data.to === APP_STATE.currentUser) {
    console.log('New friend request received from:', data.from);
    
    // Save to pending requests
    savePendingRequest(APP_STATE.currentUser, data.from);
    
    // Update UI
    loadFriendRequests();
    renderUsersList();
    
    // Show notification
    showNotification(`New friend request from ${data.from}`, 'info');
  }
});

// ADD THESE NEW SOCKET EVENTS:
socket.on('friendRequestSent', (data) => {
  console.log('Friend request sent successfully:', data);
  showNotification(`Friend request sent to ${data.to}`, 'success');
  renderUsersList();
  loadFriendRequests();
});

socket.on('friendRequestError', (data) => {
  console.error('Friend request error:', data);
  showNotification(data.error, 'error');
  
  // Remove from pending if error
  removePendingRequest(data.to, APP_STATE.currentUser);
  renderUsersList();
  loadFriendRequests();
});

socket.on('friendRequestAccepted', (data) => {
  if (data.to === APP_STATE.currentUser) {
    loadFriendsList();
    renderUsersList();
    loadFriendRequests();
    showNotification(`${data.from} accepted your friend request!`, 'success');
  }
});

socket.on('friendRequestRejected', (data) => {
  showNotification(`${data.from} rejected your friend request`, 'info');
});

socket.on('friendRemoved', (data) => {
  showNotification(`${data.from} removed you from friends`, 'info');
  loadFriendsList();
  renderUsersList();
});

// File events
socket.on('fileUpload', (fileData) => {
  if ((fileData.to === APP_STATE.currentUser && fileData.from === APP_STATE.currentChatWith) ||
      (fileData.from === APP_STATE.currentUser && fileData.to === APP_STATE.currentChatWith)) {
    addFileMessageToChat(fileData, fileData.from === APP_STATE.currentUser);
    saveChatMessage(APP_STATE.currentUser, APP_STATE.currentChatWith, {
      sender: fileData.from,
      text: `[FILE] ${fileData.fileName}`,
      time: formatTime(fileData.timestamp),
      timestamp: fileData.timestamp,
      isFile: true,
      fileData: fileData
    });
    ensureInputVisible();
  }
});

socket.on('fileUploadError', (data) => {
  showNotification(data.error, 'error');
});

socket.on('pendingRequests', (requests) => {
  APP_STATE.pendingRequests = requests;
});

socket.on('error', (data) => {
  console.error('Socket error:', data);
  showNotification(data.message || 'An error occurred', 'error');
});

// ============================
// Initialization Functions
// ============================

function initializeChat() {
  const authSection = $id('authSection');
  const chatSection = $id('chatSection');
  
  if (authSection) authSection.style.display = 'none';
  if (chatSection) chatSection.style.display = 'flex';
  
  if ($id('usernameDisplay')) {
    $id('usernameDisplay').textContent = APP_STATE.currentUser;
  }
  
  if ($id('userAvatar')) {
    $id('userAvatar').textContent = APP_STATE.currentUser.charAt(0).toUpperCase();
  }
  
  loadAllUsers();
  loadFriendsList();
  loadFriendRequests();
  
  // Request pending friend requests
  socket.emit('getPendingRequests');
}

function initializeAuth() {
  const showRegister = $id('showRegister');
  const showLogin = $id('showLogin');
  const loginForm = $id('loginForm');
  const registerForm = $id('registerForm');

  if (showRegister && showLogin && loginForm && registerForm) {
    showRegister.addEventListener('click', () => {
      loginForm.style.display = 'none';
      registerForm.style.display = 'block';
      if ($id('loginError')) $id('loginError').textContent = '';
    });

    showLogin.addEventListener('click', () => {
      registerForm.style.display = 'none';
      loginForm.style.display = 'block';
      if ($id('regError')) $id('regError').textContent = '';
    });
  }

  // Add enter key support for forms
  const loginUsername = $id('loginUsername');
  const loginPassword = $id('loginPassword');
  
  if (loginUsername && loginPassword) {
    [loginUsername, loginPassword].forEach(input => {
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
      });
    });
  }

  const regUsername = $id('regUsername');
  const regPassword = $id('regPassword');
  const regConfirmPassword = $id('regConfirmPassword');
  
  if (regUsername && regPassword && regConfirmPassword) {
    [regUsername, regPassword, regConfirmPassword].forEach(input => {
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSendOtp();
      });
    });
  }

  // OTP input handling
  const regOtp = $id('regOtp');
  if (regOtp) {
    regOtp.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleVerifyOtp();
    });
    
    // Auto-focus and auto-submit for OTP
    regOtp.addEventListener('input', (e) => {
      if (e.target.value.length === 6) {
        handleVerifyOtp();
      }
    });
  }
}

// ============================
// Main Initialization
// ============================

document.addEventListener('DOMContentLoaded', function() {
  // Check if user is already logged in
  const savedUser = localStorage.getItem('kryptoconnect_current_user');
  
  if (savedUser) {
    APP_STATE.currentUser = savedUser;
    socket.auth.username = savedUser;
    
    if (isIndex) {
      initializeChat();
    }
  } else {
    // Initialize auth system
    initializeAuth();
    
    // If on index page but not logged in, ensure auth section is visible
    if (isIndex && $id('authSection')) {
      $id('authSection').style.display = 'flex';
    }
  }

  // Initialize event listeners for chat page
  if (isIndex && APP_STATE.currentUser) {
    const messageInput = $id('messageInput');
    const sendBtn = $id('sendBtn');
    const addFriendBtn = $id('addFriendBtn');
    const closeModal = $id('closeModal');
    const sendFriendRequestBtn = $id('sendFriendRequestBtn');
    const clearChatBtn = $id('clearChatBtn');
    const attachFileBtn = $id('attachFileBtn');
    const fileInput = $id('fileInput');
    const uploadBtn = $id('uploadBtn');
    const fileRemoveBtn = $id('fileRemoveBtn');

    if (messageInput) {
      messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
      });
      messageInput.addEventListener('input', handleTyping);
    }

    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    if (addFriendBtn) addFriendBtn.addEventListener('click', () => {
      if ($id('addFriendModal')) $id('addFriendModal').style.display = 'flex';
    });
    if (closeModal) closeModal.addEventListener('click', () => {
      if ($id('addFriendModal')) $id('addFriendModal').style.display = 'none';
      if ($id('friendError')) $id('friendError').textContent = '';
    });
    if (sendFriendRequestBtn) sendFriendRequestBtn.addEventListener('click', sendFriendRequestHandler);
    if (clearChatBtn) clearChatBtn.addEventListener('click', clearChat);
    if (attachFileBtn) attachFileBtn.addEventListener('click', toggleFileUpload);
    if (fileInput) fileInput.addEventListener('change', handleFileSelect);
    if (uploadBtn) uploadBtn.addEventListener('click', uploadFile);
    if (fileRemoveBtn) fileRemoveBtn.addEventListener('click', clearFileSelection);
  }

  // OTP system event listeners
  if ($id('sendOtpBtn')) {
    $id('sendOtpBtn').addEventListener('click', handleSendOtp);
  }
  if ($id('verifyOtpBtn')) {
    $id('verifyOtpBtn').addEventListener('click', handleVerifyOtp);
  }
  if ($id('resendOtpBtn')) {
    $id('resendOtpBtn').addEventListener('click', handleResendOtp);
  }

  // Auth button listeners
  if ($id('loginBtn')) {
    $id('loginBtn').addEventListener('click', handleLogin);
  }
  if ($id('logoutBtn')) {
    $id('logoutBtn').addEventListener('click', handleLogout);
  }

  console.log('🚀 KryptoConnect Client Initialized');
  console.log('📍 User:', APP_STATE.currentUser || 'Not logged in');
  console.log('📍 Socket Connected:', APP_STATE.socketConnected);
});
