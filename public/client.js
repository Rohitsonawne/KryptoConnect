// Auth Navigation
document.addEventListener('DOMContentLoaded', function() {
    // Pages
    const loginPage = document.getElementById('loginPage');
    const signupPage = document.getElementById('signupPage');
    const forgotPage = document.getElementById('forgotPage');
    const chatApp = document.getElementById('chatApp');

    // Navigation Links
    const showSignup = document.getElementById('showSignup');
    const showLogin = document.getElementById('showLogin');
    const showForgot = document.getElementById('showForgot');
    const backToLogin = document.getElementById('backToLogin');

    // Show Page Function
    function showPage(page) {
        loginPage.style.display = 'none';
        signupPage.style.display = 'none';
        forgotPage.style.display = 'none';
        chatApp.style.display = 'none';
        page.style.display = 'block';
    }

    // Navigation Events
    showSignup.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(signupPage);
    });

    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(loginPage);
    });

    showForgot.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(forgotPage);
    });

    backToLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showPage(loginPage);
    });

    // Password Toggle
    document.querySelectorAll('.toggle-password').forEach(button => {
        button.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });
    });

    // Password Strength
    const signupPassword = document.getElementById('signupPassword');
    const passwordStrength = document.getElementById('passwordStrength');
    const strengthText = document.getElementById('strength-text');

    signupPassword.addEventListener('input', function() {
        const strength = checkPasswordStrength(this.value);
        passwordStrength.style.width = strength.percentage + '%';
        passwordStrength.style.background = strength.color;
        strengthText.textContent = strength.text;
        strengthText.style.color = strength.color;
    });

    function checkPasswordStrength(password) {
        let score = 0;
        if (password.length >= 8) score += 25;
        if (password.length >= 12) score += 15;
        if (/[A-Z]/.test(password)) score += 20;
        if (/[a-z]/.test(password)) score += 20;
        if (/[0-9]/.test(password)) score += 20;
        if (/[^A-Za-z0-9]/.test(password)) score += 20;

        if (score >= 80) return { percentage: 100, color: '#00ffcc', text: 'Strong' };
        if (score >= 60) return { percentage: 75, color: '#ffcc00', text: 'Good' };
        if (score >= 40) return { percentage: 50, color: '#ff9900', text: 'Fair' };
        return { percentage: 25, color: '#ff6b6b', text: 'Weak' };
    }

    // Form Submissions
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('signupForm').addEventListener('submit', handleSignup);
    document.getElementById('forgotForm').addEventListener('submit', handleForgotPassword);

    // Social Login
    document.querySelectorAll('.btn-google, .btn-facebook').forEach(btn => {
        btn.addEventListener('click', () => {
            alert('Social login integration coming soon!');
        });
    });
});

// Your existing functions
async function handleLogin(e) {
    e.preventDefault();
    // Your login logic here
}

async function handleSignup(e) {
    e.preventDefault();
    // Your signup logic here
}

async function handleForgotPassword(e) {
    e.preventDefault();
    document.getElementById('forgotSuccess').style.display = 'flex';
}
