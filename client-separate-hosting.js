// Alternative client.js for separate hosting
const RAILWAY_BACKEND_URL = 'https://your-railway-app.railway.app'; // Replace with your Railway URL

const API_BASE_URL = RAILWAY_BACKEND_URL;
const socket = io(RAILWAY_BACKEND_URL);

console.log('🔧 Connecting to Railway backend:', RAILWAY_BACKEND_URL);