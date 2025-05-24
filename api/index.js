require('dotenv').config();
const express = require('express');
const path = require('path');
const authRoutes = require('./auth');
const uploadRoutes = require('./upload');
const socialRoutes = require('./social');
const { initDB } = require('./db');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/social', socialRoutes);

// Serve frontend
app.get(['/', '/login.html', '/dashboard.html', '/history.html'], (req, res) => {
  console.log('Serving frontend file');
  res.sendFile(path.join(__dirname, '../public', req.path === '/' ? 'login.html' : req.path));
});

// Initialize database and start server
async function startServer() {
  try {
    await initDB();
    console.log('Database initialized successfully');

    if (process.env.NODE_ENV !== 'production') {
      const PORT = process.env.PORT || 3000;
      app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
      });
    }
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();

module.exports = app;