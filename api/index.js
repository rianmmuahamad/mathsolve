require('dotenv').config();
const express = require('express');
const path = require('path');
const authRoutes = require('./auth'); // Path relatif di folder api
const uploadRoutes = require('./upload'); // Path relatif di folder api
const { initDB } = require('./db'); // Path relatif di folder api

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public'))); // public di root proyek

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/upload', uploadRoutes);

// Serve frontend
app.get('*', (req, res) => {
  console.log('Serving index.html');
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Initialize database and start server
async function startServer() {
  try {
    await initDB(); // Initialize database with retries
    console.log('Database initialized successfully');

    // Start server only for local development
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
