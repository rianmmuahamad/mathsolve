require('dotenv').config(); // Load environment variables (for local development)
const express = require('express');
const path = require('path');
const authRoutes = require('./auth'); // Adjusted path to match your auth.js
const uploadRoutes = require('./api/upload'); // Adjusted path to match your upload.js
const { sql, initDB } = require('./api/db'); // Import sql and initDB from db.js

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.use('/auth', authRoutes);
app.use('/upload', uploadRoutes);

// Serve frontend
app.get('*', (req, res) => {
  console.log('Serving index.html');
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Initialize database and start server (for local development)
async function startServer() {
  try {
    await initDB(); // Initialize database with retries
    console.log('Database initialized successfully');

    // Only start server locally (not needed on Vercel)
    if (process.env.NODE_ENV !== 'production') {
      const PORT = process.env.PORT || 3000;
      app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
      });
    }
  } catch (err) {
    console.error('Failed to initialize database:', err);
    process.exit(1); // Exit process if DB initialization fails
  }
}

// Start the server
startServer();

module.exports = app;
