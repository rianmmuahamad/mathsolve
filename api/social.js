const express = require('express');
const jwt = require('jsonwebtoken');
const { sql } = require('./db');

const router = express.Router();

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Get list of users for social interaction
router.get('/users', authenticate, async (req, res) => {
  try {
    const { id: currentUserId } = req.user;
    const users = await sql`
      SELECT id, display_name, email
      FROM users
      WHERE id != ${currentUserId}
      ORDER BY display_name
      LIMIT 50;
    `;
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

module.exports = router;