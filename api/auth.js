const express = require('express');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const { sql, pool } = require('./db');

const router = express.Router();
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Google OAuth login route
router.get('/google', (req, res) => {
  try {
    const url = oauth2Client.generateAuthUrl({
      scope: ['profile', 'email'],
    });
    res.redirect(url);
  } catch (err) {
    console.error('Google auth URL generation error:', err);
    res.redirect('/login.html?error=auth_failed');
  }
});

// Google OAuth callback route
router.get('/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) {
      throw new Error('No code provided');
    }

    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();

    if (!data.id || !data.email) {
      throw new Error('Invalid user data from Google');
    }

    let user = await sql`
      SELECT * FROM users WHERE google_id = ${data.id};
    `;

    if (user.length === 0) {
      user = await sql`
        INSERT INTO users (google_id, email, display_name)
        VALUES (${data.id}, ${data.email}, ${data.name || data.email.split('@')[0]})
        RETURNING *;
      `;
    } else {
      user = await sql`
        UPDATE users
        SET email = ${data.email}, display_name = ${data.name || data.email.split('@')[0]}
        WHERE google_id = ${data.id}
        RETURNING *;
      `;
    }

    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not configured');
    }

    const token = jwt.sign(
      { id: user[0].id, email: user[0].email, name: user[0].display_name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.redirect(`/dashboard.html?token=${token}`);
  } catch (err) {
    console.error('Google auth callback error:', err);
    res.redirect('/login.html?error=auth_failed');
  }
});

// Profile route
router.get('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Basic token format check
    if (!token.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
      return res.status(400).json({ error: 'Malformed token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await sql`
      SELECT id, email, display_name AS name
      FROM users
      WHERE id = ${decoded.id};
    `;

    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user[0]);
  } catch (err) {
    console.error('Profile fetch error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Delete account route
router.delete('/delete-account', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Basic token format check
    if (!token.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
      return res.status(400).json({ error: 'Malformed token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Use a client from the pool for transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Delete user's uploads
      await client.query('DELETE FROM uploads WHERE user_id = $1', [userId]);
      // Delete user
      const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
      if (result.rowCount === 0) {
        throw new Error('User not found');
      }
      await client.query('COMMIT');
      res.status(200).json({ message: 'Account deleted successfully' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Account deletion error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    if (err.message === 'User not found') {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Logout route
router.get('/logout', (req, res) => {
  res.redirect('/login.html');
});

module.exports = router;