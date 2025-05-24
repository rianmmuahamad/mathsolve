const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { sql, pool } = require('./db');

const router = express.Router();

// Configure Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_REDIRECT_URI,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    if (!profile.id || !profile.emails || !profile.emails[0].value) {
      return done(new Error('Invalid user data from Google'));
    }

    const googleId = profile.id;
    const email = profile.emails[0].value;
    const displayName = profile.displayName || email.split('@')[0];

    let user = await sql`
      SELECT * FROM users WHERE google_id = ${googleId};
    `;

    if (user.length === 0) {
      user = await sql`
        INSERT INTO users (google_id, email, display_name)
        VALUES (${googleId}, ${email}, ${displayName})
        RETURNING *;
      `;
    } else {
      user = await sql`
        UPDATE users
        SET email = ${email}, display_name = ${displayName}
        WHERE google_id = ${googleId}
        RETURNING *;
      `;
    }

    done(null, user[0]);
  } catch (err) {
    done(err);
  }
}));

// Serialize user to session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await sql`
      SELECT * FROM users WHERE id = ${id};
    `;
    done(null, user.length > 0 ? user[0] : null);
  } catch (err) {
    done(err);
  }
});

// Google OAuth login route
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}));

// Google OAuth callback route
router.get('/google/callback', passport.authenticate('google', {
  failureRedirect: '/login.html?error=auth_failed',
}), (req, res) => {
  try {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not configured');
    }

    const user = req.user;
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.display_name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.redirect(`/dashboard.html?token=${token}`);
  } catch (err) {
    console.error('JWT generation error:', err);
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

    if (!token.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
      return res.status(400).json({ error: 'Malformed token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM uploads WHERE user_id = $1', [userId]);
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
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/login.html');
  });
});

module.exports = router;