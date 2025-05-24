const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const { sql } = require('./db');

const router = express.Router();

// Passport setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://www.mathsolve.my.id/api/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await sql`SELECT * FROM users WHERE google_id = ${profile.id}`;
        if (user.length === 0) {
          const displayName = profile.displayName || profile.emails[0].value.split('@')[0];
          user = await sql`
            INSERT INTO users (google_id, email, display_name)
            VALUES (${profile.id}, ${profile.emails[0].value}, ${displayName})
            RETURNING *;
          `;
        }
        return done(null, user[0]);
      } catch (err) {
        console.error('Auth error:', err);
        return done(err);
      }
    }
  )
);

// Routes
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login.html' }),
  (req, res) => {
    try {
      if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not set in environment variables');
      }
      const token = jwt.sign(
        { id: req.user.id, email: req.user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.redirect(`https://www.mathsolve.my.id/dashboard.html?token=${token}`);
    } catch (err) {
      console.error('Callback error:', err);
      res.redirect('/login.html?error=auth_failed');
    }
  }
);

router.get('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not set in environment variables');
    }
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const userData = await sql`SELECT display_name, email FROM users WHERE id = ${user.id}`;
    if (userData.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ name: userData[0].display_name, email: userData[0].email });
  } catch (err) {
    console.error('Profile fetch error:', err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/logout', (req, res) => {
  res.redirect('https://www.mathsolve.my.id/login.html');
});

module.exports = router;