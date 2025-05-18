const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const sql = require('./db');

const router = express.Router();

// Passport setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://mathsolve-five.vercel.app/api/auth/google/callback', // Full URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user exists
        let user = await sql`SELECT * FROM users WHERE google_id = ${profile.id}`;
        if (user.length === 0) {
          const displayName = profile.displayName || profile.emails[0].value.split('@')[0];
          // Insert new user
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

// Remove serialize/deserialize since we're using JWTs, not sessions
// passport.serializeUser((user, done) => done(null, user.id));
// passport.deserializeUser(async (id, done) => { ... });

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
      // Generate JWT
      const token = jwt.sign(
        { id: req.user.id, email: req.user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      // Redirect to dashboard with token
      res.redirect(`https://mathsolve-five.vercel.app/dashboard.html?token=${token}`);
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

    // Verify JWT
    const user = jwt.verify(token, process.env.JWT_SECRET);
    
    // Fetch user data
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
  // Since we're using JWTs, logout is handled client-side by removing the token
  res.redirect('https://mathsolve-five.vercel.app/login.html');
});

module.exports = router;