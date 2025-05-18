const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const sql = require('./db');

const router = express.Router();

// Passport setup
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
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
    done(null, user[0]);
  } catch (err) {
    console.error('Auth error:', err);
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await sql`SELECT * FROM users WHERE id = ${id}`;
    done(null, user[0]);
  } catch (err) {
    done(err);
  }
});

// Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.redirect(`/dashboard.html?token=${token}`);
});

router.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    try {
      const userData = await sql`SELECT display_name, email FROM users WHERE id = ${user.id}`;
      if (userData.length === 0) return res.status(404).json({ error: 'User not found' });
      res.json({ name: userData[0].display_name, email: userData[0].email });
    } catch (err) {
      console.error('Profile fetch error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });
});

router.get('/logout', (req, res) => {
  res.redirect('/login.html');
});

module.exports = router;