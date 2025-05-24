const { neon } = require('@neondatabase/serverless');

// Initialize the database connection
const sql = neon(process.env.NEON_DATABASE_URL || '');

// Initialize database tables and ensure schema
async function initDB() {
  try {
    if (!process.env.NEON_DATABASE_URL) {
      throw new Error('NEON_DATABASE_URL is not set in environment variables');
    }

    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        google_id VARCHAR(255) UNIQUE,
        email VARCHAR(255),
        display_name VARCHAR(255)
      );
    `;
    console.log('Users table checked/created');

    const columnCheck = await sql`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'display_name';
    `;
    if (columnCheck.length === 0) {
      await sql`
        ALTER TABLE users ADD COLUMN display_name VARCHAR(255);
      `;
      console.log('Added display_name column to users table');
    } else {
      console.log('display_name column already exists in users table');
    }

    await sql`
      CREATE TABLE IF NOT EXISTS uploads (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        image_path VARCHAR(255),
        response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `;
    console.log('Uploads table checked/created');
  } catch (err) {
    console.error('Error initializing database:', err);
    throw err;
  }
}

// Retry logic for database initialization
async function initDBWithRetry(maxRetries = 3, retryDelayMs = 2000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await initDB();
      console.log('Database initialized successfully');
      return;
    } catch (err) {
      console.error(`Attempt ${attempt} failed:`, err.message);
      if (attempt === maxRetries) {
        console.error('Max retries reached. Database initialization failed.');
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
}

module.exports = {
  sql,
  initDB: initDBWithRetry,
};