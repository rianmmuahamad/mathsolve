const { neon } = require('@neondatabase/serverless');

const sql = neon(process.env.NEON_DATABASE_URL);

// Initialize database tables and ensure schema
async function initDB() {
  try {
    // Create users table if not exists
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        google_id VARCHAR(255) UNIQUE,
        email VARCHAR(255),
        name VARCHAR(255)
      );
    `;
    console.log('Users table checked/created');

    // Check if 'name' column exists in users table
    const columnCheck = await sql`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'name';
    `;
    if (columnCheck.length === 0) {
      await sql`
        ALTER TABLE users ADD COLUMN name VARCHAR(255);
      `;
      console.log('Added name column to users table');
    } else {
      console.log('Name column already exists in users table');
    }

    // Create uploads table if not exists
    await sql`
      CREATE TABLE IF NOT EXISTS uploads (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        image_path VARCHAR(255),
        response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `;
    console.log('Uploads table checked/created');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}

initDB();

module.exports = sql;