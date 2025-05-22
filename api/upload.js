const express = require('express');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { sql } = require('./db'); // Import from db.js in api folder

const router = express.Router();
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

// Multer setup for in-memory storage
const upload = multer({ storage: multer.memoryStorage() });

// Rate limiter: 10 images per hour
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  keyGenerator: (req) => req.user.id,
  message: 'Maaf, Anda telah mencapai batas 10 gambar per jam. Silakan tunggu hingga reset setiap jam.'
});

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Fungsi untuk estimasi token
function estimateTokens(text) {
  return Math.ceil(text.length / 4);
}

// Fungsi untuk mendapatkan riwayat unggahan
async function getUploadHistory(userId) {
  const history = await sql`
    SELECT response, created_at
    FROM uploads
    WHERE user_id = ${userId}
    ORDER BY created_at DESC
    LIMIT 3;
  `;
  return history.map(row => ({
    role: 'assistant',
    content: `Respons sebelumnya (pada ${row.created_at}): ${row.response}`
  }));
}

// Fungsi untuk konversi buffer ke base64
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString('base64'),
      mimeType
    },
  };
}

// Upload and process image
router.post('/', authenticate, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    const userId = req.user.id;
    const userName = req.user.email.split('@')[0];
    const fileBuffer = req.file.buffer; // Use in-memory buffer
    const mimeType = req.file.mimetype;
    const fileName = `${Date.now()}-${req.file.originalname}`; // Generate filename for metadata

    // Validate GOOGLE_API_KEY
    if (!process.env.GOOGLE_API_KEY) {
      throw new Error('GOOGLE_API_KEY is not set in environment variables');
    }

    const history = await getUploadHistory(userId);
    const historyText = history
      .map(msg => `${msg.role}: ${msg.content}`)
      .join('\n');

    const prompt = `
Riwayat unggahan terbaru dari ${userName}:
${historyText || 'Tidak ada riwayat unggahan sebelumnya.'}

Anda adalah ahli matematika. Analisis gambar soal matematika yang diunggah. Berikan solusi langkah demi langkah menggunakan metode yang paling umum dan mudah dipahami dalam bahasa Indonesia. Sertakan penjelasan jelas untuk setiap langkah. Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika." Jangan tanggapi konten non-matematika.
    `;

    const requestTokens = estimateTokens(prompt) + 1500;
    const imagePart = fileToGenerativePart(fileBuffer, mimeType);
    const result = await model.generateContent([prompt, imagePart]);

    const responseText = result.response.text();
    const responseTokens = estimateTokens(responseText);
    const totalTokens = requestTokens + responseTokens;

    // Store filename (or path-like string) in database for reference
    await sql`
      INSERT INTO uploads (user_id, image_path, response)
      VALUES (${userId}, ${fileName}, ${responseText});
    `;

    res.json({ response: responseText });

    const usageCount = await sql`
      SELECT COUNT(*) as count
      FROM uploads
      WHERE user_id = ${userId}
      AND created_at > NOW() - INTERVAL '1 hour';
    `;
    const used = parseInt(usageCount[0].count);
    const limit = 10;
    const percentage = (used / limit) * 100;

    if (percentage >= 90) {
      res.set('X-Usage-Warning', `Peringatan: Anda telah menggunakan ${percentage}% dari kuota 10 gambar/jam. Kuota akan direset dalam ${60 - new Date().getMinutes()} menit.`);
    }

    console.log(`Processed image for ${userName}: ${responseText}`);
    console.log(`Usage for ${userId}: ${used}/${limit} (${percentage}%)`);
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Maaf, terjadi kesalahan saat memproses gambar. Silakan coba lagi dengan gambar beresolusi lebih rendah.' });
  }
});

module.exports = router;
