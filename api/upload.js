const express = require('express');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const math = require('mathjs');
const { sql } = require('./db');

const router = express.Router();
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

const upload = multer({ storage: multer.memoryStorage() });

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.user.id,
  message: 'Maaf, Anda telah mencapai batas 10 gambar per jam. Silakan tunggu hingga reset setiap jam.'
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

function formatMathExpressions(text) {
  // Format fractions
  text = text.replace(/(\d+)\/(\d+)/g, (match, num, denom) => {
    try {
      return math.format(math.fraction(parseInt(num), parseInt(denom)), { fraction: 'ratio' });
    } catch {
      return match;
    }
  });

  // Format exponents
  text = text.replace(/(\d+)\^(\d+)/g, (match, base, exp) => {
    try {
      return math.format(math.pow(parseInt(base), parseInt(exp)));
    } catch {
      return match;
    }
  });

  // Format square roots
  text = text.replace(/sqrt\(([^)]+)\)/g, (match, expr) => {
    try {
      return `√${math.format(math.evaluate(expr))}`;
    } catch {
      return match;
    }
  });

  // Format other math expressions
  const mathPatterns = [
    { regex: /(\d+(?:\.\d+)?)\s*\+\s*(\d+(?:\.\d+)?)/g, fn: (a, b) => math.add(parseFloat(a), parseFloat(b)) },
    { regex: /(\d+(?:\.\d+)?)\s*\-\s*(\d+(?:\.\d+)?)/g, fn: (a, b) => math.subtract(parseFloat(a), parseFloat(b)) },
    { regex: /(\d+(?:\.\d+)?)\s*\*\s*(\d+(?:\.\d+)?)/g, fn: (a, b) => math.multiply(parseFloat(a), parseFloat(b)) },
    { regex: /(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)/g, fn: (a, b) => math.divide(parseFloat(a), parseFloat(b)) }
  ];

  mathPatterns.forEach(pattern => {
    text = text.replace(pattern.regex, (match, a, b) => {
      try {
        return math.format(pattern.fn(a, b));
      } catch {
        return match;
      }
    });
  });

  return text;
}

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

function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString('base64'),
      mimeType
    },
  };
}

router.post('/', authenticate, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    const userId = req.user.id;
    const userName = req.user.email.split('@')[0];
    const fileBuffer = req.file.buffer;
    const mimeType = req.file.mimetype;
    const fileName = `${Date.now()}-${req.file.originalname}`;

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

Anda adalah ahli matematika. Analisis gambar soal matematika yang diunggah. Berikan solusi langkah demi langkah menggunakan metode yang paling umum dan mudah dipahami dalam bahasa Indonesia. Sertakan penjelasan jelas untuk setiap langkah. Format output dengan:

1. Gunakan format berikut untuk ekspresi matematika:
   - Pecahan: (a/b)
   - Eksponen: a^b
   - Akar: sqrt(ekspresi)
   - Operasi dasar: a + b, a - b, a * b, a / b

2. Jangan gunakan LaTeX atau format markup lainnya
3. Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika." Jangan tanggapi konten non-matematika.
    `;

    const imagePart = fileToGenerativePart(fileBuffer, mimeType);
    const result = await model.generateContent([prompt, imagePart]);

    let responseText = result.response.text();
    responseText = formatMathExpressions(responseText);

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