const express = require('express');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { sql } = require('./db');
const math = require('mathjs'); // Import mathjs

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

// Function to estimate tokens
function estimateTokens(text) {
  return Math.ceil(text.length / 4);
}

// Function to get upload history
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

// Function to convert buffer to base64
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString('base64'),
      mimeType
    },
  };
}

// Function to format mathematical expressions using mathjs
function formatMathResponse(response) {
  if (!response || response.trim() === '') {
    return 'Tidak ada solusi yang dapat dihasilkan atau respons kosong.';
  }

  // Split response into lines for processing
  const lines = response.split('\n');
  let formattedResponse = '';

  lines.forEach((line, index) => {
    let formattedLine = line.trim();

    // Skip empty lines
    if (!formattedLine) {
      formattedResponse += '\n';
      return;
    }

    // Detect if the line contains a mathematical expression
    try {
      // Try parsing the line or parts of it as a math expression
      const mathRegex = /(\b[\d\s\+\-\*\/\(\)\^\.\%a-zA-Z]+(?:\s*[=<>]\s*[\d\s\+\-\*\/\(\)\^\.\%a-zA-Z]+)?\b)/g;
      const matches = formattedLine.match(mathRegex);

      if (matches) {
        matches.forEach(expr => {
          try {
            // Parse expression with mathjs and convert to LaTeX
            const parsed = math.parse(expr);
            const latex = parsed.toTex({
              parenthesis: 'keep',
              implicit: 'show'
            });
            // Replace the expression with LaTeX delimited version
            formattedLine = formattedLine.replace(expr, `\\(${latex}\\)`);
          } catch (parseErr) {
            // If parsing fails, leave the expression as is
            console.warn(`Failed to parse expression: ${expr}`, parseErr.message);
          }
        });
      }
    } catch (err) {
      console.warn(`Error processing line ${index + 1}: ${formattedLine}`, err.message);
    }

    // Handle Markdown formatting
    formattedLine = formattedLine.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formattedLine = formattedLine.replace(/\*(.*?)\*/g, '<em>$1</em>');

    // Add formatted line to response
    formattedResponse += formattedLine + '\n';
  });

  // Split into sections (e.g., steps)
  const sections = formattedResponse.split(/\bStep\s+/i);
  let htmlOutput = '';

  // Handle introduction (before steps)
  if (sections.length > 0 && sections[0].trim() !== '' && !/^\d+[:.]?\s*/.test(sections[0].trim())) {
    htmlOutput += `<p>${sections[0].trim().replace(/\n/g, '<br>')}</p>`;
  }

  // Handle steps
  if (sections.length > 1) {
    for (let i = 1; i < sections.length; i++) {
      let stepText = sections[i].replace(/^\d+[:.]?\s*/, '').trim();
      if (stepText === '') continue;
      htmlOutput += `
        <div class="solution-step mb-5">
          <div class="flex items-start">
            <div class="flex-shrink-0 mt-1 mr-3 text-primary-600 font-medium">${i}.</div>
            <div class="solution-content flex-grow">${stepText.replace(/\n/g, '<br>')}</div>
          </div>
        </div>`;
    }
  } else if (htmlOutput.trim() === '' && formattedResponse.trim() !== '') {
    htmlOutput = `<p>${formattedResponse.trim().replace(/\n/g, '<br>')}</p>`;
  }

  return htmlOutput || '<p class="text-gray-500">Solusi tidak dapat diformat.</p>';
}

// Upload and process image
router.post('/', authenticate, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    const userId = req.user.id;
    const userName = req.user.email.split('@')[0];
    const fileBuffer = req.file.buffer;
    const mimeType = req.file.mimetype;
    const fileName = `${Date.now()}-${req.file.originalname}`;

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

Anda adalah ahli matematika. Analisis gambar soal matematika yang diunggah. Berikan solusi langkah demi langkah menggunakan metode yang paling umum dan mudah dipahami dalam bahasa Indonesia. Sertakan penjelasan jelas untuk setiap langkah. Gunakan format teks biasa untuk ekspresi matematika (misalnya, a/b untuk pecahan, a^b untuk eksponen, sqrt(x) untuk akar kuadrat). Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika." Jangan tanggapi konten non-matematika.
    `;

    const requestTokens = estimateTokens(prompt) + 1500;
    const imagePart = fileToGenerativePart(fileBuffer, mimeType);
    const result = await model.generateContent([prompt, imagePart]);

    const responseText = result.response.text();
    const responseTokens = estimateTokens(responseText);
    const totalTokens = requestTokens + responseTokens;

    // Format the response with mathjs
    const formattedResponse = formatMathResponse(responseText);

    // Store filename and formatted response in database
    await sql`
      INSERT INTO uploads (user_id, image_path, response)
      VALUES (${userId}, ${fileName}, ${formattedResponse});
    `;

    res.json({ response: formattedResponse });

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

    console.log(`Processed image for ${userName}: ${formattedResponse}`);
    console.log(`Usage for ${userId}: ${used}/${limit} (${percentage}%)`);
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Maaf, terjadi kesalahan saat memproses gambar. Silakan coba lagi dengan gambar beresolusi lebih rendah.' });
  }
});

module.exports = router;