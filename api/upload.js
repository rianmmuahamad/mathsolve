const express = require('express');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { sql } = require('./db');
const cheerio = require('cheerio');

const router = express.Router();
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

// Configure multer for in-memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Rate limiting configuration
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  keyGenerator: (req) => req.user.id,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Maaf, Anda telah mencapai batas 10 gambar per jam. Silakan tunggu hingga reset setiap jam.'
    });
  }
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Utility functions
function estimateTokens(text) {
  return Math.ceil(text.length / 4);
}

async function getUploadHistory(userId) {
  try {
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
  } catch (err) {
    console.error('Error fetching upload history:', err);
    return [];
  }
}

function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString('base64'),
      mimeType
    },
  };
}

// Enhanced math notation formatter
function formatMathNotation(text) {
  if (!text || typeof text !== 'string') return text;

  try {
    let formatted = text;

    // Preserve existing LaTeX blocks to avoid double-processing
    const latexBlocks = [];
    formatted = formatted.replace(/\\\(.*?\\\)/g, (match) => {
      latexBlocks.push(match);
      return `__LATEX_BLOCK_${latexBlocks.length - 1}__`;
    });

    // Handle bold and italic text
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/(?<!\*)\*([^\*]+)\*(?!\*)/g, '<em>$1</em>');

    // Enhanced LaTeX notation handling
    const replacements = [
      // Fractions
      { regex: /(\d+)\/(\d+)/g, replace: '\\(\\frac{$1}{$2}\\) ' },
      // Superscripts
      { regex: /([a-zA-Z0-9])\^(\d+)/g, replace: '\\($1^{$2}\\) ' },
      { regex: /([a-zA-Z0-9])\^\{([^}]+)\}/g, replace: '\\($1^{$2}\\) ' },
      // Subscripts
      { regex: /([a-zA-Z0-9])_(\d+)/g, replace: '\\($1_{$2}\\) ' },
      { regex: /([a-zA-Z0-9])_\{([^}]+)\}/g, replace: '\\($1_{$2}\\) ' },
      // Square roots
      { regex: /sqrt\(([^)]+)\)/g, replace: '\\(\\sqrt{$1}\\) ' },
      // Trigonometric functions
      { regex: /(sin|cos|tan|cot|sec|csc)\(([^)]+)\)/g, replace: '\\(\\$1{$2}\\) ' },
      // Limits
      { regex: /lim_\{([^}]+)\}/g, replace: '\\(\\lim_{$1}\\) ' },
      // Absolute values
      { regex: /\|([^|]+)\|/g, replace: '\\(\\|$1\\|) ' },
      // Inequalities
      { regex: /<=/g, replace: '\\(\\leq\\) ' },
      { regex: />=/g, replace: '\\(\\geq\\) ' },
      { regex: /!=/g, replace: '\\(\\neq\\) ' },
    ];

    // Greek symbols
    const greekSymbols = {
      alpha: '\\(\\alpha\\)',
      beta: '\\(\\beta\\)',
      gamma: '\\(\\gamma\\)',
      delta: '\\(\\delta\\)',
      epsilon: '\\(\\epsilon\\)',
      theta: '\\(\\theta\\)',
      pi: '\\(\\pi\\)',
      sigma: '\\(\\sigma\\)',
      omega: '\\(\\omega\\)',
    };

    // Apply LaTeX replacements
    replacements.forEach(({ regex, replace }) => {
      formatted = formatted.replace(regex, replace);
    });

    // Apply Greek symbols
    for (const [key, val] of Object.entries(greekSymbols)) {
      formatted = formatted.replace(new RegExp(`\\b${key}\\b`, 'g'), val);
    }

    // Restore LaTeX blocks
    formatted = formatted.replace(/__LATEX_BLOCK_(\d+)__/g, (_, index) => latexBlocks[index]);

    // Ensure all math expressions are wrapped in \( ... \)
    formatted = formatted.replace(/([^\\])\$([^$]+)\$/g, '$1\\($2\\)');

    return formatted;
  } catch (error) {
    console.error('Math notation formatting error:', error);
    return text;
  }
}

// Enhanced response formatter with HTML structure
function formatResponseToHTML(response) {
  if (!response) return '';

  try {
    let formatted = formatMathNotation(response);
    const $ = cheerio.load('<div class="math-solution"></div>');
    const container = $('.math-solution');

    // Split into sections by double newlines
    const sections = formatted.split(/(?:\n\s*){2,}/);
    let stepCounter = 0;

    sections.forEach(section => {
      if (!section.trim()) return;

      // Check if section is a step
      const isStep = section.match(/^(Langkah|Step)\s*\d+/i);

      if (isStep) {
        stepCounter++;
        const stepDiv = $('<div class="solution-step"></div>');

        const stepMatch = section.match(/^(Langkah|Step)\s*(\d+):?/i);
        const stepNumber = stepMatch ? stepMatch[2] : stepCounter;

        stepDiv.append(`<div class="step-number">${stepNumber}.</div>`);

        let content = section
          .replace(/^(Langkah|Step)\s*\d+:?\s*/i, '')
          .replace(/^\d+\.\s*/, '');

        const paragraphs = content.split('\n');

        paragraphs.forEach(para => {
          if (para.trim()) {
            // Wrap math expressions in span for MathJax
            const processedPara = para.replace(/\\\(.*?\\\)/g, match => `<span class="math-expression">${match}</span>`);
            stepDiv.append(`<p class="break-words">${processedPara}</p>`);
          }
        });

        container.append(stepDiv);
      } else {
        section = section.replace(/^\d+\.\s*/, '');
        if (section.trim()) {
          const processedSection = section.replace(/\\\(.*?\\\)/g, match => `<span class="math-expression">${match}</span>`);
          container.append(`<p class="break-words">${processedSection}</p>`);
        }
      }
    });

    return $.html();
  } catch (error) {
    console.error('Response formatting error:', error);
    return response;
  }
}

// Main upload endpoint
router.post('/', authenticate, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const { id: userId, email } = req.user;
    const fileBuffer = req.file.buffer;
    const mimeType = req.file.mimetype;
    const fileName = `${Date.now()}-${req.file.originalname}`;

    if (!process.env.GOOGLE_API_KEY) {
      throw new Error('GOOGLE_API_KEY is not configured');
    }

    const history = await getUploadHistory(userId);
    const historyText = history.map(msg => `${msg.role}: ${msg.content}`).join('\n');

    const prompt = `
Riwayat unggahan terbaru dari ${email.split('@')[0]}:
${historyText || 'Tidak ada riwayat unggahan sebelumnya.'}

Anda adalah ahli matematika. Analisis gambar soal matematika yang diunggah. Berikan solusi langkah demi langkah menggunakan metode yang paling umum dan mudah dipahami dalam bahasa Indonesia.

FORMAT RESPONS:
1. Gunakan notasi matematika yang tepat (contoh: \\(\\frac{1}{2}\\), \\(x^2\\), \\(\\sqrt{4}\\))
2. Pisahkan setiap langkah dengan jelas menggunakan "Langkah" di awal setiap langkah utama
3. Berikan penjelasan untuk setiap langkah
4. Gunakan format yang mudah dibaca
5. Gunakan **teks tebal** untuk penekanan
6. Gunakan *teks miring* untuk istilah penting
7. Jangan gunakan nomor acak untuk memisahkan bagian (seperti "6." atau "10.")

Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika."
    `;

    const imagePart = fileToGenerativePart(fileBuffer, mimeType);
    const result = await model.generateContent([prompt, imagePart]);
    const responseText = result.response.text();

    const formattedResponse = formatResponseToHTML(responseText);

    await sql`
      INSERT INTO uploads (user_id, image_path, response)
      VALUES (${userId}, ${fileName}, ${responseText});
    `;

    const usageCount = await sql`
      SELECT COUNT(*) as count
      FROM uploads
      WHERE user_id = ${userId}
      AND created_at > NOW() - INTERVAL '1 hour';
    `;
    const used = parseInt(usageCount[0].count);
    const limit = 10;

    const response = {
      response: responseText,
      formatted_response: formattedResponse,
      usage: { used, limit },
      timestamp: new Date().toISOString()
    };

    if (used >= limit * 0.9) {
      response.warning = `Anda telah menggunakan ${used}/${limit} kuota. Reset dalam ${60 - new Date().getMinutes()} menit.`;
    }

    res.json(response);

  } catch (err) {
    console.error('Upload processing error:', err);

    const statusCode = err.message.includes('GOOGLE_API_KEY') ? 500 :
                      err.message.includes('image') ? 400 : 500;

    res.status(statusCode).json({
      error: 'Maaf, terjadi kesalahan saat memproses gambar.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

module.exports = router;