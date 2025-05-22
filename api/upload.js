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

async function getUserPoints(userId) {
  try {
    const result = await sql`
      SELECT points
      FROM users
      WHERE id = ${userId};
    `;
    return result[0]?.points || 0;
  } catch (err) {
    console.error('Error fetching user points:', err);
    return 0;
  }
}

async function updateUserPoints(userId, pointsToAdd) {
  try {
    await sql`
      UPDATE users
      SET points = points + ${pointsToAdd}
      WHERE id = ${userId};
    `;
  } catch (err) {
    console.error('Error updating user points:', err);
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
    let formatted = text
      .replace(/lim_\{([^}]+)\}/g, '\\lim_{$1}')
      .replace(/\|([^|]+)\|/g, '\\|$1\\|')
      .replace(/(\d+)\/(\d+)/g, '\\frac{$1}{$2}')
      .replace(/(\w)\^(\d+)/g, '$1^{$2}')
      .replace(/sqrt\(([^)]+)\)/g, '\\sqrt{$1}')
      .replace(/(sin|cos|tan|cot|sec|csc)\(([^)]+)\)/g, '\\$1($2)')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // Ensure bold text is converted
      .replace(/\*(.*?)\*/g, '<em>$1</em>'); // Ensure italic text is converted

    const greekSymbols = {
      'alpha': '\\alpha', 'beta': '\\beta', 'gamma': '\\gamma',
      'delta': '\\delta', 'epsilon': '\\epsilon', 'theta': '\\theta',
      'pi': '\\pi', 'sigma': '\\sigma', 'omega': '\\omega'
    };
    
    for (const [key, val] of Object.entries(greekSymbols)) {
      formatted = formatted.replace(new RegExp(key, 'g'), val);
    }

    formatted = formatted
      .replace(/<=/g, '\\leq')
      .replace(/>=/g, '\\geq')
      .replace(/!=/g, '\\neq');

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

    const sections = formatted.split(/(?:\n\s*){2,}/);

    sections.forEach((section, index) => {
      if (!section.trim()) return;

      const isStep = section.match(/^(Langkah|Step)\s*\d+/i) || 
                    section.match(/^\d+\./) ||
                    section.length > 150;

      if (isStep) {
        const stepDiv = $('<div class="solution-step"></div>');
        
        const stepMatch = section.match(/^(Langkah|Step)\s*(\d+):?/i) || 
                         section.match(/^(\d+)\./);
        
        const stepNumber = stepMatch ? stepMatch[2] || stepMatch[1] : index + 1;
        
        stepDiv.append(`<div class="step-number">${stepNumber}.</div>`);
        
        let content = section
          .replace(/^(Langkah|Step)\s*\d+:?\s*/i, '')
          .replace(/^\d+\.\s*/, '');
        
        const paragraphs = content.split('\n');
        
        paragraphs.forEach(para => {
          if (para.trim()) {
            stepDiv.append(`<p class="break-words">${para.trim()}</p>`); // Added break-words class
          }
        });
        
        container.append(stepDiv);
      } else {
        container.append(`<p class="break-words">${section}</p>`); // Added break-words class
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
2. Pisahkan setiap langkah dengan jelas
3. Berikan penjelasan untuk setiap langkah
4. Gunakan format yang mudah dibaca
5. Gunakan **teks tebal** untuk penekanan
6. Gunakan *teks miring* untuk istilah penting

Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika."
    `;

    const imagePart = fileToGenerativePart(fileBuffer, mimeType);
    const result = await model.generateContent([prompt, imagePart]);
    const responseText = result.response.text();

    const formattedResponse = formatResponseToHTML(responseText);

    // Calculate points (e.g., 10 points per successful upload)
    const pointsToAdd = responseText.includes("Gambar ini tidak berisi soal matematika") ? 0 : 10;
    await updateUserPoints(userId, pointsToAdd);

    // Store in database
    await sql`
      INSERT INTO uploads (user_id, image_path, response)
      VALUES (${userId}, ${fileName}, ${responseText});
    `;

    // Get usage statistics
    const usageCount = await sql`
      SELECT COUNT(*) as count
      FROM uploads
      WHERE user_id = ${userId}
      AND created_at > NOW() - INTERVAL '1 hour';
    `;
    const used = parseInt(usageCount[0].count);
    const limit = 10;

    // Get user points
    const points = await getUserPoints(userId);

    const response = {
      response: responseText,
      formatted_response: formattedResponse,
      usage: { used, limit },
      points: points,
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