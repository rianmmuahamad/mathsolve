const express = require('express');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { sql } = require('./db');
const cheerio = require('cheerio');

const router = express.Router();

// Inisialisasi tiga instance model dengan tiga API key untuk Gemini 1.5 Flash
const apiKeys = [
  process.env.GOOGLE_API_KEY_1,
  process.env.GOOGLE_API_KEY_2,
  process.env.GOOGLE_API_KEY_3
];

// Validasi API keys
apiKeys.forEach((key, index) => {
  if (!key) {
    console.error(`GOOGLE_API_KEY_${index + 1} is not configured`);
    process.exit(1);
  }
});

const models = apiKeys.map(key => {
  const genAI = new GoogleGenerativeAI(key);
  return genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
});

// Variabel untuk round-robin load balancing
let currentModelIndex = 0;

// Fungsi untuk memilih model berikutnya (round-robin)
function getNextModel() {
  const model = models[currentModelIndex];
  currentModelIndex = (currentModelIndex + 1) % models.length;
  return model;
}

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
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!token.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
    return res.status(400).json({ error: 'Malformed token' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
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

function extractMathTopic(response) {
  const topics = {
    'aljabar': 'Aljabar',
    'geometri': 'Geometri',
    'kalkulus': 'Kalkulus',
    'trigonometri': 'Trigonometri',
    'statistik': 'Statistik',
    'probabilitas': 'Probabilitas',
    'matematika dasar': 'Matematika Dasar'
  };
  
  response = response.toLowerCase();
  for (const [keyword, topic] of Object.entries(topics)) {
    if (response.includes(keyword)) {
      return topic;
    }
  }
  return 'Lainnya';
}

function formatMathNotation(text) {
  if (!text || typeof text !== 'string') return text;
  
  try {
    let formatted = text;
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/(?<!\*)\*([^\*]+)\*(?!\*)/g, '<em>$1</em>');
    formatted = formatted
      .replace(/lim_\{([^}]+)\}/g, '\\lim_{$1}')
      .replace(/\|([^|]+)\|/g, '\\|$1\\|')
      .replace(/(\d+)\/(\d+)/g, '\\frac{$1}{$2}')
      .replace(/(\w)\^(\d+)/g, '$1^{$2}')
      .replace(/sqrt\(([^)]+)\)/g, '\\sqrt{$1}')
      .replace(/(sin|cos|tan|cot|sec|csc)\(([^)]+)\)/g, '\\$1($2)');

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

function formatResponseToHTML(response) {
  if (!response) return '';

  try {
    let formatted = formatMathNotation(response);
    const $ = cheerio.load('<div class="math-solution"></div>');
    const container = $('.math-solution');

    const sections = formatted.split(/(?:\n\s*){2,}/);
    let stepCounter = 0;

    sections.forEach(section => {
      if (!section.trim()) return;

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
            stepDiv.append(`<p class="break-words">${para.trim()}</p>`);
          }
        });
        
        container.append(stepDiv);
      } else {
        section = section.replace(/^\d+\.\s*/, '');
        if (section.trim()) {
          container.append(`<p class="break-words">${section}</p>`);
        }
      }
    });

    return $.html();
  } catch (error) {
    console.error('Response formatting error:', error);
    return response;
  }
}

// Main upload endpoint with load balancing
router.post('/', authenticate, uploadLimiter, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    const { id: userId, email } = req.user;
    const fileBuffer = req.file.buffer;
    const mimeType = req.file.mimetype;
    const fileName = `${Date.now()}-${req.file.originalname}`;

    const history = await getUploadHistory(userId);
    const historyText = history.map(msg => `${msg.role}: ${msg.content}`).join('\n');

    const prompt = `
Anda adalah ahli matematika dengan pengalaman mengajar yang mendalam. Tugas Anda adalah menganalisis soal matematika dari gambar yang diunggah dan memberikan solusi langkah demi langkah yang jelas, logis, dan mudah dipahami oleh siswa SMA atau mahasiswa tingkat awal. Gunakan bahasa Indonesia yang formal namun sederhana.

**Instruksi**:
1. **Identifikasi Soal**: Jelaskan secara singkat soal yang ditemukan dalam gambar, termasuk topik matematika yang relevan (misalnya, aljabar, geometri, kalkulus, trigonometri, statistik, atau probabilitas).
2. **Solusi Langkah demi Langkah**:
   - Mulai setiap langkah utama dengan "Langkah [nomor]:", misalnya, "Langkah 1:".
   - Berikan penjelasan singkat dan jelas untuk setiap langkah, termasuk alasan mengapa metode tersebut digunakan.
   - Gunakan metode yang paling umum dan mudah dipahami, hindari pendekatan yang terlalu rumit kecuali diperlukan.
3. **Notasi Matematika**:
   - Gunakan notasi LaTeX untuk rumus matematika, misalnya:
     - Pecahan: \\(\\frac{a}{b}\\)
     - Pangkat: \\(x^2\\)
     - Akar: \\(\\sqrt{x}\\)
     - Fungsi trigonometri: \\(\\sin(x)\\), \\(\\cos(x)\\)
     - Limit: \\(\\lim_{x \\to a} f(x)\\)
     - Simbol khusus: \\(\\leq\\), \\(\\geq\\), \\(\\neq\\), \\(\\pi\\), \\(\\alpha\\), dll.
   - Pastikan semua rumus ditulis dalam format LaTeX yang benar dan diletakkan di antara \\(...\\).
4. **Format Respons**:
   - Gunakan **teks tebal** untuk menyoroti konsep kunci atau langkah penting.
   - Gunakan *teks miring* untuk istilah teknis atau definisi penting.
   - Pisahkan setiap langkah dengan baris kosong untuk kejelasan.
   - Hindari penomoran acak seperti "6." atau "10." yang tidak relevan dengan langkah-langkah.
5. **Kesimpulan**:
   - Berikan jawaban akhir dalam kalimat yang jelas, misalnya, "Jadi, nilai \\(x\\) adalah \\(5\\)."
   - Jika relevan, tambahkan catatan singkat tentang aplikasi atau konteks soal.
6. **Penanganan Kasus Khusus**:
   - Jika gambar tidak berisi soal matematika, respons dengan: "Gambar ini tidak berisi soal matematika."
   - Jika soal ambigu atau tidak jelas, nyatakan asumsi yang Anda buat sebelum menyelesaikan.

**Riwayat Konteks**:
Riwayat unggahan terbaru dari pengguna (jika ada):  
${historyText || 'Tidak ada riwayat unggahan sebelumnya.'}

Sekarang, analisis soal matematika dari gambar yang diunggah dan berikan solusi sesuai format di atas.
    `;

    const imagePart = fileToGenerativePart(fileBuffer, mimeType);

    // Coba setiap model hingga berhasil atau semua gagal
    let responseText = null;
    let lastError = null;
    for (let i = 0; i < models.length; i++) {
      const model = getNextModel();
      try {
        const result = await model.generateContent([prompt, imagePart]);
        responseText = result.response.text();
        break;
      } catch (err) {
        lastError = err;
        console.error(`Error with model ${currentModelIndex} (gemini-1.5-flash):`, err.message);
        if (i === models.length - 1) {
          throw new Error('All API keys failed to process the request');
        }
      }
    }

    if (!responseText) {
      throw lastError;
    }

    const topic = extractMathTopic(responseText);
    const formattedResponse = formatResponseToHTML(responseText);

    const uploadResult = await sql`
      INSERT INTO uploads (user_id, image_path, response, topic)
      VALUES (${userId}, ${fileName}, ${responseText}, ${topic})
      RETURNING id;
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
      upload_id: uploadResult[0].id,
      topic: topic,
      usage: { used, limit },
      timestamp: new Date().toISOString()
    };

    if (used >= limit * 0.9) {
      response.warning = `Anda telah menggunakan ${used}/${limit} kuota. Reset dalam ${60 - new Date().getMinutes()} menit.`;
    }

    res.json(response);

  } catch (err) {
    console.error('Upload processing error:', err);
    
    const statusCode = err.message.includes('API key') ? 500 : 
                      err.message.includes('image') ? 400 : 500;
    
    res.status(statusCode).json({ 
      error: 'Maaf, terjadi kesalahan saat memproses gambar.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// History endpoint
router.get('/history', authenticate, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const history = await sql`
      SELECT id, image_path, response, topic, created_at
      FROM uploads
      WHERE user_id = ${userId}
      ORDER BY created_at DESC
      LIMIT 20;
    `;
    
    const formattedHistory = history.map(item => ({
      id: item.id,
      image_path: item.image_path,
      response: formatResponseToHTML(item.response),
      topic: item.topic || 'Lainnya',
      created_at: item.created_at.toISOString()
    }));

    res.json(formattedHistory);
  } catch (err) {
    console.error('Error fetching history:', err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Delete upload endpoint
router.delete('/:uploadId', authenticate, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const { uploadId } = req.params;

    const result = await sql`
      DELETE FROM uploads
      WHERE id = ${uploadId} AND user_id = ${userId}
      RETURNING id;
    `;

    if (result.length === 0) {
      return res.status(404).json({ error: 'Upload not found or unauthorized' });
    }

    res.json({ message: 'Upload deleted successfully' });
  } catch (err) {
    console.error('Error deleting upload:', err);
    res.status(500).json({ error: 'Failed to delete upload' });
  }
});

module.exports = router;