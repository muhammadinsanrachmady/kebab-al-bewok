import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { 
  initWhatsAppBot, 
  getBotStatus, 
  sendDirectMessage, 
  sendOtpMessage, 
  requestPairingCodeWithPhone 
} from './bot.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.BOT_PORT || 5001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sajikan Web Dashboard Statis
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// 1. Endpoint Cek Status Bot
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    data: getBotStatus()
  });
});

// 2. Endpoint Kirim Pesan Teks Bebas
app.post('/api/send-message', async (req, res) => {
  const { phone, message } = req.body;
  if (!phone || !message) {
    return res.status(400).json({ success: false, message: 'Nomor tujuan (phone) dan pesan (message) wajib diisi!' });
  }

  try {
    const result = await sendDirectMessage(phone, message);
    res.json({
      success: true,
      message: `Pesan WhatsApp berhasil dikirim ke ${phone}`,
      data: result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

// 3. Endpoint Kirim Kode OTP Verifikasi (Dipanggil oleh backend Kebab AL Bewok)
app.post('/api/send-otp', async (req, res) => {
  const { phone, otp, name } = req.body;
  if (!phone || !otp) {
    return res.status(400).json({ success: false, message: 'Nomor telepon dan kode OTP wajib diisi!' });
  }

  try {
    const result = await sendOtpMessage(phone, otp, name);
    res.json({
      success: true,
      message: `Kode OTP ${otp} berhasil dikirim ke WhatsApp ${phone}`,
      data: result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

// 4. Endpoint Permintaan Pairing Code (Opsional selain scan QR)
app.post('/api/pairing-code', async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ success: false, message: 'Nomor telepon wajib diisi!' });
  }

  try {
    const code = await requestPairingCodeWithPhone(phone);
    res.json({
      success: true,
      message: 'Pairing code berhasil didapatkan',
      pairingCode: code
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

// 5. Endpoint Reconnect / Inisialisasi ulang
app.post('/api/reconnect', async (req, res) => {
  try {
    await initWhatsAppBot();
    res.json({ success: true, message: 'Sinyal koneksi ulang dikirim.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Jalankan Server & Inisialisasi WhatsApp Socket
app.listen(PORT, async () => {
  console.log(`=========================================================`);
  console.log(`🚀 WA BOT SERVER RUNNING: http://localhost:${PORT}`);
  console.log(`📡 REST API siap melayani pengiriman pesan & OTP`);
  console.log(`=========================================================`);
  
  try {
    await initWhatsAppBot();
  } catch (err) {
    console.error('Inisialisasi bot awal gagal:', err.message);
  }
});
