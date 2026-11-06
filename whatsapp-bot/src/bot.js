import { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } from '@whiskeysockets/baileys';
import pino from 'pino';
import qrcodeTerminal from 'qrcode-terminal';
import QRCode from 'qrcode';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { handleIncomingMessage } from './handlers/messageHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const AUTH_DIR = path.resolve(__dirname, '../session_auth');

let sock = null;
let currentQR = null;
let currentQRDataURL = null;
let connectionStatus = 'disconnected'; // 'disconnected' | 'connecting' | 'qr_ready' | 'connected'
let botUser = null;
let pairingCode = null;
const activityLogs = [];

function addLog(type, text) {
  const item = {
    time: new Date().toLocaleTimeString('id-ID'),
    type, // 'info' | 'message' | 'error' | 'success'
    text
  };
  activityLogs.unshift(item);
  if (activityLogs.length > 50) activityLogs.pop();
  console.log(`[${item.time}] [${type.toUpperCase()}] ${text}`);
}

export async function initWhatsAppBot() {
  if (connectionStatus === 'connected' && sock) {
    return { success: true, message: 'Bot sudah dalam keadaan terhubung.' };
  }

  connectionStatus = 'connecting';
  addLog('info', 'Menginisialisasi sesi WhatsApp Multi-Device...');

  // Setup folder penyimpanan sesi
  if (!fs.existsSync(AUTH_DIR)) {
    fs.mkdirSync(AUTH_DIR, { recursive: true });
  }

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version, isLatest } = await fetchLatestBaileysVersion();
  addLog('info', `Menggunakan Baileys v${version.join('.')} (Latest: ${isLatest})`);

  sock = makeWASocket({
    version,
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: 'silent' }),
    browser: ['Kebab AL Bewok Bot', 'Chrome', '120.0.0']
  });

  // Event penyimpanan sesi
  sock.ev.on('creds.update', saveCreds);

  // Event status koneksi & QR code
  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      currentQR = qr;
      connectionStatus = 'qr_ready';
      try {
        currentQRDataURL = await QRCode.toDataURL(qr);
      } catch (e) {
        currentQRDataURL = null;
      }

      console.log('\n=========================================================');
      console.log('📌 SCAN KODE QR DI BAWAH DENGAN APLIKASI WHATSAPP ANDA:');
      console.log('Buka WA di HP > Titik Tiga / Pengaturan > Perangkat Tertaut > Tautkan');
      console.log('=========================================================\n');
      qrcodeTerminal.generate(qr, { small: true });
      console.log('\n💡 Atau buka Web Dashboard: http://localhost:5001 untuk scan QR / Pairing Code.\n');
      addLog('info', 'Kode QR baru digenerate. Silakan scan dengan WhatsApp di ponsel Anda.');
    }

    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
      connectionStatus = 'disconnected';
      currentQR = null;
      currentQRDataURL = null;
      botUser = null;

      addLog('error', `Koneksi WhatsApp terputus (Status Code: ${statusCode}). Mencoba menghubungkan kembali: ${shouldReconnect}`);

      if (shouldReconnect) {
        setTimeout(() => {
          initWhatsAppBot();
        }, 4000);
      } else {
        addLog('info', 'Sesi login telah dikeluarkan (Logged out). Menghapus data sesi...');
        try {
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        } catch (e) {}
        setTimeout(() => {
          initWhatsAppBot();
        }, 2000);
      }
    } else if (connection === 'open') {
      connectionStatus = 'connected';
      currentQR = null;
      currentQRDataURL = null;
      botUser = sock.user;

      console.log('\n=========================================================');
      console.log('✅ BOT WHATSAPP KEBAB AL BEWOK BERHASIL TERHUBUNG!');
      console.log(`📱 Nomor WA: ${botUser?.id?.split(':')[0] || 'Unknown'}`);
      console.log(`👤 Nama Akun: ${botUser?.name || 'Kebab AL Bewok'}`);
      console.log('🌐 Web Dashboard: http://localhost:5001');
      console.log('=========================================================\n');

      addLog('success', `WhatsApp terhubung sebagai ${botUser?.id?.split(':')[0] || 'Bot'}`);
    }
  });

  // Event pesan masuk
  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;
    for (const msg of messages) {
      try {
        await handleIncomingMessage(sock, msg);
      } catch (err) {
        addLog('error', `Error memproses pesan: ${err.message}`);
      }
    }
  });

  return { success: true };
}

// Format nomor ke format JID WhatsApp (misal: 0812xxx -> 62812xxx@s.whatsapp.net)
export function formatPhoneNumber(phone) {
  let cleaned = (phone || '').toString().replace(/[^0-9]/g, '');
  if (cleaned.startsWith('0')) {
    cleaned = '62' + cleaned.slice(1);
  } else if (!cleaned.startsWith('62') && cleaned.length >= 9) {
    cleaned = '62' + cleaned;
  }
  return `${cleaned}@s.whatsapp.net`;
}

// Kirim pesan teks langsung
export async function sendDirectMessage(phoneNumber, text) {
  if (connectionStatus !== 'connected' || !sock) {
    throw new Error('Bot WhatsApp belum terhubung. Silakan scan QR code terlebih dahulu.');
  }

  const jid = formatPhoneNumber(phoneNumber);
  const result = await sock.sendMessage(jid, { text });
  addLog('message', `Pesan terkirim ke ${phoneNumber}: "${text.slice(0, 50)}..."`);
  return result;
}

// Kirim OTP verifikasi login
export async function sendOtpMessage(phoneNumber, otpCode, customerName = 'Pelanggan') {
  const message = `🌯 *KEBAB AL BEWOK - KODE VERIFIKASI OTP* 🌯
━━━━━━━━━━━━━━━━━━━━━
Halo *${customerName}*,

Berikut adalah kode verifikasi OTP Anda untuk masuk ke aplikasi Kebab AL Bewok:

🔑 KODE OTP: *${otpCode}*

⏰ Kode ini berlaku selama *5 menit*.
🔒 *PERHATIAN:* Jangan berikan kode ini kepada siapa pun demi keamanan akun Anda.

Terima kasih telah menikmati sajian Kebab AL Bewok! 🙏`;

  return await sendDirectMessage(phoneNumber, message);
}

// Request Pairing Code
export async function requestPairingCodeWithPhone(phoneNumber) {
  if (!sock) {
    await initWhatsAppBot();
  }

  if (connectionStatus === 'connected') {
    throw new Error('Bot sudah terhubung dengan WhatsApp.');
  }

  let cleaned = (phoneNumber || '').toString().replace(/[^0-9]/g, '');
  if (cleaned.startsWith('0')) cleaned = '62' + cleaned.slice(1);

  if (cleaned.length < 10) {
    throw new Error('Format nomor HP tidak valid. Masukkan nomor HP aktif (contoh: 081234567890).');
  }

  try {
    const code = await sock.requestPairingCode(cleaned);
    pairingCode = code;
    addLog('info', `Pairing code untuk ${cleaned}: ${code}`);
    return code;
  } catch (err) {
    addLog('error', `Gagal request pairing code: ${err.message}`);
    throw err;
  }
}

// Status bot saat ini
export function getBotStatus() {
  return {
    status: connectionStatus,
    user: botUser ? {
      phone: botUser.id?.split(':')[0],
      name: botUser.name || 'Kebab AL Bewok'
    } : null,
    qrDataURL: currentQRDataURL,
    pairingCode,
    logs: activityLogs
  };
}
