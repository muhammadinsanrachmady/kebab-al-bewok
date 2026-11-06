import { 
  getMenuText, 
  getBranchesText, 
  getOrderStatusText, 
  getOrderHelpText 
} from './orderService.js';

export async function handleIncomingMessage(sock, msg) {
  // Hanya proses jika ada pesan dan bukan dari bot sendiri
  if (!msg.message || msg.key.fromMe) return;

  const sender = msg.key.remoteJid;
  // Jangan proses broadcast / status update
  if (sender.includes('@broadcast')) return;

  // Ekstrak teks pesan
  const messageContent = 
    msg.message.conversation ||
    msg.message.extendedTextMessage?.text ||
    msg.message.imageMessage?.caption ||
    '';

  const trimmedText = messageContent.trim();
  if (!trimmedText) return;

  console.log(`📩 [WA Diterima] Dari: ${sender} | Pesan: "${trimmedText}"`);

  const lowerText = trimmedText.toLowerCase();

  // Helper kirim balasan
  const reply = async (text) => {
    try {
      await sock.sendMessage(sender, { text }, { quoted: msg });
    } catch (err) {
      console.error(`Gagal mengirim pesan ke ${sender}:`, err.message);
    }
  };

  // 1. Perintah !ping
  if (lowerText === '!ping' || lowerText === 'ping') {
    const uptimeSec = Math.floor(process.uptime());
    const hours = Math.floor(uptimeSec / 3600);
    const mins = Math.floor((uptimeSec % 3600) / 60);
    const secs = uptimeSec % 60;
    return await reply(`🏓 *Pong!*\n🟢 Bot WhatsApp Kebab AL Bewok Aktif!\n⏱️ Uptime Server: ${hours}j ${mins}m ${secs}d`);
  }

  // 2. Perintah !menu / menu / katalog
  if (lowerText === '!menu' || lowerText === 'menu' || lowerText === 'katalog') {
    return await reply(getMenuText());
  }

  // 3. Perintah !cabang / cabang / lokasi / alamat
  if (lowerText === '!cabang' || lowerText === 'cabang' || lowerText === 'lokasi' || lowerText === 'alamat') {
    return await reply(getBranchesText());
  }

  // 4. Perintah !order / cara pesan / pesan
  if (lowerText === '!order' || lowerText === 'order' || lowerText === 'cara pesan' || lowerText === 'pesan') {
    return await reply(getOrderHelpText());
  }

  // 5. Perintah !status [KODE]
  if (lowerText.startsWith('!status') || lowerText.startsWith('status')) {
    const parts = trimmedText.split(/\s+/);
    const code = parts.slice(1).join(' ');
    return await reply(getOrderStatusText(code));
  }

  // 6. Perintah !admin / kontak / kasir / cs
  if (lowerText === '!admin' || lowerText === 'admin' || lowerText === 'cs' || lowerText === 'kontak' || lowerText === 'kasir') {
    const adminText = `📞 *KONTAK ADMIN & KASIR KEBAB AL BEWOK*
━━━━━━━━━━━━━━━━━━━━━
Jika ada kendala pemesanan, katering, atau pertanyaan seputar franchise:

📱 WhatsApp Kasir: *0852-8584-1330*
⏰ Jam Pelayanan: 15:00 - 23:00 WIB
📍 Lokasi Pusat: Cabang Pasar Baru

Ketik *!menu* untuk kembali melihat pilihan makanan & minuman lezat! 🌯`;
    return await reply(adminText);
  }

  // 7. Deteksi pengiriman format pesanan oleh pembeli
  if (lowerText.includes('format pesanan') || lowerText.includes('cabang outlet:')) {
    const orderAck = `✅ *TERIMA KASIH! FORMAT PESANAN DITERIMA* 🌯
━━━━━━━━━━━━━━━━━━━━━
Data pesanan Anda telah masuk ke sistem antrean chat Kebab AL Bewok.

Petugas kami sedang meninjau ketersediaan stok & menghitung ongkir/total tagihan. Kami akan segera membalas konfirmasi pesanan ini dalam beberapa saat.

Mohon tetap aktif di WhatsApp ya! 🙏`;
    return await reply(orderAck);
  }

  // 8. Sambutan utama jika menyapa
  const greetings = ['halo', 'hai', 'hi', 'assalamualaikum', 'assalamu\'alaikum', 'selamat sore', 'selamat malam', 'selamat siang', 'selamat pagi', 'p', 'bot', 'bantuan', 'help', '!bantuan', '!help'];
  const isGreeting = greetings.some(g => lowerText === g || lowerText.startsWith(g + ' '));

  if (isGreeting) {
    const welcome = `🌯 *SELAMAT DATANG DI KEBAB AL BEWOK* 🌯
_"Rasa Nikmat, Harga Bersahabat!"_
━━━━━━━━━━━━━━━━━━━━━
Halo! Saya adalah Bot WhatsApp Otomatis Kebab AL Bewok. Ada yang bisa kami bantu hari ini?

Silakan ketik salah satu perintah berikut:
📌 *!menu* - Lihat menu makanan & harga terbaru
📌 *!cabang* - Cek lokasi outlet & jam operasional
📌 *!order* - Format & cara pesan langsung lewat WA
📌 *!status [KODE]* - Cek proses pesanan (contoh: *!status KB-173000*)
📌 *!admin* - Hubungi WhatsApp Kasir / CS
📌 *!ping* - Tes koneksi bot

Ketik perintah yang Anda inginkan (misal: *!menu*)! Selamat menikmati sajian kami! ✨`;
    return await reply(welcome);
  }

  // 9. Balasan default ramah jika pengguna mengetik teks acak
  const defaultReply = `👋 Halo! Pesan Anda telah kami terima.
Untuk melihat pilihan layanan Kebab AL Bewok, ketik *!menu* atau ketik *!bantuan*. 🌯`;
  await reply(defaultReply);
}
