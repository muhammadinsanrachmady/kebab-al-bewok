import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path data backend Kebab AL Bewok
const DATA_DIR = path.resolve(__dirname, '../../../backend/data');
const MENU_FILE = path.join(DATA_DIR, 'menu.json');
const BRANCHES_FILE = path.join(DATA_DIR, 'branches.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

function readJSON(filePath, defaultData = []) {
  try {
    if (!fs.existsSync(filePath)) return defaultData;
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Gagal membaca ${filePath}:`, err.message);
    return defaultData;
  }
}

function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error(`Gagal menulis ${filePath}:`, err.message);
    return false;
  }
}

function formatRupiah(num) {
  return 'Rp ' + Number(num || 0).toLocaleString('id-ID');
}

export function getMenuText() {
  const menuData = readJSON(MENU_FILE, { categories: [] });
  if (!menuData.categories || menuData.categories.length === 0) {
    return '⚠️ Daftar menu sedang diperbarui. Silakan hubungi kasir/admin kami.';
  }

  let text = `🌯 *DAFTAR MENU KEBAB AL BEWOK* 🌯\n`;
  text += `_"${menuData.tagline || 'Rasa Nikmat, Harga Bersahabat!'}"_\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n\n`;

  menuData.categories.forEach(cat => {
    text += `📂 *${cat.name.toUpperCase()}*\n`;
    if (cat.description) text += `_${cat.description}_\n`;

    cat.items.forEach(item => {
      text += `\n🔹 *${item.name}*`;
      if (item.prices) {
        text += `\n   • Small: ${formatRupiah(item.prices.small)}`;
        text += `\n   • Reguler: ${formatRupiah(item.prices.reguler)}`;
        text += `\n   • Jumbo: ${formatRupiah(item.prices.jumbo)}`;
      } else if (item.price) {
        text += `\n   • Harga: ${formatRupiah(item.price)}`;
      }
    });
    text += `\n\n`;
  });

  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `💬 *Cara Pesan Langsung:* Ketik *!order* untuk panduan format pesan.\n`;
  text += `🌐 *Aplikasi Pemesanan Web:* Buka menu online di browser Anda!`;

  return text;
}

export function getBranchesText() {
  const branches = readJSON(BRANCHES_FILE, []);
  if (!branches || branches.length === 0) {
    return '⚠️ Informasi cabang belum tersedia. Silakan hubungi admin kami.';
  }

  let text = `📍 *OUTLET KEBAB AL BEWOK* 📍\n`;
  text += `Kunjungi cabang terdekat kami untuk kenikmatan maksimal:\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n\n`;

  branches.forEach((b, index) => {
    text += `🏪 *${index + 1}. ${b.name}*\n`;
    text += `📌 *Alamat:* ${b.address}\n`;
    text += `⏰ *Jam Buka:* ${b.open_hours || '15:00 - 23:00'}\n`;
    text += `📞 *Kontak:* ${b.phone || '-'}\n`;
    text += `💳 *Pembayaran:* QRIS & ${b.bank_info || 'Tunai'}\n`;
    text += `🟢 *Status:* ${b.is_open ? 'BUKA' : 'TUTUP'}\n\n`;
  });

  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `Ketik *!menu* untuk melihat hidangan favorit Anda!`;

  return text;
}

export function getOrderStatusText(codeQuery) {
  if (!codeQuery || !codeQuery.trim()) {
    return `⚠️ Format salah! Gunakan: *!status [KODE_ORDER]*\nContoh: *!status KB-173000*`;
  }

  const query = codeQuery.trim().toLowerCase();
  const orders = readJSON(ORDERS_FILE, []);

  const found = orders.find(o => 
    (o.order_code && o.order_code.toLowerCase().includes(query)) ||
    (o.id && o.id.toLowerCase().includes(query))
  );

  if (!found) {
    return `❌ Pesanan dengan kode *${codeQuery.trim()}* tidak ditemukan.\nPastikan kode pemesanan sudah benar (contoh: *KB-173000*).`;
  }

  const statusEmojis = {
    'pending': '⏳ Menunggu Konfirmasi Toko',
    'cooking': '👨‍🍳 Sedang Dimasak di Dapur',
    'delivering': '🛵 Sedang Diantar oleh Kurir',
    'ready_pickup': '🛍️ Siap Diambil di Outlet',
    'completed': '✅ Selesai (Pesanan Sudah Diterima)',
    'cancelled': '❌ Dibatalkan'
  };

  const statusText = statusEmojis[found.status] || `ℹ️ ${found.status}`;

  let text = `🧾 *DETAIL PESANAN KEBAB AL BEWOK* 🧾\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `📋 *Kode:* #${found.order_code || found.id}\n`;
  text += `👤 *Pelanggan:* ${found.customer_name} (${found.customer_phone})\n`;
  text += `🏪 *Outlet:* ${found.branch_name || 'Kebab AL Bewok'}\n`;
  text += `📍 *Alamat Antar:* ${found.delivery_address || 'Ambil di Toko'}\n`;
  text += `🔄 *Status:* ${statusText}\n`;
  text += `💳 *Pembayaran:* ${found.payment_method?.toUpperCase()} (${found.payment_status === 'paid' ? 'LUNAS' : 'BELUM DIBAYAR'})\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `🛒 *Item Pesanan:*\n`;

  if (Array.isArray(found.items)) {
    found.items.forEach(item => {
      text += `• ${item.qty}x ${item.name} (${item.variant || 'Reguler'}) - ${formatRupiah(item.price * item.qty)}\n`;
    });
  }

  text += `\n💰 *Total Bayar:* *${formatRupiah(found.total_amount)}*\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `Terima kasih telah memesan di Kebab AL Bewok! 🙏`;

  return text;
}

export function getOrderHelpText() {
  return `📝 *CARA PEMESANAN KEBAB AL BEWOK* 📝
━━━━━━━━━━━━━━━━━━━━━
Anda bisa memesan langsung melalui chat ini dengan mengisi format berikut:

*FORMAT PESANAN:*
Nama: 
Nomor HP: 
Cabang Outlet: (Pasar Baru / Alun-Alun)
Pilihan Menu & Jumlah:
Catatan Pedas: (Tidak Pedas / Sedang / Ekstra Pedas)
Alamat Lengkap / Jemput Sendiri: 
Metode Bayar: (QRIS / Tunai / Transfer)

👉 *Salin teks di atas, isi data lengkap, lalu kirim kembali ke WhatsApp ini.*
Admin/kasir kami akan segera mengonfirmasi pesanan Anda!`;
}
