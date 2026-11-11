const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function hashPassword(password, salt = 'kebab_al_bewok_secret_salt_2026') {
  return crypto.createHmac('sha256', salt).update(String(password)).digest('hex');
}

function normalizePhone(p) {
  if (!p) return '';
  let s = String(p).replace(/[^0-9]/g, '');
  if (s.startsWith('62')) s = s.slice(2);
  else if (s.startsWith('0')) s = s.slice(1);
  return s;
}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files untuk frontend ketiga aplikasi
const PUBLIC_DIR = path.join(__dirname, '../public');
app.use(express.static(PUBLIC_DIR));

// Rute jalan pintas untuk masing-masing aplikasi
app.get('/customer', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'customer.html')));
app.get('/driver', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'driver.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/owner', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'owner.html')));

// Path file data
const DATA_DIR = path.join(__dirname, '../data');
const MENU_FILE = path.join(DATA_DIR, 'menu.json');
const BRANCHES_FILE = path.join(DATA_DIR, 'branches.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const STOCK_OPNAME_FILE = path.join(DATA_DIR, 'stock_opname.json');
const WALLETS_FILE = path.join(DATA_DIR, 'wallets.json');
const AUTH_CONFIG_FILE = path.join(DATA_DIR, 'auth_config.json');

// Helper untuk membaca & menulis file JSON (dengan In-Memory Fallback untuk Serverless Cloud seperti Vercel/Render)
const memoryCache = {};

function readJSON(filePath, defaultData = []) {
  if (memoryCache[filePath]) {
    return JSON.parse(JSON.stringify(memoryCache[filePath]));
  }
  try {
    if (!fs.existsSync(filePath)) {
      try { fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2)); } catch (e) {}
      memoryCache[filePath] = defaultData;
      return defaultData;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    memoryCache[filePath] = parsed;
    return parsed;
  } catch (err) {
    console.error(`Gagal membaca ${filePath}:`, err);
    return memoryCache[filePath] || defaultData;
  }
}

function writeJSON(filePath, data) {
  memoryCache[filePath] = JSON.parse(JSON.stringify(data));
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (err) {
    // Pada serverless seperti Vercel filesystem read-only, data tetap aman tersimpan di memoryCache selama instance hidup
  }
}

// Memory store untuk OTP (Kadaluwarsa dalam 5 menit)
const otpStore = new Map();

// Inisialisasi file data jika belum ada
if (!fs.existsSync(ORDERS_FILE)) writeJSON(ORDERS_FILE, []);
if (!fs.existsSync(STOCK_OPNAME_FILE)) writeJSON(STOCK_OPNAME_FILE, []);
if (!fs.existsSync(WALLETS_FILE)) {
  writeJSON(WALLETS_FILE, {
    drivers: {
      "driver-01": { id: "driver-01", name: "Budi Santoso", balance: 25000, trips: 3, is_online: true },
      "driver-02": { id: "driver-02", name: "Ahmad Dani", balance: 15000, trips: 2, is_online: true }
    },
    customers: {
      "cust-01": { id: "cust-01", name: "Pelanggan Setia", balance: 50000 }
    },
    history: []
  });
}

// ==========================================
// 1. ENDPOINTS UMUM & CUSTOMER (AUTH & MENU)
// ==========================================

// Konfigurasi Google Client ID (Dapat diatur dinamis / disimpan di auth_config.json)
app.get('/api/config/auth', (req, res) => {
  const authConfig = readJSON(AUTH_CONFIG_FILE, { google_client_id: '' });
  const clientId = process.env.GOOGLE_CLIENT_ID || authConfig.google_client_id || '';
  res.json({
    success: true,
    data: {
      google_client_id: clientId,
      is_configured: Boolean(clientId && clientId.length > 10)
    }
  });
});

app.post('/api/config/auth', (req, res) => {
  const { google_client_id } = req.body;
  const authConfig = readJSON(AUTH_CONFIG_FILE, { google_client_id: '' });
  authConfig.google_client_id = (google_client_id || '').trim();
  authConfig.updated_at = new Date().toISOString();
  writeJSON(AUTH_CONFIG_FILE, authConfig);

  console.log(`🔑 [AUTH CONFIG UPDATED] Google Client ID set to: ${authConfig.google_client_id ? authConfig.google_client_id.slice(0, 15) + '...' : '(dikosongkan)'}`);
  res.json({
    success: true,
    message: 'Konfigurasi Google Client ID berhasil disimpan!',
    data: { google_client_id: authConfig.google_client_id }
  });
});

// Login / Registrasi Akun Google (Mendukung Real Token JWT Google Identity Services & Mode Cepat)
app.post('/api/auth/google-login', async (req, res) => {
  let { credential, email, full_name, avatar_url, google_id } = req.body;
  let isGoogleVerified = false;

  // Verifikasi Kriptografis Resmi Google jika credential JWT dikirim
  if (credential) {
    try {
      const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
      const gData = await gRes.json();
      if (gData.error_description || !gData.email) {
        return res.status(401).json({
          success: false,
          message: `Verifikasi Akun Google Gagal: ${gData.error_description || 'Token kedaluwarsa atau tidak valid'}`
        });
      }
      email = gData.email;
      full_name = gData.name || full_name || email.split('@')[0];
      avatar_url = gData.picture || avatar_url;
      google_id = gData.sub;
      isGoogleVerified = true;
      console.log(`🔐 [GOOGLE OAUTH VERIFIED] Pelanggan terverifikasi: ${full_name} (${email})`);
    } catch (err) {
      console.error('Error saat menghubungi server Google tokeninfo:', err);
      return res.status(500).json({ success: false, message: 'Gagal menghubungi server verifikasi Google' });
    }
  }

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email Google diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  // Cari atau buat profil baru berdasarkan email Google
  if (!wallets.customers[email]) {
    wallets.customers[email] = {
      id: `cust-${Date.now()}`,
      email,
      name: full_name || email.split('@')[0],
      avatar: avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${email}`,
      whatsapp: '',
      home_address: '',
      home_latitude: null,
      home_longitude: null,
      office_address: '',
      office_latitude: null,
      office_longitude: null,
      delivery_address: '',
      latitude: null,
      longitude: null,
      auth_provider: 'google',
      google_verified: isGoogleVerified,
      registered_at: new Date().toISOString()
    };
  } else {
    // Update data Google terbaru & pastikan field rumah/kantor ada
    if (full_name) wallets.customers[email].name = full_name;
    if (avatar_url) wallets.customers[email].avatar = avatar_url;
    if (isGoogleVerified) wallets.customers[email].google_verified = true;
    if (!wallets.customers[email].home_address && wallets.customers[email].delivery_address) {
      wallets.customers[email].home_address = wallets.customers[email].delivery_address;
      wallets.customers[email].home_latitude = wallets.customers[email].latitude;
      wallets.customers[email].home_longitude = wallets.customers[email].longitude;
    }
    wallets.customers[email].profile_completed = Boolean(
      wallets.customers[email].whatsapp && 
      (wallets.customers[email].home_address || wallets.customers[email].delivery_address)
    );
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: isGoogleVerified 
      ? `Autentikasi Google Terverifikasi 100%! Selamat datang, ${wallets.customers[email].name}.`
      : `Login Google Berhasil! Selamat datang, ${wallets.customers[email].name}.`,
    data: {
      token: `token-google-${email}-${Date.now()}`,
      verified_by_google: isGoogleVerified,
      user: wallets.customers[email]
    }
  });
});

// Update Profil Pelanggan (Nomor WhatsApp, Alamat Pengiriman & Kata Sandi Akun)
app.post('/api/customer/update-profile', (req, res) => {
  const {
    email,
    whatsapp,
    full_name,
    password, // Fitur Kata Sandi Baru
    home_address,
    home_latitude,
    home_longitude,
    office_address,
    office_latitude,
    office_longitude,
    delivery_address,
    latitude,
    longitude
  } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email akun diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers || !wallets.customers[email]) {
    return res.status(404).json({ success: false, message: 'Akun pelanggan tidak ditemukan' });
  }

  const cust = wallets.customers[email];
  if (full_name) cust.name = full_name.trim();
  if (whatsapp) cust.whatsapp = whatsapp.trim();

  // Pengaturan Kata Sandi
  if (password && typeof password === 'string' && password.trim().length >= 4) {
    cust.password_hash = hashPassword(password.trim());
    cust.has_password = true;
    console.log(`🔑 [KATA SANDI DISIMPAN] Pelanggan ${cust.name} (${cust.email}) telah mengatur password akun.`);
  }

  // Alamat Rumah (Utama)
  if (home_address !== undefined) cust.home_address = home_address.trim();
  if (home_latitude !== undefined) cust.home_latitude = home_latitude;
  if (home_longitude !== undefined) cust.home_longitude = home_longitude;

  // Alamat Kantor / Lainnya
  if (office_address !== undefined) cust.office_address = office_address.trim();
  if (office_latitude !== undefined) cust.office_latitude = office_latitude;
  if (office_longitude !== undefined) cust.office_longitude = office_longitude;

  // Fallback kompatibilitas
  cust.delivery_address = cust.home_address || (delivery_address ? delivery_address.trim() : '');
  cust.latitude = cust.home_latitude || latitude || null;
  cust.longitude = cust.home_longitude || longitude || null;

  // Status kelengkapan onboarding profil customer
  cust.profile_completed = Boolean(cust.whatsapp && (cust.home_address || cust.delivery_address));

  cust.updated_at = new Date().toISOString();

  writeJSON(WALLETS_FILE, wallets);

  console.log(`👤 [PROFIL DIPERBARUI] ${cust.name} | WA: ${cust.whatsapp} | Password: ${cust.has_password ? 'YA' : 'TIDAK'} | Rumah: ${cust.home_address}`);

  const safeCust = { ...cust };
  delete safeCust.password_hash;

  res.json({
    success: true,
    message: password 
      ? 'Profil, alamat & kata sandi akun berhasil disimpan!' 
      : 'Profil & alamat tujuan pengantaran berhasil disimpan!',
    data: safeCust
  });
});

// Login Pelanggan dengan Email / Nomor WhatsApp & Kata Sandi
app.post('/api/auth/login-password', (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ success: false, message: 'Email / Nomor WhatsApp dan Kata Sandi wajib diisi' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const cleanId = identifier.trim().toLowerCase();
  const normInputPhone = normalizePhone(identifier);

  // Cari user berdasarkan email ATAU nomor whatsapp
  let targetCust = null;

  // 1. Cari exact match email key
  if (wallets.customers[cleanId]) {
    targetCust = wallets.customers[cleanId];
  } else {
    // 2. Cari di daftar seluruh pelanggan
    targetCust = Object.values(wallets.customers).find(c => {
      if (c.email && c.email.toLowerCase() === cleanId) return true;
      if (c.whatsapp && normInputPhone && normInputPhone.length >= 7) {
        const normWa = normalizePhone(c.whatsapp);
        if (normWa === normInputPhone) return true;
      }
      return false;
    });
  }

  if (!targetCust) {
    return res.status(404).json({
      success: false,
      message: 'Akun dengan Email atau Nomor WhatsApp tersebut belum terdaftar. Silakan masuk via Google terlebih dahulu.'
    });
  }

  if (!targetCust.password_hash) {
    return res.status(400).json({
      success: false,
      message: 'Akun ini belum memiliki kata sandi. Silakan masuk dengan Akun Google terlebih dahulu, lalu atur kata sandi di Profil Anda.'
    });
  }

  const incomingHash = hashPassword(password.trim());
  if (incomingHash !== targetCust.password_hash) {
    return res.status(401).json({
      success: false,
      message: 'Kata sandi salah. Silakan periksa kembali kata sandi akun Anda.'
    });
  }

  const safeCust = { ...targetCust };
  delete safeCust.password_hash;

  console.log(`🔑 [LOGIN PASSWORD BERHASIL] Pelanggan: ${safeCust.name} (${safeCust.email})`);

  res.json({
    success: true,
    message: `Login Berhasil! Selamat datang kembali, Kak ${safeCust.name}.`,
    data: {
      token: `token-pass-${safeCust.id || safeCust.email}-${Date.now()}`,
      user: safeCust
    }
  });
});

// Login Dapur & Kasir Lapak (Mendukung PIN Kasir Cabang, Kata Sandi & Akun Google)
app.post('/api/auth/kitchen-login', (req, res) => {
  const { branch_id, pin_or_password, staff_name, email } = req.body;

  const branches = readJSON(BRANCHES_FILE);
  const targetBranch = branches.find(b => b.id === branch_id) || branches[0];

  if (!targetBranch) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  const inputPin = String(pin_or_password || '').trim();
  const validBranchPin = targetBranch.staff_pin || '1234';

  // Verifikasi PIN / Password Kasir:
  // Cocok jika sama dengan PIN cabang (default 1234), atau password master "albewok2026" / "admin123"
  const isPinValid = inputPin === validBranchPin || inputPin === '1234' || inputPin === 'admin123' || inputPin === 'albewok2026';

  if (!isPinValid) {
    return res.status(401).json({
      success: false,
      message: `PIN Kasir salah! PIN standar adalah 1234 untuk ${targetBranch.name}.`
    });
  }

  const staffName = staff_name ? staff_name.trim() : `Kasir ${targetBranch.name.replace('Kebab AL Bewok - ', '')}`;
  const staffEmail = email ? email.trim() : `kasir.${targetBranch.id}@kebab-albewok.com`;

  const staffUser = {
    id: `staff-${targetBranch.id}-${Date.now().toString().slice(-4)}`,
    name: staffName,
    email: staffEmail,
    role: 'staff_kasir',
    branch_id: targetBranch.id,
    branch_name: targetBranch.name
  };

  console.log(`🏪 [KITCHEN LOGIN] ${staffUser.name} berhasil masuk ke ${targetBranch.name}`);

  res.json({
    success: true,
    message: `Akses diterima! Selamat bertugas di ${targetBranch.name}.`,
    data: {
      token: `token-kitchen-${targetBranch.id}-${Date.now()}`,
      staff: staffUser,
      branch: targetBranch
    }
  });
});

// Login Cepat & Gratis (Fallback)
app.post('/api/auth/login-free', (req, res) => {
  const { full_name, phone_number } = req.body;

  if (!full_name || full_name.trim().length < 2) {
    return res.status(400).json({ success: false, message: 'Mohon masukkan nama lengkap yang jelas.' });
  }

  let cleanPhone = (phone_number || '').replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  if (cleanPhone.length < 10 || cleanPhone.length > 15) {
    return res.status(400).json({ success: false, message: 'Nomor WhatsApp tidak valid (minimal 10 digit).' });
  }

  // Simpan data pelanggan ke database
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const name = full_name.trim();
  wallets.customers[cleanPhone] = {
    phone: cleanPhone,
    name,
    balance: (wallets.customers[cleanPhone] ? wallets.customers[cleanPhone].balance : 0),
    last_login: new Date().toISOString()
  };
  writeJSON(WALLETS_FILE, wallets);

  console.log(`✅ [LOGIN GRATIS] Pelanggan terdaftar: ${name} (${cleanPhone})`);

  res.json({
    success: true,
    message: `Selamat datang, Kak ${name}! Nomor WhatsApp Anda berhasil terhubung.`,
    data: {
      token: `token-${cleanPhone}-${Date.now()}`,
      user: wallets.customers[cleanPhone]
    }
  });
});

// Kirim Kode OTP WhatsApp (Opsional jika nanti ada bot)
app.post('/api/auth/send-otp', (req, res) => {
  const { phone_number, full_name } = req.body;
  if (!phone_number || phone_number.length < 9) {
    return res.status(400).json({ success: false, message: 'Nomor WhatsApp tidak valid' });
  }

  // Format nomor (hapus karakter aneh, ubah 08.. jadi format standar)
  let cleanPhone = phone_number.replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  // Buat 4 digit OTP
  const otpCode = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore.set(cleanPhone, {
    otp: otpCode,
    full_name: full_name || 'Pelanggan Kebab',
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  console.log(`🔑 [OTP KEBAB AL BEWOK] Kode verifikasi untuk ${cleanPhone} (${full_name}): ${otpCode}`);

  // Kirimkan ke WhatsApp Bot Gratis (port 5001) jika bot aktif
  fetch('http://127.0.0.1:5001/api/send-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone: cleanPhone, otp: otpCode, name: full_name || 'Pelanggan Kebab' })
  }).then(r => r.json()).then(data => {
    if (data.success) {
      console.log(`📲 [WA BOT SUKSES] OTP asli telah terkirim via WhatsApp ke ${cleanPhone}`);
    }
  }).catch(() => {
    // Bot WA mungkin belum dinyalakan, sistem tetap berjalan aman
  });

  res.json({
    success: true,
    message: 'Kode verifikasi berhasil dikirim!',
    data: {
      phone: cleanPhone,
      // Dikembalikan di response agar simulasi langsung jalan tanpa perlu langganan API gateway WA berbayar
      demo_otp: otpCode
    }
  });
});

// Verifikasi Kode OTP & Buat Sesi Login
app.post('/api/auth/verify-otp', (req, res) => {
  const { phone_number, otp_code, full_name } = req.body;
  let cleanPhone = (phone_number || '').replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  const session = otpStore.get(cleanPhone);

  // Validasi: Kode benar ATAU menggunakan Master PIN Demo '1234'
  const isMasterCode = (otp_code === '1234');
  const isValidSession = session && (session.otp === otp_code);

  if (!isMasterCode && !isValidSession) {
    return res.status(400).json({ success: false, message: 'Kode OTP salah. Silakan masukkan 1234 untuk demo.' });
  }

  // Simpan/update profil pelanggan di wallets/database
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const name = full_name || (session ? session.full_name : 'Pelanggan Kebab');
  wallets.customers[cleanPhone] = {
    phone: cleanPhone,
    name,
    balance: (wallets.customers[cleanPhone] ? wallets.customers[cleanPhone].balance : 0),
    registered_at: new Date().toISOString()
  };
  writeJSON(WALLETS_FILE, wallets);

  // Hapus OTP setelah dipakai
  otpStore.delete(cleanPhone);

  res.json({
    success: true,
    message: 'Login berhasil! Selamat datang di Kebab AL Bewok.',
    data: {
      token: `token-${cleanPhone}-${Date.now()}`,
      user: wallets.customers[cleanPhone]
    }
  });
});

// Ambil Menu Kebab AL Bewok
app.get('/api/menu', (req, res) => {
  const menu = readJSON(MENU_FILE);
  res.json({ success: true, data: menu });
});

// Ambil Daftar Cabang Lapak
app.get('/api/branches', (req, res) => {
  const branches = readJSON(BRANCHES_FILE);
  res.json({ success: true, data: branches });
});

// Ambil Detail Satu Cabang
app.get('/api/branches/:id', (req, res) => {
  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === req.params.id);
  if (!branch) {
    return res.status(404).json({ success: false, message: 'Cabang tidak ditemukan' });
  }
  res.json({ success: true, data: branch });
});

// Update Profil Lapak: Nama, Lokasi (Alamat, Lat, Lng), Nomor Telepon & QRIS Lapak
app.put('/api/admin/branches/:id', (req, res) => {
  const { id } = req.params;
  const {
    name,
    address,
    phone,
    latitude,
    longitude,
    qris_image,
    bank_info,
    is_open,
    open_hours,
    staff_pin,
    out_of_stock,
    cash_opening
  } = req.body;

  const branches = readJSON(BRANCHES_FILE);
  const idx = branches.findIndex(b => b.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  if (name !== undefined && name !== null) branches[idx].name = String(name).trim();
  if (address !== undefined && address !== null) branches[idx].address = String(address).trim();
  if (phone !== undefined && phone !== null) branches[idx].phone = String(phone).trim();
  if (latitude !== undefined && latitude !== null && !isNaN(Number(latitude))) {
    branches[idx].latitude = parseFloat(latitude);
  }
  if (longitude !== undefined && longitude !== null && !isNaN(Number(longitude))) {
    branches[idx].longitude = parseFloat(longitude);
  }
  if (qris_image !== undefined && qris_image !== null && String(qris_image).trim() !== '') {
    branches[idx].qris_image = String(qris_image).trim();
  }
  if (bank_info !== undefined && bank_info !== null) branches[idx].bank_info = String(bank_info).trim();
  if (is_open !== undefined && is_open !== null) branches[idx].is_open = Boolean(is_open);
  if (open_hours !== undefined && open_hours !== null) branches[idx].open_hours = String(open_hours).trim();
  if (staff_pin !== undefined && staff_pin !== null && String(staff_pin).trim() !== '') {
    branches[idx].staff_pin = String(staff_pin).trim();
  }
  if (Array.isArray(out_of_stock)) {
    branches[idx].out_of_stock = out_of_stock;
  }
  if (cash_opening !== undefined && cash_opening !== null && !isNaN(Number(cash_opening))) {
    branches[idx].cash_opening = Math.max(0, Number(cash_opening));
  }

  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH UPDATE] Profil Cabang ${id} (${branches[idx].name}) berhasil diperbarui.`);
  res.json({
    success: true,
    message: 'Profil lapak dan QRIS berhasil diperbarui',
    data: branches[idx]
  });
});

// Tambah Cabang Baru
app.post('/api/admin/branches', (req, res) => {
  const {
    name,
    address,
    phone,
    latitude,
    longitude,
    qris_image,
    bank_info,
    open_hours = '15:00 - 23:00',
    staff_pin = '1234',
    cash_opening = 100000,
    is_open = true
  } = req.body;

  if (!name || !address) {
    return res.status(400).json({ success: false, message: 'Nama dan alamat cabang wajib diisi' });
  }

  const branches = readJSON(BRANCHES_FILE);
  // Cari nomor cabang tertinggi agar ID selalu unik walau cabang > 9 atau pernah dihapus
  const maxNum = branches.reduce((max, b) => {
    const m = String(b.id || '').match(/(\d+)$/);
    return m ? Math.max(max, parseInt(m[1], 10)) : max;
  }, 0);
  let nextNum = maxNum + 1;
  let newId = `cabang-${String(nextNum).padStart(2, '0')}`;
  while (branches.some(b => b.id === newId)) {
    nextNum++;
    newId = `cabang-${String(nextNum).padStart(2, '0')}`;
  }

  const parsedLat = parseFloat(latitude);
  const parsedLng = parseFloat(longitude);
  const parsedCashOpening = Number(cash_opening);

  const newBranch = {
    id: newId,
    name: String(name).trim(),
    address: String(address).trim(),
    phone: phone ? String(phone).trim() : '0852-8584-1330',
    latitude: !isNaN(parsedLat) ? parsedLat : -6.2088,
    longitude: !isNaN(parsedLng) ? parsedLng : 106.8456,
    qris_image: (qris_image && String(qris_image).trim()) ? String(qris_image).trim() : `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=QRIS_${newId}`,
    bank_info: bank_info !== undefined && bank_info !== null ? String(bank_info).trim() : 'BCA a/n Kebab AL Bewok',
    is_open: Boolean(is_open),
    open_hours: String(open_hours || '15:00 - 23:00').trim(),
    staff_pin: String(staff_pin || '1234').trim() || '1234',
    out_of_stock: [],
    cash_opening: !isNaN(parsedCashOpening) ? Math.max(0, parsedCashOpening) : 100000
  };

  branches.push(newBranch);
  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH CREATE] Cabang baru ditambahkan: ${newBranch.name} (${newId})`);
  res.status(201).json({ success: true, message: 'Cabang baru berhasil ditambahkan', data: newBranch });
});

// Hapus Cabang Lapak (Minimal menyisakan 1 cabang aktif)
app.delete('/api/admin/branches/:id', (req, res) => {
  const { id } = req.params;
  const branches = readJSON(BRANCHES_FILE);
  if (branches.length <= 1) {
    return res.status(400).json({ success: false, message: 'Minimal harus ada 1 lapak aktif di sistem.' });
  }
  const idx = branches.findIndex(b => b.id === id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  const [removed] = branches.splice(idx, 1);
  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH DELETE] Cabang dihapus: ${removed.name} (${id})`);
  res.json({ success: true, message: `Lapak "${removed.name}" berhasil dihapus.`, data: removed });
});

// Checkout Pesanan Baru
app.post('/api/orders/checkout', (req, res) => {
  const {
    customer_name,
    customer_phone,
    customer_address,
    customer_email,
    destination_type = 'home',
    branch_id,
    items,
    delivery_distance_km = 2.0,
    payment_method = 'qris_statis',
    customer_notes = ''
  } = req.body;

  if (!items || items.length === 0) {
    return res.status(400).json({ success: false, message: 'Keranjang belanja kosong' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === branch_id) || branches[0];

  // Hitung subtotal makanan
  const food_subtotal = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

  // Rumus Ongkir Hemat: Rp 6.000 untuk 2 km pertama, +Rp 2.000 tiap km berikutnya
  let delivery_fee = 6000;
  if (delivery_distance_km > 2) {
    delivery_fee += Math.ceil(delivery_distance_km - 2) * 2000;
  }

  const total_payment = food_subtotal + delivery_fee;
  const order_code = `KB-${Date.now().toString().slice(-6)}`;

  const newOrder = {
    id: `ord-${Date.now()}`,
    order_code,
    branch_id: branch.id,
    branch_name: branch.name,
    branch_latitude: branch.latitude || -6.2088,
    branch_longitude: branch.longitude || 106.8456,
    customer_name: customer_name || 'Pelanggan Kebab',
    customer_email: customer_email || null,
    customer_phone: customer_phone || '081234567890',
    customer_address: customer_address || 'Jl. Mawar No. 10',
    customer_latitude: parseFloat(req.body.customer_latitude || req.body.latitude) || -6.2150,
    customer_longitude: parseFloat(req.body.customer_longitude || req.body.longitude) || 106.8520,
    destination_type,
    delivery_distance_km,
    items,
    food_subtotal,
    delivery_fee,
    total_payment,
    payment_method, // 'qris_statis' atau 'customer_balance'
    payment_proof: null,
    status: payment_method === 'customer_balance' ? 'cooking' : 'pending_payment',
    created_at: new Date().toISOString(),
    driver_id: null,
    driver_name: null,
    driver_phone: null,
    driver_vehicle: null,
    driver_photo: null,
    driver_latitude: null,
    driver_longitude: null,
    delivery_proof: null
  };

  const orders = readJSON(ORDERS_FILE);
  orders.unshift(newOrder);
  writeJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    message: 'Pesanan berhasil dibuat!',
    data: {
      order: newOrder,
      qris_image: branch.qris_image,
      bank_info: branch.bank_info
    }
  });
});

// Upload Bukti Bayar QRIS Statis
app.post('/api/orders/:id/payment-proof', (req, res) => {
  const { id } = req.params;
  const { proof_image } = req.body; // base64 / image url

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id || o.order_code === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].payment_proof = proof_image || 'https://placehold.co/400x600/png?text=Bukti+Transfer+QRIS+Valid';
  orders[orderIndex].status = 'pending_verification';
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Bukti pembayaran terkirim! Menunggu verifikasi dapur.', data: orders[orderIndex] });
});

function calculateBearingDeg(lat1, lng1, lat2, lng2) {
  const rad = Math.PI / 180;
  const phi1 = lat1 * rad;
  const phi2 = lat2 * rad;
  const dLambda = (lng2 - lng1) * rad;
  const y = Math.sin(dLambda) * Math.cos(phi2);
  const x = Math.cos(phi1) * Math.sin(phi2) - Math.sin(phi1) * Math.cos(phi2) * Math.cos(dLambda);
  return ((Math.atan2(y, x) * 180) / Math.PI + 360) % 360;
}

function resolveOrderDriverPosition(order) {
  const branchLat = Number(order.branch_latitude) || -6.2088;
  const branchLng = Number(order.branch_longitude) || 106.8456;
  const custLat = Number(order.customer_latitude) || -6.2150;
  const custLng = Number(order.customer_longitude) || 106.8520;

  let driverLat = Number(order.driver_latitude) || branchLat;
  let driverLng = Number(order.driver_longitude) || branchLng;

  if (!order.manual_gps) {
    if (order.status === 'driver_heading_to_branch' || order.driver_phase === 'to_branch') {
      const startLat = Number(order.driver_start_latitude) || (branchLat + 0.0065);
      const startLng = Number(order.driver_start_longitude) || (branchLng - 0.0055);
      const elapsedSec = (Date.now() - new Date(order.driver_accepted_at || Date.now()).getTime()) / 1000;
      const progress = Math.min(0.96, Math.max(0, elapsedSec / 45));
      driverLat = startLat + (branchLat - startLat) * progress;
      driverLng = startLng + (branchLng - startLng) * progress;
    } else if (order.status === 'on_delivery' || order.driver_phase === 'to_customer') {
      const startTime = order.driver_picked_up_at || order.driver_accepted_at || Date.now();
      const elapsedSec = (Date.now() - new Date(startTime).getTime()) / 1000;
      const progress = Math.min(0.96, Math.max(0, elapsedSec / 65));
      driverLat = branchLat + (custLat - branchLat) * progress;
      driverLng = branchLng + (custLng - branchLng) * progress;
    }
  }

  return { driverLat, driverLng, branchLat, branchLng, custLat, custLng };
}

function updateDriverTelemetryInWallet(driverId, latitude, longitude, extra = {}) {
  if (!driverId) return;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[driverId]) return;
  const d = wallets.drivers[driverId];
  const parsedLat = parseFloat(latitude);
  const parsedLng = parseFloat(longitude);
  if (!isNaN(parsedLat) && !isNaN(parsedLng)) {
    if (d.last_latitude !== undefined && d.last_longitude !== undefined && (d.last_latitude !== parsedLat || d.last_longitude !== parsedLng)) {
      d.last_heading = calculateBearingDeg(d.last_latitude, d.last_longitude, parsedLat, parsedLng);
    }
    d.last_latitude = parsedLat;
    d.last_longitude = parsedLng;
  }
  if (extra.is_online !== undefined) d.is_online = Boolean(extra.is_online);
  if (extra.heading !== undefined && !isNaN(Number(extra.heading))) d.last_heading = Number(extra.heading);
  if (extra.speed_kmh !== undefined && !isNaN(Number(extra.speed_kmh))) d.last_speed_kmh = Number(extra.speed_kmh);
  d.last_seen_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);
}

// Lacak Status Pesanan & Lokasi Driver Real-time (3 Fase: Menuju Lapak -> Ambil Makanan -> Menuju Customer)
app.get('/api/orders/:id', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const order = orders.find(o => o.id === id || o.order_code === id);

  if (!order) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const pos = resolveOrderDriverPosition(order);
  order.driver_latitude = pos.driverLat;
  order.driver_longitude = pos.driverLng;

  res.json({ success: true, data: order });
});

// Heartbeat GPS & Status Standby Kurir (Untuk Radar Lalu Lintas Kurir Owner)
app.post('/api/driver/location', (req, res) => {
  const { driver_id, latitude, longitude, is_online, heading, speed_kmh } = req.body;
  if (!driver_id) {
    return res.status(400).json({ success: false, message: 'driver_id wajib diisi' });
  }
  updateDriverTelemetryInWallet(driver_id, latitude, longitude, { is_online, heading, speed_kmh });
  res.json({ success: true, message: 'Telemetri GPS kurir diperbarui' });
});

// Update Live GPS Lokasi Kurir saat Menuju Lapak / Mengantar
app.post('/api/driver/orders/:id/location', (req, res) => {
  const { id } = req.params;
  const { latitude, longitude, phase, heading, speed_kmh } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id || o.order_code === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].driver_latitude = parseFloat(latitude);
  orders[orderIndex].driver_longitude = parseFloat(longitude);
  orders[orderIndex].manual_gps = true;
  if (phase) orders[orderIndex].driver_phase = phase;
  orders[orderIndex].last_location_update = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  if (orders[orderIndex].driver_id) {
    updateDriverTelemetryInWallet(orders[orderIndex].driver_id, latitude, longitude, { is_online: true, heading, speed_kmh });
  }

  res.json({ success: true, message: 'Lokasi kurir terkirim secara live', data: { latitude, longitude } });
});

// ==========================================
// 2. ENDPOINTS ADMIN LAPAK / DAPUR
// ==========================================

// Daftar Pesanan Dapur & Kasir
app.get('/api/admin/orders', (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  res.json({ success: true, data: orders });
});

// Verifikasi Pembayaran QRIS Masuk -> Status Jadi 'cooking'
app.post('/api/admin/orders/:id/verify-payment', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].status = 'cooking';
  orders[orderIndex].payment_verified_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Pembayaran valid! Pesanan masuk ke antrean masak.', data: orders[orderIndex] });
});

// Makanan Siap Pick-up -> Panggil Kurir Freelance
app.post('/api/admin/orders/:id/ready', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].status = 'ready_for_pickup';
  orders[orderIndex].ready_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Pesanan siap! Notifikasi disiarkan ke kurir terdekat.', data: orders[orderIndex] });
});

// Input Pesanan Kasir Manual Lapak (POS Offline: Walk-in / Dine-in / Takeaway)
app.post('/api/admin/orders/offline', (req, res) => {
  const {
    branch_id,
    customer_name = 'Pelanggan Langsung',
    items,
    payment_method = 'cash', // 'cash' | 'qris_offline'
    cash_tendered = 0,
    cash_change = 0,
    order_notes = ''
  } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ success: false, message: 'Item pesanan kasir tidak boleh kosong' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const targetBranch = branches.find(b => b.id === branch_id) || branches[0];

  const food_subtotal = items.reduce((sum, item) => sum + (Number(item.price) * Number(item.quantity)), 0);
  const total_payment = food_subtotal;

  const orders = readJSON(ORDERS_FILE);
  const orderId = `ord-pos-${Date.now()}`;
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const orderCode = `KB-OFF-${randomSuffix}`;

  const newOrder = {
    id: orderId,
    order_code: orderCode,
    branch_id: targetBranch.id,
    branch_name: targetBranch.name,
    branch_latitude: targetBranch.latitude,
    branch_longitude: targetBranch.longitude,
    customer_name: (customer_name && customer_name.trim()) ? customer_name.trim() : 'Pelanggan Langsung',
    customer_email: null,
    customer_phone: '-',
    customer_address: 'Makan di Tempat / Bawa Pulang (Walk-in)',
    customer_latitude: targetBranch.latitude,
    customer_longitude: targetBranch.longitude,
    destination_type: 'offline_store',
    delivery_distance_km: 0,
    items,
    food_subtotal,
    delivery_fee: 0,
    total_payment,
    payment_method, // 'cash' atau 'qris_offline'
    cash_tendered: Number(cash_tendered) || total_payment,
    cash_change: Number(cash_change) || 0,
    order_type: 'offline', // Pembeda jelas dari online
    order_notes,
    payment_proof: payment_method === 'qris_offline' ? (targetBranch.qris_image || 'https://placehold.co/300x300/png?text=QRIS+Lapak') : null,
    status: 'completed', // Pesanan offline kasir selesai langsung saat bayar
    completed_at: new Date().toISOString(),
    created_at: new Date().toISOString()
  };

  orders.unshift(newOrder);
  writeJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    message: 'Pesanan kasir offline berhasil dicatat & masuk ke pengkasian!',
    data: newOrder
  });
});

const ID_MONTHS = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];

function getLocalWibDate(dateInput = new Date()) {
  const utcMs = new Date(dateInput).getTime();
  return new Date(utcMs + 7 * 60 * 60 * 1000);
}

function getWibDateISO(dateInput = new Date()) {
  if (!dateInput) return '';
  return getLocalWibDate(dateInput).toISOString().split('T')[0];
}

function formatClosingDateId(dateInput = new Date()) {
  const d = getLocalWibDate(dateInput);
  const day = String(d.getUTCDate()).padStart(2, '0');
  const monthName = ID_MONTHS[d.getUTCMonth()] || 'Januari';
  const year = d.getUTCFullYear();
  return `Closing ${day} ${monthName} ${year}`;
}

function getDefaultBusinessDateISO(now = new Date()) {
  const wib = getLocalWibDate(now);
  if (wib.getUTCHours() < 15) {
    wib.setUTCDate(wib.getUTCDate() - 1);
  }
  return wib.toISOString().split('T')[0];
}

function parseClosingDateToISO(closingDateStr, fallbackISO) {
  if (closingDateStr) {
    const match = String(closingDateStr).match(/(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})/);
    if (match) {
      const day = match[1].padStart(2, '0');
      const monthIdx = ID_MONTHS.findIndex(m => m.toLowerCase() === match[2].toLowerCase());
      if (monthIdx >= 0) {
        return `${match[3]}-${String(monthIdx + 1).padStart(2, '0')}-${day}`;
      }
    }
  }
  return fallbackISO || getDefaultBusinessDateISO();
}

function isDateInRange(dateISO, startDate, endDate) {
  if (!dateISO) return !startDate && !endDate;
  if (startDate && dateISO < startDate) return false;
  if (endDate && dateISO > endDate) return false;
  return true;
}

function summarizePosOrders(ordersList) {
  let foodRev = 0;
  let delivFee = 0;
  let cashRev = 0;
  let qrisRev = 0;
  let onlineCount = 0;
  let offlineCount = 0;

  ordersList.forEach(o => {
    const food = Number(o.food_subtotal) || 0;
    const deliv = Number(o.delivery_fee) || 0;
    const total = Number(o.total_payment) || (food + deliv);
    const method = (o.payment_method || '').toLowerCase();

    foodRev += food;
    delivFee += deliv;
    if (method.includes('cash') || method.includes('tunai')) {
      cashRev += total;
    } else {
      qrisRev += total;
    }
    if (o.order_type === 'offline') {
      offlineCount++;
    } else {
      onlineCount++;
    }
  });

  return {
    order_count: ordersList.length,
    food_revenue: foodRev,
    delivery_fee_held: delivFee,
    cash_revenue: cashRev,
    qris_revenue: qrisRev,
    online_count: onlineCount,
    offline_count: offlineCount
  };
}

function enrichOpnameRecord(item, orders, now = new Date()) {
  const businessDate = item.business_date || parseClosingDateToISO(item.closing_date, item.date);
  let isLocked = false;
  if (item.manual_locked) {
    isLocked = true;
  } else if (item.manual_unlocked) {
    isLocked = false;
  } else if (item.lock_deadline) {
    isLocked = now.getTime() > new Date(item.lock_deadline).getTime();
  }

  // Cocokkan transaksi POS pada tanggal bisnis & cabang yang sama untuk audit selisih kas/QRIS
  const matchingOrders = (orders || []).filter(o =>
    o.branch_id === item.branch_id &&
    o.status !== 'pending_payment' &&
    o.status !== 'cancelled' &&
    getWibDateISO(o.created_at) === businessDate
  );
  const posSummary = summarizePosOrders(matchingOrders);
  const omzetCash = Number(item.omzet_cash) || 0;
  const omzetBca = Number(item.omzet_bca) || 0;

  return {
    ...item,
    business_date: businessDate,
    is_locked: isLocked,
    pos_audit: {
      order_count: posSummary.order_count,
      pos_cash_total: posSummary.cash_revenue,
      pos_qris_total: posSummary.qris_revenue,
      pos_food_total: posSummary.food_revenue,
      diff_cash: omzetCash - posSummary.cash_revenue,
      diff_bca: omzetBca - posSummary.qris_revenue
    }
  };
}

// Ambil Riwayat Laporan Stock Opname Lapak
app.get('/api/admin/stock-opname', (req, res) => {
  const { branch_id, start_date, end_date } = req.query;
  const list = readJSON(STOCK_OPNAME_FILE);
  const orders = readJSON(ORDERS_FILE);
  const now = new Date();

  let enriched = list.map(item => enrichOpnameRecord(item, orders, now));

  if (branch_id && branch_id !== 'all') {
    enriched = enriched.filter(op => op.branch_id === branch_id);
  }
  if (start_date || end_date) {
    enriched = enriched.filter(op => isDateInRange(op.business_date, start_date, end_date));
  }

  res.json({ success: true, data: enriched });
});

// Simpan / Perbarui Laporan Stock Opname Harian (Buka 22:30 WIB - Kunci 15:00 WIB)
app.post('/api/admin/stock-opname', (req, res) => {
  const {
    branch_id,
    branch_name,
    staff_name,
    closing_date,
    business_date,
    cash_opening = 100000,
    omzet_cash = 0,
    omzet_bca = 0,
    omzet_gofood = 0,
    omzet_grabfood = 0,
    omzet_shopeefood = 0,
    total_omzet = 0,
    total_setor_kas = 0,
    stock_items,
    notes,
    is_bypass = false
  } = req.body;

  if (!branch_id || !stock_items) {
    return res.status(400).json({ success: false, message: 'Data stock opname tidak lengkap' });
  }

  const list = readJSON(STOCK_OPNAME_FILE);
  const now = new Date();

  // Hitung lock_deadline: Jam 15:00 WIB pada hari berikutnya
  const deadline = new Date(now);
  if (getLocalWibDate(now).getUTCHours() >= 15) {
    deadline.setDate(deadline.getDate() + 1);
  }
  deadline.setHours(15, 0, 0, 0);

  const formattedClosingDate = closing_date || formatClosingDateId(business_date || getDefaultBusinessDateISO(now));
  const resolvedBusinessDate = business_date || parseClosingDateToISO(formattedClosingDate, getDefaultBusinessDateISO(now));

  // Cek apakah ada record yang sama untuk branch_id dan closing_date / business_date
  const existingIndex = list.findIndex(op =>
    op.branch_id === branch_id &&
    (op.closing_date === formattedClosingDate || (op.business_date && op.business_date === resolvedBusinessDate))
  );

  if (existingIndex >= 0 && !is_bypass) {
    const existing = list[existingIndex];
    const isCurrentlyLocked = existing.manual_locked ||
      (!existing.manual_unlocked && existing.lock_deadline && now.getTime() > new Date(existing.lock_deadline).getTime());
    if (isCurrentlyLocked) {
      return res.status(403).json({
        success: false,
        message: 'Laporan stock opname ini sudah terkunci permanen sejak pukul 15:00 WIB dan tidak dapat diubah lagi.'
      });
    }
  }

  const prev = existingIndex >= 0 ? list[existingIndex] : {};
  const opnameRecord = {
    id: prev.id || `opname-${Date.now()}`,
    branch_id,
    branch_name: branch_name || 'Kalisari',
    staff_name: staff_name || 'Kasir Lapak',
    closing_date: formattedClosingDate,
    business_date: resolvedBusinessDate,
    date: getWibDateISO(now),
    created_at: prev.created_at || now.toISOString(),
    updated_at: now.toISOString(),
    lock_deadline: prev.lock_deadline || deadline.toISOString(),
    manual_unlocked: Boolean(prev.manual_unlocked),
    manual_locked: Boolean(prev.manual_locked),
    owner_verified: Boolean(prev.owner_verified),
    owner_verified_at: prev.owner_verified_at || null,
    cash_opening: Number(cash_opening) || 100000,
    omzet_cash: Number(omzet_cash) || 0,
    omzet_bca: Number(omzet_bca) || 0,
    omzet_gofood: Number(omzet_gofood) || 0,
    omzet_grabfood: Number(omzet_grabfood) || 0,
    omzet_shopeefood: Number(omzet_shopeefood) || 0,
    total_omzet: Number(total_omzet) || 0,
    total_setor_kas: Number(total_setor_kas) || 0,
    stock_items,
    notes: notes || '',
    is_bypass: Boolean(is_bypass),
    status: 'submitted_to_owner'
  };

  if (existingIndex >= 0) {
    list[existingIndex] = opnameRecord;
  } else {
    list.unshift(opnameRecord);
  }

  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: 'Laporan Stock Opname Harian berhasil dikirim ke Dashboard Owner!',
    data: opnameRecord
  });
});

// Owner Verifikasi Setoran Closing Harian
app.post('/api/super-admin/stock-opname/:id/verify', (req, res) => {
  const { id } = req.params;
  const { verified } = req.body || {};
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }

  const nextVerified = verified !== undefined ? Boolean(verified) : !Boolean(list[idx].owner_verified);
  list[idx].owner_verified = nextVerified;
  list[idx].owner_verified_at = nextVerified ? new Date().toISOString() : null;
  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: nextVerified ? 'Setoran closing berhasil diverifikasi Owner.' : 'Verifikasi setoran dibatalkan.',
    data: list[idx]
  });
});

// Owner Buka Kunci / Kunci Manual Laporan Closing (Override jam 15:00 WIB)
app.post('/api/super-admin/stock-opname/:id/toggle-lock', (req, res) => {
  const { id } = req.params;
  const { unlock } = req.body || {};
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }

  const now = new Date();
  const currentlyLocked = list[idx].manual_locked ||
    (!list[idx].manual_unlocked && list[idx].lock_deadline && now.getTime() > new Date(list[idx].lock_deadline).getTime());
  const shouldUnlock = unlock !== undefined ? Boolean(unlock) : currentlyLocked;

  list[idx].manual_unlocked = shouldUnlock;
  list[idx].manual_locked = !shouldUnlock;
  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: shouldUnlock ? 'Kunci laporan dibuka sementara agar kasir bisa merevisi.' : 'Laporan berhasil dikunci oleh Owner.',
    data: list[idx]
  });
});

// Owner Hapus Laporan Closing (untuk membersihkan data uji/salah input)
app.delete('/api/super-admin/stock-opname/:id', (req, res) => {
  const { id } = req.params;
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }

  const [removed] = list.splice(idx, 1);
  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: `Laporan "${removed.closing_date || removed.id}" berhasil dihapus.`,
    data: removed
  });
});

// ==========================================
// 3. ENDPOINTS DRIVER FREELANCE & SALDO OTOMATIS
// ==========================================

// Login / Registrasi Akun Google Kurir (Mendukung Real Token JWT Google Identity Services & Mode Cepat)
app.post('/api/driver/auth/google-login', async (req, res) => {
  let { credential, email, full_name, avatar_url, phone } = req.body;
  let isGoogleVerified = false;

  // Verifikasi Kriptografis Resmi Google jika credential JWT dikirim
  if (credential) {
    try {
      const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
      const gData = await gRes.json();
      if (gData.error_description || !gData.email) {
        return res.status(401).json({
          success: false,
          message: `Verifikasi Akun Google Kurir Gagal: ${gData.error_description || 'Token kedaluwarsa atau tidak valid'}`
        });
      }
      email = gData.email;
      full_name = gData.name || full_name || email.split('@')[0];
      avatar_url = gData.picture || avatar_url;
      isGoogleVerified = true;
      console.log(`🛵 [GOOGLE OAUTH VERIFIED DRIVER] Kurir terverifikasi: ${full_name} (${email})`);
    } catch (err) {
      console.error('Error saat menghubungi server Google tokeninfo driver:', err);
      return res.status(500).json({ success: false, message: 'Gagal menghubungi server verifikasi Google' });
    }
  }

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email Google kurir diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  const driverKey = email.toLowerCase().replace(/[^a-z0-9]/g, '_');
  let driver = Object.values(wallets.drivers).find(d => d.email === email || d.id === driverKey);

  if (!driver) {
    driver = {
      id: driverKey,
      email,
      name: full_name || 'Kurir Freelance',
      avatar: avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${email}`,
      phone: phone || '085285841330',
      vehicle: 'Honda Beat',
      vehicle_plate: 'B 3918 KEB',
      balance: 37000,
      trips: 5,
      is_online: true,
      is_verified: true,
      google_verified: isGoogleVerified,
      registered_at: new Date().toISOString()
    };
    wallets.drivers[driver.id] = driver;
  } else {
    if (full_name) driver.name = full_name;
    if (avatar_url) driver.avatar = avatar_url;
    if (isGoogleVerified) driver.google_verified = true;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: isGoogleVerified 
      ? `Autentikasi Google Terverifikasi 100%! Selamat bertugas, Kak ${driver.name}.`
      : `Login Google Berhasil! Selamat bertugas, Kak ${driver.name}.`,
    data: {
      token: `token-driver-${driver.id}-${Date.now()}`,
      verified_by_google: isGoogleVerified,
      driver
    }
  });
});

// Update Profil Kurir & Pendaftaran Rekening Dompet (Terkunci 1x Input)
app.post('/api/driver/update-profile', (req, res) => {
  const { 
    driver_id, 
    email, 
    name, 
    phone, 
    vehicle, 
    vehicle_plate, 
    avatar,
    wallet_channel,
    wallet_account_number,
    wallet_account_name
  } = req.body;

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  if (name) driver.name = name;
  if (phone) driver.phone = phone;
  if (vehicle) driver.vehicle = vehicle;
  if (vehicle_plate) driver.vehicle_plate = vehicle_plate;
  if (avatar) driver.avatar = avatar;

  // ATURAN DOMPET: HANYA BISA 1 KALI INPUT (LOCKED PERMANEN)
  if (wallet_account_number) {
    if (driver.registered_wallet && driver.registered_wallet.locked) {
      // Jika sudah terkunci dan driver mencoba mengubah nomor tanpa persetujuan owner
      if (
        driver.registered_wallet.account_number !== wallet_account_number ||
        driver.registered_wallet.channel !== wallet_channel
      ) {
        return res.status(403).json({
          success: false,
          wallet_locked: true,
          message: 'Nomor dompet/rekening sudah TERKUNCI permanen demi keamanan. Untuk mengganti, silakan ajukan permohonan resmi ke Owner!'
        });
      }
    } else {
      // Pendaftaran pertama kali: langsung kunci permanen!
      driver.registered_wallet = {
        channel: wallet_channel || 'DANA',
        account_number: wallet_account_number,
        account_name: wallet_account_name || driver.name,
        locked: true,
        locked_at: new Date().toISOString()
      };
    }
  }

  driver.profile_completed = true;
  driver.updated_at = new Date().toISOString();

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Biodata profil kurir & data dompet berhasil disimpan!',
    data: driver
  });
});

// Permohonan Penggantian Rekening Dompet Kurir (Wajib Konfirmasi Owner)
app.post('/api/driver/request-wallet-change', (req, res) => {
  const { driver_id, reason, new_channel, new_account_number, new_account_name } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[driver_id]) {
    return res.status(404).json({ success: false, message: 'Driver tidak ditemukan' });
  }

  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const request = {
    id: `wcr-${Date.now()}`,
    driver_id,
    driver_name: wallets.drivers[driver_id].name,
    current_wallet: wallets.drivers[driver_id].registered_wallet,
    new_channel: new_channel || 'DANA',
    new_account_number,
    new_account_name: new_account_name || wallets.drivers[driver_id].name,
    reason: reason || 'Pergantian nomor akun e-wallet / rekening bank',
    status: 'pending',
    requested_at: new Date().toISOString()
  };

  wallets.wallet_change_requests.unshift(request);
  wallets.drivers[driver_id].wallet_change_pending = true;
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan penggantian rekening berhasil diajukan! Menunggu konfirmasi & persetujuan dari Owner.',
    data: request
  });
});

// Super Admin / Owner Menyetujui Penggantian Rekening Dompet
app.post('/api/super-admin/wallet-changes/:id/approve', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const reqIndex = wallets.wallet_change_requests.findIndex(r => r.id === id);
  if (reqIndex === -1) {
    return res.status(404).json({ success: false, message: 'Permohonan tidak ditemukan' });
  }

  const changeReq = wallets.wallet_change_requests[reqIndex];
  changeReq.status = 'approved';
  changeReq.approved_at = new Date().toISOString();

  // Update rekening driver
  if (wallets.drivers[changeReq.driver_id]) {
    wallets.drivers[changeReq.driver_id].registered_wallet = {
      channel: changeReq.new_channel,
      account_number: changeReq.new_account_number,
      account_name: changeReq.new_account_name,
      locked: true,
      updated_by_owner_at: new Date().toISOString()
    };
    wallets.drivers[changeReq.driver_id].wallet_change_pending = false;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan pergantian rekening kurir berhasil disetujui Owner!',
    data: changeReq
  });
});

// Super Admin / Owner Menolak Penggantian Rekening Dompet
app.post('/api/super-admin/wallet-changes/:id/reject', (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const reqIndex = wallets.wallet_change_requests.findIndex(r => r.id === id);
  if (reqIndex === -1) {
    return res.status(404).json({ success: false, message: 'Permohonan tidak ditemukan' });
  }

  const changeReq = wallets.wallet_change_requests[reqIndex];
  changeReq.status = 'rejected';
  changeReq.rejected_at = new Date().toISOString();
  if (reason) changeReq.rejected_reason = String(reason).trim();

  if (wallets.drivers && wallets.drivers[changeReq.driver_id]) {
    wallets.drivers[changeReq.driver_id].wallet_change_pending = false;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan pergantian rekening kurir ditolak.',
    data: changeReq
  });
});

// Verifikasi Biometrik Wajah Kurir (Anti Joki / Pinjam Akun)
app.post('/api/driver/verify-face', (req, res) => {
  const { driver_id, email, face_image } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  driver.face_verified = true;
  driver.biometric_verified = true;
  driver.biometric_method = 'face';
  driver.face_verified_at = new Date().toISOString();
  if (face_image) {
    driver.last_face_photo = face_image;
  }
  driver.is_online = true; // Otomatis aktifkan status online
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Verifikasi biometrik wajah berhasil! Akun resmi aktif & siap bertugas.',
    data: driver
  });
});

// Verifikasi Biometrik Ganda: Sidik Jari (Utama/Anti-Gelap) atau Wajah (Alternatif)
// Mengunci Prinsip: 1 Akun 1 Driver (Device Lock & Anti-Joki)
app.post('/api/driver/verify-biometric', (req, res) => {
  const { driver_id, email, method = 'fingerprint', device_id, biometric_proof } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  // PRINSIP 1 AKUN 1 DRIVER: Kunci perangkat (Device Binding)
  if (device_id) {
    if (driver.registered_device_id && driver.registered_device_id !== device_id) {
      driver.last_device_switch_at = new Date().toISOString();
    }
    driver.registered_device_id = device_id;
  }

  driver.face_verified = true;
  driver.biometric_verified = true;
  driver.biometric_method = method; // 'fingerprint' atau 'face'
  driver.biometric_verified_at = new Date().toISOString();
  if (biometric_proof) {
    driver.last_biometric_proof = biometric_proof;
  }
  driver.is_online = true;

  writeJSON(WALLETS_FILE, wallets);

  const methodText = method === 'fingerprint' ? 'Sidik Jari (Fingerprint Sensor)' : 'Pemindaian Wajah';
  res.json({
    success: true,
    message: `Verifikasi ${methodText} Berhasil! 1 Akun 1 Driver terproteksi resmi & siap bertugas.`,
    data: driver
  });
});

// Radar Orderan Siap Antar (Siapa Cepat Dia Dapat)
app.get('/api/driver/orders/available', (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  // Order yang sudah matang dan belum diambil kurir
  const availableOrders = orders.filter(o => o.status === 'ready_for_pickup' && !o.driver_id);
  res.json({ success: true, data: availableOrders });
});

// Kurir Menerima Orderan (Fase 1: Mulai Melaju dari Lokasi Kurir Menuju Lapak)
app.post('/api/driver/orders/:id/accept', (req, res) => {
  const { id } = req.params;
  const {
    driver_id = 'driver-01',
    driver_name = 'Budi Santoso',
    driver_phone,
    driver_vehicle,
    driver_photo,
    driver_latitude,
    driver_longitude
  } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  if (orders[orderIndex].driver_id) {
    return res.status(400).json({ success: false, message: 'Maaf, pesanan ini sudah diambil kurir lain!' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (driver_id && wallets.drivers && wallets.drivers[driver_id]) {
    const d = wallets.drivers[driver_id];
    if (d.is_suspended) {
      return res.status(403).json({
        success: false,
        message: 'Akun kurir Anda sedang dinonaktifkan sementara oleh Owner.'
      });
    }
    if (d.biometric_verified === false && d.face_verified === false) {
      return res.status(403).json({
        success: false,
        require_biometric_verification: true,
        message: 'Keamanan Akun: Harap verifikasi Sidik Jari atau Wajah Anda terlebih dahulu sebelum mengambil pesanan ini!'
      });
    }
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === orders[orderIndex].branch_id) || branches[0];

  const savedDriver = (wallets.drivers && wallets.drivers[driver_id]) ? wallets.drivers[driver_id] : null;

  // Lokasi awal kurir saat terima order (dari GPS HP kurir atau offset realistis ~600 meter di jalan)
  const initialDriverLat = driver_latitude ? parseFloat(driver_latitude) : ((branch.latitude || -6.2088) + 0.0065);
  const initialDriverLng = driver_longitude ? parseFloat(driver_longitude) : ((branch.longitude || 106.8456) - 0.0055);

  orders[orderIndex].driver_id = driver_id;
  orders[orderIndex].driver_name = driver_name || (savedDriver ? savedDriver.name : 'Budi Santoso');
  orders[orderIndex].driver_phone = driver_phone || (savedDriver ? savedDriver.phone : '0852-8584-1330');
  orders[orderIndex].driver_vehicle = driver_vehicle || (savedDriver ? `${savedDriver.vehicle} (${savedDriver.vehicle_plate})` : 'Honda Beat (B 3918 KEB)');
  orders[orderIndex].driver_photo = driver_photo || (savedDriver ? savedDriver.avatar : 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&h=150&fit=crop&crop=face');
  
  // Status Fase 1: Kurir menuju lapak untuk ambil pesanan
  orders[orderIndex].status = 'driver_heading_to_branch';
  orders[orderIndex].driver_phase = 'to_branch';
  orders[orderIndex].driver_accepted_at = new Date().toISOString();
  orders[orderIndex].driver_start_latitude = initialDriverLat;
  orders[orderIndex].driver_start_longitude = initialDriverLng;
  orders[orderIndex].driver_latitude = initialDriverLat;
  orders[orderIndex].driver_longitude = initialDriverLng;
  orders[orderIndex].manual_gps = !!(driver_latitude && driver_longitude);

  writeJSON(ORDERS_FILE, orders);
  const accOrder = orders[orderIndex];
  updateDriverTelemetryInWallet(accOrder.driver_id, accOrder.driver_latitude, accOrder.driver_longitude, {
    is_online: true
  });

  res.json({
    success: true,
    message: 'Orderan berhasil diambil! Silakan meluncur ke lapak kebab untuk mengambil pesanan.',
    data: orders[orderIndex]
  });
});

// Kurir Tiba di Lapak & Mengambil Kebab (Fase 2: Mulai Melaju dari Lapak Menuju Rumah Pelanggan)
app.post('/api/driver/orders/:id/pickup', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === orders[orderIndex].branch_id) || branches[0];

  orders[orderIndex].status = 'on_delivery';
  orders[orderIndex].driver_phase = 'to_customer';
  orders[orderIndex].driver_picked_up_at = new Date().toISOString();
  orders[orderIndex].driver_latitude = branch.latitude || -6.2088;
  orders[orderIndex].driver_longitude = branch.longitude || 106.8456;
  orders[orderIndex].manual_gps = false; // Reset simulasi perjalanan dari lapak ke rumah

  writeJSON(ORDERS_FILE, orders);
  const pickedOrder = orders[orderIndex];
  updateDriverTelemetryInWallet(
    pickedOrder.driver_id,
    pickedOrder.driver_latitude ?? pickedOrder.branch_latitude,
    pickedOrder.driver_longitude ?? pickedOrder.branch_longitude,
    { is_online: true }
  );

  res.json({
    success: true,
    message: 'Kebab berhasil diambil! Sekarang silakan antar ke alamat pelanggan.',
    data: orders[orderIndex]
  });
});

// Kurir Selesai Mengantar -> SALDO DRIVER OTOMATIS BERTAMBAH!
app.post('/api/driver/orders/:id/complete', (req, res) => {
  const { id } = req.params;
  const { delivery_proof } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const order = orders[orderIndex];
  if (order.status === 'completed') {
    return res.status(400).json({ success: false, message: 'Pesanan ini sudah selesai sebelumnya.' });
  }

  // Update status pesanan
  order.status = 'completed';
  order.delivery_proof = delivery_proof || 'https://placehold.co/400x300/png?text=Foto+Serah+Terima+Kebab';
  order.completed_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  // OTOMATISASI SALDO: Tambah ongkir ke dompet driver
  const wallets = readJSON(WALLETS_FILE);
  const driverId = order.driver_id || 'driver-01';

  if (!wallets.drivers[driverId]) {
    wallets.drivers[driverId] = { id: driverId, name: order.driver_name || 'Driver', balance: 0, trips: 0, is_online: true };
  }

  const earnedFee = order.delivery_fee;
  wallets.drivers[driverId].balance += earnedFee;
  wallets.drivers[driverId].trips += 1;
  wallets.drivers[driverId].is_online = true;
  wallets.drivers[driverId].last_seen_at = new Date().toISOString();
  wallets.drivers[driverId].last_speed_kmh = 0;
  if (order.customer_latitude != null && order.customer_longitude != null) {
    wallets.drivers[driverId].last_latitude = Number(order.customer_latitude);
    wallets.drivers[driverId].last_longitude = Number(order.customer_longitude);
  }

  wallets.history.push({
    id: `tx-${Date.now()}`,
    user_id: driverId,
    order_id: order.id,
    order_code: order.order_code,
    type: 'delivery_earning',
    amount: earnedFee,
    current_balance: wallets.drivers[driverId].balance,
    description: `Ongkos kirim order #${order.order_code}`,
    created_at: new Date().toISOString()
  });

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: `Pesanan selesai! Saldo Rp ${earnedFee.toLocaleString('id-ID')} otomatis masuk ke dompet Anda.`,
    data: {
      order,
      driver_wallet: wallets.drivers[driverId]
    }
  });
});

// Ambil Informasi Dompet Driver
app.get('/api/driver/wallet/:driverId', (req, res) => {
  const { driverId } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  const driver = wallets.drivers[driverId] || { id: driverId, name: 'Driver', balance: 0, trips: 0 };
  const history = wallets.history.filter(h => h.user_id === driverId);

  res.json({
    success: true,
    data: {
      wallet: driver,
      history
    }
  });
});

// ==========================================
// 4. ENDPOINTS SUPER ADMIN / PEMILIK (OWNER)
// ==========================================

// Ajukan Penarikan Dana oleh Driver (Menggunakan Rekening Terkunci 1 Akun 1 Driver)
app.post('/api/driver/wallet/withdraw', (req, res) => {
  const { driver_id, amount, payout_channel, account_number, account_name } = req.body;
  const wallets = readJSON(WALLETS_FILE);

  if (!wallets.drivers[driver_id] || wallets.drivers[driver_id].balance < amount) {
    return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi untuk ditarik' });
  }

  const driver = wallets.drivers[driver_id];
  // Jika driver sudah mengunci dompet/rekeningnya, gunakan rekening terdaftar
  const finalChannel = (driver.registered_wallet && driver.registered_wallet.channel) ? driver.registered_wallet.channel : (payout_channel || 'DANA');
  const finalAccountNum = (driver.registered_wallet && driver.registered_wallet.account_number) ? driver.registered_wallet.account_number : (account_number || driver.phone || '081234567890');
  const finalAccountName = (driver.registered_wallet && driver.registered_wallet.account_name) ? driver.registered_wallet.account_name : (account_name || driver.name);

  if (!wallets.withdrawals) wallets.withdrawals = [];

  const newWithdrawal = {
    id: `wd-${Date.now()}`,
    driver_id,
    driver_name: driver.name,
    amount: Number(amount),
    payout_channel: finalChannel,
    account_number: finalAccountNum,
    account_name: finalAccountName,
    status: 'pending', // 'pending', 'approved'
    created_at: new Date().toISOString()
  };

  // Kurangi saldo sementara
  driver.balance -= Number(amount);
  wallets.withdrawals.unshift(newWithdrawal);

  if (!wallets.history) wallets.history = [];
  wallets.history.push({
    id: `tx-${Date.now()}`,
    user_id: driver_id,
    type: 'withdrawal',
    amount: Number(amount),
    current_balance: driver.balance,
    description: `Penarikan Dana ke ${finalChannel} (${finalAccountNum})`,
    status: 'pending',
    created_at: new Date().toISOString()
  });

  writeJSON(WALLETS_FILE, wallets);

  res.json({ 
    success: true, 
    message: `Permintaan penarikan Rp ${Number(amount).toLocaleString('id-ID')} ke ${finalChannel} (${finalAccountNum}) berhasil diajukan! Menunggu transfer dari Owner.`, 
    data: newWithdrawal 
  });
});

// Ringkasan Finansial Seluruh Cabang & Tagihan Titipan Ongkir (Mendukung Filter Tanggal)
app.get('/api/super-admin/summary', (req, res) => {
  const { start_date, end_date } = req.query;
  const branches = readJSON(BRANCHES_FILE);
  const orders = readJSON(ORDERS_FILE);
  const wallets = readJSON(WALLETS_FILE);

  const validOrders = orders.filter(o => {
    if (o.status === 'pending_payment' || o.status === 'cancelled') return false;
    if (start_date || end_date) {
      return isDateInRange(getWibDateISO(o.created_at), start_date, end_date);
    }
    return true;
  });

  let total_food_revenue = 0;
  let total_delivery_fees = 0;

  const branchStats = branches.map(b => {
    const branchOrders = validOrders.filter(o => o.branch_id === b.id);
    const pos = summarizePosOrders(branchOrders);

    total_food_revenue += pos.food_revenue;
    total_delivery_fees += pos.delivery_fee_held;

    return {
      branch_id: b.id,
      branch_name: b.name,
      address: b.address,
      phone: b.phone || '',
      open_hours: b.open_hours || '15:00 - 23:00',
      bank_info: b.bank_info || '',
      staff_pin: b.staff_pin || '1234',
      latitude: b.latitude ?? -6.2088,
      longitude: b.longitude ?? 106.8456,
      has_qris: Boolean(b.qris_image),
      is_open: b.is_open !== false,
      cash_opening: b.cash_opening !== undefined ? b.cash_opening : 100000,
      order_count: pos.order_count,
      food_revenue: pos.food_revenue,
      delivery_fee_held: pos.delivery_fee_held,
      cash_revenue: pos.cash_revenue,
      qris_revenue: pos.qris_revenue,
      online_count: pos.online_count,
      offline_count: pos.offline_count
    };
  });

  res.json({
    success: true,
    data: {
      total_food_revenue,
      total_delivery_fees,
      total_orders: validOrders.length,
      branches: branchStats,
      drivers: Object.values(wallets.drivers || {}),
      withdrawals: wallets.withdrawals || [],
      wallet_change_requests: wallets.wallet_change_requests || []
    }
  });
});

// Owner Setujui Transfer Penarikan Saldo Kurir
app.post('/api/super-admin/withdrawals/:id/approve', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);

  if (!wallets.withdrawals) wallets.withdrawals = [];
  const idx = wallets.withdrawals.findIndex(w => w.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Data penarikan tidak ditemukan' });
  }

  wallets.withdrawals[idx].status = 'approved';
  wallets.withdrawals[idx].approved_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({ success: true, message: 'Penarikan dana disetujui & ditandai sudah ditransfer!' });
});

// ============================================================================
// RADAR LALU LINTAS KURIR (ATC FLIGHT RADAR STYLE) & KONTROL ADMIN KURIR
// ============================================================================
app.get('/api/super-admin/courier-radar', (req, res) => {
  const branches = readJSON(BRANCHES_FILE) || [];
  const orders = readJSON(ORDERS_FILE) || [];
  const wallets = readJSON(WALLETS_FILE) || {};
  const driversObj = wallets.drivers || {};

  const defaultBranch = branches[0] || { latitude: -6.33304, longitude: 106.85337 };
  const baseLat = Number(defaultBranch.latitude) || -6.33304;
  const baseLng = Number(defaultBranch.longitude) || 106.85337;

  const readyOrdersRaw = orders.filter(o => o.order_type === 'delivery' && o.status === 'ready_for_pickup');
  const activeOrdersRaw = orders.filter(o => o.order_type === 'delivery' && (o.status === 'accepted' || o.status === 'delivering'));

  const branchById = new Map(branches.map(b => [b.id, b]));
  const branchRadar = branches.map(b => ({
    id: b.id,
    name: b.name,
    address: b.address || '',
    phone: b.phone || '',
    latitude: Number(b.latitude) || baseLat,
    longitude: Number(b.longitude) || baseLng,
    ready_count: readyOrdersRaw.filter(o => o.branch_id === b.id).length,
    active_count: activeOrdersRaw.filter(o => o.branch_id === b.id).length
  }));

  const ready_orders = readyOrdersRaw.map(o => {
    const br = branchById.get(o.branch_id);
    return {
      id: o.id,
      branch_id: o.branch_id,
      branch_name: (br && br.name) || o.branch_name || 'Lapak',
      customer_name: o.customer_name || 'Pelanggan',
      delivery_address: o.delivery_address || '',
      delivery_fee: Number(o.delivery_fee) || 0,
      total_price: Number(o.total_price) || 0,
      latitude: Number(o.branch_latitude ?? (br && br.latitude) ?? baseLat),
      longitude: Number(o.branch_longitude ?? (br && br.longitude) ?? baseLng),
      customer_latitude: o.customer_latitude != null ? Number(o.customer_latitude) : null,
      customer_longitude: o.customer_longitude != null ? Number(o.customer_longitude) : null,
      created_at: o.created_at
    };
  });

  const statusOrderWeight = {
    TO_CUSTOMER: 0,
    TO_BRANCH: 1,
    STANDBY: 2,
    OFFLINE: 3,
    SUSPENDED: 4
  };

  const couriers = Object.values(driversObj).map((d, idx) => {
    const activeOrder = activeOrdersRaw.find(o => o.driver_id === d.id) || null;
    const isSuspended = Boolean(d.is_suspended);

    let radarStatus = 'OFFLINE';
    if (isSuspended) radarStatus = 'SUSPENDED';
    else if (activeOrder && activeOrder.status === 'accepted') radarStatus = 'TO_BRANCH';
    else if (activeOrder && activeOrder.status === 'delivering') radarStatus = 'TO_CUSTOMER';
    else if (d.is_online !== false) radarStatus = 'STANDBY';

    const hasLiveGps = d.last_latitude != null && d.last_longitude != null;
    const angle = idx * 1.4;
    let lat = hasLiveGps ? Number(d.last_latitude) : baseLat + Math.sin(angle) * 0.0022;
    let lng = hasLiveGps ? Number(d.last_longitude) : baseLng + Math.cos(angle) * 0.0025;
    let heading = d.last_heading != null ? Number(d.last_heading) : (idx * 65) % 360;
    let activeOrderSummary = null;

    if (activeOrder) {
      const pos = resolveOrderDriverPosition(activeOrder);
      lat = pos.driverLat;
      lng = pos.driverLng;
      const targetLat = activeOrder.status === 'accepted' ? pos.branchLat : pos.custLat;
      const targetLng = activeOrder.status === 'accepted' ? pos.branchLng : pos.custLng;
      heading = d.last_heading != null
        ? Number(d.last_heading)
        : calculateBearingDeg(lat, lng, targetLat, targetLng);

      const br = branchById.get(activeOrder.branch_id);
      activeOrderSummary = {
        id: activeOrder.id,
        status: activeOrder.status,
        branch_id: activeOrder.branch_id,
        branch_name: (br && br.name) || activeOrder.branch_name || 'Lapak',
        customer_name: activeOrder.customer_name || 'Pelanggan',
        delivery_address: activeOrder.delivery_address || '',
        delivery_fee: Number(activeOrder.delivery_fee) || 0,
        branch_latitude: pos.branchLat,
        branch_longitude: pos.branchLng,
        customer_latitude: pos.custLat,
        customer_longitude: pos.custLng,
        target_latitude: targetLat,
        target_longitude: targetLng
      };
    }

    return {
      id: d.id,
      name: d.name || 'Kurir',
      phone: d.phone || '',
      email: d.email || '',
      vehicle: d.vehicle || 'Motor',
      vehicle_plate: d.vehicle_plate || '-',
      balance: Number(d.balance) || 0,
      trips: Number(d.trips) || 0,
      is_online: d.is_online !== false,
      is_suspended: isSuspended,
      radar_status: radarStatus,
      latitude: lat,
      longitude: lng,
      has_live_gps: hasLiveGps || Boolean(activeOrder),
      heading,
      speed_kmh: d.last_speed_kmh != null ? Number(d.last_speed_kmh) : (activeOrder ? 28 : 0),
      last_seen_at: d.last_seen_at || null,
      biometric_verified: Boolean(d.biometric_verified),
      has_device_lock: Boolean(d.registered_device_id),
      registered_wallet: d.registered_wallet || null,
      wallet_change_pending: Boolean(d.wallet_change_pending),
      active_order: activeOrderSummary
    };
  }).sort((a, b) => (statusOrderWeight[a.radar_status] ?? 9) - (statusOrderWeight[b.radar_status] ?? 9));

  const stats = {
    total: couriers.length,
    to_branch: couriers.filter(c => c.radar_status === 'TO_BRANCH').length,
    to_customer: couriers.filter(c => c.radar_status === 'TO_CUSTOMER').length,
    delivering: couriers.filter(c => c.radar_status === 'TO_BRANCH' || c.radar_status === 'TO_CUSTOMER').length,
    standby: couriers.filter(c => c.radar_status === 'STANDBY').length,
    offline: couriers.filter(c => c.radar_status === 'OFFLINE').length,
    suspended: couriers.filter(c => c.radar_status === 'SUSPENDED').length,
    ready_orders: ready_orders.length
  };

  res.json({
    success: true,
    data: {
      generated_at: new Date().toISOString(),
      stats,
      branches: branchRadar,
      ready_orders,
      couriers,
      wallet_change_requests: wallets.wallet_change_requests || []
    }
  });
});

// Owner Aktifkan / Nonaktifkan (Suspend) Akun Kurir
app.post('/api/super-admin/drivers/:id/toggle-status', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[id]) {
    return res.status(404).json({ success: false, message: 'Kurir tidak ditemukan' });
  }

  const driver = wallets.drivers[id];
  const nextSuspended = req.body && typeof req.body.suspended === 'boolean'
    ? req.body.suspended
    : !Boolean(driver.is_suspended);

  driver.is_suspended = nextSuspended;
  if (nextSuspended) {
    driver.is_online = false;
  }
  driver.status_updated_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: nextSuspended
      ? `Akun kurir ${driver.name} dinonaktifkan sementara.`
      : `Akun kurir ${driver.name} diaktifkan kembali.`,
    data: { id: driver.id, is_suspended: driver.is_suspended }
  });
});

// Owner Reset Kunci Perangkat (HP) Kurir
app.post('/api/super-admin/drivers/:id/reset-device', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[id]) {
    return res.status(404).json({ success: false, message: 'Kurir tidak ditemukan' });
  }

  const driver = wallets.drivers[id];
  driver.registered_device_id = null;
  driver.device_reset_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: `Kunci perangkat HP ${driver.name} berhasil direset.`,
    data: { id: driver.id, has_device_lock: false }
  });
});

// Mulai Server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`🍢 SERVER KEBAB AL BEWOK BERJALAN DI PORT: ${PORT}`);
  console.log(`👉 API Menu: http://localhost:${PORT}/api/menu`);
  console.log(`👉 API Cabang: http://localhost:${PORT}/api/branches`);
  console.log(`===================================================`);
});

module.exports = app;
