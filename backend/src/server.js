const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

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
const WALLETS_FILE = path.join(DATA_DIR, 'wallets.json');

// Helper untuk membaca file JSON
function readJSON(filePath, defaultData = []) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
      return defaultData;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Gagal membaca ${filePath}:`, err);
    return defaultData;
  }
}

// Helper untuk menulis file JSON
function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`Gagal menulis ${filePath}:`, err);
  }
}

// Memory store untuk OTP (Kadaluwarsa dalam 5 menit)
const otpStore = new Map();

// Inisialisasi file data jika belum ada
if (!fs.existsSync(ORDERS_FILE)) writeJSON(ORDERS_FILE, []);
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

// Login / Registrasi Akun Google (100% Gratis Selamanya)
app.post('/api/auth/google-login', (req, res) => {
  const { email, full_name, avatar_url, google_id } = req.body;

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
      delivery_address: '',
      latitude: null,
      longitude: null,
      auth_provider: 'google',
      registered_at: new Date().toISOString()
    };
  } else {
    // Update data Google terbaru
    if (full_name) wallets.customers[email].name = full_name;
    if (avatar_url) wallets.customers[email].avatar = avatar_url;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: `Login Google Berhasil! Selamat datang, ${wallets.customers[email].name}.`,
    data: {
      token: `token-google-${email}-${Date.now()}`,
      user: wallets.customers[email]
    }
  });
});

// Update Profil Pelanggan (Nomor WhatsApp & Alamat Pengiriman)
app.post('/api/customer/update-profile', (req, res) => {
  const { email, whatsapp, delivery_address, latitude, longitude, full_name } = req.body;

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
  if (delivery_address) cust.delivery_address = delivery_address.trim();
  if (latitude) cust.latitude = latitude;
  if (longitude) cust.longitude = longitude;
  cust.updated_at = new Date().toISOString();

  writeJSON(WALLETS_FILE, wallets);

  console.log(`👤 [PROFIL DIPERBARUI] ${cust.name} | WA: ${cust.whatsapp} | Alamat: ${cust.delivery_address}`);

  res.json({
    success: true,
    message: 'Profil & alamat pengiriman berhasil disimpan!',
    data: cust
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

// Checkout Pesanan Baru
app.post('/api/orders/checkout', (req, res) => {
  const {
    customer_name,
    customer_phone,
    customer_address,
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
    customer_name: customer_name || 'Pelanggan Kebab',
    customer_phone: customer_phone || '081234567890',
    customer_address: customer_address || 'Jl. Mawar No. 10',
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

// Lacak Status Pesanan
app.get('/api/orders/:id', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const order = orders.find(o => o.id === id || o.order_code === id);

  if (!order) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  res.json({ success: true, data: order });
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

// ==========================================
// 3. ENDPOINTS DRIVER FREELANCE & SALDO OTOMATIS
// ==========================================

// Radar Orderan Siap Antar (Siapa Cepat Dia Dapat)
app.get('/api/driver/orders/available', (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  // Order yang sudah matang dan belum diambil kurir
  const availableOrders = orders.filter(o => o.status === 'ready_for_pickup' && !o.driver_id);
  res.json({ success: true, data: availableOrders });
});

// Kurir Menerima Orderan
app.post('/api/driver/orders/:id/accept', (req, res) => {
  const { id } = req.params;
  const { driver_id = 'driver-01', driver_name = 'Budi Santoso' } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  if (orders[orderIndex].driver_id) {
    return res.status(400).json({ success: false, message: 'Maaf, pesanan ini sudah diambil kurir lain!' });
  }

  orders[orderIndex].driver_id = driver_id;
  orders[orderIndex].driver_name = driver_name;
  orders[orderIndex].status = 'on_delivery';
  orders[orderIndex].driver_accepted_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Berhasil mengambil orderan! Selamat mengantar.', data: orders[orderIndex] });
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

// Ajukan Penarikan Dana oleh Driver
app.post('/api/driver/wallet/withdraw', (req, res) => {
  const { driver_id, amount, payout_channel, account_number, account_name } = req.body;
  const wallets = readJSON(WALLETS_FILE);

  if (!wallets.drivers[driver_id] || wallets.drivers[driver_id].balance < amount) {
    return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi untuk ditarik' });
  }

  if (!wallets.withdrawals) wallets.withdrawals = [];

  const newWithdrawal = {
    id: `wd-${Date.now()}`,
    driver_id,
    driver_name: wallets.drivers[driver_id].name,
    amount: Number(amount),
    payout_channel: payout_channel || 'DANA',
    account_number: account_number || '081234567890',
    account_name: account_name || wallets.drivers[driver_id].name,
    status: 'pending', // 'pending', 'approved'
    created_at: new Date().toISOString()
  };

  // Kurangi saldo sementara
  wallets.drivers[driver_id].balance -= Number(amount);
  wallets.withdrawals.unshift(newWithdrawal);
  writeJSON(WALLETS_FILE, wallets);

  res.json({ success: true, message: 'Permintaan penarikan dana berhasil diajukan! Menunggu transfer dari Owner.', data: newWithdrawal });
});

// Ringkasan Finansial Seluruh Cabang & Tagihan Titipan Ongkir
app.get('/api/super-admin/summary', (req, res) => {
  const branches = readJSON(BRANCHES_FILE);
  const orders = readJSON(ORDERS_FILE);
  const wallets = readJSON(WALLETS_FILE);

  let total_food_revenue = 0;
  let total_delivery_fees = 0;

  const branchStats = branches.map(b => {
    const branchOrders = orders.filter(o => o.branch_id === b.id && o.status !== 'pending_payment' && o.status !== 'cancelled');
    const foodRev = branchOrders.reduce((sum, o) => sum + (o.food_subtotal || 0), 0);
    const delivFee = branchOrders.reduce((sum, o) => sum + (o.delivery_fee || 0), 0);

    total_food_revenue += foodRev;
    total_delivery_fees += delivFee;

    return {
      branch_id: b.id,
      branch_name: b.name,
      address: b.address,
      order_count: branchOrders.length,
      food_revenue: foodRev,
      delivery_fee_held: delivFee // Ini uang ongkir kurir yang harus disetorkan cabang ke Pusat!
    };
  });

  res.json({
    success: true,
    data: {
      total_food_revenue,
      total_delivery_fees,
      total_orders: orders.length,
      branches: branchStats,
      drivers: Object.values(wallets.drivers || {}),
      withdrawals: wallets.withdrawals || []
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

// Mulai Server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`🍢 SERVER KEBAB AL BEWOK BERJALAN DI PORT: ${PORT}`);
  console.log(`👉 API Menu: http://localhost:${PORT}/api/menu`);
  console.log(`👉 API Cabang: http://localhost:${PORT}/api/branches`);
  console.log(`===================================================`);
});
