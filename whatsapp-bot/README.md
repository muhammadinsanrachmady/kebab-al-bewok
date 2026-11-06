# 🌯 Bot WhatsApp Gratis 100% - Kebab AL Bewok

Bot WhatsApp ini dibangun menggunakan engine **Baileys (WhatsApp Multi-Device)**, sehingga:
- ✅ **100% GRATIS seumur hidup** (Tidak perlu langganan API berbayar seperti Fonnte, Wablas, Twilio, dll).
- ✅ **Bebas Biaya Meta Cloud API** (Tidak butuh kartu kredit, verifikasi Facebook Business Manager, dsb).
- ✅ **Login Praktis**: Cukup Scan QR Code atau pakai 8 Digit **Pairing Code**.
- ✅ **Sesi Tersimpan**: Setelah login pertama kali, sesi disimpan di folder `session_auth/`, tidak perlu scan ulang setiap kali bot di-restart.

---

## 🌟 Fitur Utama

1. **Auto-Reply Customer (24/7 Siaga):**
   - `!menu` : Menampilkan seluruh kategori menu (Original, Cheesy, Monster, Minuman) dan harga resmi dari database backend.
   - `!cabang` : Menampilkan alamat cabang lengkap, jam operasional, dan info rekening/QRIS.
   - `!order` : Format instan untuk memesan kebab lewat WhatsApp.
   - `!status [KODE]` : Pengecekan status proses pesanan secara real-time (contoh: `!status KB-173000`).
   - `!admin` : Nomor kontak kasir / customer service.
   - `!ping` : Tes responsivitas dan uptime bot.
   - Auto-greeting ramah saat disapa `halo`, `hai`, `assalamualaikum`, `p`, dll.

2. **Pengirim OTP & Notifikasi Otomatis (REST API Port 5001):**
   - Saat pembeli mendaftar atau login di web/aplikasi Kebab AL Bewok, backend (`server.js`) otomatis memanggil bot ini untuk mengirimkan kode OTP asli 4-digit ke WhatsApp nomor pembeli secara GRATIS!

3. **Web Dashboard Interaktif (`http://localhost:5001`):**
   - Tampilan visual QR Code besar dan jelas di browser.
   - Fitur Pairing Code (jika kamera ponsel buram).
   - Indikator status koneksi real-time (🟢 Online / 🟡 Menunggu Scan / 🔴 Terputus).
   - Form uji coba kirim pesan & kirim contoh OTP langsung dari web.
   - Live Activity Log terminal.

---

## 🚀 Cara Menjalankan Bot

### Opsi A: Cara Cepat (Windows)
Cukup klik dua kali file **`start-bot.bat`** di dalam folder `whatsapp-bot`.

### Opsi B: Lewat Terminal / Command Prompt
```bash
cd whatsapp-bot
npm install
npm start
```

Setelah dijalankan:
1. Terminal akan menampilkan **QR Code**, ATAU
2. Buka browser ke alamat: **`http://localhost:5001`**
3. Buka WhatsApp di HP Anda > ketuk menu **Titik Tiga (Android)** atau **Pengaturan (iPhone)** > pilih **Perangkat Tertaut (Linked Devices)** > pilih **Tautkan Perangkat** > Scan QR Code di layar.
4. Selesai! Bot langsung aktif dan siap membalas pesan secara otomatis.

---

## 📡 Dokumentasi Endpoint REST API (Port 5001)

| Method | Endpoint | Fungsi | Contoh Payload Body |
|--------|----------|--------|---------------------|
| `GET` | `/api/status` | Cek status koneksi bot & QR base64 | - |
| `POST` | `/api/send-message` | Kirim pesan WhatsApp bebas ke nomor manapun | `{"phone": "081234567890", "message": "Halo!"}` |
| `POST` | `/api/send-otp` | Kirim kode OTP verifikasi dengan template resmi | `{"phone": "081234567890", "otp": "4921", "name": "Budi"}` |
| `POST` | `/api/pairing-code` | Dapatkan 8 digit pairing code tanpa scan kamera | `{"phone": "081234567890"}` |

---

## ☁️ Tips Menjalankan 24 Jam Non-Stop Gratis
Jika ingin bot terus aktif tanpa harus menyalakan laptop:
1. **Termux di HP Android Bekas**: Install Node.js di Termux dan jalankan bot ini langsung dari ponsel cadangan yang terhubung WiFi.
2. **VPS Gratis**: Gunakan free tier Google Cloud (Compute Engine f1-micro gratis), Oracle Cloud Free Tier, atau Railway.
