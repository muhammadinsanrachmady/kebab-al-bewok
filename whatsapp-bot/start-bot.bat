@echo off
title Bot WhatsApp Gratis - Kebab AL Bewok
color 0A
cls
echo ========================================================
echo   BOT WHATSAPP GRATIS - KEBAB AL BEWOK
echo   Auto-Reply Menu, Cek Status Order, dan Gateway OTP
echo ========================================================
echo.
cd /d "%~dp0"

echo [1/2] Memeriksa dependensi Node.js...
if not exist node_modules (
  echo Menginstall paket yang dibutuhkan...
  call npm install
)

echo.
echo [2/2] Menjalankan Bot WhatsApp...
echo Buka browser di http://localhost:5001 untuk melihat QR Code & Dashboard!
echo.
npm start

pause
