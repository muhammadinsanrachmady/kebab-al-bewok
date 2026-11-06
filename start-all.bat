@echo off
title Ekosistem Kebab AL Bewok + WhatsApp Bot
color 0E
cls
echo ========================================================
echo   EKOSISTEM KEBAB AL BEWOK - SERVER + WHATSAPP BOT
echo ========================================================
echo.
echo [1/2] Menjalankan Backend Kebab AL Bewok (Port 5000)...
start "Backend Server (Port 5000)" cmd /k "cd backend && npm start"

timeout /t 2 >nul

echo [2/2] Menjalankan Bot WhatsApp Gratis (Port 5001)...
start "WhatsApp Bot (Port 5001)" cmd /k "cd whatsapp-bot && npm start"

echo.
echo ========================================================
echo   SEMUA SERVER BERHASIL DIJALANKAN!
echo   - Backend & Aplikasi Web: http://localhost:5000/customer
echo   - WhatsApp Bot Dashboard: http://localhost:5001
echo ========================================================
echo.
pause
