#!/bin/bash
set -e

echo "🍢 ==================================================="
echo "🍢 MEMULAI INSTALASI RESMI KEBAB AL BEWOK"
echo "🍢 ==================================================="

# 1. Update system & install dependencies
apt update && apt upgrade -y
apt install -y curl git nginx ufw

# 2. Install Node.js v20 LTS & PM2
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
npm install -g pm2

# 3. Setup directory & clone repository
mkdir -p /var/www
cd /var/www
rm -rf albewok
git clone https://github.com/muhammadinsanrachmady/kebab-al-bewok.git albewok
cd /var/www/albewok/backend
npm install --production

# 4. Start backend with PM2
pm2 delete albewok-app 2>/dev/null || true
pm2 start src/server.js --name "albewok-app"
pm2 save
env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u root --hp /root || pm2 startup systemd -u root --hp /root || true

# 5. Configure Nginx Reverse Proxy
cat << 'EOF' > /etc/nginx/sites-available/albewok
server {
    listen 80;
    server_name albewok.my.id www.albewok.my.id 149.41.198.164;

    client_max_body_size 30M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

# 6. Enable site & test Nginx
ln -sf /etc/nginx/sites-available/albewok /etc/nginx/sites-enabled/albewok
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

# 7. Configure Firewall UFW
ufw allow OpenSSH
ufw allow 'Nginx Full'
echo "y" | ufw enable || true

echo "=========================================================="
echo "✅ DEPLOYMENT SUKSES 100%!"
echo "🍢 Webapp Kebab AL Bewok sudah aktif berjalan 24 jam!"
echo "👉 Buka Domain: https://albewok.my.id"
echo "👉 Atau IP: http://149.41.198.164"
echo "=========================================================="
