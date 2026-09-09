# 🚀 GitHub Push & 24/7 Real-Life Production Deployment Guide

This guide walks you through pushing **CyberSentinel IDS** to **GitHub** and deploying it to the cloud so anyone can access and use it 24/7 without disruptions.

---

## 🐙 Part 1: Push Project to GitHub

### Step 1: Create a New GitHub Repository
1. Go to [GitHub.com](https://github.com/new).
2. Name your repository (e.g., `ids-packet-analysis`).
3. Set visibility to **Public** (so it can be displayed on your resume/portfolio).
4. Leave "Add a README file" **unchecked** (we already have a complete README).
5. Click **Create repository**.

### Step 2: Push Local Code to GitHub
Open terminal/PowerShell in your project directory `C:\Users\MANTHAN\.gemini\antigravity\scratch\ids-project` and run:

```bash
# Add your remote GitHub repository
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/ids-packet-analysis.git

# Set main branch
git branch -M main

# Push to GitHub
git push -u origin main
```

---

## 🌐 Part 2: 24/7 Real-Life Cloud Deployment

To make the dashboard accessible live to anyone on the Internet 24/7, use one of the following deployment methods:

### Method 1: Render / Railway (Easiest & Free Cloud Hosting)

1. Sign up on [Render.com](https://render.com) or [Railway.app](https://railway.app).
2. Click **New +** ➔ **Web Service**.
3. Connect your **GitHub** account and select `ids-packet-analysis`.
4. Set Environment to **Docker** (it will auto-detect `Dockerfile`).
5. Set Port to `8000`.
6. Click **Deploy Web Service**.
7. Render will build the container and provide your live HTTPS URL:
   `https://ids-packet-analysis.onrender.com`

---

### Method 2: Linux VPS Deployment (AWS EC2 / DigitalOcean / Linode)

For full raw socket sniffing on real physical network interfaces, a Linux VPS is recommended.

#### 1. SSH into your Server
```bash
ssh root@YOUR_SERVER_IP
```

#### 2. Install Docker & Git
```bash
sudo apt update && sudo apt install -y docker.io docker-compose git
```

#### 3. Clone and Launch
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/ids-packet-analysis.git
cd ids-packet-analysis
docker-compose up --build -d
```

#### 4. Configure Domain & Free SSL (Nginx + Certbot)
```bash
sudo apt install -y nginx certbot python3-certbot-nginx

# Edit Nginx config: /etc/nginx/sites-available/ids
server {
    server_name ids.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}

# Enable & activate SSL
sudo ln -s /etc/nginx/sites-available/ids /etc/nginx/sites-enabled/
sudo certbot --nginx -d ids.yourdomain.com
```

Your Intrusion Detection System is now live, SSL-encrypted (`https://`), and operating 24/7!
