# CPA Hub - Deploy Guide

## Railway Deployment (Recommended)

### Step 1: Prepare Repository
1. Create a GitHub repository
2. Push your code:
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/cpa-hub.git
git push -u origin main
```

### Step 2: Deploy on Railway
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Railway auto-detects Node.js
6. Click "Deploy"

### Step 3: Configure Environment
1. Go to your project settings
2. Under "Variables", add:
   - `PORT` = `3000`
   - `NODE_ENV` = `production`

### Step 4: Custom Domain (Optional)
1. Go to Settings → Networking
2. Add custom domain
3. Update DNS records

---

## Local Network Access

To access from other devices on your network:

### Windows (PowerShell as Admin):
```powershell
netsh advfirewall firewall add rule name="CPA Hub" dir=in action=allow protocol=tcp localport=3001
```

### Get your IP:
```bash
ipconfig
# Look for IPv4 Address (e.g., 192.168.1.100)
```

### Access:
```
http://192.168.1.100:3001
```

---

## Features
- User authentication (register/login)
- 12 CPA offers with tracking
- Dashboard with stats
- Custom avatar system
- Level & XP system
- 8 achievement badges
- Referral program
- SQLite database (auto-created)

## Tech Stack
- Node.js + Express
- SQLite
- HTML/CSS/JS (Vanilla)

## Support
For issues, check Railway logs in dashboard.
