# DevCollab — Production Operations & Deployment Guide

This manual walks through deploying **DevCollab** to a production server (Ubuntu 22.04 / 24.04 LTS or Debian 12) using Docker Compose, isolated sandboxing, and Let's Encrypt TLS.

---

## Architecture Quick Reference

| Service | Container Name | Port | Description |
| :--- | :--- | :--- | :--- |
| **Edge Proxy** | `devcollab-edge-proxy` | `80`, `443` | Nginx reverse proxy with SSL, WebSocket upgrades, rate limits |
| **Frontend** | `devcollab-frontend` | `80` (internal) | Nginx serving compiled Vite SPA with immutable `/assets` cache |
| **Backend** | `devcollab-backend` | `4000` (internal) | Node 22 LTS, Socket.IO CRDT, Express API, SQLite WAL database |
| **Sandbox** | `devcollab-piston` | `2000` (internal) | Isolated code execution engine with 1GB RAM / 2 CPU / 100 PID limits |

---

## Step 1: Provision Server & Install Docker

### 1.1 Minimum Server Hardware
- **CPU**: 2 vCPU or higher (4 vCPU recommended for concurrent code compilation)
- **RAM**: 4 GB RAM minimum (8 GB recommended)
- **Disk**: 40 GB SSD / NVMe
- **OS**: Ubuntu 22.04 LTS or Debian 12

### 1.2 Open Firewall Ports
Ensure inbound traffic is allowed on:
- **Port 22** (SSH)
- **Port 80** (HTTP / ACME Certbot challenge)
- **Port 443** (HTTPS / Secure WebSockets)

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 1.3 Install Docker Engine & Docker Compose Plugin
```bash
# Remove outdated packages
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Set up repository
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker on boot
sudo systemctl enable --now docker
```

---

## Step 2: Clone Repository & Configure Environment

### 2.1 Clone to `/opt/devcollab`
```bash
sudo mkdir -p /opt/devcollab
sudo chown -R $USER:$USER /opt/devcollab
git clone <YOUR_GIT_REPO_URL> /opt/devcollab
cd /opt/devcollab
```

### 2.2 Create Production `.env`
Generate a cryptographically secure 64-character hex secret for `JWT_SECRET`:

```bash
openssl rand -hex 32
```

Create `/opt/devcollab/.env` using the generated secret and your domain name:

```bash
cp .env.production.example .env
nano .env
```

Set:
```env
JWT_SECRET=f3a8b417c8d92e63510fa72c3d4e8b91a25c7e091b4a683e9d02c7b5a1f8e4c6
PUBLIC_DOMAIN=collab.yourdomain.com
CORS_ORIGINS=https://collab.yourdomain.com
GEMINI_API_KEY=
```

---

## Step 3: Launch the Production Stack

Build and start all 4 services in the background:

```bash
docker compose up -d --build
```

### Check Container Status:
```bash
docker compose ps
```
You should see all 4 containers in `Up` or `running` state:
- `devcollab-edge-proxy` (healthy)
- `devcollab-frontend` (healthy)
- `devcollab-backend` (healthy)
- `devcollab-piston` (running)

---

## Step 4: Configure Let's Encrypt SSL/TLS

### 4.1 Obtain SSL Certificate with Certbot
Point your DNS `A` record for `collab.yourdomain.com` to your server's public IP address, then run:

```bash
docker run -it --rm \
  -v devcollab_certbot-conf:/etc/letsencrypt \
  -v devcollab_certbot-www:/var/www/certbot \
  certbot/certbot certonly --webroot \
  -w /var/www/certbot \
  -d collab.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos --no-eff-email
```

### 4.2 Enable HTTPS in `nginx/nginx-edge.conf`
Open `nginx/nginx-edge.conf`:
```bash
nano nginx/nginx-edge.conf
```
1. In the first server block, uncomment the redirect to HTTPS:
   ```nginx
   location / {
       return 301 https://$host$request_uri;
   }
   ```
2. In the second server block, uncomment the `server { listen 443 ... }` block and replace `yourdomain.com` with your actual domain (`collab.yourdomain.com`).
3. Reload Nginx without downtime:
   ```bash
   docker compose exec edge-proxy nginx -s reload
   ```

### 4.3 Automated Certificate Renewal
Add a cron job to automatically renew certificates twice a month:
```bash
(crontab -l 2>/dev/null; echo "0 3 1,15 * * docker run --rm -v devcollab_certbot-conf:/etc/letsencrypt -v devcollab_certbot-www:/var/www/certbot certbot/certbot renew --webroot -w /var/www/certbot --quiet && docker compose -f /opt/devcollab/docker-compose.yml exec edge-proxy nginx -s reload") | crontab -
```

---

## Step 5: Verification & Health Checks

### 5.1 Test Backend API Health
```bash
curl -I https://collab.yourdomain.com/api/health
```
Expected HTTP `200 OK` response with security headers:
```
HTTP/2 200
x-content-type-options: nosniff
x-frame-options: DENY
strict-transport-security: max-age=31536000; includeSubDomains
```

Detailed JSON inspection:
```bash
curl -s https://collab.yourdomain.com/api/health | jq .
```

### 5.2 Test Real-Time Collaboration
1. Open `https://collab.yourdomain.com` in two separate browser windows.
2. Select persona **Aria (OWNER)** in Window 1 and **Liam (EDITOR)** in Window 2.
3. Observe live cursor presence and simultaneous typing synchronization.

---

## Step 6: Automated SQLite Backups

DevCollab includes an atomic hot-backup script in [`scripts/backup-sqlite.sh`](file:///c:/Users/suvig/OneDrive/Desktop/devcollab/scripts/backup-sqlite.sh).

Make the script executable:
```bash
chmod +x /opt/devcollab/scripts/backup-sqlite.sh
```

Test a manual backup run:
```bash
/opt/devcollab/scripts/backup-sqlite.sh
```
Backups are saved to `/opt/devcollab/backups/devcollab_YYYYMMDD_HHMMSS.sqlite.gz`.

### Schedule Automated Backup Cron (Every 6 Hours):
```bash
(crontab -l 2>/dev/null; echo "0 */6 * * * /opt/devcollab/scripts/backup-sqlite.sh >> /var/log/devcollab-backup.log 2>&1") | crontab -
```

---

## Step 7: Day-2 Maintenance & Updates

### Viewing Real-Time Logs:
```bash
# All services:
docker compose logs -f

# Backend only:
docker compose logs -f backend

# Reverse Proxy access & error logs:
docker compose logs -f edge-proxy
```

### Deploying New Code (Zero Downtime):
```bash
cd /opt/devcollab
git pull origin main
docker compose build
docker compose up -d --remove-orphans
docker system prune -f
```

### Restoring from a Backup:
```bash
# 1. Stop backend service
docker compose stop backend

# 2. Extract backup file
gunzip -k /opt/devcollab/backups/devcollab_TARGET.sqlite.gz

# 3. Copy to volume
docker run --rm -v devcollab_sqlite-data:/data/sqlite -v /opt/devcollab/backups:/backups alpine \
  sh -c "cp /backups/devcollab_TARGET.sqlite /data/sqlite/devcollab.sqlite && rm -f /data/sqlite/devcollab.sqlite-wal /data/sqlite/devcollab.sqlite-shm"

# 4. Restart backend
docker compose start backend
```
