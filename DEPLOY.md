# Deployment Guide

This guide covers deploying bin on an Ubuntu VPS.

## Prerequisites

- Ubuntu 20.04+ server
- Docker installed
- Traefik configured as reverse proxy (optional)
- Domain pointing to your server (optional)

## Quick Deployment

### 1. Build and Run

```bash
# Clone or copy project to server
git clone https://github.com/pybash1/bin.git
cd bin

# Build and run container
docker build -t pastebin:latest .
docker run -d \
  --name pastebin \
  --restart unless-stopped \
  -p 8000:8000 \
  pastebin:latest
```

### 2. Verify

```bash
docker logs pastebin
curl http://localhost:8000
```

## Production Deployment (with Traefik)

### 1. Create Docker Network

```bash
docker network create web
```

### 2. Configure Traefik Labels

Update your docker-compose.yml to include Traefik labels:

```yaml
services:
  pastebin:
    build: .
    container_name: pastebin
    restart: unless-stopped
    networks:
      - web
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.pastebin.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.pastebin.entrypoints=websecure"
      - "traefik.http.routers.pastebin.tls.certresolver=letsencrypt"
      - "traefik.http.services.pastebin.loadbalancer.server.port=8000"
    expose:
      - "8000"

networks:
  web:
    external: true
```

### 3. Run

```bash
docker compose up -d
```

Traefik will automatically handle HTTPS with Let's Encrypt certificates.

## Docker Compose (Alternative)

Create `docker-compose.yml`:

```yaml
services:
  pastebin:
    build: .
    container_name: pastebin
    restart: unless-stopped
    ports:
      - "8000:8000"
```

Run with:

```bash
docker compose up -d
```

## Management Commands

```bash
# View logs
docker logs -f pastebin

# Stop
docker stop pastebin

# Start
docker start pastebin

# Restart
docker restart pastebin

# Update to new version
git pull
docker build -t pastebin:latest .
docker stop pastebin
docker rm pastebin
docker run -d --name pastebin --restart unless-stopped -p 8000:8000 pastebin:latest
```

## Firewall

```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## Troubleshooting

**Container won't start:**
```bash
docker logs pastebin
```

**Port already in use:**
```bash
sudo lsof -i :8000
# Kill the process or change port in Dockerfile
```

**Check container status:**
```bash
docker ps -a | grep pastebin
```
