# Stage 1: build the React dashboard. Stage 2: Flask API serving it. Build context = repo root.
FROM node:20-alpine AS ui
WORKDIR /ui
COPY dashboard/package.json ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==22.0.0 cryptography==46.0.6
COPY cyberguard /app/cyberguard
COPY --from=ui /ui/dist /app/static
RUN useradd -r -u 10002 cg && mkdir -p /var/lib/cyberguard /etc/cyberguard \
 && chown cg /var/lib/cyberguard /etc/cyberguard
USER cg
ENV CG_STATIC_DIR=/app/static
EXPOSE 5000
# One worker: the login limiter is in-memory. Deploys can take ~20s while the proxy reloads and is verified.
CMD ["gunicorn", "-w", "1", "--threads", "8", "--timeout", "120", "-b", "0.0.0.0:5000", "cyberguard.server:app"]
