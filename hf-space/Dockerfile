# Hugging Face Spaces Dockerfile (Generated)
FROM node:18-alpine

# Install curl for health check
RUN apk add --no-cache curl

# Workdir
WORKDIR /app

# Copy package manifests first for better layer caching
COPY package.json package-lock.json* ./

# Install production deps only
RUN npm ci --omit=dev || npm i --omit=dev && npm cache clean --force

# Copy app files
COPY server.js ./server.js
COPY public/ ./public/
COPY data/ ./data/
COPY studio/ ./studio/
COPY utils/ ./utils/
COPY .env.example ./.env.example

# Ensure no persistent logs; we provided a no-op logger implementation in utils/
# Expose HF default port
EXPOSE 7860

# HF runtime envs
ENV PORT=7860
ENV HOST=0.0.0.0
ENV NODE_ENV=production

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:7860/api/health || exit 1

# Start
CMD ["node", "server.js"]
