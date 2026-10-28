# TrustGate analyst dashboard (Next.js). It talks only to the TrustGate proxy
# (TRUSTGATE_PROXY_URL); analyst tokens live in an httpOnly cookie, never in page scripts.
#
#   docker build -t trustgate-dashboard dashboard
#   docker run -p 8501:3000 -e TRUSTGATE_PROXY_URL=http://trustgate-proxy:8080 trustgate-dashboard

FROM node:22.20.0-alpine3.22 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22.20.0-alpine3.22 AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22.20.0-alpine3.22
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S -g 10001 trustgate && adduser -S -u 10001 -G trustgate trustgate
COPY --from=build --chown=10001:10001 /app/.next/standalone ./
COPY --from=build --chown=10001:10001 /app/.next/static ./.next/static
COPY --from=build --chown=10001:10001 /app/public ./public
USER 10001
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:3000/login >/dev/null || exit 1
CMD ["node", "server.js"]
