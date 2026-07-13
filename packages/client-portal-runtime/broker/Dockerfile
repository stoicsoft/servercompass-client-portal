FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY client-portal-protocol /client-portal-protocol
COPY client-portal-runtime/package.json client-portal-runtime/package-lock.json ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && npm ci --omit=dev --ignore-scripts=false \
    && rm -rf /var/lib/apt/lists/* /root/.npm

FROM node:22-bookworm-slim
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /client-portal-protocol /client-portal-protocol
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm
COPY client-portal-runtime/broker ./broker
COPY client-portal-runtime/shared ./shared
RUN node --input-type=module -e "const protocol = await import('@servercompass/client-portal-protocol'); if (protocol.PROTOCOL_VERSION !== 3) throw new Error('Unexpected client portal protocol version')"
ENV NODE_ENV=production PORT=4101 PORTAL_DB_PATH=/data/portal.db
EXPOSE 4101
CMD ["node", "broker/index.js"]
