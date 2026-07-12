FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY client-portal-protocol /client-portal-protocol
COPY client-portal-runtime/package.json ./package.json
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && npm install --omit=dev --ignore-scripts=false \
    && rm -rf /var/lib/apt/lists/* /root/.npm

FROM node:22-bookworm-slim
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm
COPY client-portal-runtime/broker ./broker
COPY client-portal-runtime/shared ./shared
ENV NODE_ENV=production PORT=4101 PORTAL_DB_PATH=/data/portal.db
EXPOSE 4101
CMD ["node", "broker/index.js"]
