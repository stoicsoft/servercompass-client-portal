FROM node:22-bookworm-slim
WORKDIR /app
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm
COPY client-portal-runtime/gateway ./gateway
COPY client-portal-runtime/shared ./shared
ENV NODE_ENV=production PORT=4100
USER node
EXPOSE 4100
CMD ["node", "gateway/index.js"]
