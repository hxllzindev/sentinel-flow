FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S sentinel \
    && adduser -S -G sentinel sentinel
COPY --chown=sentinel:sentinel package.json ./
COPY --chown=sentinel:sentinel src ./src

USER sentinel
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4000/api/health || exit 1

CMD ["node", "src/server.js"]
