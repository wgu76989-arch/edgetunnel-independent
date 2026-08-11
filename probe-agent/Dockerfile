FROM node:22-alpine

WORKDIR /app
COPY package.json server.js ./

ENV NODE_ENV=production
ENV PROBE_LISTEN_HOST=0.0.0.0
EXPOSE 8788

USER node
CMD ["node", "server.js"]
