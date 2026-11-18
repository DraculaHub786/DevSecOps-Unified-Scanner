FROM node:20.11.1-alpine
WORKDIR /app
COPY package.json ./
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "process.exit(0)"
USER 10001:10001
CMD ["node", "server.js"]
