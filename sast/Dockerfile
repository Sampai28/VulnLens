FROM node:18-alpine

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --production

# Copy source code
COPY src/ ./src/

EXPOSE 3000

CMD ["node", "src/server.js"]
