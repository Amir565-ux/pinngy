FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY app.js ./
COPY public/ ./public/
EXPOSE 8080
CMD ["node", "app.js"]
