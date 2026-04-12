# 노드 20 버전 기반
FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

CMD ["npm", "start"]

