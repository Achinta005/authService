FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install
RUN npm install -g nodemon ts-node ts-node-dev

COPY . .

EXPOSE 4001

# requires "dev": "ts-node-dev --respawn server.ts" in package.json
CMD ["npm", "run", "dev"]