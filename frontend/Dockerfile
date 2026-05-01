FROM node:22-alpine

WORKDIR /app
COPY package.json ./
RUN npm install
COPY index.html tsconfig.json ./
COPY src ./src

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--port", "3000"]

