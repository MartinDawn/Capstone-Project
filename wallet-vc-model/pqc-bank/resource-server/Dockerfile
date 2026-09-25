FROM node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e
WORKDIR /app
COPY package*.json ./
RUN apk add --no-cache python3 make g++ && npm install
COPY . .
EXPOSE 4000
CMD ["npm", "start"]
