# Stage 1: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
# Fix riproducibilità: "npm ci" al posto di "npm install".
# npm ci installa ESATTAMENTE le versioni bloccate in package-lock.json
# (build deterministica e più veloce), mentre npm install può aggiornare
# il lockfile e tirare versioni diverse ad ogni build.
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Serve
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000