FROM node:20-alpine AS build

WORKDIR /app

COPY apps/dashboard/package.json apps/dashboard/package-lock.json ./
RUN npm ci

COPY apps/dashboard/ .
RUN npm run build

FROM nginx:alpine

COPY apps/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
