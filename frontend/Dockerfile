# frontend/Dockerfile
FROM node:18-alpine AS build

WORKDIR /app
COPY package.json .
COPY public ./public
COPY src ./src

RUN npm install && npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
