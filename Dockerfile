FROM node:18.12-bullseye-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json .
RUN npm ci --omit=dev

COPY src ./src
COPY tsconfig.json .
RUN npm run build

USER node

EXPOSE 8081
CMD ["node", "dist/main"]