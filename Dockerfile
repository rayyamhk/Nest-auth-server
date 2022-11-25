FROM node:18.12-bullseye-slim
WORKDIR /app
COPY src ./src
COPY package*.json .
copy tsconfig.json .
ENV NODE_ENV=production
RUN npm ci --omit=dev
RUN npm run build
USER node
EXPOSE 8081
CMD ["node", "dist/main"]
