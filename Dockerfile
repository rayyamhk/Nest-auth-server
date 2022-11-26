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


# docker run -d -p 8081:8081 -e "API_KEY=l6krzRlrhlpA6JiniFPlx9Q8lMfwPhFxJeCkhqoOGU6ccR4KfqzFlAFkyBU9jyxk" -e "JWT_ACCESS_TOKEN_KEY=G2jwiXpwuUjprlEM4t8QdY7R3mBZVrcwyd2KXULDatEamh5A2Vf2sdwNItBavvxt" -e "JWT_REFRESH_TOKEN_KEY=13zUfTD74tKRV5YwvRwf2pmWES1wB94dFhfF9qZ29xNDeuMWklcriADlStnVCyMy" -e "AWS_ACCESS_KEY_ID=AKIA5AFKFETCWIZKJK4T" -e "AWS_SECRET_ACCESS_KEY=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" -e "REGION=us-east-2" nestjs-auth-server