FROM node:20-alpine AS builder
WORKDIR /app
# vendor/ holds the workspace @afauthhq/{core,server} tarballs that
# package.json references via file: — produced by ../scripts/pack-sdk.sh
# before `docker compose build`. Copied before install so npm resolves them.
COPY package.json ./
COPY vendor ./vendor
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc -p tsconfig.json

FROM node:20-alpine AS runtime
WORKDIR /app
COPY package.json ./
COPY vendor ./vendor
RUN npm install --omit=dev --no-audit --no-fund
COPY --from=builder /app/dist ./dist
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/server.js"]
