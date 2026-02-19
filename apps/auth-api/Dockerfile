FROM node:22-alpine AS builder

WORKDIR /app

# Copy workspace manifests first to maximize cache reuse.
COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/auth-api/package.json apps/auth-api/package.json
COPY packages/auth-contracts/package.json packages/auth-contracts/package.json

RUN npm ci

# Copy only required workspace sources.
COPY apps/auth-api apps/auth-api
COPY packages/auth-contracts packages/auth-contracts

# Build all runtime artifacts required by auth-api.
RUN npm run prisma:generate --workspace @sigfarm/auth-api
RUN npm run build --workspace @sigfarm/auth-contracts
RUN npm run build --workspace @sigfarm/auth-api

# Make auth-contracts runtime-resolvable by plain Node.js in production.
RUN node -e "const fs=require('fs');const p='packages/auth-contracts/package.json';const pkg=JSON.parse(fs.readFileSync(p,'utf8'));pkg.main='dist/index.js';pkg.types='dist/index.d.ts';fs.writeFileSync(p,JSON.stringify(pkg,null,2));"

# Keep runtime image lean.
RUN npm prune --omit=dev

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

COPY package.json package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/auth-api ./apps/auth-api
COPY --from=builder /app/packages/auth-contracts ./packages/auth-contracts

EXPOSE 3001

CMD ["node", "apps/auth-api/dist/index.js"]

