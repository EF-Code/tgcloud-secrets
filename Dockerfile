# Release builds must override NODE_IMAGE with an immutable digest, for example
# node:22-bookworm-slim@sha256:<reviewed-digest>. The tag remains useful for
# local development because image digests are registry-specific and time-bound.
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY src ./src
COPY runtime ./runtime
COPY migrations ./migrations
USER node
ENTRYPOINT ["node", "src/cli.js"]
CMD ["serve"]
