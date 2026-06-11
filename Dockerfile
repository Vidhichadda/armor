# ==========================================
# Stage 1: Builder
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package configurations for mcp-server
COPY mcp-server/package*.json ./mcp-server/
COPY mcp-server/tsconfig.json ./mcp-server/

# Install dependencies (including devDependencies for compilation)
RUN cd mcp-server && npm ci

# Copy source code
COPY mcp-server/src ./mcp-server/src

# Compile TypeScript to JavaScript
RUN cd mcp-server && npm run build

# ==========================================
# Stage 2: Production Runtime
# ==========================================
FROM node:20-alpine AS runner

WORKDIR /app

# Set production environment flags
ENV NODE_ENV=production

# Copy package configurations to the final workspace
COPY mcp-server/package*.json ./

# Install only production dependencies to optimize footprint
RUN npm ci --omit=dev && npm cache clean --force

# Copy compiled files from builder stage
COPY --from=builder /app/mcp-server/build ./build

# Audit-Ready: Configure workspace permissions for non-root execution
RUN chown -R node:node /app

# Switch to non-privileged node user to prevent container breakout exploits
USER node

# The server executes over standard I/O (StdioServerTransport)
CMD ["node", "build/index.js"]
