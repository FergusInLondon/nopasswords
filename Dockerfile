# Development Dockerfile for NoPasswords
# This provides a complete development environment with all dependencies

FROM golang:1.25-bookworm

# @risk Tampering: Pin versions to prevent supply chain attacks via compromised dependencies
# @mitigation: Use specific versions in package.json and go.mod, verify checksums

# Install Node.js and npm for client builds
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install golangci-lint for Go linting
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
    sh -s -- -b /usr/local/bin v1.61.0

# Install make and other build tools
RUN apt-get update && apt-get install -y \
    make \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy client package files for dependency installation
COPY client/package.json client/package-lock.json* ./client/

# Install client dependencies
RUN cd client && npm install && cd .. 

# Copy the rest of the source code
COPY . .

# Build everything
RUN make build && make client-build

# Default command shows available make targets
CMD ["make", "help"]
