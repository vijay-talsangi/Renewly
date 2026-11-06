# Build stage
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /renewly .

# Runtime stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S -G app app

WORKDIR /app

COPY --from=builder --chown=app:app /renewly /app/renewly

USER app

ENV PORT=8080
ENV GIN_MODE=release

EXPOSE 8080

ENTRYPOINT ["/app/renewly"]
