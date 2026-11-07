# Build stage
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The same image is used by the Cloud Run API service and reminder job.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /renewly-api .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /reminder-worker ./cmd/reminder_worker

# Runtime stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S -G app app

WORKDIR /app

COPY --from=builder --chown=app:app /renewly-api /app/renewly-api
COPY --from=builder --chown=app:app /reminder-worker /app/reminder-worker

USER app

ENV PORT=8080
ENV GIN_MODE=release

EXPOSE 8080

ENTRYPOINT ["/app/renewly-api"]
