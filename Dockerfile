FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o proxy ./cmd/proxy


FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/proxy .

EXPOSE 4318 8080 6514 6543

VOLUME ["/data"]
ENV DB_PATH=/data/tenants.db

ENTRYPOINT ["./proxy"]
