FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ipwho-tg-bot .

FROM alpine:3.20

RUN adduser -D -H app && mkdir -p /data && chown app:app /data
WORKDIR /app

COPY --from=builder /ipwho-tg-bot /usr/local/bin/ipwho-tg-bot

USER app
CMD ["ipwho-tg-bot"]
