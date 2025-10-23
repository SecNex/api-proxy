FROM golang:latest AS builder

WORKDIR /app

COPY app/go.mod ./

RUN go mod download && go mod verify

COPY app .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o proxy main.go

FROM alpine:latest AS runner

WORKDIR /app

COPY --from=builder /app/proxy ./proxy

EXPOSE 8000

CMD ["./proxy"]