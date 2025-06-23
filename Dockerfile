# Stage 1: Build (Go)
FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o kilo-taximm .

# Stage 2: Final (Scratch)
FROM scratch
WORKDIR /app
COPY --from=builder /app/kilo-taximm .
EXPOSE 8080
CMD ["./kilo-taximm"]
