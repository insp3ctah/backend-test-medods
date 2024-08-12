FROM golang:1.22

WORKDIR /app

COPY . .

RUN go mod download

CMD ["go", "run", "main.go"]