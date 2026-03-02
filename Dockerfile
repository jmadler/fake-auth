FROM golang:1.21-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o fake-auth0 .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /app/fake-auth0 .
RUN mkdir -p /data
ENV PORT=9092
ENV DB_PATH=/data/auth0.db
EXPOSE 9092
CMD ["./fake-auth0"]
