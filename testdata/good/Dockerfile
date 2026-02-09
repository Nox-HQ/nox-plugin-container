# Good Dockerfile -- follows security best practices.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN apk add --no-cache git && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app .

FROM scratch
COPY --from=build /app /app
USER 65534
HEALTHCHECK --interval=30s --timeout=5s CMD ["/app", "health"]
EXPOSE 8080
ENTRYPOINT ["/app"]
