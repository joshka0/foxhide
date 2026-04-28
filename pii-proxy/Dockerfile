FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/pii-proxy ./cmd/pii-proxy
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/pii-scrub ./cmd/pii-scrub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pii-proxy /pii-proxy
COPY --from=build /out/pii-scrub /pii-scrub
EXPOSE 8080
ENTRYPOINT ["/pii-proxy"]
