FROM golang:1.27.1-alpine3.24 AS build

WORKDIR /src
ENV GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/service ./cmd/service

FROM alpine:3.24

RUN apk add --no-cache ca-certificates
COPY --from=build /out/service /usr/local/bin/service

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/service"]