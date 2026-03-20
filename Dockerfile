FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /src
COPY . .
RUN make build

FROM alpine:3.21
RUN apk add --no-cache ca-certificates git
COPY --from=builder /src/morphex /usr/local/bin/morphex
ENTRYPOINT ["morphex"]
