# syntax=docker/dockerfile:1

# M4 adds the web UI stage here, as in CloudGraph: a node:22-alpine stage that
# builds web/ into internal/ui/dist/app, copied into the build stage below
# before "go build".

# The build stage runs on the builder's own platform and cross-compiles for the
# target, so a multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/photofinish ./cmd/photofinish

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/photofinish /usr/local/bin/photofinish
# Scenarios are mounted here: docker run --rm -v "$PWD:/work" ghcr.io/troubied3v/photofinish run scenario.yaml
WORKDIR /work
# The demo shop inside a container must listen on all interfaces; publish it to
# loopback only on the host:
#   docker run --rm -p 127.0.0.1:8443:8443 ghcr.io/troubied3v/photofinish demo --addr 0.0.0.0:8443 --expose
EXPOSE 8443
ENTRYPOINT ["photofinish"]
CMD ["help"]
