# syntax=docker/dockerfile:1

# The web UI: web/ is built into internal/ui/dist/app, which the Go build below
# embeds. The output is the same for every platform, so the stage runs on the
# builder's own platform and runs only once in a multi-arch build.
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# The build stage runs on the builder's own platform and cross-compiles for the
# target, so a multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/ui/dist/app ./internal/ui/dist/app
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/photofinish ./cmd/photofinish

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/photofinish /usr/local/bin/photofinish
# Scenarios are mounted here: docker run --rm -v "$PWD:/work" ghcr.io/troubied3v/photofinish run scenario.yaml
WORKDIR /work
# The demo shop and the web UI inside a container must listen on all
# interfaces; publish them to loopback only on the host:
#   docker run --rm -p 127.0.0.1:8443:8443 ghcr.io/troubied3v/photofinish demo --addr 0.0.0.0:8443 --expose
#   docker run --rm -p 127.0.0.1:7340:7340 -e PHOTOFINISH_TOKEN -v "$PWD:/work" ghcr.io/troubied3v/photofinish \
#     serve --addr 0.0.0.0:7340 --expose --workspace /work --data /tmp/pf
EXPOSE 7340 8443
ENTRYPOINT ["photofinish"]
CMD ["help"]
