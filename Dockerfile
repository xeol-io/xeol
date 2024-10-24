FROM gcr.io/distroless/static-debian12@sha256:69830f29ed7545c762777507426a412f97dad3d8d32bae3e74ad3fb6160917ea AS build


FROM alpine:3.20.3@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

COPY xeol /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="xeol"
LABEL org.opencontainers.image.description="A scanner for end-of-life (EOL) software in container images, filesystems, and SBOMs"
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Xeol"
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/xeol-io/xeol/main/README.md"
LABEL io.artifacthub.package.license="Apache-2.0"

ENTRYPOINT ["/xeol"]
