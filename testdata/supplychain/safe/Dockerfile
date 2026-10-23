FROM alpine:3.19.1
USER appuser
RUN curl -fsSL https://get.example.com/install.sh -o /tmp/install.sh && sha256sum -c /tmp/checksum.txt && sh /tmp/install.sh
