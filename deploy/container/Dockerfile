FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata openssh-client bash iproute2 procps && \
    addgroup -g 10001 mxpanel && adduser -D -u 10001 -G mxpanel mxpanel && \
    mkdir -p /var/lib/mx-panel /var/lib/mx-panel-access /etc/mx-panel/certificates /usr/local/lib/mx-panel && \
    chown mxpanel:mxpanel /var/lib/mx-panel /var/lib/mx-panel-access /etc/mx-panel/certificates
COPY mxioc index.html /usr/local/lib/mx-panel/
COPY container-entrypoint.sh /usr/local/bin/mx-container
RUN chmod 644 /usr/local/bin/mx-container
USER 10001:10001
WORKDIR /var/lib/mx-panel
ENTRYPOINT ["/bin/sh", "/usr/local/bin/mx-container"]
CMD ["panel"]
