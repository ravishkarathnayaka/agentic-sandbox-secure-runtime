# Minimal, non-root hardened container base image for sandbox execution workers
FROM python:3.11-alpine

# Set non-root UID/GID (nobody:nogroup standard UID 65534)
ENV USER_UID=65534 \
    USER_GID=65534 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Security hardening:
# 1. Update apk repositories & certificates
# 2. Strip SUID and SGID permissions across entire filesystem
# 3. Create unprivileged workspace directory
# 4. Remove apk package manager binaries to prevent runtime installation attacks
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates && \
    find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true && \
    mkdir -p /workspace /tmp && \
    chmod 1777 /tmp && \
    chown -R 65534:65534 /workspace && \
    rm -rf /var/cache/apk/* /sbin/apk

# Switch permanently to unprivileged non-root user
USER 65534:65534
WORKDIR /workspace

# Default execution shell
ENTRYPOINT ["python3"]
CMD ["-c", "print('Sandbox worker ready')"]
