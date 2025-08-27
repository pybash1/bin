FROM scratch

COPY bin /pastebin
COPY --from=builder /etc/passwd /etc/passwd

USER nobody
EXPOSE 8000
ENTRYPOINT ["/pastebin", "0.0.0.0:8000"]
