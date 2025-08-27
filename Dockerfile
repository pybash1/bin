FROM alpine:3.14

COPY bin /pastebin

EXPOSE 8000
ENTRYPOINT ["/pastebin", "0.0.0.0:8000"]
