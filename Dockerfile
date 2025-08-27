# Use minimal Alpine image
FROM alpine:3.18

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy the pre-built binary from project root
COPY bin /usr/local/bin/pastebin

# Make the binary executable
RUN chmod +x /usr/local/bin/pastebin

# Expose port
EXPOSE 8000

# Run the binary
ENTRYPOINT ["/usr/local/bin/pastebin", "0.0.0.0:8000"]
