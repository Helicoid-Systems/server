Place `fullchain.pem` and `private-key.pem` here after preparing the
deployment certificate. The container runs as UID/GID 10001; set this
directory to owner 10001:10001 and mode 0700, and both files to owner
10001:10001 and mode 0600. The server refuses TLS material that does not meet
its held-descriptor ownership and privacy checks.
