# Dockerfile — runs /app/chall.py under socat
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        socat \
        python3 \
        python3-pip \
        libseccomp2 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY chall.py /app/chall.py
COPY flag.txt /app/flaggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg.txt

RUN chown root:root /app/chall.py /app/flaggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg.txt && \
    chmod 644 /app/flaggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg.txt && \
    chmod 755 /app/chall.py

WORKDIR /app

RUN python3 -m pip install --no-cache-dir pyseccomp --break-system-packages

CMD ["sh", "-c", "socat tcp-l:1337,reuseaddr,fork EXEC:\"timeout -s KILL 180 python3 /app/chall.py\",stderr,su=nobody"]
