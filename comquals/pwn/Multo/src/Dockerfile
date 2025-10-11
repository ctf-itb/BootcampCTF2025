FROM ubuntu:24.04

RUN apt-get update -y && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ctf -s /bin/bash ctf && \
    echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY ./multo ./flag.txt ./

RUN chown ctf:ctf multo flag.txt && \
    chmod 0555 multo && chmod 0444 flag.txt

EXPOSE 8991
USER ctf

CMD ["socat", "TCP-LISTEN:8991,reuseaddr,fork", "EXEC:./multo,stderr"]