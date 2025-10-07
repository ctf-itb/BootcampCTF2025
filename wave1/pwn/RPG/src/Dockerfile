FROM ubuntu:24.04

RUN apt-get update -y && \
    apt-get install -y build-essential socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ctf -s /bin/bash ctf && \
    echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY ./rpg.c ./flag.txt ./

RUN gcc -Wno-deprecated-declarations -o rpg rpg.c -std=gnu99 && \
    chown ctf:ctf rpg flag.txt && \
    chmod 0555 rpg && chmod 0444 flag.txt

EXPOSE 1230
USER ctf

CMD ["socat", "TCP-LISTEN:1230,reuseaddr,fork", "EXEC:./rpg,stderr"]
