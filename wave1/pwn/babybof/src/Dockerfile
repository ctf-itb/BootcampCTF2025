FROM ubuntu:24.04

RUN apt-get update -y && \
    apt-get install -y build-essential socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ctf -s /bin/bash ctf && \
    echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY ./chall.c ./flag.txt ./

RUN gcc -no-pie -fno-stack-protector -Wno-deprecated-declarations \
         -o chall chall.c -std=gnu99 && \
    chown ctf:ctf chall flag.txt && \
    chmod 0555 chall && chmod 0444 flag.txt

EXPOSE 1330
USER ctf

CMD ["socat", "TCP-LISTEN:1330,reuseaddr,fork", "EXEC:./chall,stderr"]
