# Dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && \
    apt-get install -y xinetd libseccomp2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m user

COPY ./chall /home/user/
COPY ./flag.txt /home/user/
COPY ./libc.so.6 /home/user/libc.so.6
COPY ./ld-linux-x86-64.so.2 /home/user/ld-linux-x86-64.so.2
COPY run.sh /
COPY xinetd /etc/xinetd.d/user

WORKDIR /home/user

RUN chown -R root:root . && \
    chmod o+rx . && \
    chmod 444 flag.txt && \
    chmod a+x chall && \
    chmod +x /run.sh \
    chmod +x /home/user/ld-linux-x86-64.so.2

CMD ["/usr/sbin/xinetd", "-dontfork"]
