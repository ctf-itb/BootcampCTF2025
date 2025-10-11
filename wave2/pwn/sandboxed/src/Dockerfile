FROM ubuntu:24.04 AS base

WORKDIR /app

ADD --chmod=711 printflag .
ADD --chmod=755 chall .
ADD --chmod=755 sandbox .
ADD --chmod=755 run.sh run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_MEM=10M
