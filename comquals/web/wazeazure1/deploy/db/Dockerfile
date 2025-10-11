FROM postgres:17-alpine@sha256:d5f196a551b5cef1c70853c6dd588f456d16ca4ea733e3f31c75bc1ae2f65f3f

COPY flag /flag
COPY readflag.c /readflag.c
COPY init.sql /docker-entrypoint-initdb.d/

RUN apk add --no-cache gcc musl-dev

RUN chmod 400 /flag 
RUN gcc /readflag.c -o /readflag
RUN rm /readflag.c 
RUN chmod 4755 /readflag 
