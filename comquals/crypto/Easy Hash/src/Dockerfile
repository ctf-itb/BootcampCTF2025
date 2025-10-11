FROM python:3.13-alpine

RUN apk update && apk add socat

RUN adduser -D -h /home/ctf ctf

RUN mkdir /home/ctf/chall

COPY ./requirements.txt /home/ctf/chall
COPY ./chall.py /home/ctf/chall
COPY ./secret.py /home/ctf/chall
COPY ./run.sh /home/ctf/chall

RUN pip3 install -r /home/ctf/chall/requirements.txt

RUN chown -R root:root /home/ctf/chall
RUN chmod -R 555 /home/ctf/chall

USER ctf
WORKDIR /home/ctf/chall
CMD ["./run.sh"]