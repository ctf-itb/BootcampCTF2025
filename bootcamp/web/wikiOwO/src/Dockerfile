FROM node:21 as base
WORKDIR /app

RUN apt-get update -y && npx playwright install-deps

RUN addgroup ctf && \
    adduser --disabled-password --gecos "" ctfplayer && \
    chown -R ctfplayer:ctf /app

USER ctfplayer

COPY --chown=ctfplayer:ctf package*.json ./

RUN npm ci --only=production

COPY --chown=ctfplayer:ctf . .

ARG BROWSER=chromium
ENV BROWSER=${BROWSER}
RUN npx playwright install ${BROWSER}

EXPOSE 6971

CMD ["npm", "start"]
