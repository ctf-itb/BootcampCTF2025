FROM python:3.13-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    openssl \
    && rm -rf /var/lib/apt/lists/*
    
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN addgroup ctf && \
    adduser --disabled-password --gecos "" ctfplayer 
    
# randomize flag path
ARG FLAG=""
RUN mkdir -p /flag && \
    export FLAG_PATH="/flag/flag-$(openssl rand -hex 8).txt" && \
    echo "FLAG_PATH=$FLAG_PATH" >> /etc/environment && \
    echo $FLAG > $FLAG_PATH 

RUN mkdir -p uploads && \
    chown -R ctfplayer:ctfplayer /app /flag && \
    chmod 755 uploads

USER ctfplayer

EXPOSE 6969

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

CMD ["python", "app.py"]