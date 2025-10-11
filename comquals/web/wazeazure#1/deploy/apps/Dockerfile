FROM node:22-alpine AS node-app

RUN apk add --no-cache python3 py3-pip

WORKDIR /app/internal
COPY internal/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages
COPY internal .

WORKDIR /app/external
COPY external/package*.json .
RUN npm install --omit=dev
COPY external .
RUN npm run build

EXPOSE 4321

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]