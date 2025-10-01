const app = require("fastify")();
const proxy = require("@fastify/http-proxy");
const PORT = 8115;

app.register(proxy, {
  upstream: "http://backend:8115",
  proxyPayloads: true,

  preValidation: async (req, reply) => {
    if (req.method !== "POST" || req.url !== "/") return;
    try {
      let body = req.body;
      if (typeof body === "string") body = JSON.parse(body);
      if (body && typeof body === "object" && ("plisssakumauflaggratisss" in body)) {
        return reply.send("Nice try, but no flag for you :>");
      }
    } catch {
    }
  },

  replyOptions: {
    rewriteRequestHeaders: (req, headers) => {
      if (req.method === "POST" && req.url === "/") {
        headers["content-type"] = "application/json";
      }
      return headers;
    },
  },
});

app.listen({ port: PORT, host: "0.0.0.0" });
