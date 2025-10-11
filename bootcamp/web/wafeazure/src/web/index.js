const express = require("express");
const path = require("path");

const app = express();
const PORT = 8115;

const FLAG = process.env.FLAG ?? (console.log("No flag? :sadge:"), process.exit(1));

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.post("/", (req, res) => {
  if (req.body && typeof req.body === "object" && ("plisssakumauflaggratisss" in req.body)) {
    return res.send(FLAG);
  }
  res.status(400).send("what?");
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log("Listening on", PORT);
});
