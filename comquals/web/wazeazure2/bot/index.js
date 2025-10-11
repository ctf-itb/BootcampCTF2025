const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const jsdom = new JSDOM('');

const DOMPurify = createDOMPurify(jsdom.window);

const express = require("express");
const path = require("path");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const crypto = require("crypto");
const bot = require("./bot");

const app = express();
const route = express.Router();

// Generate a random secret for session
const secret = crypto.randomBytes(32).toString("hex");

// --- CSP Middleware ---
const cspMiddleware = (req, res, next) => {
  const nonce = crypto.randomBytes(16).toString("hex");
  res.setHeader(
    "Content-Security-Policy",
    `script-src 'self' 'nonce-${nonce}' 'unsafe-eval' https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js; base-uri 'none'; object-src 'none';`
  );

  res.locals.nonce = nonce;

  next();
};

// --- Middleware Setup ---
app.use(cspMiddleware);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: secret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// EJS setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

if (process.env.USE_PROXY) {
  app.set("trust proxy", () => true);
}

// --- Rate Limiting ---
const limit = rateLimit({
  ...bot.rateLimit,
  handler: (req, res, _next) => {
    const timeRemaining = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
    res.status(429).json({
      error: `Too many requests, please try again later after ${timeRemaining} seconds.`,
    });
  },
});

// --- Routes ---
route.post("/", limit, async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).send({ error: "Url is missing." });
  }
  if (!RegExp(bot.urlRegex).test(url)) {
    return res.status(422).send({ error: "URL didn't match this regex format " + bot.urlRegex });
  }
  if (await bot.bot(url)) {
    return res.send({ success: "Admin successfully visited the URL." });
  } else {
    return res.status(500).send({ error: "Admin failed to visit the URL." });
  }
});

// --- Search Route ---
app.get("/search", (req, res) => {
  const userInput = req.query.x || "";
  
  const clean = DOMPurify.sanitize(userInput, {
    ADD_ATTR: ["data-*"],
  });

  const utf16beBytes = [];
  for (let i = 0; i < userInput.length; i++) {
    const code = userInput.charCodeAt(i);
    if (code > 0xFFFF) {
      utf16beBytes.push(0xFF, 0xFD);
    } else {
      utf16beBytes.push((code >> 8) & 0xFF);
      utf16beBytes.push(code & 0xFF);
    }
  }

  const b64 = Buffer.from(Uint8Array.from(utf16beBytes)).toString('base64');

  res.render("search", { contentB64: b64 });
});

app.get("/redirect", (req, res) => {
  const url = req.query.url;
  if (url) {
    return res.redirect(url);
  }
  res.status(400).send("Missing url parameter");
});

route.get("/", (_, res) => {
  const { name } = bot;
  res.render("index", { name });
});

app.use("/", route);

// --- Start Server ---
app.listen(3000, () => {
  console.log("Server running at http://localhost:80");
});
