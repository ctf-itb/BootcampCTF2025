const express = require('express');
const path = require('path');
const bot_router = require("./bot/index")
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 6971;
const FLAG = process.env.FLAG || 'CTFITB2025{FAKE_FLAG_DONT_SUBMIT}'

app.use(express.urlencoded({ extended: false }))
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use("/report", bot_router)

app.get('/', (req, res) => {
    res.render('index', { title: 'wikiOwO - Learn How to Do Anything' });
});

app.get('/flag', cors(), (req, res) => {
    if (!req.socket.remoteAddress?.includes("127.0.0.1") && !req.socket.remoteAddress?.includes("::1") && !req.socket.remoteAddress?.includes("172.22.0.1")) {
        console.warn(`[IP] ${req.socket.remoteAddress} accessing dashboard`);
        res.status(400).json({ message: "Invalid IP" });
        return;
    }

    res.json({
        flag: FLAG,
        msg: "Eyyyyy congrats man."
    });
});

app.get('/setup-an-attack-server', (req, res) => {
    res.render('tutorial1', { title: 'How to Setup an Attack Server - wi`kiOwO' });
});

app.get('/how-to-create-a-revshell', (req, res) => {
    res.render('tutorial2', { title: 'How to Create a Reverse Shell - wikiOwO' });
});

app.use((req, res) => {
    res.status(404).render('404', { title: 'Page Not Found - wikiOwO' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});