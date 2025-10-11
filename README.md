# Bootcamp/Academy Capture The Flag 2025

> Format Flag: CTFITB2025{.*}


## Specification

- Soal wave1 memiliki tingkat kesulitan Baby, Easy untuk practive materi
- Soal wave2 memiliki tingkat kesulitan Easy, Medium, Hard
- Untuk soal yang membutuhkan hosting, wajib menggunakan docker compose


## Important Dates

- **Wave 1 ~Class Round~:** 28-3 September-October 2025 (online)
- **Wave2 ~Community Quals~:** 5-12 October 2025 (online)


## First blood bot
- do
```
cp .env.example .env
```
- running without history
```
python3 bot.py --interval 10
```
- running with history
```
python bot.py --existing --interval 10
```