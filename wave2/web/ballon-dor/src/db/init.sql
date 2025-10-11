CREATE DATABASE IF NOT EXISTS ballon CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE ballon;

DROP TABLE IF EXISTS players;

CREATE TABLE players (
  name TEXT,
  year INTEGER,
  club TEXT,
  description TEXT
);

INSERT INTO players (name, year, club, description) VALUES
('Cristiano Ronaldo', 2017, 'Real Madrid', "Cristiano Ronaldo claimed his fifth Ballon d'Or in 2017 after an extraordinary calendar year that included leading Real Madrid to a La Liga and UEFA Champions League double, scoring 42 league goals and 12 in the Champions League, with pivotal strikes in the UCL final against Juventus."),
('Lionel Messi', 2021, 'Paris Saint-Germain F.C.', "Lionel Messi secured his seventh Ballon d'Or in 2021, largely for captaining Argentina to their first Copa América title in 28 years, where he was the top scorer with 4 goals and 5 assists, earning Player of the Tournament honors, alongside a stellar La Liga season at Barcelona with 38 goals and 14 assists."),
('Karim Benzema', 2022, 'Real Madrid', "Karim Benzema won his maiden Ballon d'Or in 2022 following a prolific season at Real Madrid, where he netted 44 goals across all competitions, clinched the UEFA Champions League and La Liga titles, and claimed the European Golden Shoe as Europe's top scorer."),
('Lionel Messi', 2023, 'Inter Miami', "Messi lifted his eighth Ballon d'Or in 2023 after masterminding Argentina's World Cup triumph in Qatar, earning the Golden Ball as the tournament's best player with 7 goals and 3 assists, complemented by 21 goals and 20 assists in a strong debut season at PSG."),
('Rodri', 2024, 'Manchester City', "Rodri became the first midfielder to win the Ballon d'Or in 2024, anchoring Manchester City's Premier League success and captaining Spain to Euro 2024 glory as Player of the Tournament, with 12 goals and 15 assists across 63 appearances for club and country."),
('Ousmane Dembélé', 2025, 'Paris Saint-Germain F.C.', "Ousmane Dembélé earned the 2025 Ballon d'Or through a breakout redemption season at PSG, ranking in the 99th-100th percentile for chances created, progressive carries, and shots, while delivering decisive goals in major trophies and transforming into a world-class creator."),
('Lamine Yamal', 2026, 'Barcelona', "¿Y qué fue? (¿Y qué fue?), no hiciste na' (no hiciste na') Con tanta chapa vo'a hacerle ran-kitikan, kinkan. CTFITB2025{YANG_LAGI_VIRAL!!DJ_LAMINE_YAMAL_Y_QUE_FUE_X_DIGEBOY_VIRAL_TIKTOK_YANG_KALIAN_CARI_CARI}");