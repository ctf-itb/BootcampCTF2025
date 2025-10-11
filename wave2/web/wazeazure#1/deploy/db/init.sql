CREATE TABLE IF NOT EXISTS images (
  id SERIAL PRIMARY KEY,
  filename TEXT NOT NULL,
  title TEXT DEFAULT '(no title)',
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO images (filename, title, content_type, size_bytes)
VALUES
  ('1.webp', 'Example Image 1', 'image/webp', 1),
  ('2.webp', 'Example Image 2', 'image/webp', 1),
  ('3.webp', 'Example Image 3', 'image/webp', 1),
  ('4.webp', 'Example Image 4', 'image/webp', 1),
  ('5.webp', 'Example Image 5', 'image/webp', 1),
  ('6.webp', 'Example Image 6', 'image/webp', 1),
  ('7.webp', 'Example Image 7', 'image/webp', 1),
  ('2.webp', 'Example Image 8', 'image/webp', 1),
  ('5.webp', 'Example Image 9', 'image/webp', 1),
  ('3.webp', 'Example Image 10', 'image/webp', 1);