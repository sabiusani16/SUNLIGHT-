-- Private status replies: a reply is an ordinary private message that remembers which status it answers.
-- (The Worker also adds these columns automatically; running this by hand is optional.)
ALTER TABLE messages ADD COLUMN status_id INTEGER;
ALTER TABLE messages ADD COLUMN status_snap TEXT;
