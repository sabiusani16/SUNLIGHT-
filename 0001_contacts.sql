-- Run once: adds the contacts feature (safe to re-run)
-- Contacts: each row = "owner_id saved contact_id in their contact list"
CREATE TABLE IF NOT EXISTS contacts (
  owner_id INTEGER NOT NULL,
  contact_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, contact_id)   -- prevents duplicate contacts
);
CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id);
