ALTER TABLE endpoints ADD COLUMN identity_context TEXT NOT NULL DEFAULT '';
ALTER TABLE parameters ADD COLUMN identity_context TEXT NOT NULL DEFAULT '';
