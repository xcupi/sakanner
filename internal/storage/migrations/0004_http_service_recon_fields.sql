ALTER TABLE http_services ADD COLUMN redirect_chain TEXT NOT NULL DEFAULT '[]';
ALTER TABLE http_services ADD COLUMN tls_version TEXT NOT NULL DEFAULT '';
ALTER TABLE http_services ADD COLUMN tls_self_signed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE http_services ADD COLUMN tls_sans TEXT NOT NULL DEFAULT '[]';
