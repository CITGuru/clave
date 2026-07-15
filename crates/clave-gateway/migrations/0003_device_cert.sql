-- Device mTLS cert binding (doc 12 §3). The gateway mints each enrolling device a CA-signed
-- client cert; the SHA-256 fingerprint of that cert binds an inbound mTLS connection back to its
-- device row, so audit lands on the right hash chain.

ALTER TABLE device ADD COLUMN IF NOT EXISTS cert_fingerprint bytea;

CREATE UNIQUE INDEX IF NOT EXISTS device_cert_fingerprint_idx
    ON device (cert_fingerprint)
    WHERE cert_fingerprint IS NOT NULL;
