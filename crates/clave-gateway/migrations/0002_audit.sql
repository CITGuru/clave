-- Clave audit persistence (doc 10 §6). The gateway's AuditLedger verifies each device's
-- hash-chained batch on ingest; these tables are the durable backing for the verified chain
-- position, the admitted events, and the suppression/tamper alerts surfaced to the console.

CREATE TABLE IF NOT EXISTS audit_chain (
    device_id  uuid        PRIMARY KEY REFERENCES device(id),
    next_seq   bigint      NOT NULL DEFAULT 1,   -- next expected device-local sequence number
    head       bytea       NOT NULL,             -- current tamper-evident chain head hash
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_event (
    id          bigserial   PRIMARY KEY,
    device_id   uuid        NOT NULL REFERENCES device(id),
    seq         bigint      NOT NULL,             -- device-local sequence number
    ts          bigint      NOT NULL,             -- event epoch seconds
    zone        text        NOT NULL,
    action      text        NOT NULL,
    verdict     text        NOT NULL,
    app_id      text,                             -- work app that triggered the event, if known
    ingested_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, seq)
);

CREATE TABLE IF NOT EXISTS audit_alert (
    id        bigserial   PRIMARY KEY,
    device_id uuid        NOT NULL REFERENCES device(id),
    kind      text        NOT NULL,              -- 'gap' | 'tampered' | 'bad_signature'
    detail    text        NOT NULL,
    raised_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_event_device_seq ON audit_event (device_id, seq);
