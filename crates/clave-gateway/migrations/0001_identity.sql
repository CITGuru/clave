-- Clave control-plane identity schema (doc 15 §3).
-- Invitation expiry is stored as bigint epoch seconds to match `clave_identity::UnixTime` (the
-- pure core compares it directly); bookkeeping timestamps use timestamptz.

CREATE TABLE IF NOT EXISTS workspace (
    id              bigint PRIMARY KEY,
    name            text        NOT NULL DEFAULT '',
    workos_org_id   text        UNIQUE,
    allowed_domains text[]      NOT NULL DEFAULT '{}',
    sso_mode        text        NOT NULL DEFAULT 'optional',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_user (
    id          bigserial   PRIMARY KEY,
    email       text        UNIQUE NOT NULL,   -- stored normalized (lower-cased)
    idp_user_id text,                          -- WorkOS user id, null until first login
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS membership (
    workspace_id bigint      NOT NULL REFERENCES workspace(id),
    user_id      bigint      NOT NULL REFERENCES app_user(id),
    role         text        NOT NULL,         -- 'owner' | 'admin' | 'member'
    status       text        NOT NULL,         -- 'invited' | 'active' | 'suspended'
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitation (
    workspace_id bigint  NOT NULL REFERENCES workspace(id),
    email        text    NOT NULL,             -- stored normalized
    role         text    NOT NULL,
    expires_at   bigint  NOT NULL,             -- epoch seconds
    accepted     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (workspace_id, email)
);

CREATE TABLE IF NOT EXISTS device (
    id             uuid        PRIMARY KEY,
    workspace_id   bigint      NOT NULL REFERENCES workspace(id),
    enrolled_by    bigint      NOT NULL REFERENCES app_user(id),
    device_pubkey  bytea       NOT NULL,       -- Ed25519, the runtime trust anchor
    status         text        NOT NULL,       -- 'pending' | 'active' | 'locked' | 'wiped'
    policy_version bigint,
    enrolled_at    timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz,
    -- One row per (workspace, key): re-enrolling the same device key is idempotent, not a duplicate.
    UNIQUE (workspace_id, device_pubkey)
);
