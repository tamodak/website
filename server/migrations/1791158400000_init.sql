-- Up Migration

-- The whole schema of the pairing server (SPEC.md §12). The server stores public keys, routing
-- links and ciphertext; nothing here can tell it who guards whom or what a message says.

CREATE TABLE devices (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256 of the labelled signing key: the phone's address (SPEC.md §3.1).
  fingerprint    bytea       NOT NULL UNIQUE CHECK (octet_length(fingerprint) = 32),
  -- The attested P-256 key, as an uncompressed point. Every request is verified with it.
  sign_pk        bytea       NOT NULL CHECK (octet_length(sign_pk) = 65),
  -- 0 software (development only), 1 TEE, 2 StrongBox.
  security_level smallint    NOT NULL CHECK (security_level BETWEEN 0 AND 2),
  -- The attestation summary of SPEC.md §5.2, kept to understand the fleet. Never used to reject.
  attestation    jsonb       NOT NULL,
  -- The Firebase Installation ID FCM reaches the phone by (SPEC.md §9), once it sent one.
  fcm_fid        text        CHECK (octet_length(fcm_fid) BETWEEN 1 AND 4096),
  created_at     timestamptz NOT NULL DEFAULT now(),
  -- Only the day, so "last seen" stays coarse even in a database dump (PLAN.md §3.11).
  last_seen_on   date        NOT NULL DEFAULT current_date
);

CREATE TABLE attestation_challenges (
  challenge  bytea       PRIMARY KEY CHECK (octet_length(challenge) = 32),
  expires_at timestamptz NOT NULL
);
CREATE INDEX attestation_challenges_expiry ON attestation_challenges (expires_at);

-- Request nonces, kept for the whole ±5 minute window so a request can't be replayed in it.
CREATE TABLE seen_nonces (
  device     uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  nonce      bytea       NOT NULL CHECK (octet_length(nonce) = 16),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (device, nonce)
);
CREATE INDEX seen_nonces_expiry ON seen_nonces (expires_at);

CREATE TABLE invites (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- HMAC of the code under a server secret, never the code itself (SPEC.md §6.1).
  code_hash         bytea       NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
  creator           uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  joiner            uuid        REFERENCES devices (id) ON DELETE CASCADE,
  state             text        NOT NULL CHECK (state IN ('open', 'joined', 'creator_revealed', 'revealed', 'linked', 'cancelled')),
  joiner_commit     bytea       CHECK (octet_length(joiner_commit) = 32),
  creator_reveal    bytea       CHECK (octet_length(creator_reveal) = 194),
  joiner_reveal     bytea       CHECK (octet_length(joiner_reveal) = 194),
  creator_confirmed boolean     NOT NULL DEFAULT false,
  joiner_confirmed  boolean     NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  -- When it reached linked or cancelled; the purge job deletes it an hour later.
  finished_at       timestamptz,
  CHECK (joiner IS NULL OR joiner <> creator)
);
CREATE INDEX invites_creator ON invites (creator);
CREATE INDEX invites_joiner ON invites (joiner);
CREATE INDEX invites_expiry ON invites (expires_at);

-- Routing permission between two phones. Undirected: the lower id first, so a pair has one row.
CREATE TABLE links (
  device_lo  uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  device_hi  uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_lo, device_hi),
  CHECK (device_lo < device_hi)
);
CREATE INDEX links_device_hi ON links (device_hi);

-- The mailbox. The sender is kept as a fingerprint, not a reference, so messages a phone sent
-- before deleting itself are still delivered (SPEC.md §5.4).
CREATE TABLE messages (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Delivery order. Internal only: the API names messages by id, so a phone can't read the
  -- server's overall message count off it.
  seq         bigint      GENERATED ALWAYS AS IDENTITY,
  recipient   uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  sender_fp   bytea       NOT NULL CHECK (octet_length(sender_fp) = 32),
  envelope    bytea       NOT NULL CHECK (octet_length(envelope) = 8240),
  received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX messages_recipient ON messages (recipient, seq);
CREATE INDEX messages_recipient_sender ON messages (recipient, sender_fp);

-- The application role reads and writes rows and nothing else. It is created by the deployment
-- (deploy/postgres/init.sh) and by the test setup; a database without it gets no grants.
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'killit_app') THEN
    GRANT USAGE ON SCHEMA public TO killit_app;
    GRANT SELECT, INSERT, UPDATE, DELETE
      ON devices, attestation_challenges, seen_nonces, invites, links, messages
      TO killit_app;
  END IF;
END
$$;

-- Down Migration

DROP TABLE messages, links, invites, seen_nonces, attestation_challenges, devices;
