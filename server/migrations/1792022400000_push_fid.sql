-- Up Migration

-- FCM reaches a phone by its Firebase Installation ID since firebase-messaging 26 (SPEC.md §9):
-- the column holds that id, not a registration token.
ALTER TABLE devices RENAME COLUMN fcm_token TO fcm_fid;

-- Down Migration

ALTER TABLE devices RENAME COLUMN fcm_fid TO fcm_token;
