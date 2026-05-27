package store

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
	id         INTEGER PRIMARY KEY,
	name       TEXT    NOT NULL,
	source     TEXT    NOT NULL,
	orig_index BLOB    NOT NULL UNIQUE,
	orig_ct    BLOB    NOT NULL,
	mask       TEXT    NOT NULL UNIQUE,
	shape      TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	last_used  INTEGER NOT NULL,
	hits       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_secrets_mask ON secrets(mask);

CREATE TABLE IF NOT EXISTS requests (
	id          INTEGER PRIMARY KEY,
	ts          INTEGER NOT NULL,
	provider    TEXT    NOT NULL,
	host        TEXT    NOT NULL,
	method      TEXT    NOT NULL,
	path        TEXT    NOT NULL,
	status      INTEGER NOT NULL DEFAULT 0,
	sse         INTEGER NOT NULL DEFAULT 0,
	masked      INTEGER NOT NULL DEFAULT 0,
	unmasked    INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	err         TEXT    NOT NULL DEFAULT '',
	req_body    BLOB    NOT NULL DEFAULT x'',
	resp_body   BLOB    NOT NULL DEFAULT x'',
	req_body_codec    TEXT    NOT NULL DEFAULT '',
	resp_body_codec   TEXT    NOT NULL DEFAULT '',
	req_body_raw_len  INTEGER NOT NULL DEFAULT 0,
	resp_body_raw_len INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS request_secrets (
	request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
	secret_id  INTEGER NOT NULL REFERENCES secrets(id)  ON DELETE CASCADE,
	direction  TEXT    NOT NULL,
	PRIMARY KEY (request_id, secret_id, direction)
);

CREATE TABLE IF NOT EXISTS events (
	id     INTEGER PRIMARY KEY,
	ts     INTEGER NOT NULL,
	kind   TEXT    NOT NULL,
	detail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
`
