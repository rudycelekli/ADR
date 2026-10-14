PRAGMA user_version=3;
BEGIN TRANSACTION;
CREATE TABLE artifact_blocks(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, harness TEXT NOT NULL,
    session_id TEXT NOT NULL, tool TEXT NOT NULL, indicator_id TEXT NOT NULL, source_id TEXT NOT NULL,
    kind TEXT NOT NULL, generation TEXT NOT NULL, target_display TEXT NOT NULL, source TEXT NOT NULL
);
CREATE TABLE artifact_scan(
    id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL
);
CREATE TABLE audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, kind TEXT NOT NULL,
    summary TEXT NOT NULL, details TEXT NOT NULL
);
INSERT INTO "audit" VALUES(1,'2026-10-14T18:45:23.191+00:00','credential_added','Added credential: Synthetic GitHub','{"id":"06b9d91b387943baace6c939ef0caa7c"}');
INSERT INTO "audit" VALUES(2,'2026-10-14T18:45:23.191+00:00','agent_connected','Created history access: Synthetic history','{"approval_mode":"ask","history_scope":"device","project":""}');
INSERT INTO "audit" VALUES(3,'2026-10-14T18:45:23.191+00:00','synthetic','Synthetic audit entry','{"source":"fixture"}');
CREATE TABLE broker_requests(
    id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, credential_id TEXT NOT NULL,
    credential_name TEXT NOT NULL, origin TEXT NOT NULL, path TEXT NOT NULL,
    state TEXT NOT NULL, created_at TEXT NOT NULL, expires_at REAL NOT NULL,
    result TEXT, error TEXT
);
CREATE TABLE credential_session_receipts(
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL, PRIMARY KEY(session_id,run_id)
);
CREATE TABLE credentials(
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, origin TEXT NOT NULL,
    auth_type TEXT NOT NULL, header_name TEXT NOT NULL, username TEXT NOT NULL,
    allowed_paths TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL
);
INSERT INTO "credentials" VALUES('06b9d91b387943baace6c939ef0caa7c','Synthetic GitHub','https://api.github.com','bearer','Authorization','','["/user","/repos"]','active','2026-10-14T18:45:23.190+00:00');
CREATE TABLE environment_credentials(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, env_name TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE environment_run_context(
    run_id TEXT PRIMARY KEY REFERENCES environment_runs(id) ON DELETE CASCADE,
    harness TEXT NOT NULL, session_id TEXT NOT NULL, ambiguous INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE environment_runs(
    id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, state TEXT NOT NULL,
    created_at TEXT NOT NULL, exit_code INTEGER
);
CREATE TABLE grants(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    project TEXT NOT NULL, credentials TEXT NOT NULL, created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
, kind TEXT NOT NULL DEFAULT 'legacy', history_scope TEXT NOT NULL DEFAULT 'project', approval_mode TEXT NOT NULL DEFAULT 'ask');
INSERT INTO "grants" VALUES('8e6a170cda7b437c9bdd06f7af3e1589','Synthetic history','efac5de687f2a4053dcb7de41ffdd55beee14dbb339c24f20ee389ec5c0c8645','','[]','2026-10-14T18:45:23.191+00:00',0,'history','device','ask');
CREATE TABLE history_documents(
    id INTEGER PRIMARY KEY, session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    digest TEXT NOT NULL, body TEXT NOT NULL
);
INSERT INTO "history_documents" VALUES(1,'2cb7af0727f7e9516226f9540e6770f0','e30e350ab5337cc020b8e6749daced7d4db9177c490836c9aba83246545d8034','/workspace/sample
example-model
Add input validation
I checked the handler.
{"arguments":{"file_path":"app.py"},"result":"original output","tool_name":"Read"}
Add input validation

');
INSERT INTO "history_documents" VALUES(2,'7c005caa947f938076889cc4212d8790','1cbd5c9259ad4adaa4c7f68306816ab92410b2788192d5ae108886e64becdd0e','/workspace/sample
example-model
Check the parser
I checked the handler.
{"arguments":{"file_path":"app.py"},"result":"original output","tool_name":"Read"}
Check the parser

');
PRAGMA writable_schema=ON;
INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql)VALUES('table','history_search','history_search',0,'CREATE VIRTUAL TABLE history_search USING fts5(
    body, content=''history_documents'', content_rowid=''id'', tokenize=''unicode61''
)');
CREATE TABLE 'history_search_config'(k PRIMARY KEY, v) WITHOUT ROWID;
INSERT INTO "history_search_config" VALUES('version',4);
CREATE TABLE 'history_search_data'(id INTEGER PRIMARY KEY, block BLOB);
INSERT INTO "history_search_data" VALUES(1,X'0232');
INSERT INTO "history_search_data" VALUES(10,X'000000000102020002010101020101');
INSERT INTO "history_search_data" VALUES(137438953473,X'000000E20430616464010406140202707001021002087267756D656E747301020D0107636865636B656401020A01076578616D706C65010204010466696C6501020E010768616E646C657201020C01016901020902046E7075740104071401056D6F64656C01020501046E616D6501021601086F726967696E616C0102130205757470757401021401047061746801020F020179010211010472656164010217030473756C74010212010673616D706C65010203010374686501020B02036F6F6C010215010A76616C69646174696F6E010408140109776F726B73706163650102020409070D0C0C090C060A0A090D0A090609090B080810');
INSERT INTO "history_search_data" VALUES(274877906945,X'000000D2043061707002021002087267756D656E747302020D0105636865636B020406140602656402020A01076578616D706C65020204010466696C6502020E010768616E646C657202020C01016902020901056D6F64656C02020501046E616D6502021601086F726967696E616C020213020575747075740202140106706172736572020408140302746802020F020179020211010472656164020217030473756C74020212010673616D706C650202030103746865020607061002036F6F6C0202150109776F726B737061636502020204080D0B070C090C060A090D0A0C070609090B0A08');
CREATE TABLE 'history_search_docsize'(id INTEGER PRIMARY KEY, sz BLOB);
INSERT INTO "history_search_docsize" VALUES(1,X'19');
INSERT INTO "history_search_docsize" VALUES(2,X'19');
CREATE TABLE 'history_search_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
INSERT INTO "history_search_idx" VALUES(1,X'',2);
INSERT INTO "history_search_idx" VALUES(2,X'',2);
CREATE TABLE hook_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, harness TEXT NOT NULL,
    session_id TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL,
    reason TEXT NOT NULL, paths TEXT NOT NULL, rule_id TEXT
, credential_kinds TEXT NOT NULL DEFAULT '[]', phase TEXT NOT NULL DEFAULT 'pre', approval_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE prompt_blocks(
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
    harness TEXT NOT NULL, kinds TEXT NOT NULL, aliases TEXT NOT NULL
);
CREATE TABLE rules(
    id TEXT PRIMARY KEY, path TEXT NOT NULL, action TEXT NOT NULL,
    kind TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE security_review_jobs(
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL,
    digest TEXT NOT NULL, detector TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
    created_at TEXT NOT NULL, created_epoch REAL NOT NULL, finished_at TEXT,
    state TEXT NOT NULL, automatic INTEGER NOT NULL, token_charge INTEGER NOT NULL,
    cost_charge INTEGER NOT NULL, tokens INTEGER, cost_usd REAL, error TEXT,
    coverage TEXT NOT NULL, report TEXT, provider_session_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE security_review_quota(
    provider TEXT PRIMARY KEY, observation TEXT NOT NULL
);
CREATE TABLE security_review_quota_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL,
    observed_epoch REAL NOT NULL, observation TEXT NOT NULL
);
CREATE TABLE session_metadata(
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    parent_id TEXT NOT NULL, forked_from_id TEXT NOT NULL, agent_label TEXT NOT NULL,
    native_title TEXT NOT NULL, kind TEXT NOT NULL
);
INSERT INTO "session_metadata" VALUES('2cb7af0727f7e9516226f9540e6770f0','','','','','conversation');
INSERT INTO "session_metadata" VALUES('7c005caa947f938076889cc4212d8790','2cb7af0727f7e9516226f9540e6770f0','','','','subagent');
CREATE TABLE session_retrieval(
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    digest TEXT NOT NULL, started_at TEXT NOT NULL, activity_at TEXT NOT NULL,
    source TEXT NOT NULL, project TEXT NOT NULL, index_version INTEGER NOT NULL
);
INSERT INTO "session_retrieval" VALUES('2cb7af0727f7e9516226f9540e6770f0','e30e350ab5337cc020b8e6749daced7d4db9177c490836c9aba83246545d8034','2026-09-30T10:00:00.000+00:00','2026-09-30T10:00:00.000+00:00','claude','/workspace/sample',2);
INSERT INTO "session_retrieval" VALUES('7c005caa947f938076889cc4212d8790','1cbd5c9259ad4adaa4c7f68306816ab92410b2788192d5ae108886e64becdd0e','2026-09-30T10:00:00.000+00:00','2026-09-30T10:00:00.000+00:00','claude','/workspace/sample',2);
CREATE TABLE session_tools(
    session_id TEXT NOT NULL, name TEXT NOT NULL, count INTEGER NOT NULL,
    PRIMARY KEY(session_id,name)
);
INSERT INTO "session_tools" VALUES('2cb7af0727f7e9516226f9540e6770f0','Read',1);
INSERT INTO "session_tools" VALUES('7c005caa947f938076889cc4212d8790','Read',1);
CREATE TABLE sessions(
    id TEXT PRIMARY KEY, source TEXT NOT NULL, source_session_id TEXT NOT NULL,
    project TEXT NOT NULL, model TEXT NOT NULL, title TEXT NOT NULL,
    occurred_at TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    message_count INTEGER NOT NULL, tool_count INTEGER NOT NULL,
    token_usage TEXT, digest TEXT NOT NULL, partial INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "sessions" VALUES('2cb7af0727f7e9516226f9540e6770f0','claude','one','/workspace/sample','example-model','Add input validation','2026-09-30T10:00:00.000+00:00','2026-10-14T18:45:23.189+00:00','2026-10-14T18:45:23.189+00:00',2,1,NULL,'e30e350ab5337cc020b8e6749daced7d4db9177c490836c9aba83246545d8034',0);
INSERT INTO "sessions" VALUES('7c005caa947f938076889cc4212d8790','claude','two','/workspace/sample','example-model','Check the parser','2026-09-30T10:00:00.000+00:00','2026-10-14T18:45:23.190+00:00','2026-10-14T18:45:23.190+00:00',2,1,NULL,'1cbd5c9259ad4adaa4c7f68306816ab92410b2788192d5ae108886e64becdd0e',0);
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO "settings" VALUES('recording','false');
INSERT INTO "settings" VALUES('interval_seconds','300');
INSERT INTO "settings" VALUES('history_days','14');
INSERT INTO "settings" VALUES('protection_enabled','true');
INSERT INTO "settings" VALUES('opaque_tools','"ask"');
INSERT INTO "settings" VALUES('inventory_enabled','false');
INSERT INTO "settings" VALUES('onboarding_complete','false');
INSERT INTO "settings" VALUES('review_preferences','{"allow_paid":false,"background":false,"consented":false,"daily_cost_usd":2.0,"daily_jobs":5,"daily_tokens":50000,"idle_minutes":15,"max_cost_usd":0.5,"max_seconds":180,"max_tokens":12000,"mode":"budget","model":"","projects":[],"provider":"claude","reserve_percent":35,"reset_within_hours":4,"revision":"9471d1e0e9ed43d892cef2576d038a48"}');
CREATE TABLE snapshots(
    digest TEXT PRIMARY KEY, session_id TEXT NOT NULL, received_at TEXT NOT NULL, payload BLOB NOT NULL
);
INSERT INTO "snapshots" VALUES('e30e350ab5337cc020b8e6749daced7d4db9177c490836c9aba83246545d8034','2cb7af0727f7e9516226f9540e6770f0','2026-10-14T18:45:23.189+00:00',X'789C4D504B4FC3300CFE2B95CFED568684446F1CB9224EA0AA328959C3F252E20055D5FF8E338686948B3F7FAF780535234FB3C91CD202C3EB0A2A7826CF30C083D68DF1B170F389D66864133CB4908225D9964C49260EC166118E5BFB5FFBD8A899D48974C33335337A6D29EDAE6ACC593251B8578B15301D8B13039956783796A6883C577A8CBBB8C0267ACAC5D68490CCD178B44D282C1D2F3E934757FD9F08356CE336B6E082262B107DA38B96BADFB98598C20729FE8BD87F8574CA1115EDF39928944C5233F8C9E81AE8CF502849D50465B1E88AB071245F7151C0437FB8EBFAFBEEB67FBEE987BEBE17A1D45B5D8AE5C5CB45D8A80A97B371899913A1EBC4E54D0A0AB8FD0012518B07');
INSERT INTO "snapshots" VALUES('1cbd5c9259ad4adaa4c7f68306816ab92410b2788192d5ae108886e64becdd0e','7c005caa947f938076889cc4212d8790','2026-10-14T18:45:23.190+00:00',X'789C5550C14EC3300CFD952AE776942121B12B27AE881368AABCD4AC65491C258EB6A9EABF63779B06522E7E79EFF9F94DC60EC0DD3066A674369BAFC9580A8C81CDC6BC0E680F150F5845481993A94D2287F2532E1313B92CA2ED5CFFD5BD555695D82FDA0142EF30ADEE6AC859F68170EF169381B42F5E0C649ACCF7E8B08BC083D2635CC5B399458FB938DD4069DC8F015C458563B9F97401BCFABF23F466DECEDBDA78EAD1098427F0D16173996B1313FDA0E5DB8A8723A5438E60F1212F44A164949814BAE5AE136B2AD84BBECEC1EEEA191DA5A508E9477F6E92B1D78C0135F33F8C8FA4CE5492D5A0D641E975178F1EA5111F055CB7EBE7A67D699EDA8FC776D3EAFB148A567EBD2F9F8314CBA355B82CC625664E08BE11979DDC29E0FC0BC51EA35B');
CREATE INDEX snapshot_session ON snapshots(session_id,received_at DESC);
CREATE INDEX session_recent ON sessions(occurred_at DESC,id);
CREATE INDEX session_project ON sessions(project,occurred_at DESC);
CREATE INDEX hook_recent ON hook_events(timestamp DESC);
CREATE INDEX broker_pending ON broker_requests(state,created_at);
CREATE TRIGGER history_search_insert AFTER INSERT ON history_documents BEGIN
    INSERT INTO history_search(rowid,body) VALUES (new.id,new.body);
END;
CREATE TRIGGER history_search_delete AFTER DELETE ON history_documents BEGIN
    INSERT INTO history_search(history_search,rowid,body) VALUES ('delete',old.id,old.body);
END;
CREATE TRIGGER history_search_update AFTER UPDATE ON history_documents BEGIN
    INSERT INTO history_search(history_search,rowid,body) VALUES ('delete',old.id,old.body);
    INSERT INTO history_search(rowid,body) VALUES (new.id,new.body);
END;
CREATE INDEX session_parent ON session_metadata(parent_id);
CREATE INDEX credential_receipt_run ON credential_session_receipts(run_id);
CREATE INDEX session_activity_recent ON session_retrieval(activity_at DESC,session_id);
CREATE INDEX session_activity_project ON session_retrieval(project,activity_at DESC,session_id);
CREATE INDEX session_activity_source ON session_retrieval(source,activity_at DESC,session_id);
CREATE INDEX session_activity_scope
    ON session_retrieval(project,source,activity_at DESC,session_id);
CREATE INDEX hook_intervention_recent ON hook_events(id DESC)
               WHERE decision IN ('deny','ask') OR approval_requested=1;
CREATE INDEX review_recent ON security_review_jobs(created_epoch DESC);
CREATE INDEX review_snapshot ON security_review_jobs(session_id,digest,detector);
PRAGMA writable_schema=OFF;
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('audit',3);
COMMIT;
