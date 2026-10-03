# Audit Logging API Specification

Contract an API server must implement so that **unmodified upstream RustDesk
clients** produce complete audit logs, plus the admin read API used by
RustDesk Pro tooling.

Implementation status of this repo: §14.

**Sources**

| Source | Used for | Reference |
|---|---|---|
| Upstream client `rustdesk/rustdesk` | Ground truth for every client → server call | master @ `58ff78a82`, hbb_common @ `229b9045` |
| Upstream PR #15759 (`7eb915011`) "Audit retry nonce" | Response / retry / nonce contract | commit message |
| Upstream PR #15407 (`989bf80fe`) "controller user attribution" | `conn_audit_ref` flow | commit message |
| `res/audits.py` (upstream) | Admin read API (`/api/audits/*`) | official Pro API script |
| RustDesk Pro docs — [Audit Logs](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/audit-logs/), [Console](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/console/), [Admin Role](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/admin-role/) | Event catalogue, UI columns, retention, permissions | doc.rustdesk.com @ `6fb9f56` |

RustDesk Pro publishes **no OpenAPI / REST reference**. Client-facing endpoints
(§2–§8, §10–§11) are derived from client code only; the admin read API (§9) from
`audits.py` only.

Marking: **[C]** verified in upstream client code, **[PR]** stated in an
upstream PR message, **[D]** documented in Pro docs, **[S]** from `audits.py`,
**[I]** inference — not verifiable without Pro server source.

---

## 1. Overview

```
 controlling client                hbbs                     controlled client            api-server
 ──────────────────                ────                     ─────────────────            ──────────
 PunchHoleRequest{token} ───────▶  resolve token → user
                                   PunchHole/RequestRelay/
                                   FetchLocalAddr
                                   {controlled_context:
                                    conn_audit_ref} ──────▶
                                                            on_open
                                                            POST /api/audit/conn {action:new, conn_audit_ref} ──▶
                                                            login ok
                                                            POST /api/audit/conn {peer,type,...}              ──▶
 GET /api/audit/conn/active ─────────────────────────────────────────────────────────────────────────────────▶
     ◀──────────────────────────────────────────────────────────────────────────────────── "guid"
                                                            file / clipboard files
                                                            POST /api/audit/file                               ──▶
                                                            security events
                                                            POST /api/audit/alarm                              ──▶
 POST /api/audit/conn {id,session_id,note}  (menu note) ─────────────────────────────────────────────────────▶
                                                            loop exit
                                                            POST /api/audit/conn {action:close}                ──▶
 PUT  /api/audit {guid,note}  (end-of-session note) ─────────────────────────────────────────────────────────▶
```

| # | Endpoint | Sender | Auth header | Purpose |
|---|---|---|---|---|
| §3 | `POST /api/audit/conn` | controlled (Rust) | none | connection lifecycle: new / authorized / close |
| §4 | `POST /api/audit/conn` (note body) | controlling (Rust) | none | note typed during session |
| §5 | `POST /api/audit/file` | controlled (Rust) | none | file transfer & clipboard-file events |
| §6 | `POST /api/audit/alarm` | controlled (Rust) | none | security alarms |
| §7 | `GET /api/audit/conn/active` | controlling (Flutter) | Bearer | fetch conn log GUID for end-of-session note |
| §8 | `PUT /api/audit` | controlling (Flutter) | Bearer | end-of-session note by GUID |
| §9 | `GET /api/audits/{conn,file,alarm,console}` | admin tooling / console | Bearer | query logs |
| §10 | `POST /api/heartbeat` (existing) | controlled | none | web-console disconnect by `conn_id` |
| §11 | hbbs `ControlledContext` | hbbs | — | controller-user attribution |

---

## 2. Common transport contract

### 2.1 Base URL and when audit is off [C]

`get_audit_server(api, custom, typ)` → `"{api_server}/api/audit/{typ}"` (`src/common.rs`).
Audit is **disabled client-side** (no request sent) when:

- API server resolves empty: `register-device=N` builtin option, or neither
  `api-server` nor `custom-rendezvous-server` set. Fallback when only the
  rendezvous server is set: `http://<rendezvous-host>:21114`.
- API server host is `rustdesk.com` or `*.rustdesk.com`.
- Controlling side only: user is not logged in (empty `access_token`).

### 2.2 Request format [C]

- `Content-Type: application/json`, UTF-8 JSON body.
- Rust-side audit POSTs (§3–§6) send **no `Authorization` header**. The
  controlled device is generally not logged in. The server must accept them
  unauthenticated (see §12.1 for validation policy).
- Flutter calls (§7, §8) send `Authorization: Bearer <access_token>`.
- Transport: 12 s timeout per attempt; TLS retry variants; on transport error
  or 5xx a single fallback via the hbbs raw-TCP proxy. With
  `USE_RAW_TCP_FOR_API=Y` and WebSocket off the TCP proxy is used directly.
  The server may therefore see the same request via a reverse proxy **and**
  via hbbs's TCP proxy.

### 2.3 Response contract for §3, §5, §6 [C][PR]

Implemented in `Connection::post_audit_async`. **Success is a 2xx with an
empty (or whitespace-only) body.**

| Server response | Client behaviour |
|---|---|
| 2xx, empty body | stored — done |
| 2xx, `{"error": "<non-empty>"}` | retry |
| 2xx, any other non-empty body | retry ("unexpected response body") |
| 5xx, 408, 429 | retry |
| other 4xx | drop immediately, error logged |
| transport error | retry |

Retry schedule: max 3 attempts, backoff 10 s then 30 s, no attempt started
after 120 s; last attempt lands by ≈204 s.

### 2.4 Nonce deduplication [C][PR]

Every §3/§5/§6 record carries `nonce` (UUIDv4, unique per record, stable
across that record's retries). The server must:

1. Remember each nonce for **≥ 5 minutes** (client bounds its retry window
   to fit inside 300 s).
2. Answer a duplicate nonce as **already stored** (2xx, empty body).
3. Answer a **concurrent** duplicate (first attempt still being written) as
   stored, not as an error [PR].
4. **Release the nonce if the write fails**, and answer `{"error": ...}` (or
   5xx) so the retry stores the record.

Records from older clients may carry an empty or missing `nonce`; they must be
stored without dedup. Note body (§4) has no nonce.

### 2.5 Ordering [C]

- Conn records (§3) for one connection are sent **sequentially** through a
  per-connection queue; each waits for the previous one's retries. Order
  `new` → `authorized` → `close` is guaranteed per connection, but a slow
  server response delays later records.
- File (§5) and alarm (§6) posts are fire-and-forget tasks, **not** ordered
  relative to conn records. A file or alarm record may arrive before the
  `authorized` conn record.

### 2.6 Common identity fields [C]

| Field | Type | Meaning |
|---|---|---|
| `id` | string | controlled device's RustDesk ID |
| `uuid` | string | base64 of controlled device hardware UUID (same as heartbeat/sysinfo) |
| `conn_id` | integer (i32) | per-process connection counter on the controlled device. Unique only within one process lifetime **[I]**; same value as heartbeat `conns` |
| `session_id` | integer (**u64**) | controller's random session id; full 64-bit range. Must be parsed as unsigned 64-bit, never float/i64 |
| `nonce` | string | see §2.4 |

**Connection key.** `(id, uuid, conn_id)` identifies one connection across
its `new` / `authorized` / `close` / file / alarm records **[I]** (the only
fields present on all of them). A controlled-process restart resets
`conn_id`, so a server should prefer the most recent not-closed row for the
key.

---

## 3. `POST /api/audit/conn` — connection lifecycle

Sent by the controlled device. Three record kinds, distinguished by body shape.

### 3.1 `new` — connection opened (before login) [C]

Trigger: `on_open`, after IP-whitelist and "only-conn-window-open" checks pass.
Rejected connections send no `new` (IP whitelist rejection sends alarm 0).

```json
{
  "action": "new",
  "ip": "203.0.113.5",
  "conn_audit_ref": "<opaque, optional>",
  "id": "123456789", "uuid": "<b64>", "conn_id": 17,
  "session_id": 0,
  "nonce": "<uuidv4>"
}
```

- `ip`: controller's IP as seen by the controlled device (IPv4-mapped IPv6
  normalised to IPv4). Relay connections report the relay's view **[I]**.
- `session_id` is always `0` here (LoginRequest not yet received).
- `conn_audit_ref`: present only if non-empty; see §11.

Server: create a conn log row, `start_time = now`, no type yet ("Not Logged
In" [D][S]). If `conn_audit_ref` resolves, cache the controller-user snapshot
keyed by the connection key for later file/alarm attribution [PR].

### 3.2 `authorized` — login succeeded [C]

No `action` field. Recognised by presence of `peer` / `type`.

```json
{
  "peer": ["987654321", "alice-laptop"],
  "type": 0,
  "primary_auth": 2,
  "two_factor": 1,
  "id": "...", "uuid": "...", "conn_id": 17,
  "session_id": 18446744073709551615,
  "nonce": "..."
}
```

| Field | Values |
|---|---|
| `peer` | `[controller_id, controller_name]` (2-element array) |
| `type` | 0 remote desktop, 1 file transfer, 2 port forward (incl. RDP), 3 view camera, 4 terminal |
| `primary_auth` (omitted if none) | 1 click-accept, 2 temporary password, 3 permanent password, 4 switch sides |
| `two_factor` (omitted if none) | 1 TOTP, 2 trusted device. Always absent when `primary_auth` is 1 or 4 |

Server: update the row matching the connection key: set `conn_type`,
controller peer id/name, `session_id`, authentication fields.
If no `new` row exists (e.g. it was dropped), create one **[I]**.

Maps to Pro console "Authentication" column [D]: Click Confirmation,
One-time Password, Permanent Password, Switch Sides; 2FA Code, Trusted Device.

### 3.3 `close` — connection ended [C]

```json
{ "action": "close", "id": "...", "uuid": "...", "conn_id": 17, "session_id": <u64 or 0>, "nonce": "..." }
```

Sent for every connection that passed `on_open`, authorized or not. **Carries
no `conn_audit_ref`, and its nonce differs from the `new` record's.** Server
must match by connection key and set `end_time = now`.

### 3.4 Unknown shapes

A body with an unrecognised `action` should be answered 2xx empty (don't make
the client retry a record it will never be able to fix) and logged **[I]**.

---

## 4. `POST /api/audit/conn` — note from the session menu [C]

Sent by the **controlling** client (Rust `send_note`) when the user picks
"Note" in the session toolbar (Flutter: visible when not
`disable-account`, forces login; Sciter: visible when audit URL non-empty).

```json
{ "id": "<controlled peer id, may contain @server suffix>", "session_id": <u64>, "note": "text" }
```

- No `action`, `nonce`, `uuid`, `conn_id`; no auth header.
- Single attempt (plain `post_request`), response ignored.
- Recognised by presence of `note` and absence of `action` / `conn_id`.

Server: attach `note` to the conn row(s) with device `id` (strip any
`@server` suffix **[I]**) and `session_id`, preferring the most recent. The
random u64 `session_id` is the only proof of participation **[I]**.

---

## 5. `POST /api/audit/file` — file transfer and clipboard files [C]

```json
{
  "id": "<controlled id>", "uuid": "<b64>",
  "peer_id": "<controller id>",
  "conn_id": 17,
  "type": 0,
  "path": "/home/bob/Documents",
  "is_file": false,
  "info": "{\"ip\":\"203.0.113.5\",\"name\":\"alice-laptop\",\"num\":42,\"files\":[[\"a.pdf\",1048576],[\"b.txt\",12]]}",
  "nonce": "<uuidv4>"
}
```

| Field | Meaning |
|---|---|
| `type` | 0 `RemoteSend` (controlled → controller, download), 1 `RemoteReceive` (controller → controlled, upload) |
| `path` | directory / file path on the controlled device; `""` for clipboard file copy; `"Remote print"` for printer jobs |
| `is_file` | true iff a single file was transferred (one entry with empty name) |
| `info` | **JSON-encoded string**: `ip`, `name` (controller name), `num` (total file count), `files` (≤10 `[name, size]` pairs, largest first; names relative to `path`) |

Triggers (all **[C]**, `src/server/connection.rs`):

| Event | `type` | `path` |
|---|---|---|
| controller uploads files (`FileAction::Receive`) | 1 | destination dir |
| controller downloads files / printer job | 0 | source path / `"Remote print"` |
| controller pastes clipboard files into this device | 1 | `""` |
| this device's clipboard files served to controller (unix / Windows CM) | 0 | `""` |

Server: store; attribute controller user via cached snapshot for
`(id, conn_id)` [PR]. Pro console shows direction, file path, size or count,
top-10 files [D].

---

## 6. `POST /api/audit/alarm` — security alarms [C]

```json
{
  "id": "<controlled id>", "uuid": "<b64>",
  "typ": 1,
  "info": "{\"ip\":\"203.0.113.5\",\"id\":\"987654321\",\"name\":\"alice\"}",
  "conn_id": 17,
  "nonce": "<uuidv4>",
  "conn_audit_ref": "<only for typ 0 and 10, if non-empty>"
}
```

Field is **`typ`**, not `type`. `info` is a JSON-encoded string.

| `typ` | Name | Trigger | `info` | Source |
|---|---|---|---|---|
| 0 | IpWhitelist | controller IP not in `whitelist` (before login) | `{ip}` | [C][D][S] |
| 1 | ExceedThirtyAttempts | >30 failed attempts from IP | `{ip,id,name}` | [C][D][S] |
| 2 | SixAttemptsWithinOneMinute | >6 failures within a minute | `{ip,id,name}` | [C][D][S] |
| 3 | Over 30 consecutive **login** attempts | account login (server-side) | — | [D][S], not sent by client |
| 4 | Multiple login attempts within one minute | account login (server-side) | — | [D][S], not sent by client |
| 5 | Multiple login attempts within one hour | account login (server-side) | — | [D][S], not sent by client |
| 6 | ExceedIPv6PrefixAttempts | IPv6 /64 >60, /56 >80, /48 >100 failures | `{ip,id,name}` | [C][D] |
| 7 | TerminalOsLoginBackoff | terminal OS-credential login blocked by backoff | `{ip,id,name}` | [C]; doc wording mapping [I] |
| 8 | TerminalOsLoginConcurrency | Windows terminal OS login concurrency gate busy | `{ip,id,name}` | [C]; doc wording mapping [I] |
| 9 | SessionScopeViolation | out-of-scope message in session, only if `allow-scope-violation-alarm=Y` | `{id,name,ip,conn_type,message}` | [C][D] |
| 10 | IdWhitelist | controller ID not in `id-whitelist` | `{id,ip,name}` | [C] only (not in Pro docs) |

Alarm 9 `conn_type` ∈ `remote|file_transfer|port_forward|view_camera|terminal|unknown`;
`message` is the offending message family (e.g. `key_event`, `file_action`,
`misc.chat_message`).

Alarms 3–5 are generated **by the API server** on user-account login
failures (`POST /api/login`), not posted by clients [D][S].

Server: store; resolve controller user from `conn_audit_ref` (typ 0, 10) or
cached snapshot via `(id, conn_id)` [PR]. Pro console columns: Type, From
(controller / login device), Target (controlled device / account), Time [D].

---

## 7. `GET /api/audit/conn/active` — fetch conn log GUID [C]

Sent by the controlling Flutter client after each connect (peer-info
event), only when all hold: not `disable-account`; logged in; non-public API
server; local option `allow-ask-for-note=Y` (default off).

```
GET /api/audit/conn/active?id=<peer id>&session_id=<u64 decimal>&conn_type=<0..4>
Authorization: Bearer <token>
```

`conn_type` uses §3.2 values (RDP maps to 2).

| Response | Client behaviour |
|---|---|
| 200, JSON string `"<guid>"` non-empty | stored as the session's audit GUID |
| 200, `null` or `""` | retry (up to 6 attempts, 1-1-2-2-3 s apart) |
| 200, non-string JSON / invalid JSON | retry |
| non-200 | give up immediately |

The retries exist because this races the controlled side's `authorized`
record (§3.2), which is the first to carry `session_id` and `type`.

Server: find the not-closed conn row with device `id`, `session_id`,
`conn_type`; return its GUID as a JSON string, else `""` with 200 **[I]**.
Should verify the bearer token is valid, and **[I]** that the caller is the
controller of that row (controller user or `peer` id).

---

## 8. `PUT /api/audit` — end-of-session note by GUID [C]

Shown on session close when `allow-ask-for-note=Y`, a GUID was obtained (§7),
and no note was already sent via §4 in this connection.

```
PUT /api/audit
Authorization: Bearer <token>
{ "guid": "<from §7>", "note": "text" }
```

Only sent for non-empty notes; 6 s timeout; 200 = success, anything else
logged, no retry. Note: URL is `{api_server}/api/audit`, not under
`/api/audit/conn`.

Server: authenticate; set `note` on the row with that GUID **[I]** (should
check the caller is its controller).

---

## 9. Admin read API — `GET /api/audits/{kind}` [S][D]

`kind` ∈ `conn`, `file`, `alarm`, `console`. Bearer token with **Audit Log**
permission.

### 9.1 Query parameters [S]

| Param | Kinds | Notes |
|---|---|---|
| `current` | all | page number, 1-based, default 1 |
| `pageSize` | all | default 10 (max undocumented) |
| `created_at` | all | UTC `YYYY-MM-DD HH:MM:SS.000`; records created at/after **[I]** |
| `remote` | conn, file | controlled device id; SQL-LIKE pattern |
| `conn_type` | conn | exact, 0–4 |
| `device` | alarm | SQL-LIKE pattern |
| `operator` | console | username, SQL-LIKE pattern |

`audits.py` wraps string filters as `%value%` unless the value contains `%`
or equals `-`; the server therefore receives LIKE patterns and applies
`LIKE` **[S][I]**.

### 9.2 Response [S]

```json
{ "total": 123, "data": [ { ... }, ... ] }
```

Error: body with `"error"` key. Ordering undocumented (newest first **[I]**).

Row fields known from `audits.py`: `created_at`, `end_time` (Unix seconds),
`conn_type` (absent = "Not Logged In"), `typ` (alarm, console), `iop`
(console). All other fields are printed verbatim by the script and are not
specified; we define them to cover the Pro console columns [D]:

| Kind | Fields (ours) |
|---|---|
| conn | `guid`, `remote` (controlled id), `remote_name`*, `peer_id`, `peer_name`, `user` (controller user, if attributed), `ip`, `conn_type`, `primary_auth`, `two_factor`, `session_id` (string), `conn_id`, `created_at`, `end_time`, `note`, `active` (bool) |
| file | `guid`, `remote`, `peer_id`, `user`, `type` (direction), `path`, `is_file`, `num`, `files`, `ip`, `created_at` |
| alarm | `guid`, `typ`, `device`, `user`, `info` (object), `created_at` |
| console | `guid`, `typ`, `iop`, `operator`, `info` (object), `created_at` |

\* `remote_name` looked up from the peer table.

### 9.3 Related Pro features [D] (not wire-specified)

- **Disconnect** an active connection (needs `audits.edit`): implemented via
  heartbeat (§10).
- **Edit note** from the console (needs `audits.view`).
- **Export CSV** of current filter, max 1000 rows.
- **Retention**: Settings → Log Retention (Days); 0 = forever; hourly purge.
- **Visibility**: admins see all; "Only admin can access logs" setting;
  non-admins see personal logs (their devices as either side, or they are the
  controller / operator). Permissions `audits.view` (1281), `audits.edit` (1282).

### 9.4 Console log codes [S]

`typ`: 0 Group, 1 User, 2 Device, 3 Address Book management (Pro docs also
list Admin Roles / Control Roles management — codes undocumented).

`iop`: 0 User Login, 1 Add Group, 2 Add User, 3 Add Device, 4 Delete Groups,
5 Disconnect Device, 6 Enable Users, 7 Disable Users, 8 Enable Devices,
9 Disable Devices, 10 Update Group, 11 Update User, 12 Update Device,
13 Delete User, 14 Delete Device, 15 Add Address Book, 16 Delete Address
Book, 17 Change Address Book Name, 18 Delete Devices in AB Recycle Bin,
19 Empty AB Recycle Bin, 20 Add AB Permission, 21 Delete AB Permission,
22 Update AB Permission.

Console records are generated by the API server itself for admin/user actions
on its own API; no client involvement.

---

## 10. Disconnect via heartbeat (existing endpoint) [C]

`POST /api/heartbeat` request includes `"conns": [conn_id, ...]` (all live
connections, authorized or not). If the response contains
`"disconnect": [conn_id, ...]`, the controlled client closes those
connections ("Closed manually by web console"). A console "Disconnect" action
on a conn log row queues its `conn_id` for the row's device and returns it on
that device's next heartbeat.

---

## 11. Controller attribution — `ControlledContext` (hbbs) [C][PR]

`rendezvous.proto`: `message ControlledContext { string conn_audit_ref = 1; }`,
carried in `PunchHole.controlled_context` (9), `RequestRelay.controlled_context`
(10), `FetchLocalAddr.controlled_context` (5).

1. Controlling client sends its access token in `PunchHoleRequest.token` /
   `RequestRelay.token`.
2. hbbs resolves the token to a user and puts an opaque `conn_audit_ref` into
   the message it forwards to the controlled device.
3. Controlled device echoes it in conn `new` (§3.1) and alarms 0/10 (§6).
4. API server resolves the ref to the controller user and caches it per
   connection key for file/alarm attribution.

The ref format is server-defined and opaque to clients **[PR]**. Direct-IP and
LAN connections never carry a ref (no user attribution) [C]. This is an
**hbbs + API server** feature; unmodified controlling clients already send the
token.

---

## 12. Server policy (not dictated by the client)

### 12.1 Unauthenticated writes

§3–§6 carry no credentials. Recommended validation **[I]**: accept only if
`(id, uuid)` matches a registered peer; otherwise answer 2xx empty and discard
(a 4xx would only make legitimate-but-unregistered devices log errors). §4
notes are accepted only if `(id, session_id)` matches an existing row.

### 12.2 Client IP behind proxies

`ip` in conn/file/alarm records is what the controlled device saw, which is
the address hbbs resolved for the controller. Behind reverse proxies it is the
real client address only when the proxies are configured as trusted
(`TRUSTED_PROXIES`, chart `realIp`); otherwise it is a proxy address **[I]**.

### 12.3 Retention

Configurable retention in days (0 = keep), purge job at least hourly, matching
Pro [D].

---

## 13. Open questions

1. Pro's exact conn-row matching for `authorized` / `close` (we specify
   `(id, uuid, conn_id)`, most-recent not-closed).
2. ~~`conn_audit_ref` encoding (signed token vs. lookup id) — ours to choose.~~
   **Answered:** a stored lookup ref. `POST /api/audit/ref` mints a random
   32-hex id in `audit_conn_ref (ref, "user", created_at)` for the bearer's
   own user; refs older than 24 h are purged on next mint.
3. `pageSize` maximum and sort order of `/api/audits/*`.
4. Console `typ`/`iop` codes for admin/control role, 2FA, password reset.
5. ~~Whether §4 notes append or overwrite an existing note (Pro console lets
   the note be edited; we specify overwrite).~~
   **Answered:** overwrite — implemented and matches.

---

## 14. Implementation status (sctgdesk-api-server / sctgdesk-server)

**As of 2026-10-03** — api-server `feat/audit-logging` @ `caec60f19`, hbbs
`feat/audit-logging` @ `94b9f3f0e`; §2.3, §2.4, §3 and §7 rows updated
2026-10-02; §2.3, §3.1, §4, §5, §6, §7, §8, §9, §9.3 and §11 rows updated
2026-10-03 (controller-user attribution, note paths, admin read API).
Verified by code reading; items marked **(live)** were also probed against a
running deployment.

Legend: ✅ conforms · ⚠️ partial / deviates · ❌ missing

### 14.1 Client-facing endpoints

| Spec | Status | Finding |
|---|---|---|
| §2.3 success = empty 2xx | ✅ | All three endpoints answer an empty body once stored (`/conn` returned the row GUID until 2026-10-02, which made the client retry every `new`). |
| §2.3 failure → `{"error"}` / 5xx | ✅ | All three endpoints answer `{"error": ...}` when a record is not stored, so the client retries. |
| §2.4 nonce dedup | ⚠️ | `find_audit_*_by_nonce` look the nonce up in SQL (`info::jsonb->>'nonce'`); no index, so still a sequential scan inside Postgres. No unique constraint → concurrent duplicates both insert. No nonce release needed (no claim state), no 5-min expiry (harmless). |
| §2.6 `session_id` as u64 | ✅ | Fixed on `fix/audit-session-id-u64`: request field is `u64` and the active-conn lookup compares as u64. Previously `i64`, so values > i64::MAX (≈ half of all random session ids) got **422 (live)** and the record was dropped. |
| §3.1 `new` | ✅ | Row with `type` NULL ("Not Logged In"); an older open row with the same connection key is ended first (the client restarted). `ip`, `uuid`, `conn_id`, `session_id` live in the `info` JSON text. `conn_audit_ref` now resolves via `audit_conn_ref` and stores the controller user on the row (§11). |
| §3.2 `authorized` | ✅ | Matched by connection key (most recent open row; created if the `new` record was lost). Stores `type`, controller id in `local`, and `peer_name`, `primary_auth`, `two_factor`, `session_id` in `info`. |
| §3.3 `close` | ✅ | Matched by connection key `(id, uuid, conn_id)`, most recent open row (§2.6) → sets `end_time`. Until 2026-10-02 it never matched (224/224 rows on a self-hosted instance had no `end_time`). |
| §3.4 unknown shape → 2xx empty | ✅ | |
| — lost `close` on client restart | ✅ | The Linux client restarts `--server` right after the last connection closes, before the `close` record (§3.3) is sent. A heartbeat now ends the device's open rows (same `id` and `uuid`) whose `conn_id` is not in its `conns` list, once they are 30 s old (younger rows may postdate the heartbeat's snapshot). |
| — `login` action branch | — | Removed 2026-10-02; no client sends `action:"login"`. |
| §4 menu note | ✅ | Recognised by empty `action`, a `note`, no `peer`/`type`, empty `uuid`. Applied to the most recent row matching `remote = id` (`@server` suffix stripped) and `info.session_id = session_id`. Always answers 2xx empty. |
| §5 file | ✅ | Stored with `remote`=`id` (controlled device), `local`=`peer_id` (viewer) — migration 0006. `info` is stored as an object. An unknown connection key is stored unattributed (`user` NULL); only a DB failure answers `{"error":...}` so the client retries (§2.3). Attributed to the connection row's `user` (by `(id, uuid, conn_id)`) when known. |
| §6 alarm | ✅ | Stored with `typ`, `device`=`id`; `info` stored as an object. Not-stored answers `{"error":...}`. Attributed from `conn_audit_ref` (typ 0, 10, via `audit_conn_ref`) or else the connection row's `user` (§11) when known. |
| §6 alarms 3–5 (account login) | ❌ | `/api/login` generates no alarms. |
| §7 `GET /api/audit/conn/active` | ✅ | Requires a login (Bearer) and returns only the caller's own rows or rows with no attributed user — rows attributed to someone else answer `""`. |
| §8 `PUT /api/audit` | ✅ | Implemented: owner of the row's `user` (or an unattributed row) may set `note`; overwrites any existing note. 400/404 otherwise. |
| §10 heartbeat `disconnect` | ❌ **(live)** | Heartbeat returns JSON `{"modified_at": ..., "strategy": {"config_options": {...}}}` (the `strategy` field only when the device's policy changed), used for device policy sync (2026-09-29), not disconnect; no disconnect queue. `conns` ends open conn rows of connections that are gone (see "lost `close`" above). |
| §11 `ControlledContext` (hbbs) | ✅ | hbbs bumped `hbb_common` to `69cea8d`. A token on `PunchHoleRequest`/`RequestRelay` calls `POST /api/audit/ref` (5 s bound) to mint a ref, forwarded in `ControlledContext` on `PunchHole`/`FetchLocalAddr`/`RequestRelay`; a 404 (older api-server) falls back to `/api/currentUser` without a ref. The controlling-side viewer token is stripped from the forwarded `RequestRelay`. `LOGGED_IN_ONLY=Y` now also applies to relay requests. With `LOGGED_IN_ONLY=Y`, an unreachable api-server (timeout or any non-login answer) refuses the request with "Your session expired." rather than falling back. |
| §2.2 hbbs raw-TCP API proxy | ❌ | hbbs does not handle `HttpProxyRequest`; the client's fallback path fails (only matters with `USE_RAW_TCP_FOR_API=Y` or during 5xx). |

### 14.2 Admin / console

| Spec | Status | Finding |
|---|---|---|
| §9 `GET /api/audits/{conn,file,alarm,console}` | ✅ | Implemented, `audits.py`-compatible, admin only; `console` kind always answers an empty page (§9.4 not written to). |
| §9.3 console UI (logs pages, disconnect, edit note, CSV export) | ⚠️ | Webconsole has a new "Audit log" page (conn/file/alarm). Disconnect, edit-note-from-console and CSV export are not implemented. |
| §9.3 retention | ❌ | No setting, no purge job. |
| §9.3 visibility / permissions | ❌ | No `audits.view` / `audits.edit` model; nothing to read anyway. |
| §9.4 console audit (`audit_console`) | ❌ | Table exists in `0001_initial.sql`; nothing writes to it. |
| §12.1 write validation | ❌ | Any anonymous caller can insert records or (once close works) end sessions. |

### 14.3 Schema (`libs/state/migrations/0001_initial.sql`)

| Issue | Impact |
|---|---|
| `created_at` / `end_time` are `text` | sorting/filtering by time is string-based; §9 needs Unix seconds |
| No columns for `ip`, `uuid`, `conn_id`, `session_id`, `nonce`, `peer` id/name, auth fields, controller user | matching (§2.6) and filtering (§9.1) require JSON parsing of `info` |
| No indexes on audit tables | every lookup is a full scan |
| `guid bytea` | fine; §7/§8 expose it as a UUID string |

### 14.4 Tests

| Layer | Coverage |
|---|---|
| Unit (`database.rs` `db_test!`) | insert / end_time / find_active / nonce helpers in isolation |
| Integration (`tests/integration.rs`) | legacy `POST /api/audit` only |
| E2E (rustdesk-e2e) | legacy `POST /api/audit` only — no lifecycle, file, alarm, note, GUID, or read tests |

### 14.5 Summary

All client-facing write paths (§3.1–§8) now work, including both note paths
(§4, §8), the GUID lookup (§7, now authenticated and scoped to the caller),
and controller-user attribution end to end (§11, §3.1, §5, §6). The admin
read API (§9) and a webconsole "Audit log" page (§9.3) are implemented.
Still open: console Disconnect, CSV export, retention, console (admin
action) logging, §12.1 write validation, alarms 3–5, hbbs's raw-TCP API
proxy (§2.2).
