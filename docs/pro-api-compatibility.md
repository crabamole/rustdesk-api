# RustDesk Pro API compatibility

Which RustDesk Pro API endpoints this server implements. Pro publishes no API
reference: client endpoints come from the upstream client code, admin endpoints from
the official Pro scripts in `rustdesk/res/*.py`.

Sources: [C] upstream client code, [S] Pro script in `rustdesk/res/`, [D] Pro docs,
[I] inference. Status: implemented, partial (notes say what is missing), missing,
ours (not in Pro).

For the audit endpoints (`/api/audit*`, `/api/heartbeat` disconnect), see
`docs/audit-api-spec.md` for the full wire contract; this file only summarizes
implementation status.

Update this file with every API change.

## Client → server

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| POST | /api/heartbeat | [C] `src/hbbs_http/sync.rs` | implemented | updates last_online; sends `strategy.config_options` (Default strategy, allow-listed keys) when the device's `modified_at` differs; `conns` ends open audit rows of connections that are gone (30 s grace) |
| POST | /api/sysinfo | [C] `src/hbbs_http/sync.rs` (`url.replace("heartbeat","sysinfo")`) | implemented | only for a registered `(id, uuid)`; the `uuid` is not stored in the device's info |
| POST | /api/login | [C] `flutter/lib/models/user_model.dart` | implemented | password login intentionally disabled, always 401; use OIDC |
| GET | /api/login-options | [C] `src/hbbs_http/account.rs`, `flutter/lib/models/user_model.dart` | implemented | |
| POST | /api/oidc/auth | [C] `src/hbbs_http/account.rs` | implemented | requires `returnTo` (loopback `http://127.0.0.1:<port>/`, or this server's `/ui/login` or `/oidc-callback.html`) and an S256 `codeChallenge`; the callback redirects there with a one-time `result` |
| POST | /api/oidc/token | [C] `src/hbbs_http/account.rs` | ours | redeems the one-time login result with the PKCE verifier; replaces polling (`GET /api/oidc/auth-query`, removed); completing a native client login records the machine for `GET /api/viewers` |
| GET | /api/oidc/callback | [I] | ours | the IdP's redirect target: `code` sends the one-time `result` to `returnTo`; `error` (e.g. the user cancelled) sends `error=login_failed`; each outcome is written to the login audit |
| POST | /api/logout | [C] `flutter/lib/models/user_model.dart` | implemented | |
| POST | /api/currentUser | [C] `flutter/lib/models/user_model.dart` | implemented | also refreshes the last-seen time of a machine recorded by a login |
| POST | /api/audit/conn | [C] `src/server/connection.rs` | implemented | connection lifecycle (`new`, `authorized`, `close`) and session-menu note (§4) per audit-api-spec.md §3-4; stored only from a registered `(id, uuid)` (§12.1) |
| POST | /api/audit/file | [C] `src/server/connection.rs` | implemented | see audit-api-spec.md §5; stored only from a registered `(id, uuid)` (§12.1) |
| POST | /api/audit/alarm | [C] `src/server/connection.rs` | implemented | see audit-api-spec.md §6; stored only from a registered `(id, uuid)` (§12.1) |
| GET | /api/audit/conn/active | [C] `src/ui_session_interface.rs` | implemented | requires a bearer token; scoped to the row's own user or an unattributed row, per audit-api-spec.md §7 |
| POST | /api/audit/ref | [I] hbbs `ControlledContext` | ours | not a Pro endpoint; `?target=<device id>` required (422 without); mints an opaque ref for the bearer's user that attributes only records of `target`, consumed by hbbs per audit-api-spec.md §11 |
| PUT | /api/audit | [C] `flutter/lib/common/widgets/dialog.dart` (end-of-session note) | implemented | sets the note on the GUID's row (owner or unattributed only), per audit-api-spec.md §8 |
| POST | /api/switch-grant | [C] `src/hbbs_http/sync.rs` | missing | no route |
| POST | /api/devices/cli | [C] `src/core_main.rs` | missing | no `/api/devices*` route exists |
| POST | /api/devices/deploy | [C] `src/ui_interface.rs` | missing | no `/api/devices*` route exists |
| GET | /api/ab | [C] `flutter/lib/models/ab_model.dart` | implemented | pull address book |
| POST | /api/ab | [C] `flutter/lib/models/ab_model.dart` | implemented | legacy set address book |
| POST | /api/ab/personal | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/settings | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/shared/profiles | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/peers | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/tags/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/peer/add/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| PUT | /api/ab/peer/update/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| DELETE | /api/ab/peer/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| POST | /api/ab/tag/add/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| PUT | /api/ab/tag/rename/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| PUT | /api/ab/tag/update/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| DELETE | /api/ab/tag/{guid} | [C] `flutter/lib/models/ab_model.dart` | implemented | |
| GET | /api/users | [C] `flutter/lib/models/group_model.dart` | implemented | client-facing list, paginated |
| GET | /api/peers | [C] `flutter/lib/models/group_model.dart` | implemented | `info` never carries the device `uuid` |
| GET | /api/device-group/accessible | [C] `flutter/lib/models/group_model.dart` | missing | no `/api/device-group*` route exists |

Upstream clients log in by polling `GET /api/oidc/auth-query`; that login is not supported, since a login is bound to the client that started it.

## Admin API (Pro scripts)

### `strategies.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/strategies | [S] `strategies.py` | implemented | Default only; detail shape is ours, Pro's is unpublished |
| GET | /api/strategies/{guid} | [S] `strategies.py` | implemented | Default only; detail shape is ours, Pro's is unpublished |
| PUT | /api/strategies/{guid}/status | [S] `strategies.py` | missing | needs named policies |
| POST | /api/strategies/assign | [S] `strategies.py` | missing | needs named policies |
| GET | /api/devices | [S] `strategies.py` (also `devices.py`) | missing | no `/api/devices*` route exists |
| GET | /api/users | [S] `strategies.py` (also `users.py`, `user-groups.py`) | implemented | same route as client-facing `GET /api/users` |
| GET | /api/device-groups | [S] `strategies.py` (also `device-groups.py`) | missing | no `/api/device-groups*` route exists |

### `users.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/users | [S] `users.py` | implemented | see above |
| POST | /api/users/{guid}/disable | [S] `users.py` | missing | ours is `POST /api/enable-users` (body list + disable flag), path differs |
| POST | /api/users/{guid}/enable | [S] `users.py` | missing | same as above |
| DELETE | /api/users/{guid} | [S] `users.py` | missing | ours is `DELETE /api/user` (singular, body list of uuids), path differs |
| POST | /api/users | [S] `users.py` | missing | ours is `POST /api/user` (singular), path differs |
| POST | /api/users/invite | [S] `users.py` | missing | no invite flow |
| PUT | /api/users/tfa/totp/enforce | [S] `users.py` | missing | no TOTP/2FA support |
| PUT | /api/users/disable_login_verification | [S] `users.py` | missing | |
| POST | /api/users/force-logout | [S] `users.py` | missing | |

### `user-groups.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/user-groups | [S] `user-groups.py` | missing | ours is `GET /api/groups`, path differs |
| POST | /api/user-groups | [S] `user-groups.py` | missing | ours is `POST /api/group` (singular), path differs |
| PATCH | /api/user-groups/{guid} | [S] `user-groups.py` | missing | ours is `PUT /api/group` (guid in body), path differs |
| DELETE | /api/user-groups/{guid} | [S] `user-groups.py` | missing | ours is `DELETE /api/group/{guid}`, path differs |
| POST | /api/user-groups/{guid} | [S] `user-groups.py` (add members) | missing | no group-membership route |
| GET | /api/users | [S] `user-groups.py` (list members) | implemented | same route as client-facing `GET /api/users` |

### `devices.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/devices | [S] `devices.py` | missing | no `/api/devices*` route exists |
| POST | /api/devices/{guid}/disable | [S] `devices.py` | missing | |
| POST | /api/devices/{guid}/enable | [S] `devices.py` | missing | |
| DELETE | /api/devices/{guid} | [S] `devices.py` | missing | |
| POST | /api/devices/{guid}/assign | [S] `devices.py` | missing | |

### `device-groups.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/device-groups | [S] `device-groups.py` | missing | no `/api/device-groups*` route exists |
| POST | /api/device-groups | [S] `device-groups.py` | missing | |
| PATCH | /api/device-groups/{guid} | [S] `device-groups.py` | missing | |
| DELETE | /api/device-groups/{guid} | [S] `device-groups.py` | missing | |
| GET | /api/devices | [S] `device-groups.py` (list members) | missing | see `devices.py` above |
| POST | /api/device-groups/{guid} | [S] `device-groups.py` (add devices) | missing | |
| DELETE | /api/device-groups/{guid}/devices | [S] `device-groups.py` | missing | |

### `ab.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/ab/personal | [S] `ab.py` | partial | same path, but ours only answers `POST /api/ab/personal`; an unmodified Pro script's GET would fail (client also uses POST) |
| GET | /api/ab/shared/profiles | [S] `ab.py` | partial | same path, but ours only answers `POST /api/ab/shared/profiles`; an unmodified Pro script's GET would fail (client also uses POST) |
| GET | /api/ab/peers | [S] `ab.py` | partial | same path, but ours only answers `POST /api/ab/peers`; an unmodified Pro script's GET would fail (client also uses POST) |
| GET | /api/ab/tags/{guid} | [S] `ab.py` | partial | same path, but ours only answers `POST /api/ab/tags/{ab}`; an unmodified Pro script's GET would fail (client also uses POST) |
| POST | /api/ab/peer/add/{guid} | [S] `ab.py` | implemented | |
| DELETE | /api/ab/peer/{guid} | [S] `ab.py` | implemented | |
| PUT | /api/ab/peer/update/{guid} | [S] `ab.py` | implemented | |
| POST | /api/ab/tag/add/{guid} | [S] `ab.py` | implemented | |
| PUT | /api/ab/tag/update/{guid} | [S] `ab.py` | implemented | |
| DELETE | /api/ab/tag/{guid} | [S] `ab.py` | implemented | |
| POST | /api/ab/shared/add | [S] `ab.py` | implemented | |
| PUT | /api/ab/shared/update/profile | [S] `ab.py` | implemented | |
| DELETE | /api/ab/shared | [S] `ab.py` | implemented | |
| GET | /api/ab/rules | [S] `ab.py` | implemented | |
| POST | /api/ab/rule | [S] `ab.py` | implemented | |
| PATCH | /api/ab/rule | [S] `ab.py` | missing | no route; ours has `POST`/`DELETE /api/ab/rule` only, no update |
| DELETE | /api/ab/rules | [S] `ab.py` (bulk, body `rule_guids`) | missing | ours is `DELETE /api/ab/rule` (singular, one guid), path and shape differ |

### `audits.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/audits/conn | [S] `audits.py` | implemented | admin-only; newest first; `remote`/`conn_type` filters, per audit-api-spec.md §9; rows also carry the viewer machine (`peer_hostname`, `peer_os`, `peer_login_ip`) |
| GET | /api/audits/file | [S] `audits.py` | implemented | admin-only; newest first; `remote` filter, per audit-api-spec.md §9 |
| GET | /api/audits/alarm | [S] `audits.py` | implemented | admin-only; newest first; `device` filter, per audit-api-spec.md §9 |
| GET | /api/audits/console | [S] `audits.py` | partial | admin-only; always answers an empty page — nothing writes `audit_console` yet, per audit-api-spec.md §9/§14.2 |

## Our own endpoints

| Method | Path | Notes |
|---|---|---|
| POST | /api/ab/get | alias of `GET /api/ab` (same handler); not called by our client fork |
| PUT | /api/strategies/{guid} | edit options; Pro edits in its console only |
| POST | /api/strategies/{guid}/repush | force re-push to all devices |
| POST | /api/enable-users | bulk enable/disable by uuid list |
| POST | /api/user | create user (Pro uses `POST /api/users`) |
| DELETE | /api/user | bulk delete by uuid list (Pro uses `DELETE /api/users/{guid}`) |
| PUT | /api/user | update a user, self or admin (Pro has no equivalent single-user PUT) |
| GET | /api/group/{guid} | get one group |
| POST | /api/group | create group (Pro uses `POST /api/user-groups`) |
| PUT | /api/group | update group by guid in body (Pro uses `PATCH /api/user-groups/{guid}`) |
| DELETE | /api/group/{guid} | delete group (Pro uses `DELETE /api/user-groups/{guid}`) |
| GET | /api/groups | list groups, paginated (Pro uses `GET /api/user-groups`) |
| GET | /api/user-list | admin-only paginated user list with email/name filters (separate from client-facing `GET /api/users`) |
| GET | /api/peers/count/{platform} | peer count by platform |
| GET | /api/peers/cpus | cpu count per peer |
| GET | /api/audits/login | admin-only login audit: one row per OIDC login that reached the callback, with its outcome; `user` (LIKE) and `outcome` filters, per audit-api-spec.md §9 |
| GET | /api/viewers | admin-only paginated list of machines whose native client logged in through OIDC but never registered with hbbs; one row per machine and user, with the latest login address (`login_ip`) |
| GET | /api/oidc/settings | stub; always 401; TODO in source |
| PUT | /api/oidc/settings | stub; always 401; TODO in source |
| GET | /api/software/version/server | server version |
| GET | /api/software/releases/tag/{version} | echoes the requested version tag back; no real release lookup |
| GET | /api/software/download | redirects to upstream RustDesk release |
