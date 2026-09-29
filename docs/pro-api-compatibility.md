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
| POST | /api/heartbeat | [C] `src/hbbs_http/sync.rs` | partial | updates last_online; strategy push added by device policy work |
| POST | /api/sysinfo | [C] `src/hbbs_http/sync.rs` (`url.replace("heartbeat","sysinfo")`) | implemented | |
| POST | /api/login | [C] `flutter/lib/models/user_model.dart` | implemented | password login intentionally disabled, always 401; use OIDC |
| GET | /api/login-options | [C] `src/hbbs_http/account.rs`, `flutter/lib/models/user_model.dart` | implemented | |
| POST | /api/oidc/auth | [C] `src/hbbs_http/account.rs` | implemented | |
| GET | /api/oidc/auth-query | [C] `src/hbbs_http/account.rs` | implemented | |
| POST | /api/logout | [C] `flutter/lib/models/user_model.dart` | implemented | |
| POST | /api/currentUser | [C] `flutter/lib/models/user_model.dart` | implemented | |
| POST | /api/audit/conn | [C] `src/server/connection.rs` | implemented | connection lifecycle + session-menu note; see audit-api-spec.md §3-4 |
| POST | /api/audit/file | [C] `src/server/connection.rs` | implemented | see audit-api-spec.md §5 |
| POST | /api/audit/alarm | [C] `src/server/connection.rs` | implemented | see audit-api-spec.md §6 |
| GET | /api/audit/conn/active | [C] `src/ui_session_interface.rs` | partial | route exists but no auth and wrong row filter, always returns "" per audit-api-spec.md §14.1 |
| PUT | /api/audit | [C] `flutter/lib/common/widgets/dialog.dart` (end-of-session note) | missing | only legacy `POST /api/audit` exists, which just logs and does nothing |
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
| GET | /api/peers | [C] `flutter/lib/models/group_model.dart` | implemented | |
| GET | /api/device-group/accessible | [C] `flutter/lib/models/group_model.dart` | missing | no `/api/device-group*` route exists |

## Admin API (Pro scripts)

### `strategies.py`

| Method | Path | Source | Status | Notes |
|---|---|---|---|---|
| GET | /api/strategies | [S] `strategies.py` | missing | stub `GET /api/stategies` (sic) returns a fake body; see "Our own endpoints" |
| GET | /api/strategies/{guid} | [S] `strategies.py` | missing | |
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
| GET | /api/ab/personal | [S] `ab.py` | implemented | ours is `POST /api/ab/personal`, method differs (client also uses POST) |
| GET | /api/ab/shared/profiles | [S] `ab.py` | implemented | ours is `POST /api/ab/shared/profiles`, method differs (client also uses POST) |
| GET | /api/ab/peers | [S] `ab.py` | implemented | ours is `POST /api/ab/peers`, method differs (client also uses POST) |
| GET | /api/ab/tags/{guid} | [S] `ab.py` | implemented | ours is `POST /api/ab/tags/{ab}`; the admin script's GET verb differs, but the client also uses POST on this route |
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
| GET | /api/audits/{conn,file,alarm,console} | [S] `audits.py` | missing | no admin read route exists; see audit-api-spec.md §9/§14.2 |

## Our own endpoints

| Method | Path | Notes |
|---|---|---|
| GET | /api/stategies | stub (sic, typo); always returns a fake success body regardless of state; TODO in source |
| POST | /api/ab/get | alias of `GET /api/ab` (same handler); not called by our client fork |
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
| GET | /api/oidc/settings | stub; always 401; TODO in source |
| PUT | /api/oidc/settings | stub; always 401; TODO in source |
| GET | /api/software/version/server | server version |
| GET | /api/software/releases/tag/{version} | echoes the requested version tag back; no real release lookup |
| GET | /api/software/download | redirects to upstream RustDesk release |
