ZzZ
@XPxBOTS

## Endpoints

| Endpoint | What it does |
| --- | --- |
| `GET /like?uid=<UID>` | Sends one like per token and returns the before/after like counts. |
| `GET /token_status` | Token count, expiry, release version and the cluster list in use. |
| `POST /refresh_tokens` | Forces a refresh of every account in `account.bd.txt`. |
| `GET /diagnose` | Reports which hop is broken (provider → token version → cluster). |

## When `/like` fails

`Failed to get player info` with `"reason": "tokens_rejected"` means the game API
answered, but refused the tokens. The response now also carries:

* `reason` – `tokens_rejected`, `upstream_unreachable`, `rate_limited`, ...
* `hint` – the likely cause, including a release-version mismatch
* `upstream` – per-host HTTP status codes and response bodies

`GET /diagnose` (or `python3 diagnose.py`) is the quickest way to see the whole
chain at once. It prints, without exposing tokens or passwords:

1. whether the guest-JWT provider still mints tokens for your accounts and which
   `release_version` those tokens carry,
2. what every cluster in `FF_CLIENT_HOSTS` answers for a real player lookup,
3. what the cached `token_bd.json` holds.

### Garena rotates clusters and versions every patch

The OB55 update (September 2026) moved the global client cluster from
`clientbp.ggpolarbear.com` to `clientbp.ppmainecoonghj.com`, bumped
`ReleaseVersion` to `OB55` (client `1.132.3`) and added the `X-GA-SV` build-stamp
header. A bot pinned to the previous release gets HTTP 403 for *every* token,
which is exactly what used to be reported as "All game tokens were rejected".

All of that is configurable now, so the next patch is an env-var change:

| Variable | Default | Meaning |
| --- | --- | --- |
| `FF_RELEASE_VERSION` | `OB55` | OB release sent in `ReleaseVersion`. |
| `FF_X_GA_SV` | `1789638359` | Client build stamp sent in `X-GA-SV`. |
| `FF_CLIENT_HOSTS` | current + previous clusters | Comma separated cluster list, first entry preferred, the rest are failover. |
| `FF_REGION` | `BD` | Region used when a token carries none. |
| `FF_TOKEN_URL` | `https://guest-jwt.vercel.app/token` | Guest-JWT provider. |
| `FF_ACCOUNT_FILE` / `FF_TOKEN_FILE` | `account.bd.txt` / `token_bd.json` | Account list and token cache. |
| `FF_TOKEN_ATTEMPTS` | `5` | Tokens tried per player-info lookup. |
| `FF_PLAYER_INFO_BUDGET` | `25` | Wall-clock seconds budgeted for one lookup. |

Tokens are still used at the release version they were minted for; when the
provider hands out tokens for an outdated release, `/diagnose` says so and the
fix is a current provider (or minting the JWT in-process).

## Tests

`python3 tests/test_offline.py` runs the app against stub upstreams (a fake
guest-JWT provider and a fake game cluster) and covers the happy path, cluster
failover, release-version drift, a broken provider and `/diagnose`.

## Security note

`account.bd.txt` contains live `uid:password` pairs and `token_bd.json` contains
live JWTs. Keep both out of a public repository (use `FF_ACCOUNT_FILE` with a
mounted secret), and rotate the credentials if they have ever been committed -
anyone with the file can use or burn those accounts.
