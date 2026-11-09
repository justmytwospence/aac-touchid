# aac-touchid

A background [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) listener for macOS that releases each credential only after you approve it with **Touch ID** (or an Apple Watch).

Agents keep using Bitwarden's own client, `aac` 0.11:

```sh
aac run --domain "github.com | pi · homelab | check gh login" --env GH_TOKEN=password -- gh auth status
```

`--domain` (or `--id`) may carry `item | agent | reason`, or `item | reason`. The agent's name and reason are shown on the sheet and removed before the vault lookup. Both are the agent's own claims; the device name (from pairing) is verified.

The request travels end to end encrypted through the Agent Access relay to this listener on your Mac. The listener looks up the item with the Bitwarden CLI (`bw`) and shows a system sheet:

> **Bitwarden**
> Bitwarden is trying to share a password
>
> **𝗽𝗶 · 𝗵𝗼𝗺𝗲𝗹𝗮𝗯** (nuc)
> **𝗚𝗶𝘁𝗛𝘂𝗯** (you@example.com)
> check gh login

The sheet has no rich text, so the agent and item names use Unicode mathematical bold letters. macOS titles the sheet with the program's file name, so install a copy of the binary named `Bitwarden` for the service to run (see below). The sheet also says what is released: `password`, `password + 2FA code`, or `username only`. Notes are never released, because they can hold recovery codes.

If you touch the sensor, the secret goes to that device and into the command's environment. If you cancel or don't answer within 60 s, the agent gets `aac` exit code 4 ("Request denied").

### Which item is found

A host (`github.com`) or URL (`https://github.com/login` or `github.com/login`, reduced to its host) is matched on login URI hosts, deterministically:

1. Logins with a URI on exactly that host, or named exactly that host. A leading `www.` is ignored on both sides.
2. Only if there are none, logins with a URI on a subdomain of it (`github.com` finds `gist.github.com`, but `api.github.com` does not find `github.com`).

If the first tier with any logins has more than one, the request is denied as ambiguous and the agent must ask by item id. Partial matches (`hub.com`, `github.com.evil.io`, a name or username containing the text) never count, and URIs whose match detection is set to Never or Regular expression are skipped. Anything that is not a host (an item id, a name like `GitHub`) goes to `bw`'s own lookup; when that finds several items, one named exactly that (any case) is chosen, otherwise the request is ambiguous.

Lookups use the listener's own copy of the vault, synced when it unlocks and around writes. When a lookup finds nothing, the listener syncs once and looks again, so an item added elsewhere a moment ago is found.

## New logins and 2FA

Agents can also create a Bitwarden login for a new service and add 2FA to it. Stock `aac` sends only free text, so both ride in the item part of `--domain`, before the usual `| agent | reason` fields:

```sh
# Create a login with a generated password and receive that password.
aac run --domain "new:acme.io user=bot@example.com | pi · homelab | sign up for Acme" \
  --env PASSWORD=password -- ./signup.sh

# Store the 2FA seed from the signup page and receive the current code.
aac run --domain "totp:acme.io secret=JBSWY3DPEHPK3PXP | pi · homelab | enroll 2FA" \
  --env CODE=totp -- ./confirm-2fa.sh
```

| Request | What it does |
|---|---|
| `new:<name> [user=<u>] [url=<full url>] [words=3-20]` | Creates a login named `<name>` with a passphrase from `bw`'s generator and releases username, password, URI and item id. The default is 6 capitalized words joined by `-`, one with a digit (`Violet-Shrug0-Broken-Lantern-Mosaic-Thirsty`); `words=` sets the count. For a random password instead, give `length=12-128` (default 24) and/or `symbols=no`; these cannot be combined with `words=`. If `<name>` looks like a host (`acme.io`), the URI defaults to `https://<name>`. |
| `totp:<item> secret=<base32>` | Stores a TOTP seed on a login and releases its username and current code, so the agent can confirm enrollment. |
| `totp:<item> uri=otpauth://totp/...?secret=...` | The same, from an `otpauth://` URI; its other parameters (digits, period, algorithm) are kept. |
| anything else | A normal read, unchanged. |

`<name>` may have spaces and the characters `. - _ @ & + '`. `<item>` is one word: a domain, an item name without spaces, or an item id. Secrets are uppercased, `=` and `-` are dropped, and the rest must be base32 (A-Z, 2-7), 16-128 characters. Later reads use the normal flow (`--domain acme.io`).

Each write shows its own Touch ID sheet. A new login's sheet names the password format (`6-word passphrase`, `32-character password`, `24-character password without symbols`), never the password:

> Bitwarden is trying to create a login with a 6-word passphrase and share it
>
> **𝗽𝗶 · 𝗵𝗼𝗺𝗲𝗹𝗮𝗯** (nuc)
> **𝗮𝗰𝗺𝗲.𝗶𝗼** (bot@example.com)
> sign up for Acme

> Bitwarden is trying to add 2FA and share a 2FA code

Guardrails:

- `new:` is refused if an item with that name (any case) or a login for that host already exists, checked before the sheet and again after approval.
- Writes go straight to the Bitwarden server. The listener syncs its vault before a write's checks (refusing if that fails) and again after the write. Other Bitwarden apps pick up the change by their usual push notification or next sync.
- New logins go in the folder `Agent-created` (created on first use), with a note naming the agent, device and reason.
- `totp:` works only on a login that resolves to exactly one item, sits in `Agent-created`, and has no 2FA seed. An agent can never add 2FA to a login you made, and never overwrites a seed; the item is read again after approval to make sure.
- `totp:` releases only the username and the current code, never the seed or the password.
- Malformed requests are refused without a sheet: unknown or repeated options, more than one seed, HOTP (`otpauth://hotp/`), an `otpauth` URI without a secret, a length outside 12-128, a word count outside 3-20, or `words=` mixed with `length=`/`symbols=`. Error messages never repeat the request.
- Repeat denials are remembered per `new <name>` and `2FA <item>`, like reads.

It replaces the interactive `aac listen` terminal app. There is nothing to keep open, and nothing an agent can type, click or send to a terminal pane can approve a request.

## Fewer sheets: remember and batch

Two more request forms ride in the item part of `--domain`, like `new:` and `totp:`:

```sh
# Release GitHub now, and again for 15 minutes without a sheet.
aac run --domain "github.com remember=15m | pi · homelab | gh work" --env GH_TOKEN=password -- gh pr list

# Approve several items on one sheet (each is then read once within 120 s).
aac connect --domain "batch:github.com,npmjs.com remember=10m | pi · homelab | publish" --output json
```

- `remember=` takes `1m` to `24h` (`15m`, `2h`). The sheet says so: `Bitwarden is trying to share a password, and again for 15 min without asking`. Your touch approves both.
- `--max-remember-minutes` (default 60; `0` turns remembering off) caps what an agent can ask for. A longer request is clamped and the sheet shows the clamped time.
- A grant is keyed on the verified device and the resolved vault item id, never the agent's self-reported name, so `github.com` and `https://github.com/login` share one. It is in memory only.
- `batch:` takes up to 10 comma-separated items and shows one line per item. Without `remember=` each item can be read once within 120 s; with it, the remember window applies. `new:` and `totp:` writes always get their own sheet and never use grants.
- Locking the vault, `aac-touchid forget`, and revoking a device clear all grants. `aac-touchid status` lists them.

## `aac-touchid run`

`aac-touchid run` fills `bw://` references in a command's environment, then `exec`s it. With two or more items it sends one `batch:` request (one sheet), then reads each item with stock `aac connect --output json`. It also builds for Linux (the `aac-touchid-linux-x86_64` release), so the NUC can use it; `aac` must be on `PATH` there.

```dotenv
# .env.agent: references only, safe to commit
GH_TOKEN=bw://github.com
NPM_USER=bw://npmjs.com#username
DATABASE_URL=postgres://${bw://db.internal#username}:${bw://db.internal#password}@db/app
```

```sh
aac-touchid run --env-file .env.agent --agent "pi · homelab" --reason "publish release" --remember 10m -- ./release.sh
```

| Reference | Meaning |
|---|---|
| `bw://ITEM` | The item's password. `ITEM` is a host, an item name or an item id, with no spaces or `# } , \| = $ {` (use the item id for such names). |
| `bw://ITEM#FIELD` | `username`, `password`, `totp` (current code), `uri`, `domain` or `credential_id`. Notes are never released. |
| `${bw://ITEM#FIELD}` | The same, inside a longer value. |

Options: `--env-file` (repeatable; later files win), `--agent` (default `$AAC_AGENT`), `--reason`, `--remember`, `--timeout` (seconds per answer, default 240). At most 10 items per run. Inherited environment variables may hold references too.

Exit codes: `aac`'s own code when a request fails (2 connection, 3 auth, 4 denied or not found), 1 for `run`'s own errors, 127 or 126 when the command cannot be started. Otherwise the command's own status.

## Requirements

- macOS with Touch ID (or an Apple Watch set up for approvals)
- Bitwarden CLI `bw`, logged in once (`bw login`, or `bw login --apikey`)
- `aac` 0.11.x on every machine whose agents request credentials

## Use

`aac-touchid serve` is meant to run under launchd, for example with a LaunchAgent:

```xml
<key>ProgramArguments</key>
<array>
  <string>/Users/you/.local/libexec/aac-touchid/Bitwarden</string><string>serve</string>
  <string>--pair-local</string><string>my-mac</string>
  <string>--pair-ssh</string><string>my-server</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>EnvironmentVariables</key>
<dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string></dict>
```

There is no setup step. With `--pair-local NAME` and `--pair-ssh HOST` (repeatable), the listener keeps those machines' `aac` clients paired with itself: whenever it connects to the relay, and every 30 minutes, it checks each one and pairs any that isn't, by handing a one-time pre-shared-key token to that machine's `aac` over the local process or ssh (on stdin). This Mac's `aac` is paired with this listener alone (`aac` refuses to choose between several connections). An ssh host may be paired with several Macs: while a Mac has keyboard or pointer input, its listener writes `~/.local/state/aac-touchid/presence/<listener fingerprint>` on each host every minute, so a wrapper there can pass `--session` for the Mac you are using (example: [`aac` wrapper](https://github.com/justmytwospence/dotfiles/blob/main/dot_local/bin/executable_aac)). ssh runs in batch mode, so the host must accept your key without a prompt.

If the Bitwarden CLI is not logged in, the first request's dialog asks for your personal API key (client_id, then client_secret) before the master password.

Commands:

| Command | What it does |
|---|---|
| `aac-touchid pair [name]` | For a machine you can't list with `--pair-*`: prints a one-time pairing code (valid 5 minutes). Its first use (`aac run --token <code> ...`) shows a Touch ID sheet asking to pair device `name`. |
| `aac-touchid status` | Lock state, relay connection, paired devices, recent decisions. |
| `aac-touchid lock` | Locks the vault now. |
| `aac-touchid revoke <name>` | Forgets a paired device. |
| `aac-touchid forget` | Forgets every remembered approval. |
| `aac-touchid run [--env-file F]... -- <cmd>` | Runs a command with `bw://` references filled in (see above). Works on Linux. |

`serve` also takes `--max-remember-minutes` (default 60).

The vault starts locked. The first request after a restart, 8 hours idle (`--lock-after-hours`) or `lock` shows a native password dialog for your master password, then the Touch ID sheet.

State (identity key, paired devices) lives in `~/Library/Application Support/aac-touchid` (0700). Override it with `AAC_TOUCHID_STATE_DIR`. Logs go to stderr and never contain secrets.

## Security model

Trusted: the Mac's logged-in GUI session and the person at it. Untrusted: agents, the machines they run on, and the relay.

- Every write, and every read that is not under a grant, needs a biometric or Watch approval. A grant exists only because you approved a sheet that stated it (`remember=` or `batch:`), and writes always get their own sheet (LocalAuthentication `deviceOwnerAuthenticationWithBiometricsOrCompanion`, password fallback hidden). The sheet names the agent (self-reported) and its device (verified), the vault item, the username and the agent's stated reason.
- Only paired devices can ask. Automatic pairing goes only to the machines named in the service's arguments, with a one-time PSK token delivered over the local process or authenticated ssh; the Noise PSK handshake binds it to that listener. Manual pairing needs a code from `aac-touchid pair` and a Touch ID approval. A code an agent obtains alone does not pair anything.
- After a denial, the same device asking for the same item is denied silently for 60 s, and a cancelled unlock dialog is not shown again for 2 minutes, so an agent cannot spam prompts.
- The master password and vault key never go into an environment variable or a command line, where any process of the same user can read it (`ps -E`). The listener runs one `bw serve` child on a private socket pair (`--hostname fd+connected://3`, a supported `bw serve` mode) that no other process can open; the master password travels once in its `POST /unlock` body and the vault key stays inside that child. Locking calls `/lock` and stops the child.
- `bw login --apikey` reads the API key only from its environment, so on first login the key is in that one short-lived child's environment. The API key alone cannot decrypt the vault.
- Only username, password, URI and the current 2FA code (never the TOTP seed) are released.
- A `totp:` seed is in the requesting machine's `aac` command line while it runs, where processes of the same user there can read it, and the agent has seen it once on the signup page. It leaves the listener only inside the encrypted vault: logs and `status` show `totp:<item> [redacted]` and `2FA <item>`. Generated passwords and seeds are wiped from the listener's request buffers after use.
- Agent names are reduced to letters, digits, spaces and `· . - _ / @`, so a name cannot fake a device suffix or extra lines. Pairing completes only within 5 minutes of `aac-touchid pair`, and the sheet names the device and when its code was issued.
- The relay sees only device fingerprints and timing (Noise protocol, end to end).

Not covered:

- Within a grant's window, any agent on that device can read that item.
- An approved command holds that secret and can misuse it. Approve only requests you expect.
- The sheet cannot show an agent's purpose; what the agent says in its session is its own claim.
- A malicious process running as your macOS user, outside any sandbox, can still attack your account by other routes: replace this binary or its LaunchAgent and wait for you to unlock it, or show a fake password dialog. It still cannot touch the sensor for you. Agent sandboxes that keep agents from writing outside their project close those routes; run agents you don't trust on another machine or as another user.
- Agent Access is an early alpha protocol, and Bitwarden runs the default relay (`wss://ap.lesspassword.dev`) for development use.

## Build

```sh
cargo build --release --locked
```

Apache-2.0. Uses the Bitwarden Agent Access SDK. See [NOTICE](NOTICE). Not affiliated with Bitwarden.
