# aac-touchid

A background [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) listener for macOS that releases each credential only after you approve it with **Touch ID** (or an Apple Watch).

Agents keep using Bitwarden's own client, `aac` 0.11:

```sh
aac run --domain "github.com | pi · homelab | check gh login" --env GH_TOKEN=password -- gh auth status
```

`--domain` (or `--id`) may carry `item | agent | reason`, or `item | reason`. The agent's name and reason are shown on the panel and removed before the vault lookup. Both are the agent's own claims; the device name (from pairing) is verified.

The request travels end to end encrypted through the Agent Access relay to this listener on your Mac. The listener looks up the item with the Bitwarden CLI (`bw`) and shows an approval panel:

> **Share a password + 2FA code**
>
> Agent: pi · homelab
> Device: nuc
> Item: GitHub
> Username: you@example.com
> Releases: password + 2FA code
> Reason: check gh login
> Answer within: 0:57
>
> [Deny]  [Allow once]  [Allow 15 min]  [Allow 1 h]

- Agent and reason are the agent's own words, and the panel says so. The device is verified by pairing.
- Deny is on Esc. The Allow buttons stay greyed for the first second, so a stray keypress cannot approve, and the panel closes (denied) when the countdown ends. It floats above other windows, plays a sound and shows on every Space.
- You choose how long to remember the approval. An agent's `remember=` only preselects the matching button (Return); you can still pick Allow once. Writes, `ask:` and pairing offer a single Allow button.
- Allow is not final: Touch ID (or the Watch) follows, with a short sheet (`Bitwarden is trying to share GitHub with nuc`). If you cancel Touch ID the panel comes back. A click alone never approves, so nothing that can script clicks can approve either.
- macOS titles the Touch ID sheet with the program's file name, so install a copy of the binary named `Bitwarden` for the service to run (see below). The panel says what is released: `password`, `password + 2FA code`, `username only`, or `field “NAME”` for a custom field. Notes are never released, because they can hold recovery codes.
- When the Mac's screen is locked, asleep or its lid is closed, the request waits (`--wait-for-mac`, default 50 s) and a notification says an agent is waiting. If you unlock in time the panel appears; otherwise the agent gets exit 4 and `why:` says `unavailable (Mac locked, asleep or lid closed)`.

## Custom fields (API keys)

An API key is often a hidden custom field on a login or note rather than its password. Ask for one field by name after the item:

```sh
aac run --domain "openai.com field=API_KEY | pi · homelab | list models" \
  --env OPENAI_API_KEY=password -- ./list-models.sh
```

- The field's value arrives in the `password` slot, with the login's username, URI and item id. The 2FA code and notes are never included.
- `NAME` is 1-64 of `A-Z a-z 0-9 _ . -`, matched ignoring case. A space in the vault's field name is written `_` (`API Key` is `field=API_Key`).
- Text, hidden and boolean fields can be read; linked fields cannot. An empty value counts as not found, and two fields with the same name are refused as ambiguous.
- A host finds logins as usual. By item id or name, any item type works, so a key on a secure note can be read.
- It combines with `remember=` and `--id`. In `batch:`, write `<item>#field:<NAME>`: `batch:openai.com#field:API_KEY,github.com`.
- A grant covers only what its panel named: approving an item's password does not release its fields, nor the reverse.

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
| `rotate:<item> [user=<u>] [words=3-20] [length=12-128] [symbols=no]` | Replaces the password of an existing login with a generated one (the same formats as `new:`) and releases its username, new password, URI and item id. `user=` also sets the login's username in the same write; the panel shows a `New username` row. `<item>` is found like a read finds it: name the host you sign in on (`rotate:speedtest.example.com`), or use an item id. The old password stays in the item's password history. |
| `save:<name> [user=<u>] [url=<full url>] password64=<base64>` | Stores a password the agent already has as a new login (for example one it read from a config file) and releases the username, URI and item id, not the password. `password64` is the password in base64 (standard or URL-safe, 1-512 bytes of text), so characters like `\|`, `=` and spaces survive the request format. |
| `savefield:<item> name=<NAME> value64=<base64> [user=<u>] [url=<full url>]` | Stores an API key the agent already has as a hidden custom field, and releases the username, URI and item id, not the value. `<item>` is one word, found like `rotate:` finds it (a host, a name, or an item id); any item type works, yours included. When no item is found, a new login `<item>` is created in `Agent-created` that holds the field (see Saving an API key). `value64` is the key in base64 (1-4096 bytes of text). |
| `ask:<item> name=<NAME> [user=<u>] [url=<full url>]` | Has you type an API key into the panel (a hidden field) and stores it like `savefield:`, as a hidden custom field, so the agent never holds the value. It gets the username, URI and item id back, never the value. Use `--timeout 240`: you have 3 minutes to type. The same refusals and old-value handling as `savefield:`. |
| `totp:<item> secret=<base32>` | Stores a TOTP seed on a login and releases its username and current code, so the agent can confirm enrollment. |
| `totp:<item> uri=otpauth://totp/...?secret=...` | The same, from an `otpauth://` URI; its other parameters (digits, period, algorithm) are kept. |
| anything else | A normal read, unchanged. |

`<name>` may have spaces and the characters `. - _ @ & + '`. `<item>` is one word: a domain, an item name without spaces, or an item id. Secrets are uppercased, `=` and `-` are dropped, and the rest must be base32 (A-Z, 2-7), 16-128 characters. Later reads use the normal flow (`--domain acme.io`).

```sh
# Change an existing login's password and use the new one.
aac run --domain "rotate:speedtest.example.com | pi · homelab | rotate admin password" \
  --env P=password -- ./set-password.sh
```

```sh
# Store a password you already have. Prefer rotate: when the service allows it.
aac connect --domain "save:Letterboxarr user=admin url=https://letterboxarr.example.com password64=$(printf %s "$PW" | base64 | tr -d '\n') | pi · homelab | store existing login" --output json
```

### Saving an API key

```sh
aac connect --domain "savefield:openai.com name=API_KEY value64=$(printf %s "$KEY" | base64 | tr -d '\n') | pi · homelab | store new API key" --output json
```

- With an existing item, the key becomes a hidden field `NAME` on it. If a field of that name (ignoring case, `_` for a space) already holds another value, the old value is never lost: that field is renamed `NAME (replaced YYYY-MM-DD)` (with ` #2`, ` #3` if taken) and stays on the item, and the new value goes in a hidden field under the old name. Delete the old field in Bitwarden once the old key is revoked. The listener reads the item again right before writing, and reports success only after the reply shows both values.
- The same value already stored writes nothing (`unchanged`, no panel). An empty field of that name is filled in place. Two fields with that name, or a linked field, are refused.
- With no item, a login named `<item>` is created in `Agent-created` with no password and the field, with the same duplicate guard as `new:`. Its URI is `url=`, or `https://<item>` when `<item>` looks like a host; `user=` sets its username. `user=` and `url=` are ignored when the item exists. An item id that matches nothing, or a name `new:` would refuse, is not created.
- Each write shows its own panel and never uses or creates a grant. The panel's title says what is about to happen (`Save the field “API_KEY” the agent supplied`, `Replace the field ... keeping the old one`, `Create a login holding the field ...`).

Each write shows its own approval panel. A new login's panel names the password format (`new 6-word passphrase`, `new 32-character password`), never the password. The other titles are `Create a login`, `Replace a password` (with `New username` when `user=` is set), `Save a password the agent supplied` and `Add 2FA and share a 2FA code`.

Guardrails:

- `new:` is refused if an item with that name (any case) or a login a read of that host would find (a URI on exactly that host, or named that host; `www.` ignored) already exists, checked before the panel and again after approval.
- Writes go straight to the Bitwarden server. The listener syncs its vault before a write's checks (refusing if that fails) and again after the write. Other Bitwarden apps pick up the change by their usual push notification or next sync.
- New logins go in the folder `Agent-created` (created on first use), with a note naming the agent, device and reason.
- `rotate:` works on any login that resolves to exactly one item, yours included, and only after its own panel. The old password is never released; it stays in the item's password history, and the outcome says if it did not (`rotated (old password not kept in history)`).
- `save:` has the same duplicate guard as `new:`. The login goes in `Agent-created` with a note naming the agent, device and reason. The password sits in `aac`'s command line while it runs, like a `totp:` seed, and logs and `status` show `save:<name> [redacted]`. Rotating is better whenever the service allows it, because the agent then never sees the password.
- `totp:` works only on a login that resolves to exactly one item, sits in `Agent-created`, and has no 2FA seed. An agent can never add 2FA to a login you made, and never overwrites a seed; the item is read again after approval to make sure.
- `totp:` releases only the username and the current code, never the seed or the password.
- Malformed requests are refused without a panel: unknown or repeated options, more than one seed, HOTP (`otpauth://hotp/`), an `otpauth` URI without a secret, a length outside 12-128, a word count outside 3-20, or `words=` mixed with `length=`/`symbols=`. Error messages never repeat the request.
- Repeat denials are remembered per `new <name>` and `2FA <item>`, like reads.

It replaces the interactive `aac listen` terminal app. There is nothing to keep open, and nothing an agent can type, click or send to a terminal pane can approve a request.

### Typing a key yourself (`ask:`)

```sh
aac connect --domain "ask:openai.com name=API_KEY | pi · homelab | store the key you create" --timeout 240 --output json
```

The panel reads `Enter a value for the field “API_KEY”` with a hidden `Value` field. An empty value is refused, then Touch ID follows. The value goes from the panel to the listener to the vault and nowhere else.

## Why was I denied?

A refusal reaches the agent only as `aac` exit 4. `why:` asks for the reason, with no panel and no unlock:

```sh
aac connect --domain "why:" --output json
```

The reply's `domain` holds this device's last 5 decisions from the last 15 minutes, newest first, for example `new Speedtest Tracker: refused (already exists: a login for speedtest.example.com), 40 s ago`. It carries request labels and outcomes only, never vault item names or secrets.

## Fewer prompts: remember and batch

Two more request forms ride in the item part of `--domain`, like `new:` and `totp:`:

```sh
# Release GitHub now, and again for 15 minutes without a prompt.
aac run --domain "github.com remember=15m | pi · homelab | gh work" --env GH_TOKEN=password -- gh pr list

# Approve several items on one panel (each is then read once within 120 s).
aac connect --domain "batch:github.com,npmjs.com remember=10m | pi · homelab | publish" --output json
```

- `remember=` takes `1m` to `24h` (`15m`, `2h`). It preselects the matching button on the panel (`Allow 15 min`); you may pick any other, including Allow once, and the choice you make is what is remembered.
- `--max-remember-minutes` (default 60; `0` turns remembering off) caps what an agent can ask for. A longer request is clamped, and the panel offers no longer window.
- A grant is keyed on the verified device and the resolved vault item id, never the agent's self-reported name, so `github.com` and `https://github.com/login` share one. It is in memory only.
- `batch:` takes up to 10 comma-separated items and shows one row per item. Without `remember=` each item can be read once within 120 s; with it, the remember window applies. `new:` and `totp:` writes always get their own panel and never use grants.
- Locking the vault, `aac-touchid forget`, and revoking a device clear all grants. `aac-touchid status` lists them.

## `aac-touchid run`

`aac-touchid run` fills `bw://` references in a command's environment, then `exec`s it. With two or more items it sends one `batch:` request (one panel), then reads each item with stock `aac connect --output json`. It also builds for Linux (the `aac-touchid-linux-x86_64` release), so the NUC can use it; `aac` must be on `PATH` there.

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
| `bw://ITEM#field:NAME` | The custom field `NAME` (see Custom fields). |
| `${bw://ITEM#FIELD}` | The same, inside a longer value. |

Options: `--env NAME=VALUE` (repeatable; the value may hold references; wins over `--env-file`), `--env-file` (repeatable; later files win), `--dry-run` (prints the requests it would send and the variables with references, as JSON, and asks nothing), `--no-mask`, `--agent` (default `$AAC_AGENT`), `--reason`, `--remember`, `--timeout` (seconds per answer, default 240). At most 10 items per run. Inherited environment variables may hold references too.

Output is masked: the passwords and custom-field values put into the environment (6 bytes or more) are replaced by `<masked:NAME>` in the command's stdout and stderr, also when base64-, percent- or JSON-encoded or split across reads, and `run` says how many it masked. Usernames, URIs and 2FA codes are not masked. `--no-mask` runs the command directly. This is a safety net, not a sandbox: a command can still send a secret elsewhere.

When a request is denied (exit 4), `run` asks the Mac why (`why:`) and prints the reason with a note not to repeat the request, so agents need no separate call.

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
| `aac-touchid pair [name]` | For a machine you can't list with `--pair-*`: prints a one-time pairing code (valid 5 minutes). Its first use (`aac run --token <code> ...`) shows a panel asking to pair device `name`. |
| `aac-touchid status` | Lock state, relay connection, paired devices, recent decisions. |
| `aac-touchid lock` | Locks the vault now. |
| `aac-touchid revoke <name>` | Forgets a paired device. |
| `aac-touchid forget` | Forgets every remembered approval. |
| `aac-touchid run [--env-file F]... -- <cmd>` | Runs a command with `bw://` references filled in (see above). Works on Linux. |

`serve` also takes `--max-remember-minutes` (default 60) and `--wait-for-mac` (seconds a request waits for a locked or closed Mac, default 50; `aac`'s own request timeout is 120 s).

The vault starts locked. The first request after a restart, 8 hours idle (`--lock-after-hours`) or `lock` shows a native password dialog for your master password, then the approval panel.

State (identity key, paired devices) lives in `~/Library/Application Support/aac-touchid` (0700). Override it with `AAC_TOUCHID_STATE_DIR`. Logs go to stderr and never contain secrets.

## Security model

Trusted: the Mac's logged-in GUI session and the person at it. Untrusted: agents, the machines they run on, and the relay.

- Every write, and every read that is not under a grant, needs a biometric or Watch approval. A grant exists only because you approved a panel offering that window (`remember=` or `batch:`), and writes always get their own panel (the panel is a child process of the listener that reports on a pipe only the listener holds; Allow is followed by LocalAuthentication `deviceOwnerAuthenticationWithBiometricsOrCompanion`, password fallback hidden). The panel names the agent (self-reported) and its device (verified), the vault item, the username and the agent's stated reason.
- Only paired devices can ask. Automatic pairing goes only to the machines named in the service's arguments, with a one-time PSK token delivered over the local process or authenticated ssh; the Noise PSK handshake binds it to that listener. Manual pairing needs a code from `aac-touchid pair` and a Touch ID approval. A code an agent obtains alone does not pair anything.
- After a denial, the same device asking for the same item is denied silently for 60 s (not when Touch ID was unavailable and no panel appeared), and a cancelled unlock dialog is not shown again for 2 minutes, so an agent cannot spam prompts.
- The master password and vault key never go into an environment variable or a command line, where any process of the same user can read it (`ps -E`). The listener runs one `bw serve` child on a private socket pair (`--hostname fd+connected://3`, a supported `bw serve` mode) that no other process can open; the master password travels once in its `POST /unlock` body and the vault key stays inside that child. Locking calls `/lock` and stops the child.
- `bw login --apikey` reads the API key only from its environment, so on first login the key is in that one short-lived child's environment. The API key alone cannot decrypt the vault.
- `why:` releases only the asking device's own decision records (request labels and outcomes), without a panel.
- Only username, password, URI, the current 2FA code (never the TOTP seed) and a custom field the agent names, shown on the panel, are released.
- A grant covers only the fields its panel named: approving a password does not release the item's custom fields, nor the reverse.
- An `ask:` value is typed into the panel, passes to the listener over the panel's private pipe and goes into the vault; it is never sent to the agent and never appears in logs or `status`.
- `savefield:` never deletes or overwrites a stored value: a replaced value is kept on the item as `NAME (replaced DATE)`.
- A `totp:` seed, `save:` password or `savefield:` value is in the requesting machine's `aac` command line while it runs, where processes of the same user there can read it, and the agent has seen it once on the signup page. It leaves the listener only inside the encrypted vault: logs and `status` show `totp:<item> [redacted]` and `2FA <item>`. Generated passwords and seeds are wiped from the listener's request buffers after use.
- Agent names are reduced to letters, digits, spaces and `· . - _ / @`, so a name cannot fake a device suffix or extra lines. Pairing completes only within 5 minutes of `aac-touchid pair`, and the panel names the device and when its code was issued.
- The relay sees only device fingerprints and timing (Noise protocol, end to end).

Not covered:

- Within a grant's window, any agent on that device can read that item.
- An approved command holds that secret and can misuse it. Approve only requests you expect.
- The panel cannot show an agent's purpose; what the agent says in its session is its own claim.
- A malicious process running as your macOS user, outside any sandbox, can still attack your account by other routes: replace this binary or its LaunchAgent and wait for you to unlock it, or show a fake password dialog. It still cannot touch the sensor for you. Agent sandboxes that keep agents from writing outside their project close those routes; run agents you don't trust on another machine or as another user.
- Agent Access is an early alpha protocol, and Bitwarden runs the default relay (`wss://ap.lesspassword.dev`) for development use.

## Build

```sh
cargo build --release --locked
```

Apache-2.0. Uses the Bitwarden Agent Access SDK. See [NOTICE](NOTICE). Not affiliated with Bitwarden.
