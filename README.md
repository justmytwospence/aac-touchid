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

Each write shows its own Touch ID sheet:

> Bitwarden is trying to create a login and share its password
>
> **𝗽𝗶 · 𝗵𝗼𝗺𝗲𝗹𝗮𝗯** (nuc)
> **𝗮𝗰𝗺𝗲.𝗶𝗼** (bot@example.com)
> sign up for Acme

> Bitwarden is trying to add 2FA and share a 2FA code

Guardrails:

- `new:` is refused if an item with that name (any case) or a login for that host already exists, checked before the sheet and again after approval.
- New logins go in the folder `Agent-created` (created on first use), with a note naming the agent, device and reason.
- `totp:` works only on a login that resolves to exactly one item, sits in `Agent-created`, and has no 2FA seed. An agent can never add 2FA to a login you made, and never overwrites a seed; the item is read again after approval to make sure.
- `totp:` releases only the username and the current code, never the seed or the password.
- Malformed requests are refused without a sheet: unknown or repeated options, more than one seed, HOTP (`otpauth://hotp/`), an `otpauth` URI without a secret, a length outside 12-128, a word count outside 3-20, or `words=` mixed with `length=`/`symbols=`. Error messages never repeat the request.
- Repeat denials are remembered per `new <name>` and `2FA <item>`, like reads.

It replaces the interactive `aac listen` terminal app. There is nothing to keep open, and nothing an agent can type, click or send to a terminal pane can approve a request.

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

The vault starts locked. The first request after a restart, 8 hours idle (`--lock-after-hours`) or `lock` shows a native password dialog for your master password, then the Touch ID sheet.

State (identity key, paired devices) lives in `~/Library/Application Support/aac-touchid` (0700). Override it with `AAC_TOUCHID_STATE_DIR`. Logs go to stderr and never contain secrets.

## Security model

Trusted: the Mac's logged-in GUI session and the person at it. Untrusted: agents, the machines they run on, and the relay.

- Every credential and every write needs a biometric or Watch approval (LocalAuthentication `deviceOwnerAuthenticationWithBiometricsOrCompanion`, password fallback hidden). The sheet names the agent (self-reported) and its device (verified), the vault item, the username and the agent's stated reason.
- Only paired devices can ask. Automatic pairing goes only to the machines named in the service's arguments, with a one-time PSK token delivered over the local process or authenticated ssh; the Noise PSK handshake binds it to that listener. Manual pairing needs a code from `aac-touchid pair` and a Touch ID approval. A code an agent obtains alone does not pair anything.
- After a denial, the same device asking for the same item is denied silently for 60 s, and a cancelled unlock dialog is not shown again for 2 minutes, so an agent cannot spam prompts.
- The master password and vault key never go into an environment variable or a command line, where any process of the same user can read it (`ps -E`). The listener runs one `bw serve` child on a private socket pair (`--hostname fd+connected://3`, a supported `bw serve` mode) that no other process can open; the master password travels once in its `POST /unlock` body and the vault key stays inside that child. Locking calls `/lock` and stops the child.
- `bw login --apikey` reads the API key only from its environment, so on first login the key is in that one short-lived child's environment. The API key alone cannot decrypt the vault.
- Only username, password, URI and the current 2FA code (never the TOTP seed) are released.
- A `totp:` seed is in the requesting machine's `aac` command line while it runs, where processes of the same user there can read it, and the agent has seen it once on the signup page. It leaves the listener only inside the encrypted vault: logs and `status` show `totp:<item> [redacted]` and `2FA <item>`. Generated passwords and seeds are wiped from the listener's request buffers after use.
- Agent names are reduced to letters, digits, spaces and `· . - _ / @`, so a name cannot fake a device suffix or extra lines. Pairing completes only within 5 minutes of `aac-touchid pair`, and the sheet names the device and when its code was issued.
- The relay sees only device fingerprints and timing (Noise protocol, end to end).

Not covered:

- An approved command holds that secret and can misuse it. Approve only requests you expect.
- The sheet cannot show an agent's purpose; what the agent says in its session is its own claim.
- A malicious process running as your macOS user, outside any sandbox, can still attack your account by other routes: replace this binary or its LaunchAgent and wait for you to unlock it, or show a fake password dialog. It still cannot touch the sensor for you. Agent sandboxes that keep agents from writing outside their project close those routes; run agents you don't trust on another machine or as another user.
- Agent Access is an early alpha protocol, and Bitwarden runs the default relay (`wss://ap.lesspassword.dev`) for development use.

## Build

```sh
cargo build --release --locked
```

Apache-2.0. Uses the Bitwarden Agent Access SDK. See [NOTICE](NOTICE). Not affiliated with Bitwarden.
