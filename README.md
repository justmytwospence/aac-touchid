# aac-touchid

A background [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) listener for macOS that releases each credential only after you approve it with **Touch ID** (or an Apple Watch).

Agents keep using Bitwarden's own client, `aac` 0.11:

```sh
aac run --domain "github.com | check gh login" --env GH_TOKEN=password -- gh auth status
```

Text after ` | ` is the agent's one-line reason. It is shown on the sheet and removed before the vault lookup.

The request travels end to end encrypted through the Agent Access relay to this listener on your Mac. The listener looks up the item with the Bitwarden CLI (`bw`) and shows a system sheet:

> "aac-touchid" is trying to share 𝗚𝗶𝘁𝗛𝘂𝗯 (you@example.com) with "nuc" — check gh login.

The vault item's name is set in bold letters (the system sheet has no rich text, so they are Unicode mathematical bold characters).

If you touch the sensor, the secret goes to that device and into the command's environment. If you cancel or don't answer within 60 s, the agent gets `aac` exit code 4 ("Request denied").

It replaces the interactive `aac listen` terminal app. There is nothing to keep open, and nothing an agent can type, click or send to a terminal pane can approve a request.

## Requirements

- macOS with Touch ID (or an Apple Watch set up for approvals)
- Bitwarden CLI `bw`, logged in once (`bw login`, or `bw login --apikey`)
- `aac` 0.11.x on every machine whose agents request credentials

## Use

`aac-touchid serve` is meant to run under launchd, for example with a LaunchAgent:

```xml
<key>ProgramArguments</key>
<array><string>/Users/you/.local/bin/aac-touchid</string><string>serve</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>EnvironmentVariables</key>
<dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string></dict>
```

Commands:

| Command | What it does |
|---|---|
| `aac-touchid pair [name]` | Prints a one-time pairing code (valid 5 minutes). Its first use on another machine (`aac run --token <code> ...`) shows a Touch ID sheet asking to pair device `name`. |
| `aac-touchid status` | Lock state, relay connection, paired devices, recent decisions. |
| `aac-touchid lock` | Locks the vault now. |
| `aac-touchid revoke <name>` | Forgets a paired device. |

The vault starts locked. The first request after a restart, 8 hours idle (`--lock-after-hours`) or `lock` shows a native password dialog for your master password, then the Touch ID sheet.

State (identity key, paired devices) lives in `~/Library/Application Support/aac-touchid` (0700). Override it with `AAC_TOUCHID_STATE_DIR`. Logs go to stderr and never contain secrets.

## Security model

Trusted: the Mac's logged-in GUI session and the person at it. Untrusted: agents, the machines they run on, and the relay.

- Every credential needs a biometric or Watch approval (LocalAuthentication `deviceOwnerAuthenticationWithBiometricsOrCompanion`, password fallback hidden). The sheet names the vault item, the username, the device and the agent's stated reason.
- Only paired devices can ask. Pairing needs a code from `aac-touchid pair` and a Touch ID approval of the device's verification code. A code an agent obtains alone does not pair anything.
- After a denial, the same device asking for the same item is denied silently for 60 s, and a cancelled unlock dialog is not shown again for 2 minutes, so an agent cannot spam prompts.
- The Bitwarden session key lives only in this process's memory. It and the master password reach `bw` only as the environment of short-lived child processes. Locking runs `bw lock`, so a leaked session key stops working.
- The relay sees only device fingerprints and timing (Noise protocol, end to end).

Not covered:

- An approved command holds that secret and can misuse it. Approve only requests you expect.
- The sheet cannot show an agent's purpose; what the agent says in its session is its own claim.
- A malicious process running as your macOS user can attack your account by other routes (replace this binary, read a `bw` child's environment during a lookup, or show a fake password dialog). It still cannot touch the sensor for you. Run agents you don't trust on another machine or as another user.
- Agent Access is an early alpha protocol, and Bitwarden runs the default relay (`wss://ap.lesspassword.dev`) for development use.

## Build

```sh
cargo build --release --locked
```

Apache-2.0. Uses the Bitwarden Agent Access SDK. See [NOTICE](NOTICE). Not affiliated with Bitwarden.
