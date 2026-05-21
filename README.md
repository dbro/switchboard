# switchboard

A tiny local WebSocket pub/sub broker. One subscriber registers interest in a set of channels; publishers send messages to a channel and wait for a reply. The switchboard routes messages between them without inspecting payload content.

## Protocol

All messages are JSON text frames over a single WebSocket connection at `ws://127.0.0.1:PORT/ws`.

**Subscribe** — register interest in one or more channels:
```json
{"type":"subscribe","channels":["id1","id2"]}
```

**Publish** — send a message to a channel and wait for a reply:
```json
{"type":"publish","channel":"id1","replyTo":"n", ...payload...}
```
The switchboard forwards the entire message verbatim to the subscriber that registered the matching channel. If no subscriber is connected for that channel, the switchboard sends:
```json
{"type":"error","message":"No subscriber for that channel"}
```

**Reply** — subscriber routes a response back to the waiting publisher:
```json
{"type":"reply","replyTo":"n", ...payload...}
```
The switchboard matches `replyTo` to the publisher that sent the corresponding publish and forwards the reply verbatim.

Publisher connections that receive no reply within `--ttl` seconds are closed with a timeout error.

## HTTP endpoints

```
GET  /status  →  200 "ok"
POST /clear   →  disconnect all WebSocket clients, 200 "ok"
```

## Build

**Portable APE binary** (runs on Linux, macOS, Windows, FreeBSD without installation — requires [cosmocc](https://github.com/jart/cosmopolitan)):

```sh
PATH="$HOME/src/cosmocc/bin:$PATH" make
```

**Native binary**:

```sh
make
```

The Makefile detects which compiler is available automatically.

## Run

```sh
./switchboard [options]
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--port N` | 7577 | Listening port |
| `--max-conns N` | 32 | Max concurrent connections |
| `--max-blob N` | 16384 | Max message size in bytes |
| `--ttl N` | 60 | Publisher idle timeout in seconds (0 = no limit) |

The switchboard binds to `127.0.0.1` only — not reachable from other machines.

## Run continuously

### Linux (systemd)

```sh
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/switchboard.service << EOF
[Unit]
Description=switchboard

[Service]
ExecStart=/path/to/switchboard
Restart=on-failure

[Install]
WantedBy=default.target
EOF

systemctl --user enable --now switchboard
```

### macOS (launchd)

```sh
cat > ~/Library/LaunchAgents/dev.switchboard.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.switchboard</string>
  <key>ProgramArguments</key>
  <array>
    <string>/path/to/switchboard</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/dev.switchboard.plist
```

### Windows (Task Scheduler)

Run once at login via Task Scheduler, or drop a shortcut in the Startup folder:

```
shell:startup
```

Point it at `switchboard.exe`.
