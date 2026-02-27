# NAIS ChanServ - Channel Services Bot

A standalone bot that acts as a persistent host for NAIS Secure Channels, similar to traditional IRC 'ChanServ' services.

## Features

- **Long-term Channel Hosting**: Stays online 24/7 to maintain channel state and keys
- **Key Distribution**: Acts as a reliable key distribution point for new members
- **Store-and-Forward**: Queues messages for offline members (configurable TTL)
- **Metadata Management**: Maintains authoritative channel metadata
- **Multi-Channel Support**: Hosts multiple channels simultaneously
- **IRC Presence**: Maintains presence on IRC for peer discovery
- **QUIC Transport**: Direct P2P communication with peers

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      NAIS ChanServ Bot                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  IRC Client  │  │ QUIC Server  │  │  Channel Manager     │  │
│  │  (Discovery) │  │ (Transport)  │  │  (Secure Channels)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └─────────────────┴──────────────────────┘              │
│                          │                                      │
│              ┌───────────▼───────────┐                          │
│              │   Persistence Layer   │                          │
│              │  (Config, Keys, Msgs) │                          │
│              └───────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

```bash
# Start with default config
nais-chanserv

# Start with custom config file
nais-chanserv --config /path/to/chanserv.toml

# Start with specific bind address and relay hub
nais-chanserv --bind 0.0.0.0:4434 --relay-hub hub.example.com:4433
```

## Configuration

Create `chanserv.toml`:

```toml
# Server identity
nickname = "ChanServ"
display_name = "NAIS Channel Services"

# Network binding
bind_address = "0.0.0.0:4434"

# Relay hub for NAT traversal fallback
relay_hub = "hub.pugbot.net:4433"

# IRC connection for peer discovery
[irc]
server = "irc.pugbot.net"
port = 6697
use_tls = true
nick = "NAIS-ChanServ"
channels = ["#nais-chanserv"]

# Storage settings
[storage]
data_dir = "~/.nais-chanserv"
message_ttl_days = 7
max_messages_per_channel = 10000

# Hosted channels (initial list)
[[channels]]
name = "general"
topic = "General NAIS discussion"
auto_register = true

[[channels]]
name = "development"
topic = "NAIS development channel"
auto_register = true
```

## Channel Registration

Users can register channels for ChanServ hosting:

1. **Via CTCP**: Send `REGISTER <channel_id>` command to ChanServ
2. **Via Config**: Add channel to `chanserv.toml`
3. **Via API** (future): REST API for channel management

## Security

- ChanServ maintains its own identity key pair
- All communications are end-to-end encrypted
- ChanServ stores only encrypted epoch secrets
- Private keys never leave the server

## Running as a Service

### Systemd

```ini
[Unit]
Description=NAIS Channel Services Bot
After=network.target

[Service]
Type=simple
User=nais
ExecStart=/usr/local/bin/nais-chanserv --config /etc/nais-chanserv/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /build
COPY . .
RUN cargo build --release -p nais-chanserv

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/nais-chanserv /usr/local/bin/
EXPOSE 4434
CMD ["nais-chanserv"]
```
