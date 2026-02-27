# NAIS Secure Channel Services (SCS)

A standalone bot that acts as a persistent host for NAIS Secure Channels. Named "SCS" (Secure Channel Services) to distinguish it from traditional IRC ChanServ bots — this is **Convey-SCS**.

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
│               NAIS Secure Channel Services (SCS)                │
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
nais-scs

# Start with custom config file
nais-scs --config /path/to/scs.toml

# Start with specific bind address and relay hub
nais-scs --bind 0.0.0.0:4434 --relay-hub hub.example.com:4433
```

## Configuration

Create `scs.toml`:

```toml
# Server identity
nickname = "SCS"
display_name = "NAIS Secure Channel Services"

# Network binding
bind_address = "0.0.0.0:4434"

# Relay hub for NAT traversal fallback
relay_hub = "hub.pugbot.net:4433"

# IRC connection for peer discovery
[irc]
server = "irc.pugbot.net"
port = 6697
use_tls = true
nick = "Convey-SCS"
channels = ["#convey-scs"]

# Storage settings
[storage]
data_dir = "~/.nais-scs"
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

Users can register channels for SCS hosting:

1. **Via CTCP**: Send `REGISTER <channel_id>` command to Convey-SCS
2. **Via Config**: Add channel to `scs.toml`
3. **Via API** (future): REST API for channel management

## Security

- SCS maintains its own identity key pair
- All communications are end-to-end encrypted
- SCS stores only encrypted epoch secrets
- Private keys never leave the server

## Running as a Service

### Systemd

```ini
[Unit]
Description=NAIS Secure Channel Services (SCS)
After=network.target

[Service]
Type=simple
User=nais
ExecStart=/usr/local/bin/nais-scs --config /etc/nais-scs/config.toml
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
RUN cargo build --release -p nais-scs

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/nais-scs /usr/local/bin/
EXPOSE 4434
CMD ["nais-scs"]
```
