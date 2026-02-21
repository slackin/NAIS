# NAIS Relay Hub

A federation hub for Nais Secure Channels (NSC) that relays encrypted messages between peers when direct P2P connections fail.

## Purpose

The relay hub serves as a fallback transport for NSC when:
- Both peers are behind symmetric NAT (direct hole punching fails)
- Firewall blocks UDP traffic
- Network conditions prevent direct connectivity

**Important**: The relay hub only sees encrypted ciphertext. It cannot read message content, only forward it to the intended recipient.

## Features

- **QUIC Transport**: Fast, multiplexed connections with TLS 1.3
- **Peer Registration**: Clients register with their PeerId and channel subscriptions
- **Message Forwarding**: Routes encrypted envelopes between connected peers
- **Store-and-Forward**: Queues messages for offline peers (up to 7 days)
- **Health Monitoring**: Tracks peer activity, removes stale connections
- **Statistics**: Periodic logging of hub activity

## Building

```bash
# From the nais-client directory
cargo build -p nais-relay-hub --release
```

## Deployment to pugbot.net

1. Copy the binary to your server:
   ```bash
   scp target/release/relay-hub user@pugbot.net:~/
   ```

2. SSH to the server and run:
   ```bash
   # Make sure port 4433/UDP is open in firewall
   sudo ufw allow 4433/udp
   
   # Run the relay hub
   ./relay-hub --bind 0.0.0.0:4433
   
   # Or run in background with nohup
   nohup ./relay-hub --bind 0.0.0.0:4433 >> relay-hub.log 2>&1 &
   ```

3. (Optional) Create a systemd service for auto-start:
   ```bash
   sudo tee /etc/systemd/system/nais-relay.service << 'EOF'
   [Unit]
   Description=NAIS Relay Hub
   After=network.target
   
   [Service]
   Type=simple
   User=nais
   ExecStart=/home/nais/relay-hub --bind 0.0.0.0:4433
   Restart=always
   RestartSec=5
   
   [Install]
   WantedBy=multi-user.target
   EOF
   
   sudo systemctl daemon-reload
   sudo systemctl enable nais-relay
   sudo systemctl start nais-relay
   ```

## Running Locally

```bash
# Start on default port (4433)
./target/release/relay-hub

# Custom bind address
./target/release/relay-hub --bind 0.0.0.0:5000

# With debug logging
./target/release/relay-hub --log-level debug
```

## Testing with NAIS Client

1. Start the relay hub on pugbot.net (or locally)

2. The NAIS client will automatically try:
   - `127.0.0.1:4433` (local testing)
   - `pugbot.net:4433` (production relay)

3. Messages route through relay when direct P2P fails

## Protocol

The relay hub uses the same wire protocol as NSC P2P connections:

### Registration (RelayRequest)
```
RelayRegister {
    peer_id: [u8; 32],    // Client's identity hash
    channels: Vec<[u8;32]> // Channels to receive messages for
}
```

### Forwarding (RelayData)
```
RelayForward {
    target_peer_id: [u8; 32],
    envelope: Vec<u8>,     // Encrypted NSC envelope
}
```

## Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_MESSAGE_SIZE` | 64 KB | Maximum envelope size |
| `STORE_FORWARD_TTL` | 7 days | How long to keep offline messages |
| `MAX_STORED_PER_PEER` | 1000 | Max queued messages per peer |
| `PEER_TIMEOUT` | 120 sec | Disconnect inactive peers |

## Security Notes

- The hub generates a self-signed TLS certificate on startup
- All relayed content is end-to-end encrypted by NSC
- The hub validates message format but cannot verify signatures (no identity keys)
- Rate limiting can be added to prevent abuse

## Production Deployment

For production use:
1. Use a proper TLS certificate (Let's Encrypt)
2. Run behind a reverse proxy for TLS termination
3. Configure firewall rules
4. Set up monitoring and alerting
5. Consider horizontal scaling with consistent hashing

## License

Apache-2.0
