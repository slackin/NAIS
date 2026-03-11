//! TCP listener and per-connection read loop.

use crate::commands;
use crate::connection::{ClientConnection, ConnId};
use crate::protocol::Message;
use crate::state::ServerState;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

/// Start the plaintext TCP listener.
pub async fn run_listener(state: Arc<ServerState>, bind_addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    log::info!("Listening on {} (plaintext)", bind_addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        // Check connection limit
        if state.client_count() >= state.config.limits.max_clients {
            log::warn!("Connection limit reached, rejecting {}", addr);
            continue;
        }

        tokio::spawn(async move {
            let conn_id = state.next_conn_id();
            log::info!("[{}] New connection from {}", conn_id, addr);

            let (reader, writer) = stream.into_split();
            let client = ClientConnection::new(conn_id, addr, writer, false);
            state.add_client(client);

            handle_client_read(state.clone(), conn_id, reader).await;

            // Client disconnected — clean up
            if let Some(client) = state.remove_client(conn_id) {
                let prefix = client.prefix();
                let quit_msg = Message {
                    tags: None,
                    prefix: Some(prefix),
                    command: "QUIT".to_string(),
                    params: vec!["Connection closed".to_string()],
                };
                state.send_to_user_peers(conn_id, &quit_msg, false).await;
                log::info!("[{}] {} disconnected", conn_id, client.nick);
            }
        });
    }
}

/// Read loop for a single client connection.
async fn handle_client_read(
    state: Arc<ServerState>,
    conn_id: ConnId,
    reader: tokio::net::tcp::OwnedReadHalf,
) {
    let mut buf_reader = BufReader::new(reader);
    let mut line_buf = String::new();
    let reg_timeout = Duration::from_secs(state.config.limits.registration_timeout);

    loop {
        line_buf.clear();

        // Read with timeout for unregistered clients
        let is_registered = state.clients.get(&conn_id).map(|c| c.registered).unwrap_or(false);
        let timeout = if is_registered {
            Duration::from_secs(state.config.limits.ping_timeout + 30)
        } else {
            reg_timeout
        };

        let result = tokio::time::timeout(timeout, buf_reader.read_line(&mut line_buf)).await;

        match result {
            Ok(Ok(0)) => {
                // EOF
                break;
            }
            Ok(Ok(_n)) => {
                // Validate message length
                if line_buf.len() > crate::protocol::MAX_MSG_LEN_EXTENDED {
                    log::warn!("[{}] Message too long ({} bytes), ignoring", conn_id, line_buf.len());
                    continue;
                }

                if let Some(msg) = Message::parse(&line_buf) {
                    // Touch activity timer
                    if let Some(mut client) = state.clients.get_mut(&conn_id) {
                        client.touch();
                    }
                    commands::handle_message(&state, conn_id, msg).await;
                }
            }
            Ok(Err(e)) => {
                log::debug!("[{}] Read error: {}", conn_id, e);
                break;
            }
            Err(_) => {
                // Timeout
                if !is_registered {
                    log::debug!("[{}] Registration timeout", conn_id);
                } else {
                    log::debug!("[{}] Read timeout", conn_id);
                }
                break;
            }
        }
    }
}

/// Background task to ping idle clients and disconnect timed-out ones.
pub async fn run_ping_loop(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;

        let ping_timeout = Duration::from_secs(state.config.limits.ping_timeout);
        let now = Instant::now();
        let _server_name = state.server_name().to_string();

        // Collect IDs to avoid holding locks during iteration
        let conn_ids: Vec<ConnId> = state.clients.iter().map(|e| *e.key()).collect();

        for conn_id in conn_ids {
            let should_disconnect = {
                let client = match state.clients.get(&conn_id) {
                    Some(c) => c,
                    None => continue,
                };

                if !client.registered {
                    continue;
                }

                if let Some(ping_time) = client.last_ping {
                    // Already sent a ping — check if timed out
                    now.duration_since(ping_time) > Duration::from_secs(60)
                } else if now.duration_since(client.last_active) > ping_timeout {
                    // Idle too long — send a ping
                    false
                } else {
                    continue;
                }
            };

            if should_disconnect {
                // Timed out
                log::info!("[{}] Ping timeout, disconnecting", conn_id);
                if let Some(client) = state.remove_client(conn_id) {
                    let prefix = client.prefix();
                    let quit_msg = Message {
                        tags: None,
                        prefix: Some(prefix),
                        command: "QUIT".to_string(),
                        params: vec!["Ping timeout".to_string()],
                    };
                    state.send_to_user_peers(conn_id, &quit_msg, false).await;
                }
            } else {
                // Send PING
                let ping_token = format!("nais-{}", conn_id);
                let ping_msg = Message {
                    tags: None,
                    prefix: None,
                    command: "PING".to_string(),
                    params: vec![ping_token],
                };
                state.send_to(conn_id, &ping_msg).await;

                if let Some(mut client) = state.clients.get_mut(&conn_id) {
                    client.last_ping = Some(Instant::now());
                }
            }
        }
    }
}
