//! Global server state.
//!
//! Holds all connections, channels, houses, and provides
//! thread-safe access via DashMap and Arc.

use crate::config::ServerConfig;
use crate::connection::{Channel, ClientConnection, ConnId};
use crate::houses::House;
use crate::protocol::Message;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

/// A single logged message for scrollback replay.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Unix timestamp (seconds)
    pub timestamp: i64,
    /// nick!user@host of sender
    pub prefix: String,
    /// The IRC command (PRIVMSG or NOTICE)
    pub command: String,
    /// Target channel name
    pub target: String,
    /// Message text
    pub text: String,
}

/// Shared server state.
pub struct ServerState {
    /// Server configuration
    pub config: ServerConfig,
    /// Connected clients (ConnId -> ClientConnection)
    pub clients: DashMap<ConnId, ClientConnection>,
    /// Nick -> ConnId mapping for lookups
    pub nick_to_id: DashMap<String, ConnId>,
    /// Plain IRC channels (channel name -> Channel)
    pub channels: DashMap<String, Channel>,
    /// Houses (house name -> House)
    pub houses: DashMap<String, House>,
    /// Persistent message logs for channels with logging enabled (channel name -> log entries)
    pub message_logs: DashMap<String, VecDeque<LogEntry>>,
    /// Next connection ID
    next_id: AtomicU64,
    /// Server creation time
    pub created_at: std::time::Instant,
}

impl ServerState {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            clients: DashMap::new(),
            nick_to_id: DashMap::new(),
            channels: DashMap::new(),
            houses: DashMap::new(),
            message_logs: DashMap::new(),
            next_id: AtomicU64::new(1),
            created_at: std::time::Instant::now(),
        }
    }

    /// Allocate a new connection ID.
    pub fn next_conn_id(&self) -> ConnId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Server name from config.
    pub fn server_name(&self) -> &str {
        &self.config.server.name
    }

    /// Register a client connection.
    pub fn add_client(&self, conn: ClientConnection) {
        let id = conn.id;
        if !conn.nick.is_empty() {
            self.nick_to_id.insert(conn.nick.to_lowercase(), id);
        }
        self.clients.insert(id, conn);
    }

    /// Remove a client and clean up all state.
    pub fn remove_client(&self, conn_id: ConnId) -> Option<ClientConnection> {
        let client = self.clients.remove(&conn_id);
        if let Some((_, ref conn)) = client {
            // Remove nick mapping
            if !conn.nick.is_empty() {
                self.nick_to_id.remove(&conn.nick.to_lowercase());
            }
            // Remove from all channels
            for channel_name in &conn.channels {
                if let Some(mut ch) = self.channels.get_mut(channel_name) {
                    ch.members.remove(&conn_id);
                    // Clean up empty channels
                    if ch.members.is_empty() {
                        drop(ch);
                        self.channels.remove(channel_name);
                    }
                }
            }
        }
        client.map(|(_, c)| c)
    }

    /// Look up a connection by nickname.
    pub fn find_by_nick(&self, nick: &str) -> Option<ConnId> {
        self.nick_to_id.get(&nick.to_lowercase()).map(|r| *r.value())
    }

    /// Update nick mapping when a user changes nick.
    pub fn update_nick(&self, conn_id: ConnId, old_nick: &str, new_nick: &str) {
        if !old_nick.is_empty() {
            self.nick_to_id.remove(&old_nick.to_lowercase());
        }
        self.nick_to_id.insert(new_nick.to_lowercase(), conn_id);
    }

    /// Check if a nick is in use.
    pub fn nick_in_use(&self, nick: &str) -> bool {
        self.nick_to_id.contains_key(&nick.to_lowercase())
    }

    /// Send a message to a specific connection.
    pub async fn send_to(&self, conn_id: ConnId, msg: &Message) {
        if let Some(client) = self.clients.get(&conn_id) {
            let _ = client.send(msg).await;
        }
    }

    /// Send a batch of messages to a specific connection in one TCP write.
    pub async fn send_batch_to(&self, conn_id: ConnId, messages: &[Message]) {
        if let Some(client) = self.clients.get(&conn_id) {
            let _ = client.send_batch(messages).await;
        }
    }

    /// Check if a client supports NAIS fast protocol.
    pub fn is_nais_fast(&self, conn_id: ConnId) -> bool {
        self.clients.get(&conn_id).map(|c| c.nais_fast).unwrap_or(false)
    }

    /// Send a message to all members of a channel.
    /// Uses concurrent batch delivery for better throughput.
    pub async fn send_to_channel(&self, channel_name: &str, msg: &Message, exclude: Option<ConnId>) {
        if let Some(ch) = self.channels.get(channel_name) {
            let wire = msg.to_wire();
            let members: Vec<ConnId> = ch.members.keys()
                .filter(|&&id| Some(id) != exclude)
                .copied()
                .collect();
            drop(ch); // Release lock before writing

            // Batch: collect writer futures and send concurrently
            let futs: Vec<_> = members.iter().filter_map(|&id| {
                self.clients.get(&id).map(|client| {
                    let wire = wire.clone();
                    let writer = client.writer_handle();
                    async move {
                        let mut w = writer.lock().await;
                        let _ = w.write_all(wire.as_bytes()).await;
                        let _ = w.flush().await;
                    }
                })
            }).collect();

            futures::future::join_all(futs).await;
        }
    }

    /// Send a message to all members of a house room.
    pub async fn send_to_house_room(
        &self,
        house_name: &str,
        room_name: &str,
        msg: &Message,
        exclude: Option<ConnId>,
    ) {
        let irc_name = format!("#{}.{}", house_name, room_name);
        // House rooms are also tracked as channels for member lists
        self.send_to_channel(&irc_name, msg, exclude).await;
    }

    /// Send a message to all channels a user is in (e.g., for QUIT/NICK notifications).
    /// Uses concurrent delivery to all unique peers.
    pub async fn send_to_user_peers(&self, conn_id: ConnId, msg: &Message, include_self: bool) {
        let channel_names: Vec<String> = if let Some(client) = self.clients.get(&conn_id) {
            client.channels.iter().cloned().collect()
        } else {
            return;
        };

        let mut notified = std::collections::HashSet::new();
        for channel_name in &channel_names {
            if let Some(ch) = self.channels.get(channel_name) {
                for (&member_id, _) in ch.members.iter() {
                    if !include_self && member_id == conn_id {
                        continue;
                    }
                    notified.insert(member_id);
                }
            }
        }

        // Send concurrently to all unique peers
        let wire = msg.to_wire();
        let futs: Vec<_> = notified.iter().filter_map(|&id| {
            self.clients.get(&id).map(|client| {
                let wire = wire.clone();
                let writer = client.writer_handle();
                async move {
                    let mut w = writer.lock().await;
                    let _ = w.write_all(wire.as_bytes()).await;
                    let _ = w.flush().await;
                }
            })
        }).collect();

        futures::future::join_all(futs).await;
    }

    /// Find a house by name.
    pub fn find_house(&self, name: &str) -> Option<dashmap::mapref::one::Ref<'_, String, House>> {
        self.houses.get(name)
    }

    /// Find a house by name (mutable).
    pub fn find_house_mut(&self, name: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, House>> {
        self.houses.get_mut(name)
    }

    /// Get client count.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Get channel count (plain + house rooms).
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Get house count.
    pub fn house_count(&self) -> usize {
        self.houses.len()
    }

    /// Check if logging is enabled for a channel.
    /// For house rooms, checks the Room struct. For plain channels, checks Channel.logging.
    pub fn is_logging_enabled(&self, channel_lower: &str) -> bool {
        // Check house room first
        if let Some((house_name, room_name)) = crate::houses::parse_house_channel(channel_lower) {
            if let Some(house) = self.houses.get(house_name) {
                if let Some(room) = house.find_room_by_name(room_name) {
                    return room.logging;
                }
            }
        }
        // Plain channel
        self.channels.get(channel_lower)
            .map(|ch| ch.logging)
            .unwrap_or(false)
    }

    /// Append a message to the persistent log for a channel.
    /// Trims old entries if the log exceeds max_scrollback.
    pub fn log_message(&self, channel_lower: &str, prefix: &str, command: &str, target: &str, text: &str) {
        let max = self.config.limits.max_scrollback;
        let entry = LogEntry {
            timestamp: chrono::Utc::now().timestamp(),
            prefix: prefix.to_string(),
            command: command.to_string(),
            target: target.to_string(),
            text: text.to_string(),
        };
        let mut log = self.message_logs.entry(channel_lower.to_string()).or_insert_with(VecDeque::new);
        log.push_back(entry);
        while log.len() > max {
            log.pop_front();
        }
    }

    /// Get scrollback log entries for a channel (returns empty if logging not enabled or no history).
    pub fn get_scrollback(&self, channel_lower: &str) -> Vec<LogEntry> {
        self.message_logs.get(channel_lower)
            .map(|log| log.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove the log for a channel (e.g., when logging is disabled or channel deleted).
    pub fn clear_log(&self, channel_lower: &str) {
        self.message_logs.remove(channel_lower);
    }
}
