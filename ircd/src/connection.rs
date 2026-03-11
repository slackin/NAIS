//! Client connection and session management.

use crate::protocol::Message;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Unique connection identifier.
pub type ConnId = u64;

// =============================================================================
// User Modes
// =============================================================================

#[derive(Debug, Clone, Default)]
pub struct UserModes {
    pub invisible: bool,   // +i
    pub oper: bool,        // +o
    pub wallops: bool,     // +w
    pub registered: bool,  // +r (authenticated with NickServ / account)
}

impl UserModes {
    pub fn mode_string(&self) -> String {
        let mut modes = "+".to_string();
        if self.invisible { modes.push('i'); }
        if self.oper { modes.push('o'); }
        if self.wallops { modes.push('w'); }
        if self.registered { modes.push('r'); }
        if modes.len() == 1 { modes.clear(); }
        modes
    }
}

// =============================================================================
// Client Connection
// =============================================================================

/// Represents a connected client session.
pub struct ClientConnection {
    /// Unique connection ID
    pub id: ConnId,
    /// Client's remote address
    pub addr: SocketAddr,
    /// Write half for sending messages
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    /// Whether using TLS
    pub tls: bool,

    // --- Registration state ---
    /// Nickname (empty until NICK received)
    pub nick: String,
    /// Username (from USER command)
    pub user: String,
    /// Realname (from USER command)
    pub realname: String,
    /// Hostname (resolved or IP)
    pub hostname: String,
    /// Whether registration is complete (NICK + USER received)
    pub registered: bool,
    /// PASS value (if provided before registration)
    pub server_pass: Option<String>,

    // --- Session state ---
    /// Channels this user is in (includes house rooms as #house.room)
    pub channels: HashSet<String>,
    /// User modes
    pub modes: UserModes,
    /// Away message (None = not away)
    pub away: Option<String>,
    /// Last activity time (for ping/timeout)
    pub last_active: Instant,
    /// Last ping sent (waiting for PONG)
    pub last_ping: Option<Instant>,
    /// Account name (if authenticated via OPER or future NickServ)
    pub account: Option<String>,
    /// Whether this client has been sent the welcome burst
    pub welcomed: bool,
    /// Connection time
    pub connected_at: Instant,
    /// Whether this client supports NAIS fast/batch protocol
    pub nais_fast: bool,
}

impl ClientConnection {
    pub fn new(
        id: ConnId,
        addr: SocketAddr,
        writer: tokio::net::tcp::OwnedWriteHalf,
        tls: bool,
    ) -> Self {
        Self {
            id,
            addr,
            writer: Arc::new(Mutex::new(writer)),
            tls,
            nick: String::new(),
            user: String::new(),
            realname: String::new(),
            hostname: addr.ip().to_string(),
            registered: false,
            server_pass: None,
            channels: HashSet::new(),
            modes: UserModes::default(),
            away: None,
            last_active: Instant::now(),
            last_ping: None,
            account: None,
            welcomed: false,
            connected_at: Instant::now(),
            nais_fast: false,
        }
    }

    /// Get the full prefix for this user (nick!user@host).
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.hostname)
    }

    /// Get a clone of the writer handle for concurrent access.
    pub fn writer_handle(&self) -> Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>> {
        Arc::clone(&self.writer)
    }

    /// Send a raw IRC message to this client.
    pub async fn send(&self, msg: &Message) -> Result<(), std::io::Error> {
        let wire = msg.to_wire();
        let mut writer = self.writer.lock().await;
        writer.write_all(wire.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Send a raw string to this client.
    pub async fn send_raw(&self, data: &str) -> Result<(), std::io::Error> {
        let mut writer = self.writer.lock().await;
        writer.write_all(data.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Send multiple IRC messages in a single TCP write + flush.
    /// This dramatically reduces syscall overhead for burst operations
    /// like NAMES, LIST, WHO that send many messages to one client.
    pub async fn send_batch(&self, messages: &[Message]) -> Result<(), std::io::Error> {
        if messages.is_empty() {
            return Ok(());
        }
        let mut buf = String::with_capacity(messages.len() * 256);
        for msg in messages {
            buf.push_str(&msg.to_wire());
        }
        let mut writer = self.writer.lock().await;
        writer.write_all(buf.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Send a numeric reply.
    pub async fn send_numeric(
        &self,
        server_name: &str,
        numeric: u16,
        text: &str,
    ) -> Result<(), std::io::Error> {
        let target = if self.nick.is_empty() { "*" } else { &self.nick };
        let msg = Message::numeric(server_name, numeric, target, text);
        self.send(&msg).await
    }

    /// Send an error reply.
    pub async fn send_error(
        &self,
        server_name: &str,
        numeric: u16,
        text: &str,
    ) -> Result<(), std::io::Error> {
        self.send_numeric(server_name, numeric, text).await
    }

    /// Touch last-active timestamp.
    pub fn touch(&mut self) {
        self.last_active = Instant::now();
        self.last_ping = None;
    }
}

// =============================================================================
// Channel State (for plain IRC channels outside houses)
// =============================================================================

/// Channel modes.
#[derive(Debug, Clone, Default)]
pub struct ChannelModes {
    pub invite_only: bool,   // +i
    pub moderated: bool,     // +m
    pub no_external: bool,   // +n
    pub secret: bool,        // +s
    pub topic_lock: bool,    // +t
    pub key: Option<String>, // +k
    pub limit: Option<u32>,  // +l
}

impl ChannelModes {
    pub fn mode_string(&self) -> String {
        let mut modes = "+".to_string();
        if self.invite_only { modes.push('i'); }
        if self.moderated { modes.push('m'); }
        if self.no_external { modes.push('n'); }
        if self.secret { modes.push('s'); }
        if self.topic_lock { modes.push('t'); }
        if self.key.is_some() { modes.push('k'); }
        if self.limit.is_some() { modes.push('l'); }
        if modes.len() == 1 { modes.clear(); }
        modes
    }
}

/// IRC channel membership with status prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberStatus {
    Normal,
    Voice,   // +v
    HalfOp,  // +h (%) 
    Op,      // +o (@)
    Admin,   // +a (&)
    Owner,   // +q (~)
}

impl MemberStatus {
    pub fn prefix_char(&self) -> Option<char> {
        match self {
            MemberStatus::Owner => Some('~'),
            MemberStatus::Admin => Some('&'),
            MemberStatus::Op => Some('@'),
            MemberStatus::HalfOp => Some('%'),
            MemberStatus::Voice => Some('+'),
            MemberStatus::Normal => None,
        }
    }

    pub fn mode_char(&self) -> Option<char> {
        match self {
            MemberStatus::Owner => Some('q'),
            MemberStatus::Admin => Some('a'),
            MemberStatus::Op => Some('o'),
            MemberStatus::HalfOp => Some('h'),
            MemberStatus::Voice => Some('v'),
            MemberStatus::Normal => None,
        }
    }
}

/// A plain IRC channel (not part of a house).
pub struct Channel {
    pub name: String,
    pub topic: String,
    pub topic_setter: String,
    pub topic_time: i64,
    pub modes: ChannelModes,
    pub members: std::collections::HashMap<ConnId, MemberStatus>,
    pub ban_list: Vec<String>,
    pub invite_list: Vec<String>,
    pub created_at: i64,
    /// Whether server-side persistent logging is enabled for this channel.
    /// Off by default. Toggled via MODE +L/-L by channel operators.
    pub logging: bool,
}

impl Channel {
    pub fn new(name: &str) -> Self {
        Channel {
            name: name.to_string(),
            topic: String::new(),
            topic_setter: String::new(),
            topic_time: 0,
            modes: ChannelModes {
                no_external: true,
                topic_lock: true,
                ..Default::default()
            },
            members: std::collections::HashMap::new(),
            ban_list: Vec::new(),
            invite_list: Vec::new(),
            created_at: chrono::Utc::now().timestamp(),
            logging: false,
        }
    }

    /// Get the highest status prefix for NAMES reply.
    pub fn member_prefix(&self, conn_id: ConnId) -> String {
        if let Some(status) = self.members.get(&conn_id) {
            status.prefix_char().map(|c| c.to_string()).unwrap_or_default()
        } else {
            String::new()
        }
    }
}
