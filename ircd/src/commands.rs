//! IRC Command Handlers
//!
//! Implements RFC 2812 commands plus NAIS extensions for houses/rooms.
//! Supports NAIS fast/batch protocol for clients that negotiate
//! the nais.dev/fast capability — larger packets, JSON-packed responses,
//! and write coalescing for dramatically reduced latency.

use crate::connection::{Channel, ConnId, MemberStatus};
use crate::houses::{self, House, Room, RoomType};
use crate::permissions::*;
use crate::protocol::*;
use crate::state::ServerState;
use std::sync::Arc;

/// Dispatch an incoming IRC message to the appropriate handler.
pub async fn handle_message(state: &Arc<ServerState>, conn_id: ConnId, msg: Message) {
    let cmd = msg.command.as_str();
    match cmd {
        // --- Connection registration ---
        "PASS" => handle_pass(state, conn_id, &msg).await,
        "NICK" => handle_nick(state, conn_id, &msg).await,
        "USER" => handle_user(state, conn_id, &msg).await,
        "QUIT" => handle_quit(state, conn_id, &msg).await,
        "PING" => handle_ping(state, conn_id, &msg).await,
        "PONG" => handle_pong(state, conn_id, &msg).await,

        // --- Standard IRC commands ---
        "JOIN" => handle_join(state, conn_id, &msg).await,
        "PART" => handle_part(state, conn_id, &msg).await,
        "PRIVMSG" => handle_privmsg(state, conn_id, &msg).await,
        "NOTICE" => handle_notice(state, conn_id, &msg).await,
        "TOPIC" => handle_topic(state, conn_id, &msg).await,
        "NAMES" => handle_names(state, conn_id, &msg).await,
        "LIST" => handle_list(state, conn_id, &msg).await,
        "MODE" => handle_mode(state, conn_id, &msg).await,
        "KICK" => handle_kick(state, conn_id, &msg).await,
        "WHO" => handle_who(state, conn_id, &msg).await,
        "WHOIS" => handle_whois(state, conn_id, &msg).await,
        "AWAY" => handle_away(state, conn_id, &msg).await,
        "OPER" => handle_oper(state, conn_id, &msg).await,
        "MOTD" => handle_motd(state, conn_id, &msg).await,
        "USERHOST" => handle_userhost(state, conn_id, &msg).await,
        "CAP" => handle_cap(state, conn_id, &msg).await,

        // --- NAIS House extensions ---
        "HOUSE" => handle_house(state, conn_id, &msg).await,

        _ => {
            send_numeric(state, conn_id, ERR_UNKNOWNCOMMAND,
                &format!("{} :Unknown command", cmd)).await;
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

async fn send_numeric(state: &Arc<ServerState>, conn_id: ConnId, numeric: u16, text: &str) {
    if let Some(client) = state.clients.get(&conn_id) {
        let _ = client.send_numeric(state.server_name(), numeric, text).await;
    }
}

fn get_nick(state: &ServerState, conn_id: ConnId) -> String {
    state.clients.get(&conn_id)
        .map(|c| c.nick.clone())
        .unwrap_or_else(|| "*".to_string())
}

fn get_prefix(state: &ServerState, conn_id: ConnId) -> String {
    state.clients.get(&conn_id)
        .map(|c| c.prefix())
        .unwrap_or_else(|| "unknown".to_string())
}

fn require_registered(state: &ServerState, conn_id: ConnId) -> bool {
    state.clients.get(&conn_id).map(|c| c.registered).unwrap_or(false)
}

// =============================================================================
// Connection Registration
// =============================================================================

async fn handle_pass(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "PASS :Not enough parameters").await;
        return;
    }
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        if client.registered {
            send_numeric(state, conn_id, ERR_ALREADYREGISTRED,
                ":You may not reregister").await;
            return;
        }
        client.server_pass = Some(msg.params[0].clone());
    }
}

async fn handle_nick(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NONICKNAMEGIVEN, ":No nickname given").await;
        return;
    }

    let new_nick = &msg.params[0];
    if !is_valid_nick(new_nick) {
        send_numeric(state, conn_id, ERR_ERRONEUSNICKNAME,
            &format!("{} :Erroneous nickname", new_nick)).await;
        return;
    }

    // Check if nick is in use by someone else
    if let Some(existing_id) = state.find_by_nick(new_nick) {
        if existing_id != conn_id {
            send_numeric(state, conn_id, ERR_NICKNAMEINUSE,
                &format!("{} :Nickname is already in use", new_nick)).await;
            return;
        }
    }

    let (old_nick, was_registered) = {
        let client = state.clients.get(&conn_id);
        match client {
            Some(c) => (c.nick.clone(), c.registered),
            None => return,
        }
    };

    // Update nick
    state.update_nick(conn_id, &old_nick, new_nick);
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.nick = new_nick.to_string();
    }

    if was_registered {
        // Send NICK change to all peers
        let nick_msg = Message {
            tags: None,
            prefix: Some(format!("{}!{}@{}", old_nick,
                state.clients.get(&conn_id).map(|c| c.user.clone()).unwrap_or_default(),
                state.clients.get(&conn_id).map(|c| c.hostname.clone()).unwrap_or_default())),
            command: "NICK".to_string(),
            params: vec![new_nick.to_string()],
        };
        state.send_to_user_peers(conn_id, &nick_msg, true).await;
    } else {
        try_complete_registration(state, conn_id).await;
    }
}

async fn handle_user(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 4 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "USER :Not enough parameters").await;
        return;
    }

    let already_registered = state.clients.get(&conn_id).map(|c| c.registered).unwrap_or(true);
    if already_registered {
        send_numeric(state, conn_id, ERR_ALREADYREGISTRED, ":You may not reregister").await;
        return;
    }

    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.user = msg.params[0].clone();
        client.realname = msg.params[3].clone();
    }

    try_complete_registration(state, conn_id).await;
}

async fn try_complete_registration(state: &Arc<ServerState>, conn_id: ConnId) {
    let (_nick, _user, has_nick, has_user) = {
        let client = match state.clients.get(&conn_id) {
            Some(c) => c,
            None => return,
        };
        (
            client.nick.clone(),
            client.user.clone(),
            !client.nick.is_empty(),
            !client.user.is_empty(),
        )
    };

    if !has_nick || !has_user {
        return;
    }

    // Check server password
    if let Some(ref expected_pass) = state.config.server.password {
        let client_pass = state.clients.get(&conn_id).and_then(|c| c.server_pass.clone());
        if client_pass.as_deref() != Some(expected_pass.as_str()) {
            send_numeric(state, conn_id, ERR_PASSWDMISMATCH, ":Password incorrect").await;
            // Disconnect
            state.remove_client(conn_id);
            return;
        }
    }

    // Mark registered
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.registered = true;
    }

    send_welcome_burst(state, conn_id).await;
}

async fn send_welcome_burst(state: &Arc<ServerState>, conn_id: ConnId) {
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();
    let network = state.config.server.network.clone();
    let _desc = state.config.server.description.clone();

    // Batch the entire welcome burst into a single TCP write
    let mut messages = Vec::new();

    messages.push(Message::numeric(&server, RPL_WELCOME, &nick,
        &format!("Welcome to the {} IRC Network, {}!", network, nick)));
    messages.push(Message::numeric(&server, RPL_YOURHOST, &nick,
        &format!("Your host is {}, running NAIS-IRCd v0.1.0", server)));
    messages.push(Message::numeric(&server, RPL_CREATED, &nick,
        "This server was created with love and Rust"));
    messages.push(Message::numeric(&server, RPL_MYINFO, &nick,
        &format!("{} nais-ircd-0.1.0 iowrs imnstklbeI", server)));

    // ISUPPORT (005) — advertise capabilities
    messages.push(Message::numeric(&server, RPL_ISUPPORT, &nick, &format!(
        "NETWORK={} CHANTYPES=#& PREFIX=(qaohv)~&@%+ CHANMODES=beI,k,l,imnstL STATUSMSG=~&@%+ CASEMAPPING=ascii NICKLEN=30 CHANNELLEN=50 TOPICLEN=390 HOUSE LOGGING :are supported by this server",
        network
    )));

    // MOTD
    let motd = &state.config.server.motd;
    if motd.is_empty() {
        messages.push(Message::numeric(&server, 422, &nick, ":MOTD File is missing"));
    } else {
        messages.push(Message::numeric(&server, RPL_MOTDSTART, &nick,
            &format!(":- {} Message of the Day -", server)));
        for line in motd {
            messages.push(Message::numeric(&server, RPL_MOTD, &nick,
                &format!(":- {}", line)));
        }
        messages.push(Message::numeric(&server, RPL_ENDOFMOTD, &nick,
            ":End of /MOTD command"));
    }

    // Send entire welcome burst in one TCP write
    state.send_batch_to(conn_id, &messages).await;

    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.welcomed = true;
    }
}

// =============================================================================
// PING / PONG
// =============================================================================

async fn handle_ping(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    let token = msg.params.first().map(|s| s.as_str()).unwrap_or(state.server_name());
    let reply = Message {
        tags: None,
        prefix: Some(state.server_name().to_string()),
        command: "PONG".to_string(),
        params: vec![state.server_name().to_string(), token.to_string()],
    };
    state.send_to(conn_id, &reply).await;
}

async fn handle_pong(state: &Arc<ServerState>, conn_id: ConnId, _msg: &Message) {
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.last_ping = None;
        client.touch();
    }
}

// =============================================================================
// JOIN / PART
// =============================================================================

async fn handle_join(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) {
        send_numeric(state, conn_id, ERR_NOTREGISTERED, ":You have not registered").await;
        return;
    }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "JOIN :Not enough parameters").await;
        return;
    }

    let channels: Vec<&str> = msg.params[0].split(',').collect();
    let keys: Vec<&str> = msg.params.get(1)
        .map(|k| k.split(',').collect())
        .unwrap_or_default();

    for (i, chan_name) in channels.iter().enumerate() {
        let key = keys.get(i).copied();
        join_channel(state, conn_id, chan_name, key).await;
    }
}

async fn join_channel(state: &Arc<ServerState>, conn_id: ConnId, name: &str, key: Option<&str>) {
    if !is_valid_channel(name) {
        send_numeric(state, conn_id, ERR_NOSUCHCHANNEL,
            &format!("{} :No such channel", name)).await;
        return;
    }

    let nick = get_nick(state, conn_id);
    let prefix = get_prefix(state, conn_id);

    // Check if this is a house room
    if let Some((house_name, room_name)) = houses::parse_house_channel(name) {
        join_house_room(state, conn_id, house_name, room_name, name).await;
        return;
    }

    // Check limits
    let user_chan_count = state.clients.get(&conn_id).map(|c| c.channels.len()).unwrap_or(0);
    if user_chan_count >= state.config.limits.max_channels_per_user {
        send_numeric(state, conn_id, ERR_CHANNELISFULL,
            &format!("{} :You have joined too many channels", name)).await;
        return;
    }

    let name_lower = name.to_lowercase();
    let is_new = !state.channels.contains_key(&name_lower);

    // Create channel if needed
    if is_new {
        state.channels.insert(name_lower.clone(), Channel::new(name));
    }

    // Check channel modes
    if let Some(ch) = state.channels.get(&name_lower) {
        if ch.members.contains_key(&conn_id) {
            return; // Already in channel
        }
        if let Some(ref ch_key) = ch.modes.key {
            if key != Some(ch_key.as_str()) {
                send_numeric(state, conn_id, ERR_BADCHANNELKEY,
                    &format!("{} :Cannot join channel (+k)", name)).await;
                return;
            }
        }
        if ch.modes.invite_only {
            let nick_lower = nick.to_lowercase();
            let on_invite_list = ch.invite_list.iter().any(|i| i.to_lowercase() == nick_lower);
            if !on_invite_list {
                send_numeric(state, conn_id, ERR_INVITEONLYCHAN,
                    &format!("{} :Cannot join channel (+i)", name)).await;
                return;
            }
        }
        if let Some(limit) = ch.modes.limit {
            if ch.members.len() as u32 >= limit {
                send_numeric(state, conn_id, ERR_CHANNELISFULL,
                    &format!("{} :Cannot join channel (+l)", name)).await;
                return;
            }
        }
        // Check ban list
        let user_mask = prefix.to_lowercase();
        let is_banned = ch.ban_list.iter().any(|b| mask_matches(&user_mask, b));
        if is_banned {
            send_numeric(state, conn_id, ERR_BANNEDFROMCHAN,
                &format!("{} :Cannot join channel (+b)", name)).await;
            return;
        }
    }

    // Add member
    let status = if is_new { MemberStatus::Owner } else { MemberStatus::Normal };
    if let Some(mut ch) = state.channels.get_mut(&name_lower) {
        ch.members.insert(conn_id, status);
    }
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.channels.insert(name_lower.clone());
    }

    // Send JOIN to all channel members
    let join_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "JOIN".to_string(),
        params: vec![name.to_string()],
    };
    state.send_to_channel(&name_lower, &join_msg, None).await;

    // Send topic
    if let Some(ch) = state.channels.get(&name_lower) {
        if !ch.topic.is_empty() {
            send_numeric(state, conn_id, RPL_TOPIC,
                &format!("{} :{}", name, ch.topic)).await;
            send_numeric(state, conn_id, RPL_TOPICWHOTIME,
                &format!("{} {} {}", name, ch.topic_setter, ch.topic_time)).await;
        }
    }

    // Send NAMES
    send_names(state, conn_id, &name_lower).await;

    // Send scrollback history if logging is enabled
    if state.is_logging_enabled(&name_lower) {
        send_scrollback(state, conn_id, &name_lower, name).await;
    }
}

async fn join_house_room(
    state: &Arc<ServerState>,
    conn_id: ConnId,
    house_name: &str,
    room_name: &str,
    irc_name: &str,
) {
    let nick = get_nick(state, conn_id);
    let prefix = get_prefix(state, conn_id);

    // Check house exists
    let house = match state.find_house(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    // Check membership
    if !house.is_member(&nick) {
        send_numeric(state, conn_id, ERR_NOTHOUSEMEMBER,
            &format!("{} :You are not a member of this house", house_name)).await;
        return;
    }

    // Find room
    let room = match house.find_room_by_name(room_name) {
        Some(r) => r,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHROOM,
                &format!("#{}.{} :No such room in house", house_name, room_name)).await;
            return;
        }
    };

    // Check room permissions
    let room_id = room.id.clone();
    let perms = house.compute_room_permissions(&nick, &room_id);
    drop(house);

    if !has_permission(perms, PERM_READ_MESSAGES) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("#{}.{} :You don't have permission to view this room", house_name, room_name)).await;
        return;
    }

    let name_lower = irc_name.to_lowercase();

    // Create IRC channel wrapper if needed
    if !state.channels.contains_key(&name_lower) {
        state.channels.insert(name_lower.clone(), Channel::new(irc_name));
    }

    if let Some(ch) = state.channels.get(&name_lower) {
        if ch.members.contains_key(&conn_id) {
            return; // Already joined
        }
    }

    // Add member
    if let Some(mut ch) = state.channels.get_mut(&name_lower) {
        ch.members.insert(conn_id, MemberStatus::Normal);
    }
    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.channels.insert(name_lower.clone());
    }

    // Send JOIN
    let join_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "JOIN".to_string(),
        params: vec![irc_name.to_string()],
    };
    state.send_to_channel(&name_lower, &join_msg, None).await;

    // Send topic
    if let Some(ch) = state.channels.get(&name_lower) {
        if !ch.topic.is_empty() {
            send_numeric(state, conn_id, RPL_TOPIC,
                &format!("{} :{}", irc_name, ch.topic)).await;
        }
    }

    // Send NAMES
    send_names(state, conn_id, &name_lower).await;

    // Send scrollback history if logging is enabled
    if state.is_logging_enabled(&name_lower) {
        send_scrollback(state, conn_id, &name_lower, irc_name).await;
    }
}

async fn handle_part(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) {
        send_numeric(state, conn_id, ERR_NOTREGISTERED, ":You have not registered").await;
        return;
    }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "PART :Not enough parameters").await;
        return;
    }

    let channels: Vec<&str> = msg.params[0].split(',').collect();
    let reason = msg.params.get(1).cloned().unwrap_or_default();

    for chan_name in channels {
        part_channel(state, conn_id, chan_name, &reason).await;
    }
}

async fn part_channel(state: &Arc<ServerState>, conn_id: ConnId, name: &str, reason: &str) {
    let name_lower = name.to_lowercase();
    let prefix = get_prefix(state, conn_id);

    let in_channel = state.channels.get(&name_lower)
        .map(|ch| ch.members.contains_key(&conn_id))
        .unwrap_or(false);

    if !in_channel {
        send_numeric(state, conn_id, ERR_NOTONCHANNEL,
            &format!("{} :You're not on that channel", name)).await;
        return;
    }

    // Send PART to channel
    let part_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "PART".to_string(),
        params: if reason.is_empty() {
            vec![name.to_string()]
        } else {
            vec![name.to_string(), reason.to_string()]
        },
    };
    state.send_to_channel(&name_lower, &part_msg, None).await;

    // Remove from channel
    let should_remove = if let Some(mut ch) = state.channels.get_mut(&name_lower) {
        ch.members.remove(&conn_id);
        ch.members.is_empty()
    } else {
        false
    };

    if should_remove {
        state.channels.remove(&name_lower);
    }

    if let Some(mut client) = state.clients.get_mut(&conn_id) {
        client.channels.remove(&name_lower);
    }
}

// =============================================================================
// PRIVMSG / NOTICE
// =============================================================================

async fn handle_privmsg(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    handle_message_send(state, conn_id, msg, "PRIVMSG").await;
}

async fn handle_notice(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    handle_message_send(state, conn_id, msg, "NOTICE").await;
}

async fn handle_message_send(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message, cmd: &str) {
    if !require_registered(state, conn_id) {
        send_numeric(state, conn_id, ERR_NOTREGISTERED, ":You have not registered").await;
        return;
    }
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            &format!("{} :Not enough parameters", cmd)).await;
        return;
    }

    let target = &msg.params[0];
    let text = &msg.params[1];
    let prefix = get_prefix(state, conn_id);
    let nick = get_nick(state, conn_id);

    if target.starts_with('#') || target.starts_with('&') {
        // Channel message
        let target_lower = target.to_lowercase();

        // Check if user is in channel
        let in_channel = state.channels.get(&target_lower)
            .map(|ch| ch.members.contains_key(&conn_id))
            .unwrap_or(false);

        // Check no-external-messages mode
        let no_external = state.channels.get(&target_lower)
            .map(|ch| ch.modes.no_external)
            .unwrap_or(false);

        if !in_channel && no_external {
            send_numeric(state, conn_id, ERR_CANNOTSENDTOCHAN,
                &format!("{} :Cannot send to channel", target)).await;
            return;
        }

        // For house rooms, check SEND_MESSAGES permission
        if let Some((house_name, room_name)) = houses::parse_house_channel(target) {
            if let Some(house) = state.find_house(house_name) {
                if let Some(room) = house.find_room_by_name(room_name) {
                    let perms = house.compute_room_permissions(&nick, &room.id);
                    if !has_permission(perms, PERM_SEND_MESSAGES) {
                        send_numeric(state, conn_id, ERR_CANNOTSENDTOCHAN,
                            &format!("{} :You don't have permission to send messages here",
                                target)).await;
                        return;
                    }
                    // Check if user is timed out
                    if let Some(member) = house.members.get(&nick) {
                        if member.is_timed_out() {
                            send_numeric(state, conn_id, ERR_CANNOTSENDTOCHAN,
                                &format!("{} :You are timed out in this house", target)).await;
                            return;
                        }
                    }
                }
            }
        }

        // Check moderated mode
        let moderated = state.channels.get(&target_lower)
            .map(|ch| ch.modes.moderated)
            .unwrap_or(false);
        if moderated {
            let has_voice = state.channels.get(&target_lower)
                .and_then(|ch| ch.members.get(&conn_id).copied())
                .map(|s| s >= MemberStatus::Voice)
                .unwrap_or(false);
            if !has_voice {
                send_numeric(state, conn_id, ERR_CANNOTSENDTOCHAN,
                    &format!("{} :Cannot send to channel (+m)", target)).await;
                return;
            }
        }

        let out_msg = Message {
            tags: None,
            prefix: Some(prefix.clone()),
            command: cmd.to_string(),
            params: vec![target.to_string(), text.to_string()],
        };
        state.send_to_channel(&target_lower, &out_msg, Some(conn_id)).await;

        // Log message for scrollback if logging is enabled on this channel
        if state.is_logging_enabled(&target_lower) {
            state.log_message(&target_lower, &prefix, cmd, target, text);
        }
    } else {
        // Private message to user
        if let Some(target_id) = state.find_by_nick(target) {
            let out_msg = Message {
                tags: None,
                prefix: Some(prefix),
                command: cmd.to_string(),
                params: vec![target.to_string(), text.to_string()],
            };
            state.send_to(target_id, &out_msg).await;

            // Send AWAY reply if target is away
            if cmd == "PRIVMSG" {
                if let Some(target_client) = state.clients.get(&target_id) {
                    if let Some(ref away_msg) = target_client.away {
                        send_numeric(state, conn_id, 301,
                            &format!("{} :{}", target, away_msg)).await;
                    }
                }
            }
        } else {
            send_numeric(state, conn_id, ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", target)).await;
        }
    }
}

// =============================================================================
// TOPIC
// =============================================================================

async fn handle_topic(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) {
        send_numeric(state, conn_id, ERR_NOTREGISTERED, ":You have not registered").await;
        return;
    }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "TOPIC :Not enough parameters").await;
        return;
    }

    let channel = &msg.params[0];
    let channel_lower = channel.to_lowercase();
    let nick = get_nick(state, conn_id);

    if msg.params.len() == 1 {
        // Query topic
        if let Some(ch) = state.channels.get(&channel_lower) {
            if ch.topic.is_empty() {
                send_numeric(state, conn_id, 331,
                    &format!("{} :No topic is set", channel)).await;
            } else {
                send_numeric(state, conn_id, RPL_TOPIC,
                    &format!("{} :{}", channel, ch.topic)).await;
                send_numeric(state, conn_id, RPL_TOPICWHOTIME,
                    &format!("{} {} {}", channel, ch.topic_setter, ch.topic_time)).await;
            }
        } else {
            send_numeric(state, conn_id, ERR_NOSUCHCHANNEL,
                &format!("{} :No such channel", channel)).await;
        }
        return;
    }

    // Set topic
    let new_topic = &msg.params[1];

    // Check if house room and permissions
    if let Some((house_name, room_name)) = houses::parse_house_channel(channel) {
        if let Some(house) = state.find_house(house_name) {
            if let Some(room) = house.find_room_by_name(room_name) {
                let perms = house.compute_room_permissions(&nick, &room.id);
                if !has_permission(perms, PERM_SET_TOPIC) {
                    send_numeric(state, conn_id, ERR_CHANOPRIVSNEEDED,
                        &format!("{} :You don't have permission to change the topic", channel)).await;
                    return;
                }
            }
        }
    } else {
        // Plain channel — check topic lock
        if let Some(ch) = state.channels.get(&channel_lower) {
            if ch.modes.topic_lock {
                let is_op = ch.members.get(&conn_id)
                    .map(|s| *s >= MemberStatus::HalfOp)
                    .unwrap_or(false);
                if !is_op {
                    send_numeric(state, conn_id, ERR_CHANOPRIVSNEEDED,
                        &format!("{} :You're not channel operator", channel)).await;
                    return;
                }
            }
        }
    }

    let prefix = get_prefix(state, conn_id);

    if let Some(mut ch) = state.channels.get_mut(&channel_lower) {
        ch.topic = new_topic.to_string();
        ch.topic_setter = nick.clone();
        ch.topic_time = chrono::Utc::now().timestamp();
    }

    let topic_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "TOPIC".to_string(),
        params: vec![channel.to_string(), new_topic.to_string()],
    };
    state.send_to_channel(&channel_lower, &topic_msg, None).await;
}

// =============================================================================
// NAMES / LIST / WHO
// =============================================================================

async fn send_names(state: &Arc<ServerState>, conn_id: ConnId, channel_lower: &str) {
    if state.is_nais_fast(conn_id) {
        send_names_fast(state, conn_id, channel_lower).await;
        return;
    }

    let (display_name, names) = if let Some(ch) = state.channels.get(channel_lower) {
        let mut names_list = Vec::new();
        for (&member_id, status) in ch.members.iter() {
            if let Some(client) = state.clients.get(&member_id) {
                let prefix = status.prefix_char().map(|c| c.to_string()).unwrap_or_default();
                names_list.push(format!("{}{}", prefix, client.nick));
            }
        }
        (ch.name.clone(), names_list.join(" "))
    } else {
        return;
    };

    // Standard path: chunk into 512-byte messages
    send_numeric(state, conn_id, RPL_NAMREPLY,
        &format!("= {} :{}", display_name, names)).await;
    send_numeric(state, conn_id, RPL_ENDOFNAMES,
        &format!("{} :End of /NAMES list", display_name)).await;
}

/// Fast NAMES: send entire user list as a single JSON-packed message.
/// Format: 810 nick #channel :json_array
/// JSON: [{"n":"nick","p":"@"},{"n":"user2","p":""}]
/// This replaces N individual RPL_NAMREPLY messages with 1 message.
async fn send_names_fast(state: &Arc<ServerState>, conn_id: ConnId, channel_lower: &str) {
    let (display_name, json_data) = if let Some(ch) = state.channels.get(channel_lower) {
        let mut entries = Vec::new();
        for (&member_id, status) in ch.members.iter() {
            if let Some(client) = state.clients.get(&member_id) {
                let prefix = status.prefix_char().map(|c| c.to_string()).unwrap_or_default();
                entries.push(serde_json::json!({"n": client.nick, "p": prefix}));
            }
        }
        (ch.name.clone(), serde_json::Value::Array(entries).to_string())
    } else {
        return;
    };

    let msg = Message::numeric(state.server_name(), RPL_BATCHNAMES,
        &get_nick(state, conn_id), &format!("{} :{}", display_name, json_data));
    state.send_to(conn_id, &msg).await;
}

/// Send scrollback history to a client joining a channel with logging enabled.
/// For fast/batch clients, sends a single JSON message.
/// For standard clients, sends individual PRIVMSG-style history lines.
async fn send_scrollback(state: &Arc<ServerState>, conn_id: ConnId, channel_lower: &str, display_name: &str) {
    let entries = state.get_scrollback(channel_lower);
    if entries.is_empty() {
        return;
    }

    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();

    if state.is_nais_fast(conn_id) {
        // Fast path: single JSON message with all history
        let json_entries: Vec<_> = entries.iter().map(|e| {
            serde_json::json!({
                "ts": e.timestamp,
                "f": e.prefix,
                "c": e.command,
                "t": e.text,
            })
        }).collect();
        let json_data = serde_json::Value::Array(json_entries).to_string();
        let msg = Message::numeric(&server, RPL_BATCHSCROLLBACK,
            &nick, &format!("{} :{}", display_name, json_data));
        state.send_to(conn_id, &msg).await;
    } else {
        // Standard path: send each history line as RPL_SCROLLBACK
        // Format: 820 nick #channel timestamp prefix :text
        let mut messages = Vec::new();
        for e in &entries {
            messages.push(Message::numeric(&server, RPL_SCROLLBACK, &nick,
                &format!("{} {} {} {} :{}", display_name, e.timestamp, e.prefix, e.command, e.text)));
        }
        messages.push(Message::numeric(&server, RPL_SCROLLBACKEND, &nick,
            &format!("{} :End of scrollback", display_name)));
        state.send_batch_to(conn_id, &messages).await;
    }
}

async fn handle_names(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    if msg.params.is_empty() { return; }

    for channel in msg.params[0].split(',') {
        send_names(state, conn_id, &channel.to_lowercase()).await;
    }
}

async fn handle_list(state: &Arc<ServerState>, conn_id: ConnId, _msg: &Message) {
    if !require_registered(state, conn_id) { return; }

    if state.is_nais_fast(conn_id) {
        handle_list_fast(state, conn_id).await;
        return;
    }

    // Standard path: one RPL_LIST per channel
    let mut messages = Vec::new();
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();
    for entry in state.channels.iter() {
        let ch = entry.value();
        if ch.modes.secret { continue; }
        let count = ch.members.len();
        messages.push(Message::numeric(&server, RPL_LIST, &nick,
            &format!("{} {} :{}", ch.name, count, ch.topic)));
    }
    messages.push(Message::numeric(&server, RPL_LISTEND, &nick,
        ":End of /LIST"));

    // Use batch write for standard clients too
    state.send_batch_to(conn_id, &messages).await;
}

/// Fast LIST: send all channels as a single JSON-packed message.
/// Format: 811 nick :json_array
/// JSON: [{"n":"#channel","c":42,"t":"topic text"},...]
async fn handle_list_fast(state: &Arc<ServerState>, conn_id: ConnId) {
    let mut entries = Vec::new();
    for entry in state.channels.iter() {
        let ch = entry.value();
        if ch.modes.secret { continue; }
        entries.push(serde_json::json!({
            "n": ch.name,
            "c": ch.members.len(),
            "t": ch.topic,
        }));
    }
    let json_data = serde_json::Value::Array(entries).to_string();
    let msg = Message::numeric(state.server_name(), RPL_BATCHLIST,
        &get_nick(state, conn_id), &json_data);
    state.send_to(conn_id, &msg).await;
}

async fn handle_who(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("*");

    if state.is_nais_fast(conn_id) {
        handle_who_fast(state, conn_id, target).await;
        return;
    }

    // Standard path: use batch write for all replies
    let mut messages = Vec::new();
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();

    if target.starts_with('#') || target.starts_with('&') {
        let channel_lower = target.to_lowercase();
        if let Some(ch) = state.channels.get(&channel_lower) {
            for (&member_id, status) in ch.members.iter() {
                if let Some(client) = state.clients.get(&member_id) {
                    let prefix_char = status.prefix_char().map(|c| c.to_string()).unwrap_or_default();
                    let away_flag = if client.away.is_some() { "G" } else { "H" };
                    messages.push(Message::numeric(&server, RPL_WHOREPLY, &nick,
                        &format!("{} {} {} {} {} {}{} :0 {}",
                            target, client.user, client.hostname,
                            state.server_name(), client.nick,
                            away_flag, prefix_char, client.realname)));
                }
            }
        }
    }

    messages.push(Message::numeric(&server, RPL_ENDOFWHO, &nick,
        &format!("{} :End of /WHO list", target)));

    state.send_batch_to(conn_id, &messages).await;
}

/// Fast WHO: send all entries as a single JSON-packed message.
/// Format: 812 nick target :json_array
/// JSON: [{"n":"nick","u":"user","h":"host","s":"server","r":"realname","a":"H","p":"@"},...]
async fn handle_who_fast(state: &Arc<ServerState>, conn_id: ConnId, target: &str) {
    let mut entries = Vec::new();

    if target.starts_with('#') || target.starts_with('&') {
        let channel_lower = target.to_lowercase();
        if let Some(ch) = state.channels.get(&channel_lower) {
            for (&member_id, status) in ch.members.iter() {
                if let Some(client) = state.clients.get(&member_id) {
                    let prefix_char = status.prefix_char().map(|c| c.to_string()).unwrap_or_default();
                    let away_flag = if client.away.is_some() { "G" } else { "H" };
                    entries.push(serde_json::json!({
                        "n": client.nick,
                        "u": client.user,
                        "h": client.hostname,
                        "s": state.server_name(),
                        "r": client.realname,
                        "a": away_flag,
                        "p": prefix_char,
                    }));
                }
            }
        }
    }

    let json_data = serde_json::Value::Array(entries).to_string();
    let msg = Message::numeric(state.server_name(), RPL_BATCHWHO,
        &get_nick(state, conn_id), &format!("{} :{}", target, json_data));
    state.send_to(conn_id, &msg).await;
}

// =============================================================================
// WHOIS
// =============================================================================

async fn handle_whois(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NONICKNAMEGIVEN, ":No nickname given").await;
        return;
    }

    let target_nick = &msg.params[msg.params.len() - 1]; // Handle WHOIS server nick
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();

    if let Some(target_id) = state.find_by_nick(target_nick) {
        if let Some(target) = state.clients.get(&target_id) {
            let mut messages = Vec::new();

            messages.push(Message::numeric(&server, RPL_WHOISUSER, &nick,
                &format!("{} {} {} * :{}", target.nick, target.user,
                    target.hostname, target.realname)));
            messages.push(Message::numeric(&server, RPL_WHOISSERVER, &nick,
                &format!("{} {} :{}", target.nick, state.server_name(),
                    state.config.server.description)));

            if target.modes.oper {
                messages.push(Message::numeric(&server, RPL_WHOISOPERATOR, &nick,
                    &format!("{} :is an IRC operator", target.nick)));
            }

            if let Some(ref acct) = target.account {
                messages.push(Message::numeric(&server, RPL_WHOISACCOUNT, &nick,
                    &format!("{} {} :is logged in as", target.nick, acct)));
            }

            // Channels
            let channels: Vec<String> = target.channels.iter()
                .filter_map(|ch_name| {
                    state.channels.get(ch_name).map(|ch| {
                        let pref = ch.member_prefix(target_id);
                        format!("{}{}", pref, ch.name)
                    })
                })
                .collect();
            if !channels.is_empty() {
                messages.push(Message::numeric(&server, RPL_WHOISCHANNELS, &nick,
                    &format!("{} :{}", target.nick, channels.join(" "))));
            }

            messages.push(Message::numeric(&server, RPL_ENDOFWHOIS, &nick,
                &format!("{} :End of /WHOIS list", target_nick)));

            state.send_batch_to(conn_id, &messages).await;
        } else {
            send_numeric(state, conn_id, RPL_ENDOFWHOIS,
                &format!("{} :End of /WHOIS list", target_nick)).await;
        }
    } else {
        send_numeric(state, conn_id, ERR_NOSUCHNICK,
            &format!("{} :No such nick/channel", target_nick)).await;
    }
}

// =============================================================================
// MODE
// =============================================================================

async fn handle_mode(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "MODE :Not enough parameters").await;
        return;
    }

    let target = &msg.params[0];
    let nick = get_nick(state, conn_id);

    if target.starts_with('#') || target.starts_with('&') {
        // Channel mode
        let channel_lower = target.to_lowercase();
        if msg.params.len() == 1 {
            // Query mode
            if let Some(ch) = state.channels.get(&channel_lower) {
                let mut modes = ch.modes.mode_string();
                if ch.logging {
                    if modes.is_empty() { modes.push('+'); }
                    modes.push('L');
                }
                let mode_str = if modes.is_empty() { "+".to_string() } else { modes };
                send_numeric(state, conn_id, RPL_CHANNELMODEIS,
                    &format!("{} {}", target, mode_str)).await;
            }
            return;
        }

        // Set mode — require op
        let is_op = state.channels.get(&channel_lower)
            .and_then(|ch| ch.members.get(&conn_id).copied())
            .map(|s| s >= MemberStatus::HalfOp)
            .unwrap_or(false);

        // For house rooms, also check MANAGE_ROOMS permission
        if let Some((house_name, _room_name)) = houses::parse_house_channel(target) {
            if let Some(house) = state.find_house(house_name) {
                let has_perm = house.is_owner(&nick) ||
                    house.get_member_roles(&nick).iter().any(|r| r.has_permission(PERM_MANAGE_ROOMS));
                if !has_perm && !is_op {
                    send_numeric(state, conn_id, ERR_CHANOPRIVSNEEDED,
                        &format!("{} :You're not channel operator", target)).await;
                    return;
                }
            }
        } else if !is_op {
            send_numeric(state, conn_id, ERR_CHANOPRIVSNEEDED,
                &format!("{} :You're not channel operator", target)).await;
            return;
        }

        apply_channel_modes(state, conn_id, target, &msg.params[1..]).await;
    } else {
        // User mode
        if !target.eq_ignore_ascii_case(&nick) {
            send_numeric(state, conn_id, 502,
                ":Can't change mode for other users").await;
            return;
        }
        if msg.params.len() == 1 {
            let modes = state.clients.get(&conn_id)
                .map(|c| c.modes.mode_string())
                .unwrap_or_default();
            send_numeric(state, conn_id, RPL_UMODEIS, &modes).await;
            return;
        }
        apply_user_modes(state, conn_id, &msg.params[1]).await;
    }
}

async fn apply_channel_modes(
    state: &Arc<ServerState>,
    conn_id: ConnId,
    channel: &str,
    mode_params: &[String],
) {
    let channel_lower = channel.to_lowercase();
    let mode_str = &mode_params[0];
    let mut param_idx = 1;
    let mut adding = true;
    let mut applied = String::new();
    let mut applied_params = Vec::new();

    for ch in mode_str.chars() {
        match ch {
            '+' => { adding = true; applied.push('+'); }
            '-' => { adding = false; applied.push('-'); }
            'i' => { if let Some(mut c) = state.channels.get_mut(&channel_lower) { c.modes.invite_only = adding; applied.push('i'); } }
            'm' => { if let Some(mut c) = state.channels.get_mut(&channel_lower) { c.modes.moderated = adding; applied.push('m'); } }
            'n' => { if let Some(mut c) = state.channels.get_mut(&channel_lower) { c.modes.no_external = adding; applied.push('n'); } }
            's' => { if let Some(mut c) = state.channels.get_mut(&channel_lower) { c.modes.secret = adding; applied.push('s'); } }
            't' => { if let Some(mut c) = state.channels.get_mut(&channel_lower) { c.modes.topic_lock = adding; applied.push('t'); } }
            'k' => {
                if adding {
                    if let Some(key) = mode_params.get(param_idx) {
                        if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                            c.modes.key = Some(key.clone());
                            applied.push('k');
                            applied_params.push(key.clone());
                        }
                        param_idx += 1;
                    }
                } else {
                    if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                        c.modes.key = None;
                        applied.push('k');
                    }
                }
            }
            'l' => {
                if adding {
                    if let Some(limit_str) = mode_params.get(param_idx) {
                        if let Ok(limit) = limit_str.parse::<u32>() {
                            if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                                c.modes.limit = Some(limit);
                                applied.push('l');
                                applied_params.push(limit_str.clone());
                            }
                        }
                        param_idx += 1;
                    }
                } else {
                    if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                        c.modes.limit = None;
                        applied.push('l');
                    }
                }
            }
            'o' | 'h' | 'v' | 'a' | 'q' => {
                if let Some(target_nick) = mode_params.get(param_idx) {
                    if let Some(target_id) = state.find_by_nick(target_nick) {
                        let status = match ch {
                            'q' => MemberStatus::Owner,
                            'a' => MemberStatus::Admin,
                            'o' => MemberStatus::Op,
                            'h' => MemberStatus::HalfOp,
                            'v' => MemberStatus::Voice,
                            _ => MemberStatus::Normal,
                        };
                        if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                            if adding {
                                c.members.insert(target_id, status);
                            } else {
                                c.members.insert(target_id, MemberStatus::Normal);
                            }
                            applied.push(ch);
                            applied_params.push(target_nick.clone());
                        }
                    }
                    param_idx += 1;
                }
            }
            'b' => {
                if let Some(mask) = mode_params.get(param_idx) {
                    if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                        if adding {
                            if !c.ban_list.contains(mask) {
                                c.ban_list.push(mask.clone());
                            }
                        } else {
                            c.ban_list.retain(|b| b != mask);
                        }
                        applied.push('b');
                        applied_params.push(mask.clone());
                    }
                    param_idx += 1;
                }
            }
            'L' => {
                // Toggle persistent logging mode
                if let Some(mut c) = state.channels.get_mut(&channel_lower) {
                    c.logging = adding;
                    applied.push('L');
                    if !adding {
                        // Clear log when logging is disabled
                        drop(c);
                        state.clear_log(&channel_lower);
                    }
                }
            }
            _ => {}
        }
    }

    if applied.len() > 1 {
        let prefix = get_prefix(state, conn_id);
        let mut params = vec![channel.to_string(), applied];
        params.extend(applied_params);
        let mode_msg = Message {
            tags: None,
            prefix: Some(prefix),
            command: "MODE".to_string(),
            params,
        };
        state.send_to_channel(&channel_lower, &mode_msg, None).await;
    }
}

async fn apply_user_modes(state: &Arc<ServerState>, conn_id: ConnId, mode_str: &str) {
    let mut adding = true;
    let mut applied = String::new();

    for ch in mode_str.chars() {
        match ch {
            '+' => { adding = true; applied.push('+'); }
            '-' => { adding = false; applied.push('-'); }
            'i' => {
                if let Some(mut c) = state.clients.get_mut(&conn_id) {
                    c.modes.invisible = adding;
                    applied.push('i');
                }
            }
            'w' => {
                if let Some(mut c) = state.clients.get_mut(&conn_id) {
                    c.modes.wallops = adding;
                    applied.push('w');
                }
            }
            _ => {}
        }
    }

    if applied.len() > 1 {
        let nick = get_nick(state, conn_id);
        let mode_msg = Message {
            tags: None,
            prefix: Some(nick.clone()),
            command: "MODE".to_string(),
            params: vec![nick, applied],
        };
        state.send_to(conn_id, &mode_msg).await;
    }
}

// =============================================================================
// KICK
// =============================================================================

async fn handle_kick(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "KICK :Not enough parameters").await;
        return;
    }

    let channel = &msg.params[0];
    let target_nick = &msg.params[1];
    let reason = msg.params.get(2).cloned().unwrap_or_else(|| get_nick(state, conn_id));
    let channel_lower = channel.to_lowercase();
    let nick = get_nick(state, conn_id);

    // Check if kicker has permission
    let can_kick = if let Some((house_name, _room_name)) = houses::parse_house_channel(channel) {
        if let Some(house) = state.find_house(house_name) {
            let roles = house.get_member_roles(&nick);
            house.is_owner(&nick) || roles.iter().any(|r| r.has_permission(PERM_KICK))
        } else {
            false
        }
    } else {
        state.channels.get(&channel_lower)
            .and_then(|ch| ch.members.get(&conn_id).copied())
            .map(|s| s >= MemberStatus::HalfOp)
            .unwrap_or(false)
    };

    if !can_kick {
        send_numeric(state, conn_id, ERR_CHANOPRIVSNEEDED,
            &format!("{} :You're not channel operator", channel)).await;
        return;
    }

    let target_id = match state.find_by_nick(target_nick) {
        Some(id) => id,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", target_nick)).await;
            return;
        }
    };

    let in_channel = state.channels.get(&channel_lower)
        .map(|ch| ch.members.contains_key(&target_id))
        .unwrap_or(false);

    if !in_channel {
        send_numeric(state, conn_id, ERR_USERNOTINCHANNEL,
            &format!("{} {} :They aren't on that channel", target_nick, channel)).await;
        return;
    }

    let prefix = get_prefix(state, conn_id);
    let kick_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "KICK".to_string(),
        params: vec![channel.to_string(), target_nick.to_string(), reason],
    };
    state.send_to_channel(&channel_lower, &kick_msg, None).await;

    // Remove target from channel
    if let Some(mut ch) = state.channels.get_mut(&channel_lower) {
        ch.members.remove(&target_id);
    }
    if let Some(mut client) = state.clients.get_mut(&target_id) {
        client.channels.remove(&channel_lower);
    }
}

// =============================================================================
// QUIT
// =============================================================================

async fn handle_quit(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    let reason = msg.params.first().map(|s| s.as_str()).unwrap_or("Client Quit");
    let prefix = get_prefix(state, conn_id);

    let quit_msg = Message {
        tags: None,
        prefix: Some(prefix),
        command: "QUIT".to_string(),
        params: vec![reason.to_string()],
    };

    state.send_to_user_peers(conn_id, &quit_msg, false).await;
    state.remove_client(conn_id);
}

// =============================================================================
// AWAY
// =============================================================================

async fn handle_away(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }

    if msg.params.is_empty() {
        // Unmark away
        if let Some(mut client) = state.clients.get_mut(&conn_id) {
            client.away = None;
        }
        send_numeric(state, conn_id, 305, ":You are no longer marked as being away").await;
    } else {
        if let Some(mut client) = state.clients.get_mut(&conn_id) {
            client.away = Some(msg.params[0].clone());
        }
        send_numeric(state, conn_id, 306, ":You have been marked as being away").await;
    }
}

// =============================================================================
// OPER
// =============================================================================

async fn handle_oper(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "OPER :Not enough parameters").await;
        return;
    }

    let oper_name = &msg.params[0];
    let password = &msg.params[1];

    let found = state.config.opers.iter().find(|o| o.name == *oper_name);
    match found {
        Some(oper_conf) => {
            // Verify password with argon2
            let hash = argon2::PasswordHash::new(&oper_conf.password_hash);
            let valid = hash.ok().map(|h| {
                argon2::PasswordVerifier::verify_password(
                    &argon2::Argon2::default(),
                    password.as_bytes(),
                    &h,
                ).is_ok()
            }).unwrap_or(false);

            if !valid {
                send_numeric(state, conn_id, ERR_PASSWDMISMATCH, ":Password incorrect").await;
                return;
            }

            if let Some(mut client) = state.clients.get_mut(&conn_id) {
                client.modes.oper = true;
                client.account = Some(oper_name.clone());
            }
            send_numeric(state, conn_id, 381, ":You are now an IRC operator").await;

            let nick = get_nick(state, conn_id);
            let mode_msg = Message {
                tags: None,
                prefix: Some(nick.clone()),
                command: "MODE".to_string(),
                params: vec![nick, "+o".to_string()],
            };
            state.send_to(conn_id, &mode_msg).await;
        }
        None => {
            send_numeric(state, conn_id, ERR_PASSWDMISMATCH, ":Password incorrect").await;
        }
    }
}

// =============================================================================
// MOTD
// =============================================================================

async fn handle_motd(state: &Arc<ServerState>, conn_id: ConnId, _msg: &Message) {
    handle_motd_inner(state, conn_id).await;
}

async fn handle_motd_inner(state: &Arc<ServerState>, conn_id: ConnId) {
    let motd = &state.config.server.motd;
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();

    if motd.is_empty() {
        send_numeric(state, conn_id, 422, ":MOTD File is missing").await;
        return;
    }

    let mut messages = Vec::new();
    messages.push(Message::numeric(&server, RPL_MOTDSTART, &nick,
        &format!(":- {} Message of the Day -", server)));
    for line in motd {
        messages.push(Message::numeric(&server, RPL_MOTD, &nick,
            &format!(":- {}", line)));
    }
    messages.push(Message::numeric(&server, RPL_ENDOFMOTD, &nick,
        ":End of /MOTD command"));
    state.send_batch_to(conn_id, &messages).await;
}

// =============================================================================
// USERHOST
// =============================================================================

async fn handle_userhost(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) { return; }
    let mut replies = Vec::new();
    for nick in &msg.params {
        if let Some(target_id) = state.find_by_nick(nick) {
            if let Some(target) = state.clients.get(&target_id) {
                let oper_flag = if target.modes.oper { "*" } else { "" };
                let away_flag = if target.away.is_some() { "-" } else { "+" };
                replies.push(format!("{}{}={}{}@{}", target.nick, oper_flag,
                    away_flag, target.user, target.hostname));
            }
        }
    }
    send_numeric(state, conn_id, 302, &format!(":{}", replies.join(" "))).await;
}

// =============================================================================
// CAP (IRCv3 capability negotiation — minimal)
// =============================================================================

async fn handle_cap(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.is_empty() { return; }
    let subcmd = msg.params[0].to_uppercase();
    match subcmd.as_str() {
        "LS" => {
            // Advertise NAIS capabilities including fast/batch protocol
            let cap_msg = Message {
                tags: None,
                prefix: Some(state.server_name().to_string()),
                command: "CAP".to_string(),
                params: vec!["*".to_string(), "LS".to_string(),
                    "nais.dev/house nais.dev/fast multi-prefix".to_string()],
            };
            state.send_to(conn_id, &cap_msg).await;
        }
        "REQ" => {
            let caps = msg.params.get(1).cloned().unwrap_or_default();
            // Track if client requests nais.dev/fast
            if caps.contains("nais.dev/fast") {
                if let Some(mut client) = state.clients.get_mut(&conn_id) {
                    client.nais_fast = true;
                }
            }
            let ack_msg = Message {
                tags: None,
                prefix: Some(state.server_name().to_string()),
                command: "CAP".to_string(),
                params: vec!["*".to_string(), "ACK".to_string(), caps],
            };
            state.send_to(conn_id, &ack_msg).await;
        }
        "END" => {
            // CAP negotiation done, continue registration
        }
        _ => {}
    }
}

// =============================================================================
// HOUSE Command (NAIS Extension)
// =============================================================================
//
// HOUSE CREATE <name>                       — Create a new house
// HOUSE DELETE <name>                       — Delete a house (owner only)
// HOUSE LIST                                — List all houses
// HOUSE INFO <name>                         — Show house info
// HOUSE JOIN <name> [invite_code]           — Join a house
// HOUSE LEAVE <name>                        — Leave a house
// HOUSE INVITE <house> [max_uses] [ttl_sec] — Generate invite code
// HOUSE KICK <house> <nick> [reason]        — Kick from house
// HOUSE BAN <house> <nick> [reason]         — Ban from house
// HOUSE UNBAN <house> <nick>                — Unban from house
// HOUSE ROOM CREATE <house> <name> [type]   — Create room (text|voice|announce|stage)
// HOUSE ROOM DELETE <house> <name>          — Delete room
// HOUSE ROOM LIST <house>                   — List rooms in a house
// HOUSE ROOM LOG <house> <room> ON|OFF      — Toggle persistent logging for a room
// HOUSE ROLE CREATE <house> <name> <perms>  — Create role (perms = decimal bitfield)
// HOUSE ROLE DELETE <house> <role_id>       — Delete role
// HOUSE ROLE LIST <house>                   — List roles
// HOUSE ROLE GRANT <house> <nick> <role_id> — Assign role to member
// HOUSE ROLE REVOKE <house> <nick> <role_id>— Remove role from member
// HOUSE MEMBERS <name>                      — List house members
// HOUSE TIMEOUT <house> <nick> <seconds>    — Timeout a member

async fn handle_house(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if !require_registered(state, conn_id) {
        send_numeric(state, conn_id, ERR_NOTREGISTERED, ":You have not registered").await;
        return;
    }
    if msg.params.is_empty() {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS, "HOUSE :Not enough parameters").await;
        return;
    }

    let subcmd = msg.params[0].to_uppercase();
    match subcmd.as_str() {
        "CREATE" => house_create(state, conn_id, msg).await,
        "DELETE" => house_delete(state, conn_id, msg).await,
        "LIST" => house_list(state, conn_id).await,
        "INFO" => house_info(state, conn_id, msg).await,
        "JOIN" => house_join(state, conn_id, msg).await,
        "LEAVE" => house_leave(state, conn_id, msg).await,
        "INVITE" => house_invite(state, conn_id, msg).await,
        "KICK" => house_kick(state, conn_id, msg).await,
        "BAN" => house_ban(state, conn_id, msg).await,
        "UNBAN" => house_unban(state, conn_id, msg).await,
        "ROOM" => house_room(state, conn_id, msg).await,
        "ROLE" => house_role(state, conn_id, msg).await,
        "MEMBERS" => house_members(state, conn_id, msg).await,
        "TIMEOUT" => house_timeout(state, conn_id, msg).await,
        _ => {
            send_numeric(state, conn_id, ERR_UNKNOWNCOMMAND,
                &format!("HOUSE {} :Unknown HOUSE subcommand", subcmd)).await;
        }
    }
}

async fn house_create(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE CREATE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let nick = get_nick(state, conn_id);

    if !crate::protocol::is_valid_house_name(house_name) {
        send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
            &format!("{} :Invalid house name", house_name)).await;
        return;
    }

    if state.houses.contains_key(house_name) {
        send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
            &format!("{} :House already exists", house_name)).await;
        return;
    }

    // Check house ownership limit
    let owned = state.houses.iter()
        .filter(|h| h.value().owner.eq_ignore_ascii_case(&nick))
        .count();
    if owned >= state.config.limits.max_houses_per_user {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            ":You own too many houses").await;
        return;
    }

    let house = House::new(house_name, &nick);
    state.houses.insert(house_name.to_string(), house);

    let server = state.server_name().to_string();
    let notice = Message::server_notice(&server, &nick,
        &format!("House '{}' created successfully. Use HOUSE ROOM LIST {} to see rooms.", house_name, house_name));
    state.send_to(conn_id, &notice).await;

    log::info!("{} created house '{}'", nick, house_name);
}

async fn house_delete(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE DELETE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let nick = get_nick(state, conn_id);

    let is_owner = state.find_house(house_name)
        .map(|h| h.is_owner(&nick))
        .unwrap_or(false);
    let is_oper = state.clients.get(&conn_id).map(|c| c.modes.oper).unwrap_or(false);

    if !is_owner && !is_oper {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :Only the owner can delete a house", house_name)).await;
        return;
    }

    // Remove all IRC channels for this house
    if let Some((_, house)) = state.houses.remove(house_name) {
        for room in house.rooms.values() {
            let irc_name = room.irc_channel_name(house_name).to_lowercase();
            state.channels.remove(&irc_name);
        }
    }

    let server = state.server_name().to_string();
    let notice = Message::server_notice(&server, &nick,
        &format!("House '{}' has been deleted.", house_name));
    state.send_to(conn_id, &notice).await;

    log::info!("{} deleted house '{}'", nick, house_name);
}

async fn house_list(state: &Arc<ServerState>, conn_id: ConnId) {
    if state.is_nais_fast(conn_id) {
        // Fast path: single JSON message
        let mut entries = Vec::new();
        for entry in state.houses.iter() {
            let house = entry.value();
            entries.push(serde_json::json!({
                "n": house.name,
                "o": house.owner,
                "m": house.members.len(),
                "d": house.description,
            }));
        }
        let json_data = serde_json::Value::Array(entries).to_string();
        let msg = Message::numeric(state.server_name(), RPL_BATCHHOUSELIST,
            &get_nick(state, conn_id), &json_data);
        state.send_to(conn_id, &msg).await;
        return;
    }

    // Standard path: use batch write
    let mut messages = Vec::new();
    let nick = get_nick(state, conn_id);
    let server = state.server_name().to_string();
    for entry in state.houses.iter() {
        let house = entry.value();
        messages.push(Message::numeric(&server, RPL_HOUSELIST, &nick,
            &format!("{} {} {} :{}", house.name, house.owner,
                house.members.len(), house.description)));
    }
    messages.push(Message::numeric(&server, RPL_HOUSELISTEND, &nick,
        ":End of HOUSE LIST"));
    state.send_batch_to(conn_id, &messages).await;
}

async fn house_info(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE INFO :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    match state.find_house(house_name) {
        Some(house) => {
            send_numeric(state, conn_id, RPL_HOUSEINFO,
                &format!("{} owner={} members={} rooms={} roles={} created={}",
                    house.name, house.owner, house.members.len(),
                    house.rooms.len(), house.roles.len(), house.created_at)).await;
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
        }
    }
}

async fn house_join(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE JOIN :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let invite_code = msg.params.get(2);
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    if house.is_banned(&nick) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You are banned from this house", house_name)).await;
        return;
    }

    if house.is_member(&nick) {
        send_numeric(state, conn_id, ERR_ALREADYHOUSEMEMBER,
            &format!("{} :You are already a member", house_name)).await;
        return;
    }

    // Try invite code if provided
    if let Some(code) = invite_code {
        match house.use_invite(code, &nick) {
            Ok(()) => {
                let server = state.server_name().to_string();
                drop(house);
                let notice = Message::server_notice(&server, &nick,
                    &format!("You have joined house '{}'.", house_name));
                state.send_to(conn_id, &notice).await;
            }
            Err(e) => {
                send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
                    &format!("{} :{}", house_name, e)).await;
            }
        }
    } else {
        // Direct join (houses are open by default; add invite-only mode later)
        match house.add_member(&nick) {
            Ok(()) => {
                let server = state.server_name().to_string();
                drop(house);
                let notice = Message::server_notice(&server, &nick,
                    &format!("You have joined house '{}'.", house_name));
                state.send_to(conn_id, &notice).await;
            }
            Err(e) => {
                send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
                    &format!("{} :{}", house_name, e)).await;
            }
        }
    }
}

async fn house_leave(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE LEAVE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let nick = get_nick(state, conn_id);

    match state.find_house_mut(house_name) {
        Some(mut house) => {
            match house.remove_member(&nick) {
                Ok(()) => {
                    let server = state.server_name().to_string();
                    drop(house);
                    // Part all house rooms
                    let room_channels: Vec<String> = state.clients.get(&conn_id)
                        .map(|c| c.channels.iter()
                            .filter(|ch| ch.starts_with(&format!("#{}", house_name.to_lowercase())))
                            .cloned()
                            .collect())
                        .unwrap_or_default();
                    for ch in room_channels {
                        part_channel(state, conn_id, &ch, "Left the house").await;
                    }
                    let notice = Message::server_notice(&server, &nick,
                        &format!("You have left house '{}'.", house_name));
                    state.send_to(conn_id, &notice).await;
                }
                Err(e) => {
                    send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
                        &format!("{} :{}", house_name, e)).await;
                }
            }
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
        }
    }
}

async fn house_invite(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE INVITE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let max_uses: u32 = msg.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let ttl: Option<i64> = msg.params.get(3).and_then(|s| s.parse().ok());
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    // Check INVITE_MEMBERS permission
    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_INVITE_MEMBERS) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to invite", house_name)).await;
        return;
    }

    let code = house.create_invite(&nick, max_uses, ttl);
    let server = state.server_name().to_string();
    drop(house);

    let notice = Message::server_notice(&server, &nick,
        &format!("Invite code for '{}': {}  (max_uses={}, ttl={:?})",
            house_name, code, max_uses, ttl));
    state.send_to(conn_id, &notice).await;
}

async fn house_kick(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 3 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE KICK :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let target_nick = &msg.params[2];
    let reason = msg.params.get(3).cloned().unwrap_or_else(|| "Kicked".to_string());
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_KICK) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to kick", house_name)).await;
        return;
    }

    match house.remove_member(target_nick) {
        Ok(()) => {
            let server = state.server_name().to_string();
            drop(house);
            // Notify kicked user
            if let Some(target_id) = state.find_by_nick(target_nick) {
                let notice = Message::server_notice(&server, target_nick,
                    &format!("You have been kicked from house '{}': {}", house_name, reason));
                state.send_to(target_id, &notice).await;
            }
            let notice = Message::server_notice(&server, &nick,
                &format!("Kicked {} from house '{}'.", target_nick, house_name));
            state.send_to(conn_id, &notice).await;
        }
        Err(e) => {
            send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
                &format!("{} :{}", house_name, e)).await;
        }
    }
}

async fn house_ban(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 3 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE BAN :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let target_nick = &msg.params[2];
    let reason = msg.params.get(3).cloned().unwrap_or_else(|| "Banned".to_string());
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_BAN) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to ban", house_name)).await;
        return;
    }

    if house.is_owner(target_nick) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :Cannot ban the house owner", house_name)).await;
        return;
    }

    // Remove member and add to ban list
    let _ = house.remove_member(target_nick);
    house.bans.insert(target_nick.to_string(), reason.clone());

    let server = state.server_name().to_string();
    drop(house);

    if let Some(target_id) = state.find_by_nick(target_nick) {
        let notice = Message::server_notice(&server, target_nick,
            &format!("You have been banned from house '{}': {}", house_name, reason));
        state.send_to(target_id, &notice).await;
    }

    let notice = Message::server_notice(&server, &nick,
        &format!("Banned {} from house '{}'.", target_nick, house_name));
    state.send_to(conn_id, &notice).await;
}

async fn house_unban(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 3 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE UNBAN :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let target_nick = &msg.params[2];
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_BAN) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to unban", house_name)).await;
        return;
    }

    if house.bans.remove(target_nick).is_some() {
        let server = state.server_name().to_string();
        drop(house);
        let notice = Message::server_notice(&server, &nick,
            &format!("Unbanned {} from house '{}'.", target_nick, house_name));
        state.send_to(conn_id, &notice).await;
    } else {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :User is not banned", house_name)).await;
    }
}

// =============================================================================
// HOUSE ROOM subcommands
// =============================================================================

async fn house_room(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROOM :Not enough parameters").await;
        return;
    }

    let subcmd = msg.params[1].to_uppercase();
    match subcmd.as_str() {
        "CREATE" => house_room_create(state, conn_id, msg).await,
        "DELETE" => house_room_delete(state, conn_id, msg).await,
        "LIST" => house_room_list(state, conn_id, msg).await,
        "LOG" => house_room_log(state, conn_id, msg).await,
        _ => {
            send_numeric(state, conn_id, ERR_UNKNOWNCOMMAND,
                &format!("HOUSE ROOM {} :Unknown subcommand", subcmd)).await;
        }
    }
}

async fn house_room_create(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROOM CREATE <house> <name> [type]
    if msg.params.len() < 4 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROOM CREATE :Not enough parameters (HOUSE ROOM CREATE <house> <name> [type])").await;
        return;
    }

    let house_name = &msg.params[2];
    let room_name = &msg.params[3];
    let room_type_str = msg.params.get(4).map(|s| s.as_str()).unwrap_or("text");
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_MANAGE_ROOMS) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage rooms", house_name)).await;
        return;
    }

    if house.rooms.len() >= state.config.limits.max_rooms_per_house {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :House has reached maximum room count", house_name)).await;
        return;
    }

    let room = match room_type_str {
        "voice" => Room::new_voice(room_name),
        "announcement" | "announce" => Room::new_announcement(room_name),
        "text" | _ => Room::new_text(room_name),
    };

    match house.add_room(room) {
        Ok(_) => {
            let server = state.server_name().to_string();
            drop(house);
            let notice = Message::server_notice(&server, &nick,
                &format!("Room '#{}.{}' created (type: {}).", house_name, room_name, room_type_str));
            state.send_to(conn_id, &notice).await;
        }
        Err(e) => {
            send_numeric(state, conn_id, ERR_NOSUCHROOM,
                &format!("{} :{}", room_name, e)).await;
        }
    }
}

async fn house_room_delete(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROOM DELETE <house> <name>
    if msg.params.len() < 4 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROOM DELETE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    let room_name = &msg.params[3];
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_MANAGE_ROOMS) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage rooms", house_name)).await;
        return;
    }

    let room_id = house.find_room_by_name(room_name).map(|r| r.id.clone());
    match room_id {
        Some(id) => {
            house.remove_room(&id).ok();
            let irc_name = format!("#{}.{}", house_name, room_name).to_lowercase();
            drop(house);
            state.channels.remove(&irc_name);
            let server = state.server_name().to_string();
            let notice = Message::server_notice(&server, &nick,
                &format!("Room '#{}.{}' deleted.", house_name, room_name));
            state.send_to(conn_id, &notice).await;
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHROOM,
                &format!("#{}.{} :No such room", house_name, room_name)).await;
        }
    }
}

async fn house_room_list(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROOM LIST <house>
    if msg.params.len() < 3 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROOM LIST :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    match state.find_house(house_name) {
        Some(house) => {
            if state.is_nais_fast(conn_id) {
                // Fast path: single JSON message
                let mut entries = Vec::new();
                for room in house.rooms.values() {
                    let type_str = match room.room_type {
                        RoomType::Text => "text",
                        RoomType::Voice => "voice",
                        RoomType::Announcement => "announce",
                        RoomType::Stage => "stage",
                    };
                    entries.push(serde_json::json!({
                        "n": room.name,
                        "h": house_name,
                        "ty": type_str,
                        "t": room.topic,
                        "log": room.logging,
                    }));
                }
                let json_data = serde_json::Value::Array(entries).to_string();
                let msg = Message::numeric(state.server_name(), RPL_BATCHROOMLIST,
                    &get_nick(state, conn_id), &format!("{} :{}", house_name, json_data));
                state.send_to(conn_id, &msg).await;
            } else {
                // Standard path: batch write
                let mut messages = Vec::new();
                let nick = get_nick(state, conn_id);
                let server = state.server_name().to_string();
                for room in house.rooms.values() {
                    let type_str = match room.room_type {
                        RoomType::Text => "text",
                        RoomType::Voice => "voice",
                        RoomType::Announcement => "announce",
                        RoomType::Stage => "stage",
                    };
                    messages.push(Message::numeric(&server, RPL_HOUSEROOMLIST, &nick,
                        &format!("#{}.{} {} :{}", house_name, room.name,
                            type_str, room.topic)));
                }
                messages.push(Message::numeric(&server, RPL_HOUSEROOMLISTEND, &nick,
                    &format!("{} :End of room list", house_name)));
                state.send_batch_to(conn_id, &messages).await;
            }
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
        }
    }
}

/// HOUSE ROOM LOG <house> <room> ON|OFF
/// Toggle persistent server-side message logging for a house room.
/// Requires PERM_MANAGE_LOGGING or PERM_MANAGE_ROOMS. Off by default.
/// When enabled, messages are stored server-side and replayed to users on join.
/// Not applicable to secure channels (messages never reach the server).
async fn house_room_log(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROOM LOG <house> <room> ON|OFF
    if msg.params.len() < 5 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROOM LOG :Not enough parameters (HOUSE ROOM LOG <house> <room> ON|OFF)").await;
        return;
    }

    let house_name = &msg.params[2];
    let room_name = &msg.params[3];
    let toggle = msg.params[4].to_uppercase();
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    // Check permissions: MANAGE_LOGGING or MANAGE_ROOMS
    let perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(perms, PERM_MANAGE_LOGGING) && !has_permission(perms, PERM_MANAGE_ROOMS) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage logging", house_name)).await;
        return;
    }

    let enable = match toggle.as_str() {
        "ON" | "TRUE" | "1" | "ENABLE" => true,
        "OFF" | "FALSE" | "0" | "DISABLE" => false,
        _ => {
            send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
                "HOUSE ROOM LOG :Expected ON or OFF").await;
            return;
        }
    };

    let room = match house.find_room_by_name_mut(room_name) {
        Some(r) => r,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHROOM,
                &format!("#{}.{} :No such room in house", house_name, room_name)).await;
            return;
        }
    };

    room.logging = enable;
    let irc_name = format!("#{}.{}", house_name, room_name).to_lowercase();

    // Also sync the logging flag to the IRC channel wrapper if it exists
    if let Some(mut ch) = state.channels.get_mut(&irc_name) {
        ch.logging = enable;
    }

    if !enable {
        // Clear stored log when logging is disabled
        drop(house);
        state.clear_log(&irc_name);
    } else {
        drop(house);
    }

    let server = state.server_name().to_string();
    let status = if enable { "enabled" } else { "disabled" };
    let notice = Message::server_notice(&server, &nick,
        &format!("Persistent logging {} for room #{}.{}.", status, house_name, room_name));
    state.send_to(conn_id, &notice).await;

    // Notify the channel
    let chan_notice = Message::server_notice(&server, &format!("#{}.{}", house_name, room_name),
        &format!("Persistent message logging has been {} by {}.", status, nick));
    state.send_to_channel(&irc_name, &chan_notice, None).await;

    log::info!("{} {} logging for #{}.{}", nick, status, house_name, room_name);
}

// =============================================================================
// HOUSE ROLE subcommands
// =============================================================================

async fn house_role(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE :Not enough parameters").await;
        return;
    }

    let subcmd = msg.params[1].to_uppercase();
    match subcmd.as_str() {
        "CREATE" => house_role_create(state, conn_id, msg).await,
        "DELETE" => house_role_delete(state, conn_id, msg).await,
        "LIST" => house_role_list(state, conn_id, msg).await,
        "GRANT" => house_role_grant(state, conn_id, msg).await,
        "REVOKE" => house_role_revoke(state, conn_id, msg).await,
        _ => {
            send_numeric(state, conn_id, ERR_UNKNOWNCOMMAND,
                &format!("HOUSE ROLE {} :Unknown subcommand", subcmd)).await;
        }
    }
}

async fn house_role_create(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROLE CREATE <house> <name> <perms_decimal> [position]
    if msg.params.len() < 5 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE CREATE :Not enough parameters (HOUSE ROLE CREATE <house> <name> <perms>)").await;
        return;
    }

    let house_name = &msg.params[2];
    let role_name = &msg.params[3];
    let perms_val: u64 = match msg.params[4].parse() {
        Ok(v) => v,
        Err(_) => {
            send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
                "HOUSE ROLE CREATE :Invalid permissions value (must be decimal number)").await;
            return;
        }
    };
    let position: i32 = msg.params.get(5).and_then(|s| s.parse().ok()).unwrap_or(10);
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let user_perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(user_perms, PERM_MANAGE_ROLES) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage roles", house_name)).await;
        return;
    }

    if house.roles.len() >= state.config.limits.max_roles_per_house {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :House has reached maximum role count", house_name)).await;
        return;
    }

    let role = Role {
        id: uuid::Uuid::new_v4().to_string(),
        name: role_name.to_string(),
        permissions: perms_val,
        position,
        color: None,
        mentionable: false,
        hoist: false,
    };

    let role_id = role.id.clone();
    match house.add_role(role) {
        Ok(()) => {
            let server = state.server_name().to_string();
            drop(house);
            let notice = Message::server_notice(&server, &nick,
                &format!("Role '{}' created in house '{}' (id: {}, perms: {}).",
                    role_name, house_name, role_id, perms_val));
            state.send_to(conn_id, &notice).await;
        }
        Err(e) => {
            send_numeric(state, conn_id, ERR_NOSUCHROLE,
                &format!("{} :{}", role_name, e)).await;
        }
    }
}

async fn house_role_delete(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROLE DELETE <house> <role_id>
    if msg.params.len() < 4 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE DELETE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    let role_id = &msg.params[3];
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let user_perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(user_perms, PERM_MANAGE_ROLES) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage roles", house_name)).await;
        return;
    }

    match house.remove_role(role_id) {
        Ok(()) => {
            let server = state.server_name().to_string();
            drop(house);
            let notice = Message::server_notice(&server, &nick,
                &format!("Role '{}' deleted from house '{}'.", role_id, house_name));
            state.send_to(conn_id, &notice).await;
        }
        Err(e) => {
            send_numeric(state, conn_id, ERR_NOSUCHROLE,
                &format!("{} :{}", role_id, e)).await;
        }
    }
}

async fn house_role_list(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROLE LIST <house>
    if msg.params.len() < 3 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE LIST :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    match state.find_house(house_name) {
        Some(house) => {
            let mut roles: Vec<&Role> = house.roles.values().collect();
            roles.sort_by(|a, b| b.position.cmp(&a.position));

            if state.is_nais_fast(conn_id) {
                // Fast path: single JSON message
                let entries: Vec<_> = roles.iter().map(|role| {
                    serde_json::json!({
                        "id": role.id,
                        "n": role.name,
                        "p": role.permissions,
                        "pos": role.position,
                        "c": role.color,
                    })
                }).collect();
                let json_data = serde_json::Value::Array(entries).to_string();
                let msg = Message::numeric(state.server_name(), RPL_BATCHROLES,
                    &get_nick(state, conn_id), &format!("{} :{}", house_name, json_data));
                state.send_to(conn_id, &msg).await;
            } else {
                // Standard path: batch write
                let mut messages = Vec::new();
                let nick = get_nick(state, conn_id);
                let server = state.server_name().to_string();
                for role in roles {
                    messages.push(Message::numeric(&server, RPL_HOUSEROLES, &nick,
                        &format!("{} {} {} {} :{}",
                            house_name, role.id, role.name, role.permissions,
                            role.color.as_deref().unwrap_or("none"))));
                }
                messages.push(Message::numeric(&server, RPL_HOUSEROLESEND, &nick,
                    &format!("{} :End of role list", house_name)));
                state.send_batch_to(conn_id, &messages).await;
            }
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
        }
    }
}

async fn house_role_grant(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROLE GRANT <house> <nick> <role_id>
    if msg.params.len() < 5 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE GRANT :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    let target_nick = &msg.params[3];
    let role_id = &msg.params[4];
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let user_perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(user_perms, PERM_MANAGE_ROLES) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage roles", house_name)).await;
        return;
    }

    if !house.roles.contains_key(role_id) {
        send_numeric(state, conn_id, ERR_NOSUCHROLE,
            &format!("{} :No such role", role_id)).await;
        return;
    }

    if let Some(member) = house.members.get_mut(target_nick) {
        member.add_role(role_id);
        let server = state.server_name().to_string();
        drop(house);
        let notice = Message::server_notice(&server, &nick,
            &format!("Granted role '{}' to {} in house '{}'.", role_id, target_nick, house_name));
        state.send_to(conn_id, &notice).await;
    } else {
        send_numeric(state, conn_id, ERR_NOTHOUSEMEMBER,
            &format!("{} :User is not a member of this house", target_nick)).await;
    }
}

async fn house_role_revoke(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE ROLE REVOKE <house> <nick> <role_id>
    if msg.params.len() < 5 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE ROLE REVOKE :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[2];
    let target_nick = &msg.params[3];
    let role_id = &msg.params[4];
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let user_perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(user_perms, PERM_MANAGE_ROLES) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to manage roles", house_name)).await;
        return;
    }

    if let Some(member) = house.members.get_mut(target_nick) {
        member.remove_role(role_id);
        let server = state.server_name().to_string();
        drop(house);
        let notice = Message::server_notice(&server, &nick,
            &format!("Revoked role '{}' from {} in house '{}'.", role_id, target_nick, house_name));
        state.send_to(conn_id, &notice).await;
    } else {
        send_numeric(state, conn_id, ERR_NOTHOUSEMEMBER,
            &format!("{} :User is not a member of this house", target_nick)).await;
    }
}

// =============================================================================
// HOUSE MEMBERS / TIMEOUT
// =============================================================================

async fn house_members(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    if msg.params.len() < 2 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE MEMBERS :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    match state.find_house(house_name) {
        Some(house) => {
            if state.is_nais_fast(conn_id) {
                // Fast path: single JSON message
                let mut entries = Vec::new();
                for (nick, member) in &house.members {
                    let status = if house.is_owner(nick) {
                        "owner"
                    } else if member.is_timed_out() {
                        "timed-out"
                    } else {
                        "member"
                    };
                    entries.push(serde_json::json!({
                        "n": nick,
                        "s": status,
                        "r": member.roles,
                    }));
                }
                let json_data = serde_json::Value::Array(entries).to_string();
                let msg = Message::numeric(state.server_name(), RPL_BATCHMEMBERS,
                    &get_nick(state, conn_id), &format!("{} :{}", house_name, json_data));
                state.send_to(conn_id, &msg).await;
            } else {
                // Standard path: batch write
                let mut messages = Vec::new();
                let nick = get_nick(state, conn_id);
                let server = state.server_name().to_string();
                for (member_nick, member) in &house.members {
                    let roles_str = member.roles.join(",");
                    let status = if house.is_owner(member_nick) {
                        "owner"
                    } else if member.is_timed_out() {
                        "timed-out"
                    } else {
                        "member"
                    };
                    messages.push(Message::numeric(&server, RPL_HOUSEMEMBERS, &nick,
                        &format!("{} {} {} :{}", house_name, member_nick, status, roles_str)));
                }
                messages.push(Message::numeric(&server, RPL_HOUSEMEMBERSEND, &nick,
                    &format!("{} :End of member list", house_name)));
                state.send_batch_to(conn_id, &messages).await;
            }
        }
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
        }
    }
}

async fn house_timeout(state: &Arc<ServerState>, conn_id: ConnId, msg: &Message) {
    // HOUSE TIMEOUT <house> <nick> <seconds>
    if msg.params.len() < 4 {
        send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
            "HOUSE TIMEOUT :Not enough parameters").await;
        return;
    }

    let house_name = &msg.params[1];
    let target_nick = &msg.params[2];
    let seconds: i64 = match msg.params[3].parse() {
        Ok(v) => v,
        Err(_) => {
            send_numeric(state, conn_id, ERR_NEEDMOREPARAMS,
                "HOUSE TIMEOUT :Invalid seconds value").await;
            return;
        }
    };
    let nick = get_nick(state, conn_id);

    let mut house = match state.find_house_mut(house_name) {
        Some(h) => h,
        None => {
            send_numeric(state, conn_id, ERR_NOSUCHHOUSE,
                &format!("{} :No such house", house_name)).await;
            return;
        }
    };

    let user_perms = {
        let roles = house.get_member_roles(&nick);
        let role_ids = house.get_member_role_ids(&nick);
        crate::permissions::compute_permissions(house.is_owner(&nick), &roles, &[], &role_ids, &nick)
    };

    if !has_permission(user_perms, PERM_TIMEOUT) {
        send_numeric(state, conn_id, ERR_HOUSEPERMDENIED,
            &format!("{} :You don't have permission to timeout members", house_name)).await;
        return;
    }

    if let Some(member) = house.members.get_mut(target_nick) {
        member.timeout_until = chrono::Utc::now().timestamp() + seconds;
        let server = state.server_name().to_string();
        drop(house);

        if let Some(target_id) = state.find_by_nick(target_nick) {
            let notice = Message::server_notice(&server, target_nick,
                &format!("You have been timed out in house '{}' for {} seconds.", house_name, seconds));
            state.send_to(target_id, &notice).await;
        }

        let notice = Message::server_notice(&server, &nick,
            &format!("Timed out {} in house '{}' for {} seconds.", target_nick, house_name, seconds));
        state.send_to(conn_id, &notice).await;
    } else {
        send_numeric(state, conn_id, ERR_NOTHOUSEMEMBER,
            &format!("{} :User is not a member of this house", target_nick)).await;
    }
}

// =============================================================================
// Utilities
// =============================================================================

/// Simple IRC-style wildcard mask matching (supports * and ?).
fn mask_matches(text: &str, pattern: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    let mut ti = text.chars().peekable();
    let mut pi = pattern.chars().peekable();

    let mut star_p = None;
    let mut star_t = None;

    loop {
        match (pi.peek(), ti.peek()) {
            (Some(&'*'), _) => {
                star_p = Some(pi.clone());
                pi.next();
                star_t = Some(ti.clone());
            }
            (Some(&'?'), Some(_)) => {
                pi.next();
                ti.next();
            }
            (Some(&pc), Some(&tc)) if pc == tc => {
                pi.next();
                ti.next();
            }
            (None, None) => return true,
            _ => {
                if let (Some(mut sp), Some(mut st)) = (star_p.clone(), star_t.clone()) {
                    st.next();
                    star_t = Some(st.clone());
                    sp.next(); // skip the *
                    pi = sp;
                    ti = st;
                } else {
                    return false;
                }
            }
        }
    }
}
