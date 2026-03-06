//! Console/terminal interface for the IRC client.
//!
//! Provides a traditional irssi-style text interface using crossterm for
//! colors and raw terminal input. Reuses the same `irc_client` core as
//! the Dioxus GUI — talks through `CoreHandle` channels.

use std::collections::HashMap;
use std::io::{self, Write};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{self, Color, Stylize},
    terminal,
};

use crate::irc_client::{
    self, AppState, ChatMessage, ConnectionStatus, CoreHandle, IrcCommandEvent, IrcEvent,
    ServerState,
};
use crate::profile::{self, Profile, ProfileStore};

// ── Colours ──────────────────────────────────────────────────────────
const COLOR_NICK: Color = Color::Cyan;
const COLOR_OWN_NICK: Color = Color::Green;
const COLOR_SYSTEM: Color = Color::DarkYellow;
const COLOR_ACTION: Color = Color::Magenta;
const COLOR_ERROR: Color = Color::Red;
const COLOR_CHANNEL: Color = Color::Yellow;
const COLOR_PROMPT: Color = Color::Blue;
const COLOR_TIMESTAMP: Color = Color::DarkGrey;

// ── Console state ────────────────────────────────────────────────────
struct ConsoleState {
    app: AppState,
    profiles: ProfileStore,
    handles: HashMap<String, CoreHandle>,
    active_profile: String,
    /// Input line buffer
    input: String,
    /// Cursor position within `input`
    cursor_pos: usize,
    /// Command history
    history: Vec<String>,
    /// Current position in history (history.len() == "new line")
    history_idx: usize,
    /// Whether the client is running
    running: bool,
}

impl ConsoleState {
    fn active_server(&self) -> Option<&ServerState> {
        self.app.servers.get(&self.active_profile)
    }
    fn active_server_mut(&mut self) -> Option<&mut ServerState> {
        self.app.servers.get_mut(&self.active_profile)
    }
    fn active_channel(&self) -> String {
        self.active_server()
            .map(|s| s.current_channel.clone())
            .unwrap_or_default()
    }
    fn active_handle(&self) -> Option<&CoreHandle> {
        self.handles.get(&self.active_profile)
    }
    fn profile_config(&self) -> Option<&Profile> {
        self.profiles
            .profiles
            .iter()
            .find(|p| p.name == self.active_profile)
    }
}

// ── Entry point ──────────────────────────────────────────────────────
pub fn run() {
    // Load profiles
    let store = profile::load_store();
    let initial_profile = profile::select_profile(&store);
    let active_profile = initial_profile.name.clone();

    let mut state = ConsoleState {
        app: AppState {
            active_profile: active_profile.clone(),
            servers: HashMap::new(),
        },
        profiles: store,
        handles: HashMap::new(),
        active_profile: active_profile.clone(),
        input: String::new(),
        cursor_pos: 0,
        history: Vec::new(),
        history_idx: 0,
        running: true,
    };

    // Initialise server states for all profiles
    for p in &state.profiles.profiles {
        let ss = irc_client::default_server_state(
            p.server.clone(),
            p.nickname.clone(),
            p.channel.clone(),
        );
        state.app.servers.insert(p.name.clone(), ss);
    }

    // Print banner
    print_banner(&state);

    // Auto-connect profiles that have auto_connect set
    for p in state.profiles.profiles.clone() {
        if p.auto_connect {
            connect_profile(&mut state, &p.name.clone());
        }
    }

    // Enable raw mode for key-by-key input
    terminal::enable_raw_mode().expect("Failed to enable raw mode");
    // Make sure we restore on panic
    let _raw_guard = RawModeGuard;

    draw_prompt(&state);

    // Main loop: poll for keyboard events and IRC events
    loop {
        if !state.running {
            break;
        }

        // Poll for keyboard input (non-blocking, 50ms timeout)
        if event::poll(std::time::Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                handle_key(&mut state, key);
                if !state.running {
                    break;
                }
            }
        }

        // Drain all pending IRC events from every connection
        let profile_names: Vec<String> = state.handles.keys().cloned().collect();
        for pname in profile_names {
            loop {
                let evt = {
                    let Some(handle) = state.handles.get(&pname) else {
                        break;
                    };
                    handle.evt_rx.try_recv()
                };
                match evt {
                    Ok(event) => handle_irc_event(&mut state, &pname, event),
                    Err(_) => break,
                }
            }
        }
    }

    // Graceful shutdown — send QUIT on all connections
    for (name, handle) in &state.handles {
        log::info!("Sending QUIT to profile: {}", name);
        let _ = handle
            .cmd_tx
            .try_send(IrcCommandEvent::Quit {
                message: Some("Client closing".to_string()),
            });
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
}

// Guard that restores the terminal on drop (including panics)
struct RawModeGuard;
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Show);
        println!();
    }
}

// ── Banner / welcome ─────────────────────────────────────────────────
fn print_banner(state: &ConsoleState) {
    let mut out = io::stdout();
    let _ = execute!(out, style::Print("\r\n"));
    let _ = execute!(
        out,
        style::PrintStyledContent("  Convey IRC Client — Console Mode\r\n".bold())
    );
    let _ = execute!(
        out,
        style::PrintStyledContent(
            "  Type /help for commands, /profiles to list profiles, /quit to exit\r\n"
                .with(COLOR_SYSTEM)
        )
    );

    let _ = execute!(out, style::Print("\r\n"));
    let _ = execute!(
        out,
        style::PrintStyledContent("  Profiles:\r\n".with(COLOR_CHANNEL))
    );
    for p in &state.profiles.profiles {
        let marker = if p.name == state.active_profile {
            " ▶ "
        } else {
            "   "
        };
        let auto = if p.auto_connect { " (auto)" } else { "" };
        let tls = if p.use_tls { " [TLS]" } else { "" };
        let _ = execute!(
            out,
            style::Print(format!(
                "  {}{}  →  {} as {}{}{}\r\n",
                marker, p.name, p.server, p.nickname, tls, auto
            ))
        );
    }
    let _ = execute!(out, style::Print("\r\n"));
}

// ── Prompt drawing ───────────────────────────────────────────────────
fn draw_prompt(state: &ConsoleState) {
    let mut out = io::stdout();
    // Move to beginning of line, clear it
    let _ = execute!(out, cursor::MoveToColumn(0), terminal::Clear(terminal::ClearType::CurrentLine));

    let channel = state.active_channel();
    let prompt_label = if channel.is_empty() {
        format!("[{}]", state.active_profile)
    } else {
        format!("[{}|{}]", state.active_profile, channel)
    };

    let _ = execute!(
        out,
        style::PrintStyledContent(prompt_label.with(COLOR_PROMPT)),
        style::Print("> "),
        style::Print(&state.input),
    );
    // Position cursor correctly if it's not at end
    let trail = state.input.len() - state.cursor_pos;
    if trail > 0 {
        let _ = execute!(out, cursor::MoveLeft(trail as u16));
    }
    let _ = out.flush();
}

// ── Clear the current line (before printing a message) ───────────────
fn clear_input_line() {
    let mut out = io::stdout();
    let _ = execute!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine)
    );
}

// ── Print a coloured message line then redraw the prompt ─────────────
fn print_msg(state: &ConsoleState, msg: &ChatMessage) {
    clear_input_line();
    let mut out = io::stdout();

    // Timestamp
    let ts = chrono::DateTime::from_timestamp(msg.timestamp, 0)
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_default();

    let _ = execute!(
        out,
        style::PrintStyledContent(format!("[{}] ", ts).with(COLOR_TIMESTAMP))
    );

    // Channel tag (if not the active channel)
    let active_ch = state.active_channel();
    if !msg.channel.is_empty() && msg.channel != active_ch {
        let _ = execute!(
            out,
            style::PrintStyledContent(format!("{} ", msg.channel).with(COLOR_CHANNEL))
        );
    }

    if msg.is_system {
        let _ = execute!(
            out,
            style::PrintStyledContent(format!("* {}", msg.text).with(COLOR_SYSTEM))
        );
    } else if msg.is_action {
        let _ = execute!(
            out,
            style::PrintStyledContent(format!("* {} {}", msg.user, msg.text).with(COLOR_ACTION))
        );
    } else {
        // Determine nick colour
        let nick_col = if state
            .active_server()
            .map(|s| s.nickname.eq_ignore_ascii_case(&msg.user))
            .unwrap_or(false)
        {
            COLOR_OWN_NICK
        } else {
            COLOR_NICK
        };
        let _ = execute!(
            out,
            style::PrintStyledContent(format!("<{}>", msg.user).with(nick_col)),
            style::Print(format!(" {}", msg.text))
        );
    }

    let _ = execute!(out, style::Print("\r\n"));
    draw_prompt(state);
}

fn print_system(state: &ConsoleState, channel: &str, text: &str) {
    clear_input_line();
    let mut out = io::stdout();

    let ts = chrono::Utc::now().format("%H:%M").to_string();
    let _ = execute!(
        out,
        style::PrintStyledContent(format!("[{}] ", ts).with(COLOR_TIMESTAMP))
    );

    let active_ch = state.active_channel();
    if !channel.is_empty() && channel != active_ch {
        let _ = execute!(
            out,
            style::PrintStyledContent(format!("{} ", channel).with(COLOR_CHANNEL))
        );
    }

    let _ = execute!(
        out,
        style::PrintStyledContent(format!("* {}", text).with(COLOR_SYSTEM)),
        style::Print("\r\n")
    );
    draw_prompt(state);
}

fn print_error(state: &ConsoleState, text: &str) {
    clear_input_line();
    let mut out = io::stdout();
    let _ = execute!(
        out,
        style::PrintStyledContent(format!("!! {}", text).with(COLOR_ERROR)),
        style::Print("\r\n")
    );
    draw_prompt(state);
}

// ── Key handling ─────────────────────────────────────────────────────
fn handle_key(state: &mut ConsoleState, key: KeyEvent) {
    match key.code {
        // Submit input
        KeyCode::Enter => {
            let line = state.input.clone();
            state.input.clear();
            state.cursor_pos = 0;
            if !line.is_empty() {
                state.history.push(line.clone());
                state.history_idx = state.history.len();
                process_input(state, &line);
            }
            if state.running {
                draw_prompt(state);
            }
        }
        // Editing
        KeyCode::Backspace => {
            if state.cursor_pos > 0 {
                state.cursor_pos -= 1;
                state.input.remove(state.cursor_pos);
                draw_prompt(state);
            }
        }
        KeyCode::Delete => {
            if state.cursor_pos < state.input.len() {
                state.input.remove(state.cursor_pos);
                draw_prompt(state);
            }
        }
        KeyCode::Left => {
            if state.cursor_pos > 0 {
                state.cursor_pos -= 1;
                draw_prompt(state);
            }
        }
        KeyCode::Right => {
            if state.cursor_pos < state.input.len() {
                state.cursor_pos += 1;
                draw_prompt(state);
            }
        }
        KeyCode::Home => {
            state.cursor_pos = 0;
            draw_prompt(state);
        }
        KeyCode::End => {
            state.cursor_pos = state.input.len();
            draw_prompt(state);
        }
        // History navigation
        KeyCode::Up => {
            if !state.history.is_empty() && state.history_idx > 0 {
                state.history_idx -= 1;
                state.input = state.history[state.history_idx].clone();
                state.cursor_pos = state.input.len();
                draw_prompt(state);
            }
        }
        KeyCode::Down => {
            if state.history_idx < state.history.len() {
                state.history_idx += 1;
                if state.history_idx == state.history.len() {
                    state.input.clear();
                } else {
                    state.input = state.history[state.history_idx].clone();
                }
                state.cursor_pos = state.input.len();
                draw_prompt(state);
            }
        }
        // Ctrl+C / Ctrl+D → quit
        KeyCode::Char('c') | KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.running = false;
        }
        // Ctrl+U → clear input line
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.input.clear();
            state.cursor_pos = 0;
            draw_prompt(state);
        }
        // Ctrl+W → delete word backwards
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if state.cursor_pos > 0 {
                let before = &state.input[..state.cursor_pos];
                let trimmed = before.trim_end();
                let new_pos = trimmed.rfind(' ').map(|i| i + 1).unwrap_or(0);
                state.input = format!("{}{}", &state.input[..new_pos], &state.input[state.cursor_pos..]);
                state.cursor_pos = new_pos;
                draw_prompt(state);
            }
        }
        // Ctrl+A → home
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.cursor_pos = 0;
            draw_prompt(state);
        }
        // Ctrl+E → end
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.cursor_pos = state.input.len();
            draw_prompt(state);
        }
        // Tab — cycle active channel
        KeyCode::Tab => {
            cycle_channel(state, false);
            draw_prompt(state);
        }
        KeyCode::BackTab => {
            cycle_channel(state, true);
            draw_prompt(state);
        }
        // Normal character
        KeyCode::Char(c) => {
            state.input.insert(state.cursor_pos, c);
            state.cursor_pos += 1;
            draw_prompt(state);
        }
        _ => {}
    }
}

// ── Channel cycling (Tab / Shift+Tab) ────────────────────────────────
fn cycle_channel(state: &mut ConsoleState, reverse: bool) {
    let Some(server) = state.app.servers.get_mut(&state.active_profile) else {
        return;
    };
    if server.channels.len() <= 1 {
        return;
    }
    let current = &server.current_channel;
    let idx = server
        .channels
        .iter()
        .position(|c| c == current)
        .unwrap_or(0);
    let next = if reverse {
        if idx == 0 {
            server.channels.len() - 1
        } else {
            idx - 1
        }
    } else {
        (idx + 1) % server.channels.len()
    };
    server.current_channel = server.channels[next].clone();
    let switched_to = server.current_channel.clone();
    print_system(state, "", &format!("Switched to {}", switched_to));
}

// ── Connect a profile ────────────────────────────────────────────────
fn connect_profile(state: &mut ConsoleState, profile_name: &str) {
    let profile = state
        .profiles
        .profiles
        .iter()
        .find(|p| p.name == *profile_name)
        .cloned();
    let Some(profile) = profile else {
        print_error(state, &format!("Unknown profile: {}", profile_name));
        return;
    };

    // Start a new core for this profile
    let handle = irc_client::start_core();
    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Connect {
        server: profile.server.clone(),
        nickname: profile.nickname.clone(),
        channel: profile.channel.clone(),
        use_tls: profile.use_tls,
        hide_host: profile.hide_host,
    });

    // Ensure server state exists
    state
        .app
        .servers
        .entry(profile.name.clone())
        .or_insert_with(|| {
            irc_client::default_server_state(
                profile.server.clone(),
                profile.nickname.clone(),
                profile.channel.clone(),
            )
        });

    if let Some(ss) = state.app.servers.get_mut(&profile.name) {
        ss.status = ConnectionStatus::Connecting;
    }

    state.handles.insert(profile.name.clone(), handle);
    print_system(
        state,
        "",
        &format!(
            "Connecting to {} as {} …",
            profile.server, profile.nickname
        ),
    );
}

// ── Process a line of input ──────────────────────────────────────────
fn process_input(state: &mut ConsoleState, line: &str) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }

    // Slash command?
    if trimmed.starts_with('/') {
        // Split into /command and the rest
        let mut parts = trimmed.splitn(2, ' ');
        let command = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().unwrap_or("").to_string();

        dispatch_command(state, &command, &arg);
    } else {
        // Regular message to current channel
        send_message(state, trimmed);
    }
}

fn send_message(state: &mut ConsoleState, text: &str) {
    let channel = state.active_channel();
    if channel.is_empty() {
        print_error(state, "No active channel. Use /join #channel first.");
        return;
    }
    let Some(handle) = state.active_handle() else {
        print_error(state, "Not connected.");
        return;
    };
    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Send {
        channel: channel.clone(),
        text: text.to_string(),
    });
    // Echo locally
    let nick = state
        .active_server()
        .map(|s| s.nickname.clone())
        .unwrap_or_else(|| "me".into());
    let msg = ChatMessage {
        id: 0,
        channel: channel.clone(),
        user: nick,
        text: text.to_string(),
        is_system: false,
        is_action: false,
        timestamp: chrono::Utc::now().timestamp(),
    };
    print_msg(state, &msg);

    // Persist into state for logging
    let pc = state.profile_config().cloned();
    if let Some(server_state) = state.active_server_mut() {
        server_state.messages.push(msg);
        if let Some(ref pc) = pc {
            if pc.enable_logging {
                let _ = irc_client::save_messages(
                    &server_state.server,
                    &channel,
                    &server_state.messages,
                    pc.log_buffer_size,
                );
            }
        }
    }
}

// ── Command dispatch ─────────────────────────────────────────────────
fn dispatch_command(state: &mut ConsoleState, command: &str, arg: &str) {
    let channel = state.active_channel();

    match command {
        // ── Connection management ────────────────────────────────
        "/quit" | "/exit" => {
            state.running = false;
        }
        "/disconnect" => {
            let message = if arg.is_empty() { None } else { Some(arg.to_string()) };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Quit { message });
            }
            print_system(state, "", "Disconnecting…");
        }
        "/connect" => {
            if arg.is_empty() {
                // Reconnect current profile
                connect_profile(state, &state.active_profile.clone());
            } else {
                // Connect by profile name (substring match)
                let found = state
                    .profiles
                    .profiles
                    .iter()
                    .find(|p| p.name.to_lowercase().contains(&arg.to_lowercase()))
                    .map(|p| p.name.clone());
                if let Some(name) = found {
                    connect_profile(state, &name);
                } else {
                    print_error(state, &format!("No profile matching '{}'", arg));
                }
            }
        }

        // ── Profile switching ────────────────────────────────────
        "/profile" | "/server" => {
            if arg.is_empty() {
                // List profiles
                print_system(state, "", "Profiles:");
                for p in &state.profiles.profiles {
                    let status = state
                        .app
                        .servers
                        .get(&p.name)
                        .map(|s| match s.status {
                            ConnectionStatus::Connected => "connected",
                            ConnectionStatus::Connecting => "connecting",
                            ConnectionStatus::Disconnected => "disconnected",
                        })
                        .unwrap_or("unknown");
                    let marker = if p.name == state.active_profile {
                        "▶"
                    } else {
                        " "
                    };
                    print_system(
                        state,
                        "",
                        &format!("  {} {} [{}]", marker, p.name, status),
                    );
                }
            } else {
                // Switch to profile by substring
                let found = state
                    .profiles
                    .profiles
                    .iter()
                    .find(|p| p.name.to_lowercase().contains(&arg.to_lowercase()))
                    .map(|p| p.name.clone());
                if let Some(name) = found {
                    state.active_profile = name.clone();
                    state.app.active_profile = name.clone();
                    print_system(state, "", &format!("Switched to profile: {}", name));
                } else {
                    print_error(state, &format!("No profile matching '{}'", arg));
                }
            }
        }
        "/profiles" => {
            print_system(state, "", "Profiles:");
            for p in &state.profiles.profiles {
                let status = state
                    .app
                    .servers
                    .get(&p.name)
                    .map(|s| match s.status {
                        ConnectionStatus::Connected => "connected",
                        ConnectionStatus::Connecting => "connecting",
                        ConnectionStatus::Disconnected => "disconnected",
                    })
                    .unwrap_or("unknown");
                let marker = if p.name == state.active_profile {
                    "▶"
                } else {
                    " "
                };
                print_system(
                    state,
                    "",
                    &format!("  {} {} — {} as {} [{}]", marker, p.name, p.server, p.nickname, status),
                );
            }
        }

        // ── Channel commands ─────────────────────────────────────
        "/join" => {
            if arg.is_empty() {
                print_error(state, "Usage: /join #channel");
                return;
            }
            let target = if arg.starts_with('#') {
                arg.to_string()
            } else {
                format!("#{}", arg)
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Join {
                    channel: target.clone(),
                });
            }
            print_system(state, &target, &format!("Joining {}…", target));
        }
        "/part" | "/leave" => {
            let (target, reason) = if arg.is_empty() {
                (channel.clone(), None)
            } else if arg.starts_with('#') {
                let mut parts = arg.splitn(2, ' ');
                let ch = parts.next().unwrap().to_string();
                let reason = parts.next().map(String::from);
                (ch, reason)
            } else {
                (channel.clone(), Some(arg.to_string()))
            };
            if target.is_empty() {
                print_error(state, "No channel to leave.");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Part {
                    channel: target.clone(),
                    reason,
                });
            }
            print_system(state, &target, &format!("Leaving {}…", target));
        }
        "/nick" => {
            if arg.is_empty() {
                print_error(state, "Usage: /nick <newname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Nick {
                    nickname: arg.to_string(),
                });
            }
        }
        "/topic" => {
            if arg.is_empty() {
                // Show topic for current channel
                if let Some(server) = state.active_server() {
                    if let Some(topic) = server.topics_by_channel.get(&channel) {
                        print_system(state, &channel, &format!("Topic: {}", topic));
                    } else {
                        print_system(state, &channel, "No topic set.");
                    }
                }
                return;
            }
            // Could be /topic #channel new topic  or  /topic new topic
            let (target, new_topic) = if arg.starts_with('#') {
                let mut parts = arg.splitn(2, ' ');
                let ch = parts.next().unwrap().to_string();
                let topic = parts.next().map(String::from);
                (ch, topic)
            } else {
                (channel.clone(), Some(arg.to_string()))
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Topic {
                    channel: target,
                    topic: new_topic,
                });
            }
        }
        "/msg" | "/query" => {
            let mut parts = arg.splitn(2, ' ');
            let target = parts.next().unwrap_or("").to_string();
            let text = parts.next().unwrap_or("").to_string();
            if target.is_empty() {
                print_error(state, "Usage: /msg <target> <message>");
                return;
            }
            if text.is_empty() && command == "/msg" {
                print_error(state, "Usage: /msg <target> <message>");
                return;
            }
            if !text.is_empty() {
                if let Some(handle) = state.active_handle() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Msg {
                        target: target.clone(),
                        text: text.clone(),
                    });
                }
                print_system(state, &target, &format!("→ {} : {}", target, text));
            } else {
                // /query — just switch to the PM "channel"
                if let Some(server) = state.active_server_mut() {
                    if !server.channels.contains(&target) {
                        server.channels.push(target.clone());
                    }
                    server.current_channel = target.clone();
                }
                print_system(state, "", &format!("Opened query with {}", target));
            }
        }
        "/notice" => {
            let mut parts = arg.splitn(2, ' ');
            let target = parts.next().unwrap_or("").to_string();
            let text = parts.next().unwrap_or("").to_string();
            if target.is_empty() || text.is_empty() {
                print_error(state, "Usage: /notice <target> <message>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Notice {
                    target: target.clone(),
                    text: text.clone(),
                });
            }
            print_system(state, &target, &format!("→ NOTICE {} : {}", target, text));
        }
        "/me" => {
            if arg.is_empty() {
                print_error(state, "Usage: /me <action>");
                return;
            }
            let channel = state.active_channel();
            if channel.is_empty() {
                print_error(state, "No active channel.");
                return;
            }
            // /me is sent as a CTCP ACTION
            let action = format!("\x01ACTION {}\x01", arg);
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Send {
                    channel: channel.clone(),
                    text: action,
                });
            }
            // Echo locally as action
            let nick = state
                .active_server()
                .map(|s| s.nickname.clone())
                .unwrap_or_else(|| "me".into());
            let msg = ChatMessage {
                id: 0,
                channel: channel.clone(),
                user: nick,
                text: arg.to_string(),
                is_system: false,
                is_action: true,
                timestamp: chrono::Utc::now().timestamp(),
            };
            print_msg(state, &msg);
        }
        "/whois" => {
            if arg.is_empty() {
                print_error(state, "Usage: /whois <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Whois {
                    nickname: arg.to_string(),
                });
            }
            print_system(state, "", &format!("WHOIS {}…", arg));
        }
        "/who" => {
            let target = if arg.is_empty() {
                channel.clone()
            } else {
                arg.to_string()
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Who {
                    target: target.clone(),
                });
            }
        }
        "/kick" => {
            let mut parts = arg.splitn(2, ' ');
            let user = parts.next().unwrap_or("").to_string();
            let reason = parts.next().map(String::from);
            if user.is_empty() {
                print_error(state, "Usage: /kick <user> [reason]");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Kick {
                    channel: channel.clone(),
                    user: user.clone(),
                    reason,
                });
            }
        }
        "/mode" => {
            if arg.is_empty() {
                print_error(state, "Usage: /mode [target] <modes> [args]");
                return;
            }
            let parts: Vec<&str> = arg.splitn(3, ' ').collect();
            let (target, modes, mode_args) = if parts[0].starts_with('#') || parts[0].starts_with('+') || parts[0].starts_with('-') {
                if parts[0].starts_with('#') {
                    (
                        parts[0].to_string(),
                        parts.get(1).unwrap_or(&"").to_string(),
                        parts.get(2).map(|s| s.to_string()),
                    )
                } else {
                    (channel.clone(), parts[0].to_string(), parts.get(1).map(|s| s.to_string()))
                }
            } else {
                (parts[0].to_string(), parts.get(1).unwrap_or(&"").to_string(), parts.get(2).map(|s| s.to_string()))
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target,
                    modes,
                    args: mode_args,
                });
            }
        }
        "/invite" => {
            let mut parts = arg.splitn(2, ' ');
            let nickname = parts.next().unwrap_or("").to_string();
            let chan = parts
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| channel.clone());
            if nickname.is_empty() {
                print_error(state, "Usage: /invite <nickname> [#channel]");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Invite {
                    nickname: nickname.clone(),
                    channel: chan.clone(),
                });
            }
            print_system(state, "", &format!("Invited {} to {}", nickname, chan));
        }
        "/away" => {
            let message = if arg.is_empty() { None } else { Some(arg.to_string()) };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Away { message });
            }
        }
        "/list" => {
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::List);
            }
            print_system(state, "", "Fetching channel list…");
        }
        "/raw" | "/quote" => {
            if arg.is_empty() {
                print_error(state, "Usage: /raw <irc command>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Raw {
                    command: arg.to_string(),
                });
            }
            print_system(state, "", &format!("Sent: {}", arg));
        }
        "/ctcp" => {
            let mut parts = arg.splitn(3, ' ');
            let target = parts.next().unwrap_or("").to_string();
            let ctcp_cmd = parts.next().unwrap_or("").trim().to_uppercase();
            let ctcp_args = parts.next().unwrap_or("").to_string();
            if target.is_empty() || ctcp_cmd.is_empty() {
                print_error(state, "Usage: /ctcp <target> <command> [args]");
                return;
            }
            let ctcp_msg = if ctcp_args.is_empty() {
                format!("\x01{}\x01", ctcp_cmd)
            } else {
                format!("\x01{} {}\x01", ctcp_cmd, ctcp_args)
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                    target,
                    message: ctcp_msg,
                });
            }
        }
        "/ping" => {
            if arg.is_empty() {
                print_error(state, "Usage: /ping <nickname>");
                return;
            }
            let ts = chrono::Utc::now().timestamp().to_string();
            let ctcp_msg = format!("\x01PING {}\x01", ts);
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                    target: arg.to_string(),
                    message: ctcp_msg,
                });
            }
            print_system(state, "", &format!("PING sent to {}…", arg));
        }
        "/version" => {
            if arg.is_empty() {
                print_error(state, "Usage: /version <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                    target: arg.to_string(),
                    message: "\x01VERSION\x01".to_string(),
                });
            }
            print_system(state, "", &format!("VERSION request sent to {}…", arg));
        }
        "/time" => {
            if arg.is_empty() {
                print_error(state, "Usage: /time <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                    target: arg.to_string(),
                    message: "\x01TIME\x01".to_string(),
                });
            }
            print_system(state, "", &format!("TIME request sent to {}…", arg));
        }
        "/op" => {
            if arg.is_empty() {
                print_error(state, "Usage: /op <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "+o".to_string(),
                    args: Some(arg.to_string()),
                });
            }
        }
        "/deop" => {
            if arg.is_empty() {
                print_error(state, "Usage: /deop <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "-o".to_string(),
                    args: Some(arg.to_string()),
                });
            }
        }
        "/devoice" => {
            if arg.is_empty() {
                print_error(state, "Usage: /devoice <nickname>");
                return;
            }
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "-v".to_string(),
                    args: Some(arg.to_string()),
                });
            }
        }
        "/ban" => {
            if arg.is_empty() {
                print_error(state, "Usage: /ban <mask>");
                return;
            }
            let ban_mask = if arg.contains('!') || arg.contains('@') {
                arg.to_string()
            } else {
                format!("{}!*@*", arg)
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "+b".to_string(),
                    args: Some(ban_mask),
                });
            }
        }
        "/unban" => {
            if arg.is_empty() {
                print_error(state, "Usage: /unban <mask>");
                return;
            }
            let ban_mask = if arg.contains('!') || arg.contains('@') {
                arg.to_string()
            } else {
                format!("{}!*@*", arg)
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "-b".to_string(),
                    args: Some(ban_mask),
                });
            }
        }
        "/kickban" | "/kb" => {
            let mut parts = arg.splitn(2, ' ');
            let user = parts.next().unwrap_or("").to_string();
            let reason = parts.next().map(String::from);
            if user.is_empty() {
                print_error(state, "Usage: /kickban <nickname> [reason]");
                return;
            }
            let ban_mask = format!("{}!*@*", user);
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                    target: channel.clone(),
                    modes: "+b".to_string(),
                    args: Some(ban_mask),
                });
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Kick {
                    channel: channel.clone(),
                    user,
                    reason,
                });
            }
        }
        "/names" => {
            let target = if arg.is_empty() {
                channel.clone()
            } else if arg.starts_with('#') {
                arg.to_string()
            } else {
                format!("#{}", arg)
            };
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Raw {
                    command: format!("NAMES {}", target),
                });
            }
        }
        "/users" => {
            // Show locally-cached user list for current channel
            let ch = if arg.is_empty() {
                channel.clone()
            } else {
                arg.to_string()
            };
            if let Some(server) = state.active_server() {
                if let Some(users) = server.users_by_channel.get(&ch) {
                    print_system(
                        state,
                        &ch,
                        &format!("Users ({}): {}", users.len(), users.join(", ")),
                    );
                } else {
                    print_system(state, &ch, "No user list available.");
                }
            }
        }
        "/clear" => {
            // Clear messages for current channel
            if let Some(server) = state.active_server_mut() {
                server.messages.retain(|m| m.channel != channel);
            }
            print_system(state, &channel, "Chat cleared.");
        }
        "/channels" | "/windows" => {
            if let Some(server) = state.active_server() {
                if server.channels.is_empty() {
                    print_system(state, "", "No channels joined.");
                } else {
                    print_system(state, "", "Channels:");
                    for ch in &server.channels {
                        let marker = if *ch == server.current_channel {
                            "▶"
                        } else {
                            " "
                        };
                        let users = server
                            .users_by_channel
                            .get(ch)
                            .map(|u| u.len())
                            .unwrap_or(0);
                        print_system(
                            state,
                            "",
                            &format!("  {} {} ({} users)", marker, ch, users),
                        );
                    }
                }
            }
        }
        "/switch" | "/w" => {
            if arg.is_empty() {
                cycle_channel(state, false);
                return;
            }
            // Switch to specific channel by name or number
            let result = if let Some(server) = state.active_server_mut() {
                if let Ok(idx) = arg.parse::<usize>() {
                    if idx > 0 && idx <= server.channels.len() {
                        server.current_channel = server.channels[idx - 1].clone();
                        Ok(server.current_channel.clone())
                    } else {
                        Err("Channel number out of range.".to_string())
                    }
                } else {
                    let target = if arg.starts_with('#') {
                        arg.to_string()
                    } else {
                        format!("#{}", arg)
                    };
                    if server.channels.contains(&target) {
                        server.current_channel = target.clone();
                        Ok(target)
                    } else {
                        Err(format!("Not in channel: {}", target))
                    }
                }
            } else {
                Err("Not connected.".to_string())
            };
            match result {
                Ok(ch) => print_system(state, "", &format!("Switched to {}", ch)),
                Err(e) => print_error(state, &e),
            }
        }

        // ── NAIS Secure Channel Commands ────────────────────────────
        "/createchannel" => {
            if arg.is_empty() {
                print_error(state, "Usage: /createchannel <scs_bot_nick> <channel_name>");
                return;
            }
            let mut parts = arg.splitn(2, ' ');
            let target_bot = parts.next().unwrap_or("").to_string();
            let channel_name = parts.next().unwrap_or("").trim().to_string();
            if target_bot.is_empty() || channel_name.is_empty() {
                print_error(state, "Usage: /createchannel <scs_bot_nick> <channel_name>");
                return;
            }
            let ctcp_msg = format!("\x01NAIS_CREATE_CHANNEL {}\x01", channel_name);
            if let Some(handle) = state.active_handle() {
                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                    target: target_bot.clone(),
                    message: ctcp_msg,
                });
            }
            print_system(state, "", &format!("Requesting SCS bot '{}' to create channel '{}'…", target_bot, channel_name));
        }

        // ── Help ─────────────────────────────────────────────────
        "/help" => {
            if arg.is_empty() {
                print_system(state, "", "Commands:");
                print_system(state, "", "  Connection:  /connect /disconnect /quit /profile /profiles");
                print_system(state, "", "  Channels:    /join /part /topic /list /names /channels /switch /clear");
                print_system(state, "", "  Messages:    /msg /query /notice /me /ctcp /ping /version /time");
                print_system(state, "", "  Users:       /nick /whois /who /invite /away /users");
                print_system(state, "", "  Moderation:  /kick /mode /op /deop /devoice /ban /unban /kickban");
                print_system(state, "", "  NAIS:        /createchannel");
                print_system(state, "", "  Other:       /raw /help");
                print_system(state, "", "");
                print_system(state, "", "  Tab/Shift+Tab to cycle channels  •  Ctrl+C to quit");
                print_system(state, "", "  Use /help <command> for details");
            } else {
                let help = match arg.trim_start_matches('/').to_lowercase().as_str() {
                    "join" => "/join <#channel> — Join a channel",
                    "part" | "leave" => "/part [#channel] [reason] — Leave a channel",
                    "nick" => "/nick <newname> — Change your nickname",
                    "me" => "/me <action> — Send an action message",
                    "msg" | "query" => "/msg <target> <message> — Send a private message\n/query <target> — Open a private message window",
                    "notice" => "/notice <target> <message> — Send a notice",
                    "whois" => "/whois <nickname> — Get information about a user",
                    "who" => "/who [target] — List users in channel",
                    "topic" => "/topic [#channel] [new topic] — View or set channel topic",
                    "mode" => "/mode [target] <modes> [args] — Set channel/user modes",
                    "kick" => "/kick <nickname> [reason] — Kick a user",
                    "invite" => "/invite <nickname> [#channel] — Invite a user to a channel",
                    "away" => "/away [message] — Set/clear away status",
                    "quit" | "exit" => "/quit — Exit the client",
                    "disconnect" => "/disconnect [message] — Disconnect from current server",
                    "connect" => "/connect [profile] — Connect (or reconnect) a profile",
                    "list" => "/list — List available channels",
                    "ctcp" => "/ctcp <target> <command> [args] — Send a CTCP command",
                    "ping" => "/ping <nickname> — Ping a user",
                    "version" => "/version <nickname> — Request client version",
                    "time" => "/time <nickname> — Request time from user",
                    "raw" | "quote" => "/raw <command> — Send a raw IRC command",
                    "op" => "/op <nickname> — Give operator status",
                    "deop" => "/deop <nickname> — Remove operator status",
                    "ban" => "/ban <mask> — Ban a user",
                    "unban" => "/unban <mask> — Remove a ban",
                    "kickban" | "kb" => "/kickban <nickname> [reason] — Ban and kick",
                    "names" => "/names [#channel] — Request user list from server",
                    "users" => "/users [#channel] — Show cached user list",
                    "clear" => "/clear — Clear messages for current channel",
                    "channels" | "windows" => "/channels — List joined channels",
                    "switch" | "w" => "/switch <#channel|number> — Switch to a channel",
                    "profile" | "server" => "/profile [name] — List or switch profiles",
                    "profiles" => "/profiles — List all profiles",
                    "help" => "/help [command] — Show help",
                    "createchannel" => "/createchannel <scs_bot_nick> <channel_name> — Ask an SCS bot to create a new secure channel and invite you",
                    _ => "Unknown command. Use /help for a list.",
                };
                print_system(state, "", help);
            }
        }

        _ => {
            print_error(state, &format!("Unknown command: {}. Type /help for commands.", command));
        }
    }
}

// ── Handle IRC events from the core ──────────────────────────────────
fn handle_irc_event(state: &mut ConsoleState, profile: &str, event: IrcEvent) {
    // Retrieve profile config for logging settings
    let pc = state
        .profiles
        .profiles
        .iter()
        .find(|p| p.name == *profile)
        .cloned();
    let enable_logging = pc.as_ref().map(|p| p.enable_logging).unwrap_or(false);
    let scrollback_limit = pc.as_ref().map(|p| p.scrollback_limit).unwrap_or(1000);
    let log_buffer_size = pc.as_ref().map(|p| p.log_buffer_size).unwrap_or(1000);

    // Is this the active profile?
    let is_active = profile == state.active_profile;

    match &event {
        IrcEvent::Connected { server } => {
            if is_active {
                print_system(state, "", &format!("Connected to {}", server));
            }
        }
        IrcEvent::Disconnected => {
            if is_active {
                print_system(state, "", "Disconnected.");
            }
        }
        IrcEvent::Joined { channel } => {
            if is_active {
                print_system(state, channel, &format!("Joined {}", channel));
            }
        }
        IrcEvent::Parted { channel } => {
            if is_active {
                print_system(state, channel, &format!("Left {}", channel));
            }
        }
        IrcEvent::UserJoined { channel, user } => {
            if is_active {
                print_system(state, channel, &format!("→ {} has joined", user));
            }
        }
        IrcEvent::UserParted { channel, user } => {
            if is_active {
                print_system(state, channel, &format!("← {} has left", user));
            }
        }
        IrcEvent::UserQuit { user } => {
            if is_active {
                print_system(state, "", &format!("← {} has quit", user));
            }
        }
        IrcEvent::UserNickChanged { old_nick, new_nick } => {
            if is_active {
                print_system(state, "", &format!("{} is now known as {}", old_nick, new_nick));
            }
        }
        IrcEvent::NickChanged { new_nick } => {
            if is_active {
                print_system(state, "", &format!("You are now known as {}", new_nick));
            }
        }
        IrcEvent::Users { channel, users } => {
            if is_active {
                print_system(
                    state,
                    channel,
                    &format!("Users ({}): {}", users.len(), users.join(", ")),
                );
            }
        }
        IrcEvent::Message { channel, user, text } => {
            if is_active {
                let msg = ChatMessage {
                    id: 0,
                    channel: channel.clone(),
                    user: user.clone(),
                    text: text.clone(),
                    is_system: false,
                    is_action: false,
                    timestamp: chrono::Utc::now().timestamp(),
                };
                print_msg(state, &msg);
            }
        }
        IrcEvent::Action { channel, user, text } => {
            if is_active {
                let msg = ChatMessage {
                    id: 0,
                    channel: channel.clone(),
                    user: user.clone(),
                    text: text.clone(),
                    is_system: false,
                    is_action: true,
                    timestamp: chrono::Utc::now().timestamp(),
                };
                print_msg(state, &msg);
            }
        }
        IrcEvent::System { channel, text } => {
            if is_active {
                print_system(state, channel, text);
            }
        }
        IrcEvent::Topic { channel, topic } => {
            if is_active {
                print_system(state, channel, &format!("Topic: {}", topic));
            }
        }
        IrcEvent::ChannelListItem {
            channel,
            user_count,
            topic,
        } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("  {} ({} users) — {}", channel, user_count, topic),
                );
            }
        }
        IrcEvent::ChannelListEnd => {
            if is_active {
                print_system(state, "", "End of channel list.");
            }
        }
        IrcEvent::WhoisUser {
            nick,
            user,
            host,
            realname,
        } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("WHOIS {} — {}@{} ({})", nick, user, host, realname),
                );
            }
        }
        IrcEvent::WhoisServer {
            nick,
            server,
            server_info,
        } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("WHOIS {} — server: {} ({})", nick, server, server_info),
                );
            }
        }
        IrcEvent::WhoisChannels { nick, channels } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("WHOIS {} — channels: {}", nick, channels),
                );
            }
        }
        IrcEvent::WhoisIdle { nick, idle_secs } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("WHOIS {} — idle: {}s", nick, idle_secs),
                );
            }
        }
        IrcEvent::WhoisEnd { nick } => {
            if is_active {
                print_system(state, "", &format!("End of WHOIS for {}", nick));
            }
        }
        IrcEvent::CtcpResponse {
            from,
            command,
            response,
        } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("CTCP {} reply from {}: {}", command, from, response),
                );
            }
        }
        IrcEvent::Invited { from, channel } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("{} invited you to {} — /join {} to accept", from, channel, channel),
                );
            }
        }
        // Voice / NAIS events — just display them as system messages
        IrcEvent::VoiceCtcp { from, command, args } => {
            if is_active {
                print_system(
                    state,
                    "",
                    &format!("Voice CTCP from {}: {} {}", from, command, args.join(" ")),
                );
            }
        }
        IrcEvent::NaisCtcp { from, command, args } => {
            if is_active {
                // Handle NAIS_CREATE_CHANNEL_RESPONSE specially for user-friendly output
                if command == "NAIS_CREATE_CHANNEL_RESPONSE" {
                    if args.first().map(|s| s.as_str()) == Some("OK") {
                        let chan_name = args.get(1).map(|s| s.as_str()).unwrap_or("?");
                        let irc_chan = args.get(2).map(|s| s.as_str()).unwrap_or("?");
                        let chan_id = args.get(3).map(|s| s.as_str()).unwrap_or("?");
                        print_system(
                            state,
                            "",
                            &format!("SCS bot '{}' created channel '{}' (IRC: {}, ID: {})", from, chan_name, irc_chan, chan_id),
                        );
                        print_system(
                            state,
                            "",
                            &format!("You should receive an invite to {} shortly.", irc_chan),
                        );
                    } else if args.first().map(|s| s.as_str()) == Some("ERROR") {
                        let reason = args[1..].join(" ");
                        print_system(
                            state,
                            "",
                            &format!("SCS bot '{}' failed to create channel: {}", from, reason),
                        );
                    } else {
                        print_system(
                            state,
                            "",
                            &format!("NAIS from {}: {} {}", from, command, args.join(" ")),
                        );
                    }
                } else if command == "NAIS_CHANNEL_INVITE" {
                    // A NAIS channel invite received (e.g. from SCS bot after channel creation)
                    let irc_chan = args.first().map(|s| s.as_str()).unwrap_or("?");
                    print_system(
                        state,
                        "",
                        &format!("{} invited you to NAIS channel {} — /join {} to accept", from, irc_chan, irc_chan),
                    );
                } else {
                    print_system(
                        state,
                        "",
                        &format!("NAIS from {}: {} {}", from, command, args.join(" ")),
                    );
                }
            }
        }
    }

    // Apply the event to state (updates channels, users, messages, etc.)
    irc_client::apply_event(
        &mut state.app,
        profile,
        event,
        enable_logging,
        scrollback_limit,
        log_buffer_size,
    );
}
