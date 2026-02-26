use dioxus::prelude::*;
use dioxus::document;
use futures_timer::Delay;
use std::collections::HashMap;
use std::time::Duration;
use scraper::{Html, Selector};
use std::sync::{Arc, Mutex};
#[allow(unused_imports)]
use image::ImageBuffer;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

use crate::irc_client::{self, ChatMessage, ConnectionStatus, IrcCommandEvent, IrcEvent};
use crate::profile;

/// Global registry of IRC command senders for graceful shutdown
/// Maps profile names to their command channel senders
static SHUTDOWN_HANDLES: std::sync::LazyLock<Mutex<HashMap<String, async_channel::Sender<IrcCommandEvent>>>> = 
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register an IRC connection for graceful shutdown
fn register_shutdown_handle(profile: &str, cmd_tx: async_channel::Sender<IrcCommandEvent>) {
    if let Ok(mut handles) = SHUTDOWN_HANDLES.lock() {
        handles.insert(profile.to_string(), cmd_tx);
    }
}

/// Unregister an IRC connection (called when disconnecting)
#[allow(dead_code)]
fn unregister_shutdown_handle(profile: &str) {
    if let Ok(mut handles) = SHUTDOWN_HANDLES.lock() {
        handles.remove(profile);
    }
}

/// Send QUIT to all connected IRC servers for graceful shutdown
fn graceful_shutdown() {
    log::info!("Initiating graceful shutdown of IRC connections...");
    if let Ok(handles) = SHUTDOWN_HANDLES.lock() {
        for (profile, cmd_tx) in handles.iter() {
            log::info!("Sending QUIT to profile: {}", profile);
            let _ = cmd_tx.try_send(IrcCommandEvent::Quit {
                message: Some("Client closing".to_string()),
            });
        }
    }
    // Give a brief moment for QUIT messages to be sent
    std::thread::sleep(std::time::Duration::from_millis(500));
    log::info!("Graceful shutdown complete");
}

/// Accumulated WHOIS information for popup display
#[derive(Clone, Default, Debug)]
struct WhoisInfo {
    nick: String,
    user: Option<String>,
    host: Option<String>,
    realname: Option<String>,
    server: Option<String>,
    server_info: Option<String>,
    channels: Option<String>,
    idle_secs: Option<String>,
}

/// CTCP response information for popup display
#[derive(Clone, Debug)]
struct CtcpResponseInfo {
    from: String,
    command: String,
    response: String,
}

/// Information for channel invite popup
#[derive(Clone, Debug)]
struct ChannelInviteInfo {
    /// Target user to invite
    target_nick: String,
    /// Whether the target is a NAIS client
    is_nais_client: bool,
    /// Current server/profile name
    current_profile: String,
}

/// Information for a cross-network invite we received
#[derive(Clone, Debug)]
struct CrossNetworkInviteInfo {
    /// User who sent the invite
    from_nick: String,
    /// Channel to join
    channel: String,
    /// Server address to connect to
    server: String,
    /// Whether this is a NAIS encrypted channel
    is_nais: bool,
    /// Profile name where we received this invite (for context)
    _received_on_profile: String,
}

/// Information for an incoming IRC invite (standard INVITE command)
#[derive(Clone, Debug)]
struct IncomingIrcInviteInfo {
    /// User who sent the invite
    from_nick: String,
    /// Channel we're being invited to
    channel: String,
    /// Profile/server where we received the invite
    profile: String,
}

/// A channel option for the invite selector
#[derive(Clone, Debug)]
struct InviteChannelOption {
    /// Display name for the channel
    display_name: String,
    /// IRC channel name (e.g., #channel)
    channel: String,
    /// Server/profile name (for cross-server invites)
    profile: String,
    /// Server address
    server: String,
    /// Whether this is a NAIS channel
    is_nais: bool,
}

pub fn run() {
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::Config;
        use tao::event::{Event, WindowEvent};
        use std::sync::atomic::{AtomicBool, Ordering};
        
        // Track whether we've already initiated shutdown
        static SHUTDOWN_STARTED: AtomicBool = AtomicBool::new(false);
        
        // Configure desktop with a custom event handler to intercept close
        let config = Config::new()
            .with_custom_event_handler(move |event, _target| {
                if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
                    // Only run graceful shutdown once
                    if !SHUTDOWN_STARTED.swap(true, Ordering::SeqCst) {
                        graceful_shutdown();
                    }
                }
            });
        
        dioxus::LaunchBuilder::desktop()
            .with_cfg(config)
            .launch(app);
    }
    
    #[cfg(not(feature = "desktop"))]
    {
        dioxus::launch(app);
    }
}

// Desktop-only file picker button component
#[cfg(feature = "desktop")]
fn file_picker_button(input: Signal<String>) -> Element {
    rsx! {
        button {
            class: "send",
            style: "padding: 8px 12px; min-width: unset;",
            onclick: move |_| {
                if let Some(result) = rfd::FileDialog::new()
                    .add_filter("Images", &["png", "jpg", "jpeg", "gif", "webp"])
                    .pick_file() {
                    let mut input_clone = input.clone();
                    spawn(async move {
                        if let Ok(bytes) = std::fs::read(&result) {
                            println!("Uploading image: {} bytes", bytes.len());
                            if let Some(url) = upload_simple_image(bytes).await {
                                let current = input_clone.read().clone();
                                let new_text = if current.is_empty() {
                                    url
                                } else {
                                    format!("{} {}", current, url)
                                };
                                input_clone.set(new_text);
                            }
                        }
                    });
                }
            },
            "📎"
        }
    }
}

// Mobile stub for file picker (not yet implemented)
#[cfg(not(feature = "desktop"))]
fn file_picker_button(_input: Signal<String>) -> Element {
    rsx! {}
}

// Helper function to apply IRC event with profile-specific config
fn apply_event_with_config(
    state: &mut irc_client::AppState,
    profiles: &[profile::Profile],
    profile_name: &str,
    event: IrcEvent,
) {
    let (enable_logging, scrollback_limit, log_buffer_size) = profiles.iter()
        .find(|p| p.name == profile_name)
        .map(|p| (p.enable_logging, p.scrollback_limit, p.log_buffer_size))
        .unwrap_or((true, 1000, 1000));
    
    irc_client::apply_event(state, profile_name, event, enable_logging, scrollback_limit, log_buffer_size);
}

fn app() -> Element {
    let store = profile::load_store();
    let initial_profile = profile::select_profile(&store);
    let mut default_nick = use_signal(|| store.default_nickname.clone());

    let mut state = use_signal(|| {
        let mut servers = HashMap::new();
        for profile in store.profiles.iter() {
            servers.insert(
                profile.name.clone(),
                irc_client::default_server_state(
                    profile.server.clone(),
                    profile.nickname.clone(),
                    profile.channel.clone(),
                ),
            );
        }
        irc_client::AppState {
            active_profile: initial_profile.name.clone(),
            servers,
        }
    });

    let mut profiles = use_signal(|| store.profiles.clone());
    let mut last_used = use_signal(|| store.last_used.clone());
    let mut cores: Signal<HashMap<String, irc_client::CoreHandle>> = use_signal(HashMap::new);
    let mut skip_reconnect: Signal<HashMap<String, bool>> = use_signal(HashMap::new);
    let mut profile_status: Signal<HashMap<String, ConnectionStatus>> = use_signal(HashMap::new);
    let mut show_server_log: Signal<HashMap<String, bool>> = use_signal(HashMap::new);

    let input = use_signal(|| String::new());
    let history = use_signal(Vec::new);
    let mut history_index = use_signal(|| None::<usize>);

    // Tab completion state
    let mut tab_completion_prefix = use_signal(|| String::new());
    let mut tab_completion_matches: Signal<Vec<String>> = use_signal(Vec::new);
    let mut tab_completion_index = use_signal(|| 0usize);
    let mut skip_tab_reset = use_signal(|| false);

    let mut show_new_profile = use_signal(|| false);
    let mut show_edit_profile = use_signal(|| false);
    let mut show_import_modal = use_signal(|| false);
    let mut show_settings = use_signal(|| false);
    let mut show_channel_browser = use_signal(|| false);
    let mut show_first_run_setup = use_signal(|| store.default_nickname.is_none());
    let mut profile_menu_open = use_signal(|| None::<String>);

    // Settings modal input state
    let mut settings_default_nick = use_signal(|| store.default_nickname.clone().unwrap_or_default());
    let mut settings_enable_logging = use_signal(|| true);
    let mut settings_scrollback_limit = use_signal(|| 1000usize);
    let mut settings_log_buffer_size = use_signal(|| 1000usize);
    
    // Audio/Voice settings
    let mut settings_noise_suppression = use_signal(|| true);
    let mut settings_noise_suppression_strength = use_signal(|| 1.0f32);
    let mut settings_noise_gate = use_signal(|| true);
    let mut settings_noise_gate_threshold = use_signal(|| 0.01f32);
    let mut settings_highpass_filter = use_signal(|| true);
    let mut settings_highpass_cutoff = use_signal(|| 80.0f32);
    
    // Display settings
    let mut settings_show_timestamps = use_signal(|| store.show_timestamps);
    let mut settings_show_advanced = use_signal(|| store.show_advanced);
    // Channel users for nick highlighting
    let mut channel_users: Signal<Vec<String>> = use_signal(Vec::new);
    // Provide global access to these settings
    use_context_provider(|| settings_show_timestamps);
    use_context_provider(|| settings_show_advanced);
    use_context_provider(|| channel_users);

    let mut new_server_input = use_signal(String::new);
    let mut new_nick_input = use_signal(String::new);
    let mut new_channel_input = use_signal(String::new);
    let mut new_tls_input = use_signal(|| true);
    let mut new_auto_connect_input = use_signal(|| true);
    let mut new_hide_host_input = use_signal(|| true);
    
    let mut first_run_nick_input = use_signal(|| {
        store.default_nickname.clone().unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "nais".to_string())
        })
    });

    // Auto-focus first-run nickname input
    use_effect(move || {
        if show_first_run_setup() {
            spawn(async move {
                Delay::new(Duration::from_millis(100)).await;
                let _ = document::eval(
                    r#"
                    const input = document.getElementById('first-run-nick-input');
                    if (input) {
                        input.focus();
                        input.select();
                    }
                    "#
                );
            });
        }
    });

    let mut edit_name_input = use_signal(String::new);
    let mut edit_server_input = use_signal(String::new);
    let mut edit_nick_input = use_signal(String::new);
    let mut edit_channel_input = use_signal(String::new);
    let mut edit_tls_input = use_signal(|| true);
    let mut edit_auto_connect_input = use_signal(|| true);
    let mut edit_hide_host_input = use_signal(|| true);

    let mut search_input = use_signal(String::new);
    let mut channel_list: Signal<Vec<(String, u32, String)>> = use_signal(Vec::new);
    let mut channel_search_input = use_signal(String::new);
    let mut list_loading = use_signal(|| false);
    let mut channels_collapsed = use_signal(|| false);
    let mut userlist_collapsed = use_signal(|| false);
    let mut topic_collapsed = use_signal(|| false);
    let mut user_menu_open: Signal<Option<String>> = use_signal(|| None);
    let mut ctcp_submenu_open: Signal<bool> = use_signal(|| false);
    
    // Virtual scrolling state for message performance optimization
    // Only render messages within the visible viewport + buffer
    let mut visible_message_range: Signal<(usize, usize)> = use_signal(|| (0, 100));
    // Cache for sorted user lists per channel (profile+channel -> sorted users)
    let mut cached_sorted_users: Signal<HashMap<String, Vec<String>>> = use_signal(HashMap::new);

    // WHOIS popup state
    let mut whois_popup: Signal<Option<WhoisInfo>> = use_signal(|| None);
    let whois_building: Signal<Option<WhoisInfo>> = use_signal(|| None);
    
    // CTCP response popup state
    let mut ctcp_response_popup: Signal<Option<CtcpResponseInfo>> = use_signal(|| None);

    // Channel invite popup state
    let mut channel_invite_popup: Signal<Option<ChannelInviteInfo>> = use_signal(|| None);
    // Known NAIS users (nick -> true means confirmed NAIS client)
    let known_nais_users: Signal<HashMap<String, bool>> = use_signal(HashMap::new);
    // Pending VERSION probes for invite detection (nick -> true means waiting)  
    let mut pending_invite_probes: Signal<HashMap<String, bool>> = use_signal(HashMap::new);
    
    // Cross-network invite popup state (when we receive an invite to another server)
    let mut cross_network_invite: Signal<Option<CrossNetworkInviteInfo>> = use_signal(|| None);
    
    // Incoming IRC invite popup state (standard IRC INVITE command)
    let mut incoming_irc_invite: Signal<Option<IncomingIrcInviteInfo>> = use_signal(|| None);

    // Voice chat state
    let mut voice_state: Signal<crate::voice_chat::VoiceState> = use_signal(|| crate::voice_chat::VoiceState::Idle);
    let mut voice_muted = use_signal(|| false);
    let mut voice_incoming_call: Signal<Option<(String, String, u16, String, Option<String>)>> = use_signal(|| None); // (from, ext_ip, port, session_id, local_ip)
    let mut voice_current_peer: Signal<Option<String>> = use_signal(|| None);
    let mut voice_session_id: Signal<Option<String>> = use_signal(|| None);
    let mut voice_local_port: Signal<u16> = use_signal(|| 0);
    let mut voice_external_ip: Signal<String> = use_signal(|| String::new());
    let mut voice_event_rx: Signal<Option<async_channel::Receiver<crate::voice_chat::VoiceEvent>>> = use_signal(|| None);
    let voice_muted_arc: Signal<std::sync::Arc<std::sync::Mutex<bool>>> = use_signal(|| std::sync::Arc::new(std::sync::Mutex::new(false)));
    let mut voice_stop_flag: Signal<Option<std::sync::Arc<std::sync::Mutex<bool>>>> = use_signal(|| None);
    let mut voice_peer_addr_tx: Signal<Option<async_channel::Sender<(String, u16)>>> = use_signal(|| None);
    
    // Voice debug state
    let mut voice_mic_level: Signal<f32> = use_signal(|| 0.0);
    let mut voice_available_devices: Signal<Vec<crate::voice_chat::AudioInputDevice>> = use_signal(|| {
        crate::voice_chat::list_audio_input_devices()
    });
    let mut voice_selected_device: Signal<Option<String>> = use_signal(|| None);
    let mut voice_debug_expanded = use_signal(|| true);
    let mut voice_level_monitor: Signal<Option<std::sync::Arc<crate::voice_chat::AudioLevelMonitor>>> = use_signal(|| None);
    
    // Voice output debug state
    let mut voice_output_level: Signal<f32> = use_signal(|| 0.0);
    let mut voice_output_devices: Signal<Vec<crate::voice_chat::AudioOutputDevice>> = use_signal(|| {
        crate::voice_chat::list_audio_output_devices()
    });
    let mut voice_selected_output_device: Signal<Option<String>> = use_signal(|| None);
    let mut voice_output_monitor: Signal<Option<std::sync::Arc<crate::voice_chat::AudioOutputLevelMonitor>>> = use_signal(|| None);
    
    // Voice network stats
    let mut voice_network_stats: Signal<crate::voice_chat::VoiceNetworkStats> = use_signal(|| crate::voice_chat::VoiceNetworkStats::new());

    // Nais Secure Channel state
    let mut show_new_nsc_modal = use_signal(|| false);
    let mut nsc_channel_name_input = use_signal(|| String::new());
    // Selected network for new NSC channel creation (defaults to active profile)
    let mut nsc_selected_network = use_signal(|| String::new());
    let mut nsc_channels: Signal<Vec<crate::nsc_manager::ChannelInfo>> = use_signal(Vec::new);
    let mut nsc_loading = use_signal(|| false);
    let mut nsc_fingerprint = use_signal(|| String::new());
    // Currently selected NSC channel (None = IRC channel, Some(id) = NSC channel)
    let mut nsc_current_channel: Signal<Option<String>> = use_signal(|| None);
    // Messages for NSC channels: channel_id -> Vec<(timestamp, sender, text)>
    let mut nsc_messages: Signal<HashMap<String, Vec<(u64, String, String)>>> = use_signal(HashMap::new);
    // Pending NSC invites: invite_id -> PendingInvite
    let mut nsc_pending_invites: Signal<Vec<crate::nsc_manager::PendingInvite>> = use_signal(Vec::new);
    // NSC invite modal state: (nick, profile) when showing channel selection
    let mut nsc_invite_modal: Signal<Option<(String, String)>> = use_signal(|| None);
    // NSC channel members for the sidebar
    let mut nsc_channel_members: Signal<Vec<crate::nsc_manager::NscChannelMember>> = use_signal(Vec::new);
    
    // Load existing NSC channels on startup
    use_effect(move || {
        spawn(async move {
            let manager = crate::nsc_manager::get_nsc_manager_async().await;
            let mgr = manager.read().await;
            let channels = mgr.list_channels().await;
            let fp = mgr.fingerprint();
            drop(mgr);
            
            // Load stored messages for all channels
            for channel in &channels {
                let stored = crate::nsc_manager::load_messages_async(&channel.channel_id).await;
                if !stored.is_empty() {
                    let mut msgs = nsc_messages.write();
                    let channel_msgs = msgs.entry(channel.channel_id.clone()).or_insert_with(Vec::new);
                    for m in stored {
                        channel_msgs.push((m.timestamp, m.sender, m.text));
                    }
                }
            }
            
            nsc_channels.set(channels);
            nsc_fingerprint.set(fp);
        });
    });
    
    // Initialize NSC transport and start listening for incoming messages
    use_effect(move || {
        spawn(async move {
            let manager = crate::nsc_manager::get_nsc_manager_async().await;
            
            // Initialize transport
            {
                let mgr = manager.read().await;
                if let Err(e) = mgr.init_transport().await {
                    log::warn!("Failed to initialize NSC transport: {}", e);
                    return;
                }
                
                if let Some(port) = mgr.local_port().await {
                    log::info!("NSC transport listening on port {}", port);
                }
            }
            
            // Start message listener
            let mut rx = {
                let mgr = manager.read().await;
                match mgr.start_listener().await {
                    Ok(rx) => rx,
                    Err(e) => {
                        log::warn!("Failed to start NSC listener: {}", e);
                        return;
                    }
                }
            };
            
            // Process incoming messages
            while let Some((channel_id, msg)) = rx.recv().await {
                log::debug!("Received NSC message in channel {}: {} chars from {}", 
                    &channel_id[..8], msg.text.len(), msg.sender);
                
                // Add message to the appropriate channel
                let mut msgs = nsc_messages.write();
                let channel_msgs = msgs.entry(channel_id).or_insert_with(Vec::new);
                channel_msgs.push((msg.timestamp, msg.sender, msg.text));
            }
        });
    });
    
    // Fetch NSC channel members when NSC channel changes
    // Also subscribe to NSC events to refresh members when they join/leave
    use_effect(move || {
        let channel_id = nsc_current_channel.read().clone();
        if let Some(ch_id) = channel_id.clone() {
            // Initial fetch
            let ch_id_initial = ch_id.clone();
            spawn(async move {
                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                let mgr = manager.read().await;
                let members = mgr.get_channel_members(&ch_id_initial).await;
                nsc_channel_members.set(members);
            });
            
            // Periodic refresh to catch member changes (every 3 seconds)
            let ch_id_poll = ch_id.clone();
            spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
                loop {
                    interval.tick().await;
                    
                    // Check if channel is still the same
                    let current = nsc_current_channel.read().clone();
                    if current.as_ref() != Some(&ch_id_poll) {
                        break;
                    }
                    
                    let manager = crate::nsc_manager::get_nsc_manager_async().await;
                    let mgr = manager.read().await;
                    let members = mgr.get_channel_members(&ch_id_poll).await;
                    nsc_channel_members.set(members);
                }
            });
        } else {
            nsc_channel_members.set(Vec::new());
        }
    });

    // Update channel_users context when channel or user list changes
    use_effect(move || {
        let state_read = state.read();
        let active_profile = state_read.active_profile.clone();
        let current_channel = state_read.servers
            .get(&active_profile)
            .map(|s| s.current_channel.clone())
            .unwrap_or_default();
        let users = state_read.servers
            .get(&active_profile)
            .and_then(|s| s.users_by_channel.get(&current_channel).cloned())
            .unwrap_or_default();
        drop(state_read);
        channel_users.set(users);
    });

    // Scroll behavior state
    let mut is_at_bottom = use_signal(|| true);
    let mut force_scroll_to_bottom = use_signal(|| false);
    let mut last_channel_key = use_signal(|| String::new());

    // Smart auto-scroll: only scroll if at bottom or forced
    use_effect(move || {
        // Track state changes to re-run this effect when messages update
        let state_read = state.read();
        let active_profile = state_read.active_profile.clone();
        let current_channel = state_read.servers
            .get(&active_profile)
            .map(|s| s.current_channel.clone())
            .unwrap_or_default();
        let _message_count = state_read.servers
            .get(&active_profile)
            .map(|s| s.messages.len())
            .unwrap_or(0);
        drop(state_read);
        
        // Create a unique key for the current channel
        let channel_key = format!("{}:{}", active_profile, current_channel);
        let channel_changed = channel_key != last_channel_key();
        
        if channel_changed {
            last_channel_key.set(channel_key);
            force_scroll_to_bottom.set(true);
        }
        
        // Only scroll if: forced, or at bottom
        let should_scroll = force_scroll_to_bottom() || is_at_bottom();
        
        if should_scroll {
            spawn(async move {
                Delay::new(Duration::from_millis(10)).await;
                let _ = document::eval(
                    r#"
                    const messagesDiv = document.querySelector('.messages');
                    if (messagesDiv) {
                        messagesDiv.scrollTop = messagesDiv.scrollHeight;
                    }
                    "#
                );
            });
            
            if force_scroll_to_bottom() {
                force_scroll_to_bottom.set(false);
                is_at_bottom.set(true);
            }
        }
    });

    // Track pasteboard and OG image resolution for re-rendering
    let mut last_cache_version = use_signal(|| (0u64, 0u64, 0u64));
    use_effect(move || {
        spawn(async move {
            loop {
                Delay::new(Duration::from_millis(500)).await;
                let current_version = {
                    let pasteboard_cache = PASTEBOARD_CACHE.lock().unwrap();
                    let og_cache = OG_IMAGE_CACHE.lock().unwrap();
                    let discourse_cache = DISCOURSE_CACHE.lock().unwrap();
                    (pasteboard_cache.1, og_cache.1, discourse_cache.1)
                };
                if current_version != last_cache_version() {
                    last_cache_version.set(current_version);
                }
            }
        });
    });
    
    // Voice level monitor effect - start/stop based on call state
    use_effect(move || {
        let is_active = matches!(voice_state(), crate::voice_chat::VoiceState::Active { .. });
        
        if is_active && voice_level_monitor.read().is_none() {
            // Start input monitoring when call becomes active
            let device_name = voice_selected_device.read().clone();
            if let Some(monitor) = crate::voice_chat::AudioLevelMonitor::start(device_name.as_deref()) {
                let monitor_arc = std::sync::Arc::new(monitor);
                voice_level_monitor.set(Some(monitor_arc.clone()));
                
                // Spawn a task to periodically update the input level
                spawn(async move {
                    loop {
                        Delay::new(Duration::from_millis(50)).await;
                        if let Some(ref m) = *voice_level_monitor.read() {
                            let level = m.get_level();
                            voice_mic_level.set(level);
                        } else {
                            break;
                        }
                    }
                });
            }
            
            // Start output monitoring - this tracks audio being played
            let output_monitor = crate::voice_chat::AudioOutputLevelMonitor::new();
            voice_output_monitor.set(Some(std::sync::Arc::new(output_monitor)));
            
            // Reset network stats for new call
            voice_network_stats.set(crate::voice_chat::VoiceNetworkStats::new());
        } else if !is_active && voice_level_monitor.read().is_some() {
            // Stop monitoring when call ends
            voice_level_monitor.set(None);
            voice_mic_level.set(0.0);
            voice_output_monitor.set(None);
            voice_output_level.set(0.0);
        }
    });

    // Voice event polling effect - receive events from voice system
    use_effect(move || {
        spawn(async move {
            loop {
                Delay::new(Duration::from_millis(50)).await;
                
                // Check if we have an event receiver
                let rx_opt = voice_event_rx.read().clone();
                if let Some(ref rx) = rx_opt {
                    // Try to receive voice events
                    while let Ok(event) = rx.try_recv() {
                        match event {
                            crate::voice_chat::VoiceEvent::NetworkStats { stats } => {
                                voice_network_stats.set(stats);
                            }
                            crate::voice_chat::VoiceEvent::OutputLevel { level } => {
                                voice_output_level.set(level);
                            }
                            crate::voice_chat::VoiceEvent::AudioLevel { is_local: true, level } => {
                                voice_mic_level.set(level);
                            }
                            crate::voice_chat::VoiceEvent::CallEnded { peer: _, reason } => {
                                log::info!("Voice call ended: {}", reason);
                                voice_state.set(crate::voice_chat::VoiceState::Idle);
                                voice_current_peer.set(None);
                                voice_session_id.set(None);
                                voice_event_rx.set(None);
                            }
                            crate::voice_chat::VoiceEvent::Error { message } => {
                                log::error!("Voice error: {}", message);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    });

    // Main event loop to poll cores for IRC events
    use_effect(move || {
        let mut state_handle = state;
        let mut status_handle = profile_status;
        let mut channel_list_handle = channel_list;
        let mut list_loading_handle = list_loading;
        let mut voice_state_handle = voice_state;
        let mut voice_incoming_handle = voice_incoming_call;
        let mut voice_peer_handle = voice_current_peer;
        let mut voice_session_handle = voice_session_id;
        let mut voice_event_rx_handle = voice_event_rx;
        let mut voice_stop_flag_handle = voice_stop_flag;
        let voice_peer_addr_tx_handle = voice_peer_addr_tx;
        let voice_external_ip_handle = voice_external_ip;
        let mut whois_building_handle = whois_building;
        let mut whois_popup_handle = whois_popup;
        let mut ctcp_response_popup_handle = ctcp_response_popup;
        let mut channel_invite_popup_handle = channel_invite_popup;
        let mut known_nais_users_handle = known_nais_users;
        let mut pending_invite_probes_handle = pending_invite_probes;
        let mut cross_network_invite_handle = cross_network_invite;
        let mut incoming_irc_invite_handle = incoming_irc_invite;
        spawn(async move {
            let mut channel_buffer: Vec<(String, u32, String)> = Vec::new();
            const BATCH_SIZE: usize = 200;
            
            loop {
                let state_read = state_handle.read();
                let profile_names: Vec<String> =
                    state_read.servers.keys().cloned().collect();
                drop(state_read);

                for profile_name in profile_names {
                    let cores_read = cores.read();
                    if let Some(handle) = cores_read.get(&profile_name) {
                        let evt_rx = handle.evt_rx.clone();
                        drop(cores_read);

                        // Process only a few events per iteration to stay responsive
                        const MAX_EVENTS_PER_ITERATION: usize = 5;
                        let mut events_processed = 0;
                        
                        while let Ok(event) = evt_rx.try_recv() {
                            // Handle channel list events - but skip rendering until we have a batch
                            match &event {
                                IrcEvent::ChannelListItem { channel, user_count, topic } => {
                                    channel_buffer.push((
                                        channel.clone(),
                                        *user_count,
                                        topic.clone(),
                                    ));
                                    
                                    // Only update UI when we have a large batch
                                    if channel_buffer.len() >= BATCH_SIZE {
                                        channel_list_handle.write().extend(channel_buffer.drain(..));
                                        // Yield after batch update
                                        Delay::new(Duration::from_millis(5)).await;
                                    }
                                    
                                    // Don't count channel list items toward event limit
                                    continue;
                                }
                                IrcEvent::ChannelListEnd => {
                                    // Flush any remaining buffered channels
                                    if !channel_buffer.is_empty() {
                                        channel_list_handle.write().extend(channel_buffer.drain(..));
                                    }
                                    list_loading_handle.set(false);
                                    // Cache the channel list in ServerState
                                    let mut state_mut = state_handle.write();
                                    if let Some(server_state) = state_mut.servers.get_mut(&profile_name) {
                                        server_state.cached_channel_list = channel_list_handle.read().clone();
                                    }
                                    drop(state_mut);
                                    continue;
                                }
                                IrcEvent::VoiceCtcp { from, command, args } => {
                                    // Handle voice CTCP commands
                                    match command.as_str() {
                                        crate::voice_chat::CTCP_VOICE_CALL => {
                                            // Incoming call: VOICE_CALL <ext_ip> <port> <session_id> [<local_ip>]
                                            if args.len() >= 3 {
                                                let ext_ip = args[0].clone();
                                                let port = args[1].parse::<u16>().unwrap_or(0);
                                                let session_id = args[2].clone();
                                                // Optional local IP for same-LAN detection (4th argument)
                                                let local_ip = args.get(3).cloned();
                                                if port > 0 {
                                                    voice_incoming_handle.set(Some((from.clone(), ext_ip.clone(), port, session_id, local_ip)));
                                                    voice_state_handle.set(crate::voice_chat::VoiceState::Incoming {
                                                        peer: from.clone(),
                                                        ip: ext_ip,
                                                        port,
                                                    });
                                                }
                                            }
                                        }
                                        crate::voice_chat::CTCP_VOICE_ACCEPT => {
                                            // Our call was accepted - peer sent their IP:port
                                            // Format: VOICE_ACCEPT <ext_ip> <port> <session_id> [<local_ip>]
                                            // Send peer address to our listener to try reverse connection
                                            if args.len() >= 3 {
                                                let peer_ext_ip = args[0].clone();
                                                let peer_port: u16 = args[1].parse().unwrap_or(0);
                                                let session_id = args[2].clone();
                                                // Optional local IP for same-LAN detection
                                                let peer_local_ip = args.get(3).map(|s| s.as_str());
                                                
                                                // Resolve: use local IP if same LAN, otherwise external
                                                let our_ext_ip = voice_external_ip_handle.read().clone();
                                                let resolved_ip = crate::voice_chat::resolve_peer_address(
                                                    &peer_ext_ip, 
                                                    peer_local_ip, 
                                                    &our_ext_ip
                                                );
                                                
                                                log::info!("VOICE_ACCEPT received from {} - peer ext={}:{}, resolved to {}", from, peer_ext_ip, peer_port, resolved_ip);
                                                
                                                if voice_session_handle.read().as_ref() == Some(&session_id) {
                                                    voice_state_handle.set(crate::voice_chat::VoiceState::Active {
                                                        peer: from.clone(),
                                                    });
                                                    voice_peer_handle.set(Some(from.clone()));
                                                    
                                                    // Send resolved peer address through channel to trigger reverse connection
                                                    // The listener will race between inbound and outbound
                                                    if peer_port > 0 {
                                                        if let Some(tx) = voice_peer_addr_tx_handle.read().clone() {
                                                            log::info!("Sending resolved peer address {} to listener for reverse connection attempt", resolved_ip);
                                                            let _ = tx.try_send((resolved_ip.clone(), peer_port));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        crate::voice_chat::CTCP_VOICE_REJECT => {
                                            // Our call was rejected - stop our listener
                                            if let Some(stop_flag) = voice_stop_flag_handle.read().clone() {
                                                if let Ok(mut stopped) = stop_flag.lock() {
                                                    *stopped = true;
                                                }
                                            }
                                            voice_state_handle.set(crate::voice_chat::VoiceState::Idle);
                                            voice_session_handle.set(None);
                                            voice_peer_handle.set(None);
                                            voice_event_rx_handle.set(None);
                                            voice_stop_flag_handle.set(None);
                                        }
                                        crate::voice_chat::CTCP_VOICE_CANCEL => {
                                            // Call was cancelled by peer - stop our audio stream
                                            if let Some(stop_flag) = voice_stop_flag_handle.read().clone() {
                                                if let Ok(mut stopped) = stop_flag.lock() {
                                                    *stopped = true;
                                                }
                                            }
                                            voice_state_handle.set(crate::voice_chat::VoiceState::Idle);
                                            voice_incoming_handle.set(None);
                                            voice_peer_handle.set(None);
                                            voice_session_handle.set(None);
                                            voice_event_rx_handle.set(None);
                                            voice_stop_flag_handle.set(None);
                                        }
                                        _ => {}
                                    }
                                    continue;
                                }
                                IrcEvent::WhoisUser { nick, user, host, realname } => {
                                    // Start building whois info
                                    whois_building_handle.set(Some(WhoisInfo {
                                        nick: nick.clone(),
                                        user: Some(user.clone()),
                                        host: Some(host.clone()),
                                        realname: Some(realname.clone()),
                                        ..Default::default()
                                    }));
                                }
                                IrcEvent::WhoisServer { nick, server, server_info } => {
                                    let current = { whois_building_handle.read().clone() };
                                    if let Some(mut info) = current {
                                        if info.nick == *nick {
                                            info.server = Some(server.clone());
                                            info.server_info = Some(server_info.clone());
                                            whois_building_handle.set(Some(info));
                                        }
                                    }
                                }
                                IrcEvent::WhoisChannels { nick, channels } => {
                                    let current = { whois_building_handle.read().clone() };
                                    if let Some(mut info) = current {
                                        if info.nick == *nick {
                                            info.channels = Some(channels.clone());
                                            whois_building_handle.set(Some(info));
                                        }
                                    }
                                }
                                IrcEvent::WhoisIdle { nick, idle_secs } => {
                                    let current = { whois_building_handle.read().clone() };
                                    if let Some(mut info) = current {
                                        if info.nick == *nick {
                                            info.idle_secs = Some(idle_secs.clone());
                                            whois_building_handle.set(Some(info));
                                        }
                                    }
                                }
                                IrcEvent::WhoisEnd { nick } => {
                                    let current = { whois_building_handle.read().clone() };
                                    if let Some(info) = current {
                                        if info.nick == *nick {
                                            // Show the popup with accumulated info
                                            whois_popup_handle.set(Some(info));
                                            whois_building_handle.set(None);
                                        }
                                    }
                                }
                                IrcEvent::CtcpResponse { from, command, response } => {
                                    // Check if this is a VERSION response for a pending invite probe
                                    // Use lowercase for case-insensitive matching (IRC nicks are case-insensitive)
                                    let from_lower = from.to_lowercase();
                                    let pending_probes = pending_invite_probes_handle.read();
                                    let pending_keys: Vec<_> = pending_probes.keys().cloned().collect();
                                    let is_pending_invite = pending_probes.contains_key(&from_lower);
                                    drop(pending_probes);
                                    
                                    log::info!("CtcpResponse: from='{}', from_lower='{}', command='{}', response='{}', pending_probes={:?}, is_pending_invite={}", 
                                        from, from_lower, command, response, pending_keys, is_pending_invite);
                                    
                                    if is_pending_invite && command == "VERSION" {
                                        // Check if this is a NAIS client - check for multiple variations
                                        // Response could be "NAIS-client v0.1.0 (Rust)" or similar
                                        let response_upper = response.to_uppercase();
                                        let contains_nais = response_upper.contains("NAIS");
                                        let contains_nais_client = response_upper.contains("NAIS-CLIENT");
                                        let contains_nais_underscore = response_upper.contains("NAIS_CLIENT");
                                        let is_nais = contains_nais || contains_nais_client || contains_nais_underscore;
                                        
                                        log::info!("NAIS detection for '{}': response='{}', response_upper='{}', contains_nais={}, contains_nais_client={}, is_nais={}", 
                                            from, response, response_upper, contains_nais, contains_nais_client, is_nais);
                                        
                                        if is_nais {
                                            // Found NAIS client! Remove from pending and show popup immediately
                                            pending_invite_probes_handle.write().remove(&from_lower);
                                            
                                            // Track known NAIS users
                                            known_nais_users_handle.write().insert(from.clone(), true);
                                            
                                            // Show channel invite popup
                                            channel_invite_popup_handle.set(Some(ChannelInviteInfo {
                                                target_nick: from.clone(),
                                                is_nais_client: true,
                                                current_profile: profile_name.clone(),
                                            }));
                                        } else {
                                            // Non-NAIS response, but there might be more responses coming
                                            // (some clients send multiple VERSION responses)
                                            // Spawn a delayed check - if still pending after 500ms, show as non-NAIS
                                            let from_clone = from.clone();
                                            let from_lower_clone = from_lower.clone();
                                            let mut pending_handle = pending_invite_probes_handle.clone();
                                            let mut popup_handle = channel_invite_popup_handle.clone();
                                            let mut known_users_handle = known_nais_users_handle.clone();
                                            let profile = profile_name.clone();
                                            spawn(async move {
                                                // Wait for more responses
                                                Delay::new(Duration::from_millis(500)).await;
                                                // If still pending (no NAIS response came), show as non-NAIS
                                                if pending_handle.write().remove(&from_lower_clone).is_some() {
                                                    log::info!("Timeout reached for '{}', showing as non-NAIS client", from_clone);
                                                    known_users_handle.write().insert(from_clone.clone(), false);
                                                    popup_handle.set(Some(ChannelInviteInfo {
                                                        target_nick: from_clone,
                                                        is_nais_client: false,
                                                        current_profile: profile,
                                                    }));
                                                }
                                            });
                                        }
                                    } else {
                                        // Show CTCP response in popup (normal behavior)
                                        ctcp_response_popup_handle.set(Some(CtcpResponseInfo {
                                            from: from.clone(),
                                            command: command.clone(),
                                            response: response.clone(),
                                        }));
                                        
                                        // Get current channel for system message
                                        let current_channel = state_handle.read().servers.get(&profile_name)
                                            .map(|s| s.current_channel.clone())
                                            .unwrap_or_default();
                                        
                                        // Show system message for non-invite CTCP responses
                                        let mut state_mut = state_handle.write();
                                        let profiles_read = profiles.read();
                                        apply_event_with_config(
                                            &mut state_mut,
                                            &profiles_read,
                                            &profile_name,
                                            IrcEvent::System {
                                                channel: current_channel,
                                                text: format!("[CTCP {}] {} reply from {}", command, response, from),
                                            },
                                        );
                                        drop(state_mut);
                                    }
                                }
                                IrcEvent::NaisCtcp { from, command, args } => {
                                    // Handle NAIS channel CTCP commands
                                    match command.as_str() {
                                        crate::nais_channel::CTCP_NAIS_PROBE => {
                                            // Someone is probing us for NAIS capability
                                            // Respond with our info if we're in that channel
                                            if let Some(irc_channel) = args.first() {
                                                // Get our info from state
                                                let state_read = state_handle.read();
                                                if let Some(server) = state_read.servers.get(&profile_name) {
                                                    // Check if we're in this channel and it's a NAIS channel
                                                    if server.channels.contains(&irc_channel.to_string()) {
                                                        if let Some(topic) = server.topics_by_channel.get(irc_channel) {
                                                            if let Some((_version, channel_id, _fp)) = crate::nais_channel::parse_nais_topic(topic) {
                                                                // We're in a NAIS channel - respond with our info
                                                                let our_fingerprint = crate::nais_channel::generate_fingerprint();
                                                                let info_msg = crate::nais_channel::create_info_ctcp(
                                                                    &channel_id,
                                                                    &our_fingerprint,
                                                                    "0.0.0.0", // Would be our external IP
                                                                    0, // Would be our listening port
                                                                );
                                                                
                                                                // Send response via NOTICE (CTCP response)
                                                                if let Some(core) = cores.read().get(&profile_name) {
                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Notice {
                                                                        target: from.clone(),
                                                                        text: info_msg,
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                drop(state_read);
                                            }
                                        }
                                        crate::nais_channel::CTCP_NAIS_INFO => {
                                            // Received NAIS info from a peer
                                            // Format: channel_id fingerprint ip port
                                            if args.len() >= 4 {
                                                let channel_id = &args[0];
                                                let fingerprint = &args[1];
                                                let ip = &args[2];
                                                let port = &args[3];
                                                
                                                // Get current channel before borrowing state mutably
                                                let current_channel = state_handle.read().servers.get(&profile_name)
                                                    .map(|s| s.current_channel.clone())
                                                    .unwrap_or_default();
                                                
                                                // Add system message about discovered peer
                                                let mut state_mut = state_handle.write();
                                                let profiles_read = profiles.read();
                                                apply_event_with_config(
                                                    &mut state_mut,
                                                    &profiles_read,
                                                    &profile_name,
                                                    IrcEvent::System {
                                                        channel: current_channel,
                                                        text: format!("[NAIS] Discovered peer: {} ({}:{}) in channel {}", 
                                                            from, ip, port, &channel_id[..8.min(channel_id.len())]),
                                                    },
                                                );
                                                drop(state_mut);
                                                
                                                log::info!("NAIS peer discovered: {} fingerprint={} at {}:{}", 
                                                    from, fingerprint, ip, port);
                                            }
                                        }
                                        crate::nais_channel::CTCP_NAIS_JOIN | 
                                        crate::nais_channel::CTCP_NAIS_ACCEPT |
                                        crate::nais_channel::CTCP_NAIS_CONNECT |
                                        crate::nais_channel::CTCP_NAIS_LEAVE => {
                                            // Log other NAIS commands for debugging
                                            log::info!("NAIS {} from {}: {:?}", command, from, args);
                                        }
                                        crate::nais_channel::CTCP_NAIS_CHANNEL_INVITE => {
                                            // Someone is inviting us to a channel
                                            // Format: channel server type(nais|irc)
                                            if args.len() >= 3 {
                                                let channel = &args[0];
                                                let server = &args[1];
                                                let channel_type = &args[2];
                                                
                                                // Get current channel before borrowing state mutably
                                                let current_channel = state_handle.read().servers.get(&profile_name)
                                                    .map(|s| s.current_channel.clone())
                                                    .unwrap_or_default();
                                                
                                                // Add system message about the invite
                                                let mut state_mut = state_handle.write();
                                                let profiles_read = profiles.read();
                                                let type_indicator = if channel_type == "nais" { "🔒" } else { "" };
                                                apply_event_with_config(
                                                    &mut state_mut,
                                                    &profiles_read,
                                                    &profile_name,
                                                    IrcEvent::System {
                                                        channel: current_channel,
                                                        text: format!("[NAIS] {} {} invites you to join {}{} on {}", 
                                                            type_indicator, from, channel, 
                                                            if channel_type == "nais" { " (NAIS encrypted)" } else { "" },
                                                            server),
                                                    },
                                                );
                                                drop(state_mut);
                                                
                                                // Show the cross-network invite popup
                                                cross_network_invite_handle.set(Some(CrossNetworkInviteInfo {
                                                    from_nick: from.clone(),
                                                    channel: channel.clone(),
                                                    server: server.clone(),
                                                    is_nais: channel_type == "nais",
                                                    _received_on_profile: profile_name.clone(),
                                                }));
                                                
                                                log::info!("NAIS channel invite from {}: channel={} server={} type={}", 
                                                    from, channel, server, channel_type);
                                            }
                                        }
                                        cmd if cmd.starts_with("NSC_") => {
                                            // Handle NSC (Nais Secure Channels) CTCP commands
                                            log::info!("[UI NSC] Handling {} from {}", cmd, from);
                                            
                                            let from_nick = from.clone();
                                            let cmd_str = command.clone();
                                            let args_str = args.join(" ");
                                            let pname = profile_name.clone();
                                            let cores_clone = cores.clone();
                                            
                                            // Get current IRC channel from state
                                            let irc_channel = state_handle.read().servers.get(&profile_name)
                                                .map(|s| s.current_channel.clone())
                                                .unwrap_or_default();
                                            
                                            log::info!("[UI NSC] Processing {} from {} in IRC channel '{}'", cmd_str, from_nick, irc_channel);
                                            
                                            // Spawn async handler
                                            spawn(async move {
                                                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                let mgr = manager.read().await;
                                                
                                                log::info!("[UI NSC] Calling handle_nsc_ctcp for {} from {} on profile {}", cmd_str, from_nick, pname);
                                                
                                                if let Some(response) = mgr.handle_nsc_ctcp(&from_nick, &irc_channel, &cmd_str, &args_str, &pname).await {
                                                    log::info!("[UI NSC] Sending response to {}", from_nick);
                                                    // Send NSC CTCP via PRIVMSG/CTCP for better compatibility
                                                    // Note: response already includes CTCP delimiters from encode_ctcp
                                                    if let Some(core) = cores_clone.read().get(&pname) {
                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                            target: from_nick.clone(),
                                                            message: response,
                                                        });
                                                    }
                                                }
                                                
                                                // Refresh pending invites signal
                                                let invites = mgr.get_pending_invites().await;
                                                log::info!("[UI NSC] Refreshed pending invites: {} invites", invites.len());
                                                drop(mgr);
                                                nsc_pending_invites.set(invites);
                                            });
                                            
                                            log::debug!("NSC CTCP {} from {}: {:?}", command, from, args);
                                        }
                                        _ => {}
                                    }
                                }
                                IrcEvent::Topic { channel, topic } => {
                                    // Check if this is a NAIS channel topic
                                    if crate::nais_channel::is_nais_topic(topic) {
                                        if let Some((_version, channel_id, _fingerprint)) = crate::nais_channel::parse_nais_topic(topic) {
                                            // This is a NAIS channel - auto-probe users
                                            let state_read = state_handle.read();
                                            if let Some(server) = state_read.servers.get(&profile_name) {
                                                if let Some(users) = server.users_by_channel.get(channel.as_str()) {
                                                    let our_nick = server.nickname.clone();
                                                    let probe_msg = crate::nais_channel::create_probe_ctcp(channel);
                                                    
                                                    // Probe each user in the channel
                                                    for user in users {
                                                        let clean_user = user.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~');
                                                        if clean_user == our_nick {
                                                            continue;
                                                        }
                                                        
                                                        if let Some(core) = cores.read().get(&profile_name) {
                                                            let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                target: clean_user.to_string(),
                                                                message: probe_msg.clone(),
                                                            });
                                                        }
                                                    }
                                                    
                                                    // Also send NSC probes to discover NSC-capable peers
                                                    let users_to_probe: Vec<String> = users.iter()
                                                        .map(|u| u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~').to_string())
                                                        .filter(|u| u != &our_nick)
                                                        .collect();
                                                    let cores_clone = cores.clone();
                                                    let pname = profile_name.clone();
                                                    
                                                    spawn(async move {
                                                        let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                        let mgr = manager.read().await;
                                                        let nsc_probe = mgr.create_probe_ctcp();
                                                        drop(mgr);
                                                        
                                                        if !nsc_probe.is_empty() {
                                                            for clean_user in users_to_probe {
                                                                if let Some(core) = cores_clone.read().get(&pname) {
                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                        target: clean_user,
                                                                        message: nsc_probe.clone(),
                                                                    });
                                                                }
                                                            }
                                                            log::info!("Sent NSC probes to channel users");
                                                        }
                                                    });
                                                    
                                                    // Add system message
                                                    drop(state_read);
                                                    let mut state_mut = state_handle.write();
                                                    let profiles_read = profiles.read();
                                                    apply_event_with_config(
                                                        &mut state_mut,
                                                        &profiles_read,
                                                        &profile_name,
                                                        IrcEvent::System {
                                                            channel: channel.clone(),
                                                            text: format!("[NAIS] Detected secure channel (ID: {}). Probing for peers...", 
                                                                &channel_id[..8.min(channel_id.len())]),
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                IrcEvent::Invited { from, channel } => {
                                    // Show incoming IRC invite popup
                                    incoming_irc_invite_handle.set(Some(IncomingIrcInviteInfo {
                                        from_nick: from.clone(),
                                        channel: channel.clone(),
                                        profile: profile_name.clone(),
                                    }));
                                    
                                    log::info!("Received IRC INVITE from {} to channel {}", from, channel);
                                }
                                IrcEvent::UserJoined { channel, user } => {
                                    // When a user joins an NSC discovery channel or a channel mapped to NSC,
                                    // probe them to discover if they're an NSC peer
                                    let should_probe = channel.starts_with("#nais-");
                                    
                                    // Also check if this channel is mapped to an NSC secure channel
                                    let cores_clone = cores.clone();
                                    let pname = profile_name.clone();
                                    let irc_channel = channel.clone();
                                    
                                    // Get our nick to avoid probing ourselves
                                    let our_nick = state_handle.read()
                                        .servers.get(&profile_name)
                                        .map(|s| s.nickname.clone())
                                        .unwrap_or_default();
                                    let clean_user = user.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~').to_string();
                                    
                                    if clean_user != our_nick {
                                        spawn(async move {
                                            let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                            let mgr = manager.read().await;
                                            
                                            // Check if this channel maps to an NSC channel
                                            let is_nsc_channel = should_probe || mgr.get_channel_by_irc(&irc_channel).await.is_some();
                                            
                                            if is_nsc_channel {
                                                // Record pending probe so we can associate the response with this channel
                                                mgr.record_pending_probe(&clean_user, &irc_channel).await;
                                                let nsc_probe = mgr.create_probe_ctcp();
                                                drop(mgr);
                                                
                                                if !nsc_probe.is_empty() {
                                                    if let Some(core) = cores_clone.read().get(&pname) {
                                                        log::info!("User {} joined channel {} (NSC-related), sending probe", clean_user, irc_channel);
                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                            target: clean_user.to_string(),
                                                            message: nsc_probe,
                                                        });
                                                    }
                                                }
                                            }
                                        });
                                    }
                                }
                                IrcEvent::Users { channel, users } => {
                                    // When we receive the user list for an NSC discovery channel or mapped channel,
                                    // probe all users to discover NSC peers
                                    let should_probe = channel.starts_with("#nais-");
                                    let cores_clone = cores.clone();
                                    let pname = profile_name.clone();
                                    let irc_channel = channel.clone();
                                    let users_to_probe = users.clone();
                                    
                                    // Get our nick to avoid probing ourselves
                                    let our_nick = state_handle.read()
                                        .servers.get(&profile_name)
                                        .map(|s| s.nickname.clone())
                                        .unwrap_or_default();
                                    
                                    spawn(async move {
                                        let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                        let mgr = manager.read().await;
                                        
                                        // Check if this channel maps to an NSC channel
                                        let is_nsc_channel = should_probe || mgr.get_channel_by_irc(&irc_channel).await.is_some();
                                        
                                        if is_nsc_channel {
                                            // Clean the user list and record pending probes
                                            let clean_users: Vec<String> = users_to_probe.iter()
                                                .map(|u| u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~').to_string())
                                                .filter(|u| *u != our_nick)
                                                .collect();
                                            
                                            // Record pending probes so we can associate responses with this channel
                                            mgr.record_pending_probes(&clean_users, &irc_channel).await;
                                            let nsc_probe = mgr.create_probe_ctcp();
                                            drop(mgr);
                                            
                                            if !nsc_probe.is_empty() {
                                                if let Some(core) = cores_clone.read().get(&pname) {
                                                    for clean_user in clean_users {
                                                        log::info!("Probing user {} in channel {} (NSC-related)", clean_user, irc_channel);
                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                            target: clean_user.to_string(),
                                                            message: nsc_probe.clone(),
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                                _ => {}
                            }
                            
                            let mut state_mut = state_handle.write();
                            let profiles_read = profiles.read();
                            apply_event_with_config(&mut state_mut, &profiles_read, &profile_name, event.clone());
                            
                            // Update profile_status signal based on the event
                            if matches!(event, IrcEvent::Connected { .. }) {
                                status_handle.write().insert(profile_name.clone(), ConnectionStatus::Connected);
                                
                                // Auto-rejoin NSC discovery channels when IRC connects
                                let profile_for_nsc = profile_name.clone();
                                spawn(async move {
                                    // Small delay to let the connection stabilize
                                    Delay::new(Duration::from_millis(500)).await;
                                    
                                    let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                    let mgr = manager.read().await;
                                    let channels = mgr.list_channels().await;
                                    drop(mgr);
                                    
                                    // Join each NSC channel's IRC discovery channel
                                    for channel in channels {
                                        if !channel.irc_channel.is_empty() && channel.network == profile_for_nsc {
                                            if let Some(core) = cores.read().get(&profile_for_nsc) {
                                                log::info!("Auto-rejoining NSC discovery channel: {} for '{}'", 
                                                    channel.irc_channel, channel.name);
                                                let cmd_tx = core.cmd_tx.clone();
                                                let join_channel = channel.irc_channel.clone();
                                                let profile_for_join = profile_for_nsc.clone();
                                                spawn(async move {
                                                    if let Err(e) = cmd_tx.send(irc_client::IrcCommandEvent::Join {
                                                        channel: join_channel.clone(),
                                                    }).await {
                                                        log::error!(
                                                            "Failed to auto-rejoin NSC discovery channel {} on profile {}: {}",
                                                            join_channel,
                                                            profile_for_join,
                                                            e
                                                        );
                                                        return;
                                                    }
                                                    log::info!(
                                                        "Queued auto-rejoin JOIN for NSC discovery channel {} on profile {}",
                                                        join_channel,
                                                        profile_for_join
                                                    );

                                                    // Retry once in case the first JOIN races with post-connect server readiness.
                                                    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                                                    if let Err(e) = cmd_tx.send(irc_client::IrcCommandEvent::Join {
                                                        channel: join_channel.clone(),
                                                    }).await {
                                                        log::warn!(
                                                            "NSC auto-rejoin retry failed for channel {} on profile {}: {}",
                                                            join_channel,
                                                            profile_for_join,
                                                            e
                                                        );
                                                    } else {
                                                        log::info!(
                                                            "Queued NSC auto-rejoin retry JOIN for channel {} on profile {}",
                                                            join_channel,
                                                            profile_for_join
                                                        );
                                                    }
                                                });
                                            }
                                        }
                                    }
                                });
                            } else if matches!(event, IrcEvent::Disconnected) {
                                status_handle.write().insert(profile_name.clone(), ConnectionStatus::Disconnected);
                            }
                            drop(state_mut);
                            
                            events_processed += 1;
                            if events_processed >= MAX_EVENTS_PER_ITERATION {
                                break; // Yield to let UI update
                            }
                        }
                    } else {
                        drop(cores_read);
                    }
                }

                // Small delay to yield control but process events quickly
                Delay::new(Duration::from_millis(16)).await; // ~60fps
            }
        });
    });

    // Auto-connect to profiles on startup
    {
        use_effect(move || {
            for profile in profiles.read().iter() {
                if profile.auto_connect {
                    let prof_name = profile.name.clone();
                    let server_state = state.read().servers.get(&prof_name).cloned();
                    
                    if let Some(ss) = server_state {
                        if ss.status == ConnectionStatus::Disconnected {
                            connect_profile(
                                ss.server.clone(),
                                ss.nickname.clone(),
                                ss.current_channel.clone(),
                                profile.use_tls,
                                profile.hide_host,
                                prof_name,
                                state,
                                profiles,
                                last_used,
                                profile_status,
                                cores,
                                skip_reconnect,
                                show_server_log,
                            );
                        }
                    }
                }
            }
        });
    }

    rsx! {
        style { "{APP_STYLES}" }

        div {
            style: "display:flex; flex-direction:column; height:100vh; background:var(--bg); color:var(--text); font-family:var(--font); gap:12px; padding:12px;",

            // Combined Header and Profile Bar
            div {
                class: "top-bar",
                div {
                    class: "top-bar-left",
                    h1 { 
                        class: "app-title",
                        "NAIS-client" 
                    }
                    input {
                        class: "profile-search compact",
                        r#type: "text",
                        placeholder: "Search profiles...",
                        value: "{search_input}",
                        oninput: move |evt| {
                            search_input.set(evt.value());
                        },
                    }
                }
                div {
                    class: "top-bar-right",
                    div {
                        class: "status-indicator",
                        if let Some(server_state) = state.read().servers.get(&state.read().active_profile) {
                            match server_state.status {
                                ConnectionStatus::Connected => {
                                    rsx! {
                                        span {
                                            class: "status-dot connected",
                                        }
                                        "Connected"
                                    }
                                }
                                ConnectionStatus::Connecting => {
                                    rsx! {
                                        span {
                                            class: "status-dot connecting",
                                        }
                                        "Connecting"
                                    }
                                }
                                ConnectionStatus::Disconnected => {
                                    rsx! {
                                        span {
                                            class: "status-dot disconnected",
                                        }
                                        "Disconnected"
                                    }
                                }
                            }
                        }
                    }
                    button {
                        class: "compact-btn",
                        onclick: move |_| {
                            show_new_profile.set(true);
                        },
                        "New"
                    }
                    button {
                        class: "compact-btn",
                        onclick: move |_| {
                            show_import_modal.set(true);
                        },
                        "Import"
                    }
                    button {
                        class: "compact-btn settings-btn",
                        onclick: move |_| {
                            // Load current profile settings into the modal
                            let active = state.read().active_profile.clone();
                            if let Some(profile) = profiles.read().iter().find(|p| p.name == active) {
                                settings_enable_logging.set(profile.enable_logging);
                                settings_scrollback_limit.set(profile.scrollback_limit);
                                settings_log_buffer_size.set(profile.log_buffer_size);
                            }
                            settings_default_nick.set(default_nick.read().clone().unwrap_or_default());
                            show_settings.set(true);
                        },
                        "⚙ Settings"
                    }
                    // Voice Channel button
                    {
                        let is_hosting = matches!(voice_state(), crate::voice_chat::VoiceState::Hosting);
                        let is_active = matches!(voice_state(), crate::voice_chat::VoiceState::Active { .. });
                        let is_in_call = !matches!(voice_state(), crate::voice_chat::VoiceState::Idle);
                        
                        rsx! {
                            button {
                                class: if is_in_call { "compact-btn voice-btn active" } else { "compact-btn voice-btn" },
                                onclick: move |_| {
                                    let current_state = voice_state();
                                    match current_state {
                                        crate::voice_chat::VoiceState::Idle => {
                                            // Start hosting a voice channel
                                            let session_id = crate::voice_chat::VoiceChatManager::generate_session_id();
                                            let config = crate::voice_chat::VoiceConfig::default();
                                            let muted_arc_clone = voice_muted_arc.read().clone();
                                            
                                            if let Some((external_ip, port, evt_rx, stop_flag, peer_tx)) = crate::voice_chat::start_voice_listener(config, muted_arc_clone) {
                                                voice_external_ip.set(external_ip.clone());
                                                voice_local_port.set(port);
                                                voice_event_rx.set(Some(evt_rx));
                                                voice_stop_flag.set(Some(stop_flag));
                                                voice_peer_addr_tx.set(Some(peer_tx));
                                                voice_state.set(crate::voice_chat::VoiceState::Hosting);
                                                voice_session_id.set(Some(session_id));
                                                voice_current_peer.set(None);
                                                log::info!("Voice channel started at {}:{}", external_ip, port);
                                            } else {
                                                log::error!("Failed to start voice listener");
                                            }
                                        }
                                        crate::voice_chat::VoiceState::Hosting | crate::voice_chat::VoiceState::Active { .. } => {
                                            // Stop the voice channel
                                            if let Some(stop_flag) = voice_stop_flag() {
                                                if let Ok(mut stopped) = stop_flag.lock() {
                                                    *stopped = true;
                                                }
                                            }
                                            voice_state.set(crate::voice_chat::VoiceState::Idle);
                                            voice_current_peer.set(None);
                                            voice_session_id.set(None);
                                            voice_event_rx.set(None);
                                            voice_stop_flag.set(None);
                                            log::info!("Voice channel stopped");
                                        }
                                        _ => {}
                                    }
                                },
                                if is_hosting {
                                    "📞 End Channel"
                                } else if is_active {
                                    "📞 In Call"
                                } else {
                                    "📞 Voice"
                                }
                            }
                        }
                    }
                    // Nais Secure Channel button
                    button {
                        class: "compact-btn nsc-btn",
                        onclick: move |_| {
                            show_new_nsc_modal.set(true);
                        },
                        "🔒 Secure"
                    }
                }
            }

            // Profile tabs
            div {
                class: "profile-strip",
                    { 
                        let profile_list: Vec<_> = profiles.read().iter().cloned().collect();
                        rsx! {
                            for (_idx, prof) in profile_list.into_iter().enumerate() {
                                {
                                    let prof_name = prof.name.clone();
                                    let prof_name_for_menu = prof.name.clone();
                                    let prof_name_for_connect = prof.name.clone();
                                    let prof_name_for_edit = prof.name.clone();
                                    let prof_name_for_log_toggle = prof.name.clone();
                                    let prof_name_for_browse = prof.name.clone();
                                    let prof_name_for_delete = prof.name.clone();
                                    
                                    let is_active = prof.name == state.read().active_profile;
                                    let status = profile_status.read().get(&prof.name).cloned()
                                        .unwrap_or(ConnectionStatus::Disconnected);
                                    let status_class = match status {
                                        ConnectionStatus::Connected => "connected",
                                        ConnectionStatus::Connecting => "connecting",
                                        ConnectionStatus::Disconnected => "disconnected",
                                    };
                                    let menu_open = profile_menu_open.read().as_ref().map(|m| m == &prof.name).unwrap_or(false);

                                    rsx! {
                                        div {
                                            key: "{prof.name}",
                                            style: "position:relative;",
                                            button {
                                                class: if is_active { "pill active" } else { "pill" },
                                                onclick: move |_| {
                                                    state.write().active_profile = prof_name.clone();
                                                    profile_menu_open.set(None);
                                                    // Focus the chat input
                                                    let _ = document::eval(
                                                        r#"
                                                        const input = document.getElementById('chat-input');
                                                        if (input) input.focus();
                                                        "#
                                                    );
                                                },
                                                div {
                                                    class: "profile-name",
                                                    span {
                                                        class: "profile-status",
                                                        class: "{status_class}",
                                                        title: "{status:?}",
                                                    }
                                                    "{prof.name}"
                                                    button {
                                                        class: "menu-button",
                                                        onclick: move |evt| {
                                                            evt.stop_propagation();
                                                            if menu_open {
                                                                profile_menu_open.set(None);
                                                            } else {
                                                                profile_menu_open.set(Some(prof_name_for_menu.clone()));
                                                            }
                                                        },
                                                        "⚙"
                                                    }
                                                }
                                            }

                                    if menu_open {
                                        div {
                                            class: "menu-panel",
                                            onclick: move |evt| {
                                                evt.stop_propagation();
                                            },
                                            button {
                                                class: "menu-item",
                                                onclick: move |_| {
                                                    let prof_name_clone = prof_name_for_connect.clone();
                                                    let server_state = state.read().servers.get(&prof_name_clone).cloned();
                                                    let profile_data = profiles.read().iter().find(|p| p.name == prof_name_clone).cloned();
                                                    if let (Some(ss), Some(prof)) = (server_state, profile_data) {
                                                        connect_profile(
                                                            ss.server.clone(),
                                                            ss.nickname.clone(),
                                                            ss.current_channel.clone(),
                                                            prof.use_tls,
                                                            prof.hide_host,
                                                            prof_name_clone.clone(),
                                                            state,
                                                            profiles,
                                                            last_used,
                                                            profile_status,
                                                            cores,
                                                            skip_reconnect,
                                                            show_server_log,
                                                        );
                                                    }
                                                    profile_menu_open.set(None);
                                                },
                                                "Connect"
                                            }
                                            button {
                                                class: "menu-item",
                                                onclick: move |_| {
                                                    state.write().active_profile = prof_name_for_edit.clone();
                                                    
                                                    // Get the current profile from profiles list
                                                    let profs = profiles.read();
                                                    if let Some(profile) = profs.iter().find(|p| p.name == prof_name_for_edit) {
                                                        edit_name_input.set(profile.name.clone());
                                                        edit_server_input.set(profile.server.clone());
                                                        edit_nick_input.set(profile.nickname.clone());
                                                        edit_channel_input.set(profile.channel.clone());
                                                        edit_tls_input.set(profile.use_tls);
                                                        edit_auto_connect_input.set(profile.auto_connect);
                                                        edit_hide_host_input.set(profile.hide_host);
                                                    }
                                                    drop(profs);
                                                    
                                                    show_edit_profile.set(true);
                                                    profile_menu_open.set(None);
                                                },
                                                "Edit"
                                            }
                                            // Server Log toggle - only available in advanced mode
                                            if *settings_show_advanced.read() {
                                            button {
                                                class: "menu-item",
                                                onclick: move |_| {
                                                    let current = show_server_log.read().get(&prof_name_for_log_toggle).copied().unwrap_or(false);
                                                    show_server_log.write().insert(prof_name_for_log_toggle.clone(), !current);
                                                    
                                                    // If we're turning off the log and currently viewing it, switch to first channel
                                                    if current {
                                                        let active = state.read().active_profile.clone();
                                                        if active == prof_name_for_log_toggle {
                                                            let should_switch = state.read().servers.get(&active)
                                                                .map(|s| s.current_channel == "Server Log")
                                                                .unwrap_or(false);
                                                            
                                                            if should_switch {
                                                                let first_channel = state.read().servers.get(&active)
                                                                    .and_then(|s| s.channels.first().cloned())
                                                                    .unwrap_or_default();
                                                                
                                                                if let Some(server) = state.write().servers.get_mut(&active) {
                                                                    server.current_channel = first_channel;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    profile_menu_open.set(None);
                                                },
                                                {
                                                    let is_visible = show_server_log.read().get(&prof_name_for_log_toggle).copied().unwrap_or(false);
                                                    if is_visible { "Hide Server Log" } else { "Show Server Log" }
                                                }
                                            }
                                            }
                                            button {
                                                class: "menu-item",
                                                onclick: move |_| {
                                                    let prof_name_clone = prof_name_for_browse.clone();
                                                    let status = profile_status.read().get(&prof_name_clone).cloned()
                                                        .unwrap_or(ConnectionStatus::Disconnected);
                                                    
                                                    if status != ConnectionStatus::Connected {
                                                        return;
                                                    }
                                                    
                                                    // Check if we have a cached channel list
                                                    let state_read = state.read();
                                                    let cached_list = state_read.servers.get(&prof_name_clone)
                                                        .map(|s| s.cached_channel_list.clone())
                                                        .unwrap_or_default();
                                                    drop(state_read);
                                                    
                                                    if !cached_list.is_empty() {
                                                        // Use cached list
                                                        channel_list.set(cached_list);
                                                        list_loading.set(false);
                                                    } else {
                                                        // No cache, fetch new list
                                                        channel_list.set(Vec::new());
                                                        list_loading.set(true);
                                                        
                                                        // Send LIST command
                                                        let cores_read = cores.read();
                                                        if let Some(handle) = cores_read.get(&prof_name_clone) {
                                                            let cmd_tx = handle.cmd_tx.clone();
                                                            drop(cores_read);
                                                            spawn(async move {
                                                                let _ = cmd_tx.send(irc_client::IrcCommandEvent::List).await;
                                                            });
                                                        } else {
                                                            drop(cores_read);
                                                        }
                                                    }
                                                    
                                                    show_channel_browser.set(true);
                                                    profile_menu_open.set(None);
                                                },
                                                "Browse Channels"
                                            }
                                            button {
                                                class: "menu-item",
                                                onclick: move |_| {
                                                    let idx_opt = profiles.read().iter().position(|p| &p.name == &prof_name_for_delete);
                                                    if let Some(idx) = idx_opt {
                                                        let prof_to_remove = profiles.read()[idx].clone();
                                                        
                                                        let mut profs = profiles.write();
                                                        profs.remove(idx);
                                                        drop(profs);

                                                        let mut state_mut = state.write();
                                                        state_mut.servers.remove(&prof_to_remove.name);
                                                        if state_mut.active_profile == prof_to_remove.name {
                                                            state_mut.active_profile = profiles.read().first()
                                                                .map(|p| p.name.clone())
                                                                .unwrap_or_default();
                                                        }
                                                        drop(state_mut);

                                                        let store = profile::ProfileStore {
                                                            profiles: profiles.read().clone(),
                                                            last_used: last_used.read().clone(),
                                                            default_nickname: default_nick.read().clone(),
                                                            show_timestamps: *settings_show_timestamps.read(),
                                                            show_advanced: *settings_show_advanced.read(),
                                                        };
                                                        let _ = profile::save_store(&store);
                                                        profile_menu_open.set(None);
                                                    }
                                                },
                                                "Delete"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }

            // Body: 3-column grid
            {
                let grid_cols = if channels_collapsed() { "60px" } else { "200px" };
                let userlist_cols = if userlist_collapsed() { "40px" } else { "200px" };
                rsx! {
                    div {
                        class: "body",
                        style: "display:grid; grid-template-columns:{grid_cols} 1fr {userlist_cols}; gap:12px; flex:1; overflow:hidden;",

                        // Channels sidebar
                        div {
                            class: if channels_collapsed() { "channels collapsed" } else { "channels" },
                    div {
                        class: "section-title",
                        style: "display:flex; justify-content:space-between; align-items:center;",
                        if !channels_collapsed() {
                            "Channels"
                        }
                        button {
                            class: "collapse-btn",
                            onclick: move |_| {
                                channels_collapsed.set(!channels_collapsed());
                            },
                            if channels_collapsed() { "»" } else { "«" }
                        }
                    }
                    ul {
                        // Server Log channel - show if enabled for this profile and advanced mode is on
                        {
                            let active_profile = state.read().active_profile.clone();
                            let log_visible = show_server_log.read().get(&active_profile).copied().unwrap_or(false);
                            let advanced_on = *settings_show_advanced.read();
                            
                            if log_visible && advanced_on {
                                Some(rsx! {
                                    li {
                                        button {
                                            class: if state.read().servers
                                                .get(&state.read().active_profile)
                                                .map(|s| s.current_channel == "Server Log")
                                                .unwrap_or(false)
                                            { "row active" } else { "row" },
                                            onclick: move |_| {
                                                let active = state.read().active_profile.clone();
                                                if let Some(server) = state.write().servers.get_mut(&active) {
                                                    server.current_channel = "Server Log".to_string();
                                                }
                                                // Force scroll to bottom on channel change
                                                force_scroll_to_bottom.set(true);
                                            },
                                            title: "Server Log",
                                            if channels_collapsed() {
                                                div {
                                                    class: "channel-icon",
                                                    style: "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);",
                                                    "📋"
                                                }
                                            } else {
                                                "📋 Server Log"
                                            }
                                        }
                                    }
                                })
                            } else {
                                None
                            }
                        }
                        
                        // Server channel - shows server-level IRC communication (advanced only)
                        {
                            let advanced_on = *settings_show_advanced.read();
                            
                            if advanced_on {
                                Some(rsx! {
                                    li {
                                        button {
                                            class: if state.read().servers
                                                .get(&state.read().active_profile)
                                                .map(|s| s.current_channel == "Server")
                                                .unwrap_or(false)
                                            { "row active" } else { "row" },
                                            onclick: move |_| {
                                                let active = state.read().active_profile.clone();
                                                if let Some(server) = state.write().servers.get_mut(&active) {
                                                    server.current_channel = "Server".to_string();
                                                }
                                                // Force scroll to bottom on channel change
                                                force_scroll_to_bottom.set(true);
                                            },
                                            title: "Server",
                                            if channels_collapsed() {
                                                div {
                                                    class: "channel-icon",
                                                    style: "background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%);",
                                                    "🖥️"
                                                }
                                            } else {
                                                "🖥️ Server"
                                            }
                                        }
                                    }
                                })
                            } else {
                                None
                            }
                        }
                        
                        // Regular channels
                        {
                            let advanced_on = *settings_show_advanced.read();
                            let channels: Vec<String> = state.read()
                                .servers
                                .get(&state.read().active_profile)
                                .map(|s| s.channels.clone())
                                .unwrap_or_default()
                                .into_iter()
                                // Hide #nais-* IRC channels when Advanced Features is off
                                .filter(|c| advanced_on || !c.starts_with("#nais-"))
                                .collect();
                            
                            let topics_map = state.read()
                                .servers
                                .get(&state.read().active_profile)
                                .map(|s| s.topics_by_channel.clone())
                                .unwrap_or_default();
                            
                            rsx! {
                                for (idx, channel) in channels.into_iter().enumerate() {
                                    {
                                        let channel_clone = channel.clone();
                                        let first_letter = channel.chars()
                                            .find(|c| c.is_alphanumeric())
                                            .unwrap_or('#')
                                            .to_uppercase()
                                            .to_string();
                                        
                                        // Generate a color based on the channel name
                                        let hash = channel.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
                                        let hue = hash % 360;
                                        let color = format!("hsl({}, 65%, 55%)", hue);
                                        
                                        // Check for custom icon in topic
                                        let custom_icon_url = topics_map.get(&channel)
                                            .and_then(|topic| extract_icon_from_topic(topic));
                                        
                                        rsx! {
                                            li {
                                                key: "{idx}",
                                                button {
                                                    class: if state.read().servers
                                                        .get(&state.read().active_profile)
                                                        .map(|s| s.current_channel == channel)
                                                        .unwrap_or(false)
                                                    { "row active" } else { "row" },
                                                    onclick: move |_| {
                                                        let active = state.read().active_profile.clone();
                                                        if let Some(server) = state.write().servers.get_mut(&active) {
                                                            server.current_channel = channel_clone.clone();
                                                        }
                                                        // Clear NSC channel selection
                                                        nsc_current_channel.set(None);
                                                        // Reset virtual scroll to show only recent messages
                                                        visible_message_range.set((0, 100));
                                                        // Force scroll to bottom on channel change
                                                        force_scroll_to_bottom.set(true);
                                                        // Focus the chat input
                                                        let _ = document::eval(
                                                            r#"
                                                            const input = document.getElementById('chat-input');
                                                            if (input) input.focus();
                                                            "#
                                                        );
                                                    },
                                                    title: "{channel}",
                                                    if channels_collapsed() {
                                                        if let Some(icon_url) = custom_icon_url {
                                                            div {
                                                                class: "channel-icon",
                                                                style: "background: {color};",
                                                                img {
                                                                    src: "{icon_url}",
                                                                    class: "channel-icon-img",
                                                                    alt: "{channel}",
                                                                }
                                                            }
                                                        } else {
                                                            div {
                                                                class: "channel-icon",
                                                                style: "background: {color};",
                                                                "{first_letter}"
                                                            }
                                                        }
                                                    } else {
                                                        "{channel}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // NSC Secure Channels section
                        if !nsc_channels.read().is_empty() {
                            li {
                                style: "margin-top: 12px; padding-top: 8px; border-top: 1px solid var(--border);",
                                if !channels_collapsed() {
                                    div {
                                        style: "font-size: 11px; color: var(--muted); padding: 4px 8px; text-transform: uppercase; letter-spacing: 0.5px;",
                                        "🔒 Secure Channels"
                                    }
                                }
                            }
                            for channel in nsc_channels.read().iter().cloned() {
                                {
                                    let channel_id = channel.channel_id.clone();
                                    let channel_id_click = channel.channel_id.clone();
                                    let channel_id_load = channel.channel_id.clone();
                                    let channel_name = channel.name.clone();
                                    let is_active = nsc_current_channel.read().as_ref() == Some(&channel_id);
                                    
                                    rsx! {
                                        li {
                                            key: "{channel_id}",
                                            button {
                                                class: if is_active { "row active" } else { "row" },
                                                onclick: move |_| {
                                                    // Select this NSC channel
                                                    nsc_current_channel.set(Some(channel_id_click.clone()));
                                                    // Clear IRC channel selection
                                                    let active = state.read().active_profile.clone();
                                                    if let Some(server) = state.write().servers.get_mut(&active) {
                                                        server.current_channel = String::new();
                                                    }
                                                    
                                                    // Load stored messages for this channel if not already loaded
                                                    let channel_id_inner = channel_id_load.clone();
                                                    {
                                                        let current_msgs = nsc_messages.read();
                                                        if current_msgs.get(&channel_id_inner).map(|m| m.is_empty()).unwrap_or(true) {
                                                            drop(current_msgs);
                                                            // Load from storage asynchronously
                                                            spawn(async move {
                                                                let stored = crate::nsc_manager::load_messages_async(&channel_id_inner).await;
                                                                if !stored.is_empty() {
                                                                    let mut msgs = nsc_messages.write();
                                                                    let channel_msgs = msgs.entry(channel_id_inner).or_insert_with(Vec::new);
                                                                    for m in stored {
                                                                        channel_msgs.push((m.timestamp, m.sender, m.text));
                                                                    }
                                                                }
                                                            });
                                                        }
                                                    }
                                                    
                                                    // Reset virtual scroll to show only recent messages
                                                    visible_message_range.set((0, 100));
                                                    force_scroll_to_bottom.set(true);
                                                    // Focus the chat input
                                                    let _ = document::eval(
                                                        r#"
                                                        const input = document.getElementById('chat-input');
                                                        if (input) input.focus();
                                                        "#
                                                    );
                                                },
                                                title: "{channel_name}",
                                                if channels_collapsed() {
                                                    div {
                                                        class: "channel-icon",
                                                        style: "background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);",
                                                        "🔒"
                                                    }
                                                } else {
                                                    div {
                                                        style: "display: flex; align-items: center; gap: 6px;",
                                                        span { "🔒" }
                                                        span { "{channel_name}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Chat area
                div {
                    class: "chat",
                    div {
                        class: "chat-header",
                        div {
                            class: "room",
                            // Show NSC channel name or IRC channel
                            {
                                let nsc_ch = nsc_current_channel.read().clone();
                                if let Some(ref nsc_id) = nsc_ch {
                                    // Find the NSC channel name
                                    let name = nsc_channels.read().iter()
                                        .find(|c| &c.channel_id == nsc_id)
                                        .map(|c| format!("🔒 {}", c.name))
                                        .unwrap_or_else(|| "Unknown Secure Channel".to_string());
                                    rsx! { "{name}" }
                                } else {
                                    let ch = state.read().servers
                                        .get(&state.read().active_profile)
                                        .map(|s| s.current_channel.clone())
                                        .unwrap_or_else(|| "No channel".to_string());
                                    rsx! { "{ch}" }
                                }
                            }
                        }
                        // Topic inline with channel name
                        {
                            let current_channel = state.read().servers
                                .get(&state.read().active_profile)
                                .map(|s| s.current_channel.clone())
                                .unwrap_or_default();
                            
                            let topic = state.read().servers
                                .get(&state.read().active_profile)
                                .and_then(|s| s.topics_by_channel.get(&current_channel).cloned())
                                .unwrap_or_default();
                            
                            let show_topic = !topic.is_empty() && current_channel != "Server Log";
                            let is_collapsed = topic_collapsed();
                            
                            rsx! {
                                if show_topic {
                                    div {
                                        class: "topic-banner",
                                        div {
                                            class: "topic-icon clickable",
                                            onclick: move |_| {
                                                topic_collapsed.set(!topic_collapsed());
                                            },
                                            "📌"
                                        }
                                        if !is_collapsed {
                                            div {
                                                class: "topic-text",
                                                "{topic}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div {
                        class: "messages",
                        // CSS optimization: hint that content will scroll for GPU acceleration
                        style: "will-change: scroll-position; contain: content;",
                        onscroll: move |_evt| {
                            // Detect if user is at the bottom of scroll
                            spawn(async move {
                                if let Ok(result) = document::eval(
                                    r#"
                                    const messagesDiv = document.querySelector('.messages');
                                    if (messagesDiv) {
                                        const isAtBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop <= messagesDiv.clientHeight + 5;
                                        dioxus.send(isAtBottom);
                                    }
                                    "#
                                ).recv::<serde_json::Value>().await {
                                    if let Some(is_bottom) = result.as_bool() {
                                        is_at_bottom.set(is_bottom);
                                    }
                                }
                            });
                        },
                        {
                            // Check if we're in an NSC channel first
                            let nsc_ch = nsc_current_channel.read().clone();
                            
                            if let Some(ref nsc_id) = nsc_ch {
                                // Display NSC channel messages
                                let channel_name = nsc_channels.read().iter()
                                    .find(|c| &c.channel_id == nsc_id)
                                    .map(|c| c.name.clone())
                                    .unwrap_or_else(|| "Secure Channel".to_string());
                                
                                let messages = nsc_messages.read()
                                    .get(nsc_id)
                                    .cloned()
                                    .unwrap_or_default();
                                
                                rsx! {
                                    if messages.is_empty() {
                                        div {
                                            class: "message system",
                                            div {
                                                class: "system-text",
                                                style: "text-align: center; padding: 40px 20px;",
                                                div {
                                                    style: "font-size: 48px; margin-bottom: 16px;",
                                                    "🔒"
                                                }
                                                div {
                                                    style: "font-weight: 600; font-size: 16px; margin-bottom: 8px;",
                                                    "Welcome to {channel_name}"
                                                }
                                                div {
                                                    style: "color: var(--muted); font-size: 13px; max-width: 400px; margin: 0 auto;",
                                                    "This is an end-to-end encrypted channel. Messages are sent directly peer-to-peer and never pass through IRC servers."
                                                }
                                                div {
                                                    style: "margin-top: 20px; padding: 12px; background: rgba(99, 102, 241, 0.1); border-radius: 8px; font-size: 12px;",
                                                    div {
                                                        style: "color: var(--muted); margin-bottom: 4px;",
                                                        "To invite someone, share your identity fingerprint:"
                                                    }
                                                    div {
                                                        style: "font-family: monospace; word-break: break-all; color: var(--accent);",
                                                        "{nsc_fingerprint}"
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        for (i, (_timestamp, sender, text)) in messages.iter().enumerate() {
                                            div {
                                                key: "{i}",
                                                class: "message",
                                                span {
                                                    class: "username",
                                                    style: "color: var(--accent);",
                                                    "{sender}"
                                                }
                                                span {
                                                    class: "text",
                                                    "{text}"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Read state once and extract only what we need for the current view
                                let state_read = state.read();
                                let active_profile = state_read.active_profile.clone();
                                let server_state = state_read.servers.get(&active_profile);
                                
                                let current_channel = server_state
                                    .map(|s| s.current_channel.clone())
                                    .unwrap_or_default();
                                
                                if current_channel == "Server Log" {
                                // Clone only log entries (typically small)
                                let log_entries = server_state
                                    .map(|s| s.connection_log.clone())
                                    .unwrap_or_default();
                                drop(state_read);
                                
                                rsx! {
                                    if log_entries.is_empty() {
                                        div {
                                            class: "message system",
                                            div {
                                                class: "system-text",
                                                "No connection events logged yet. Click Connect to start."
                                            }
                                        }
                                    } else {
                                        for (i, log_entry) in log_entries.iter().enumerate() {
                                            div {
                                                key: "{i}",
                                                class: "message system",
                                                div {
                                                    class: "system-text",
                                                    style: "font-family: monospace; font-size: 12px;",
                                                    "{log_entry}"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if current_channel == "Server" {
                                // Clone and filter in one pass - only server messages
                                let filtered: Vec<_> = server_state
                                    .map(|s| s.messages.iter()
                                        .filter(|m| {
                                            m.channel == "Server" || 
                                            (m.is_system && 
                                             !m.channel.starts_with('#') && 
                                             !m.channel.starts_with('&') && 
                                             !m.channel.starts_with('+') && 
                                             !m.channel.starts_with('!'))
                                        })
                                        .cloned()
                                        .collect())
                                    .unwrap_or_default();
                                drop(state_read);
                                
                                rsx! {
                                    if filtered.is_empty() {
                                        div {
                                            class: "message system",
                                            div {
                                                class: "system-text",
                                                "No server messages yet. Connect to see MOTD and server notices."
                                            }
                                        }
                                    } else {
                                        for msg in filtered {
                                            {
                                                let id = msg.id;
                                                message_view(msg, id)
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Clone and filter in one pass - only current channel messages
                                // Performance optimization: only render the last N messages
                                const MAX_VISIBLE_MESSAGES: usize = 150;
                                
                                let all_filtered: Vec<_> = server_state
                                    .map(|s| s.messages.iter()
                                        .filter(|m| m.channel == current_channel)
                                        .cloned()
                                        .collect())
                                    .unwrap_or_default();
                                drop(state_read);
                                
                                let total_count = all_filtered.len();
                                let (visible_start, _) = *visible_message_range.read();
                                
                                // Calculate start index: show from visible_start or from (total - MAX) if not expanded
                                let start_idx = if visible_start > 0 {
                                    0 // User wants to see older messages
                                } else if total_count > MAX_VISIBLE_MESSAGES {
                                    total_count - MAX_VISIBLE_MESSAGES
                                } else {
                                    0
                                };
                                
                                let visible_messages: Vec<_> = all_filtered.into_iter()
                                    .skip(start_idx)
                                    .collect();
                                
                                let hidden_count = start_idx;
                                
                                rsx! {
                                    if hidden_count > 0 {
                                        div {
                                            class: "message system",
                                            style: "text-align: center; cursor: pointer;",
                                            onclick: move |_| {
                                                // Expand to show all messages
                                                visible_message_range.set((1, 0));
                                            },
                                            div {
                                                class: "system-text",
                                                style: "color: var(--accent);",
                                                "⬆ Load {hidden_count} earlier messages"
                                            }
                                        }
                                    }
                                    for msg in visible_messages {
                                        {
                                            let id = msg.id;
                                            message_view(msg, id)
                                        }
                                    }
                                }
                            }
                            }
                        }
                    }
                }

                // Who sidebar
                div {
                    class: if userlist_collapsed() { "who collapsed" } else { "who" },
                    {
                        // Check if we're viewing an NSC channel first
                        let nsc_ch = nsc_current_channel.read().clone();
                        
                        if let Some(ref _nsc_channel_id) = nsc_ch {
                            // Show NSC channel members
                            let members = nsc_channel_members.read();
                            
                            rsx! {
                                div {
                                    class: "section-title",
                                    style: "display:flex; justify-content:space-between; align-items:center; color: var(--accent);",
                                    if !userlist_collapsed() {
                                        "🔒 Secure Members — {members.len()}"
                                    }
                                    button {
                                        class: "collapse-btn",
                                        onclick: move |_| {
                                            userlist_collapsed.set(!userlist_collapsed());
                                        },
                                        if userlist_collapsed() { "‹" } else { "›" }
                                    }
                                }
                                if !userlist_collapsed() {
                                    ul {
                                        if members.is_empty() {
                                            li {
                                                div {
                                                    class: "row user-row",
                                                    style: "opacity: 0.5; font-style: italic;",
                                                    "Loading members..."
                                                }
                                            }
                                        } else {
                                            for member in members.iter() {
                                                li {
                                                    div {
                                                        class: "row user-row",
                                                        style: "display: flex; align-items: center;",
                                                        if member.is_owner {
                                                            span {
                                                                style: "color: #FFD700; margin-right: 6px; font-weight: bold;",
                                                                "★"
                                                            }
                                                        }
                                                        span {
                                                            style: if member.is_self { "color: var(--accent); opacity: 0.7;" } else { "color: var(--fg);" },
                                                            "{member.display_name}"
                                                            if member.is_self {
                                                                " (you)"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                        let current_channel = state.read().servers
                            .get(&state.read().active_profile)
                            .map(|s| s.current_channel.clone())
                            .unwrap_or_default();

                        // Check if this is a PM channel (doesn't start with channel prefixes)
                        let is_pm_channel = !current_channel.is_empty() 
                            && !current_channel.starts_with('#') 
                            && !current_channel.starts_with('&') 
                            && !current_channel.starts_with('+') 
                            && !current_channel.starts_with('!')
                            && current_channel != "Server Log";
                        
                        if current_channel == "Server Log" {
                            // Show connection info instead of users
                            rsx! {
                                div {
                                    class: "section-title",
                                    style: "display:flex; justify-content:space-between; align-items:center;",
                                    if !userlist_collapsed() {
                                        "Connection Info"
                                    }
                                    button {
                                        class: "collapse-btn",
                                        onclick: move |_| {
                                            userlist_collapsed.set(!userlist_collapsed());
                                        },
                                        if userlist_collapsed() { "‹" } else { "›" }
                                    }
                                }
                                if !userlist_collapsed() {
                                    div {
                                        style: "padding:12px; font-size:12px;",
                                        {
                                            let server_state = state.read().servers.get(&state.read().active_profile).cloned();
                                        if let Some(ss) = server_state {
                                            rsx! {
                                                div { style: "margin-bottom:8px;", strong { "Server:" } }
                                                div { style: "margin-bottom:12px; word-break:break-all;", "{ss.server}" }
                                                div { style: "margin-bottom:8px;", strong { "Nickname:" } }
                                                div { style: "margin-bottom:12px;", "{ss.nickname}" }
                                                div { style: "margin-bottom:8px;", strong { "Status:" } }
                                                div {
                                                    match ss.status {
                                                        irc_client::ConnectionStatus::Connected => "✓ Connected",
                                                        irc_client::ConnectionStatus::Connecting => "⋯ Connecting",
                                                        irc_client::ConnectionStatus::Disconnected => "✗ Disconnected",
                                                    }
                                                }
                                            }
                                        } else {
                                            rsx! { div { "No info" } }
                                        }
                                        }
                                    }
                                }
                            }
                        } else if is_pm_channel {
                            // Show PM participants (you and the other person)
                            let my_nick = state.read().servers
                                .get(&state.read().active_profile)
                                .map(|s| s.nickname.clone())
                                .unwrap_or_default();
                            let other_nick = current_channel.clone();
                            
                            rsx! {
                                div {
                                    class: "section-title",
                                    style: "display:flex; justify-content:space-between; align-items:center; color: var(--status-connected);",
                                    if !userlist_collapsed() {
                                        "Conversation — 2"
                                    }
                                    button {
                                        class: "collapse-btn",
                                        onclick: move |_| {
                                            userlist_collapsed.set(!userlist_collapsed());
                                        },
                                        if userlist_collapsed() { "‹" } else { "›" }
                                    }
                                }
                                if !userlist_collapsed() {
                                    ul {
                                        li {
                                            div {
                                                class: "row user-row",
                                                style: "display: flex; align-items: center;",
                                                span {
                                                    style: "color: {username_color(&other_nick)};",
                                                    "{other_nick}"
                                                }
                                            }
                                        }
                                        li {
                                            div {
                                                class: "row user-row",
                                                style: "display: flex; align-items: center;",
                                                span {
                                                    style: "color: {username_color(&my_nick)}; opacity: 0.7;",
                                                    "{my_nick} (you)"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // Show regular users list
                            // IMPORTANT: Capture active_profile here so click handlers use the profile
                            // that was active when the user list was rendered, not when clicked
                            let userlist_profile = state.read().active_profile.clone();
                            
                            // Get raw user list for current channel
                            let raw_users = state.read()
                                .servers
                                .get(&userlist_profile)
                                .and_then(|s| {
                                    s.users_by_channel.get(&current_channel).cloned()
                                })
                                .unwrap_or_default();
                            
                            // Create cache key for this profile+channel
                            let cache_key = format!("{}:{}", userlist_profile, current_channel);
                            
                            // Check if we need to re-sort (compare with cached)
                            let cached = cached_sorted_users.read();
                            let need_resort = cached.get(&cache_key)
                                .map(|sorted| sorted.len() != raw_users.len())
                                .unwrap_or(true);
                            drop(cached);
                            
                            let users = if need_resort {
                                // Sort users: ops (@) first, then voice (+), then regular users
                                let mut sorted = raw_users;
                                sorted.sort_by(|a, b| {
                                    let a_prefix = a.chars().next().unwrap_or(' ');
                                    let b_prefix = b.chars().next().unwrap_or(' ');
                                    
                                    let a_rank = match a_prefix {
                                        '@' => 0, // Ops first
                                        '+' => 1, // Voice second
                                        _ => 2,   // Regular users last
                                    };
                                    let b_rank = match b_prefix {
                                        '@' => 0,
                                        '+' => 1,
                                        _ => 2,
                                    };
                                    
                                    // First compare by rank, then alphabetically
                                    a_rank.cmp(&b_rank).then_with(|| {
                                        let a_name = a.trim_start_matches(['@', '+']);
                                        let b_name = b.trim_start_matches(['@', '+']);
                                        a_name.to_lowercase().cmp(&b_name.to_lowercase())
                                    })
                                });
                                // Update cache with newly sorted list
                                cached_sorted_users.write().insert(cache_key.clone(), sorted.clone());
                                sorted
                            } else {
                                // Use cached sorted list
                                cached_sorted_users.read().get(&cache_key).cloned().unwrap_or_default()
                            };
                            
                            rsx! {
                                div {
                                    class: "section-title",
                                    style: "display:flex; justify-content:space-between; align-items:center; color: var(--status-connected);",
                                    if !userlist_collapsed() {
                                        "Users — {users.len()}"
                                    }
                                    button {
                                        class: "collapse-btn",
                                        onclick: move |_| {
                                            userlist_collapsed.set(!userlist_collapsed());
                                        },
                                        if userlist_collapsed() { "‹" } else { "›" }
                                    }
                                }
                                if !userlist_collapsed() {
                                    ul {
                                        for user in users {
                                        {
                                            let first_char = user.chars().next().unwrap_or(' ');
                                            let (symbol, color, username) = match first_char {
                                                '@' => ("★", "#FFD700", user.trim_start_matches('@')),
                                                '+' => ("◆", "#00CED1", user.trim_start_matches('+')),
                                                _ => ("", "#CCCCCC", user.as_str()),
                                            };
                                            let user_nick = username.to_string();
                                            let menu_key = user_nick.clone();
                                            // Clone userlist_profile for use in click handlers within this iteration
                                            let user_profile = userlist_profile.clone();
                                            let is_menu_open = user_menu_open.read().as_ref() == Some(&menu_key);
                                            
                                            rsx! {
                                                li {
                                                    div {
                                                        class: "row user-row",
                                                        style: "display: flex; align-items: center; justify-content: space-between; position: relative;",
                                                        div {
                                                            style: "display: flex; align-items: center;",
                                                            if !symbol.is_empty() {
                                                                span {
                                                                    style: "color: {color}; margin-right: 6px; font-weight: bold;",
                                                                    "{symbol}"
                                                                }
                                                            }
                                                            span {
                                                                "{username}"
                                                            }
                                                        }
                                                        // Meatball menu button
                                                        div {
                                                            style: "position: relative;",
                                                            button {
                                                                class: "user-menu-btn",
                                                                onclick: {
                                                                    let key = menu_key.clone();
                                                                    move |e: Event<MouseData>| {
                                                                        e.stop_propagation();
                                                                        if user_menu_open.read().as_ref() == Some(&key) {
                                                                            user_menu_open.set(None);
                                                                            ctcp_submenu_open.set(false);
                                                                        } else {
                                                                            user_menu_open.set(Some(key.clone()));
                                                                            ctcp_submenu_open.set(false);
                                                                        }
                                                                    }
                                                                },
                                                                "⋮"
                                                            }
                                                            // Dropdown menu
                                                            if is_menu_open {
                                                                div {
                                                                    class: "user-menu-panel",
                                                                    onclick: move |e: Event<MouseData>| {
                                                                        e.stop_propagation();
                                                                    },
                                                                    // Private Message option
                                                                    button {
                                                                        class: "menu-item",
                                                                        onclick: {
                                                                            let nick = user_nick.clone();
                                                                            let profile_for_pm = user_profile.clone();
                                                                            move |_| {
                                                                                user_menu_open.set(None);
                                                                                ctcp_submenu_open.set(false);
                                                                                // Open private message tab with this user
                                                                                let active = profile_for_pm.clone();
                                                                                {
                                                                                    let mut state_write = state.write();
                                                                                    if let Some(server) = state_write.servers.get_mut(&active) {
                                                                                        // Add nick as a channel if not already present
                                                                                        if !server.channels.contains(&nick) {
                                                                                            server.channels.push(nick.clone());
                                                                                        }
                                                                                        server.current_channel = nick.clone();
                                                                                    }
                                                                                }
                                                                                force_scroll_to_bottom.set(true);
                                                                                // Focus the chat input
                                                                                let _ = document::eval(
                                                                                    r#"
                                                                                    const input = document.getElementById('chat-input');
                                                                                    if (input) input.focus();
                                                                                    "#
                                                                                );
                                                                            }
                                                                        },
                                                                        "💬 Private Message"
                                                                    }
                                                                    // Invite to Voice Channel option (only when hosting)
                                                                    {
                                                                        let is_hosting = matches!(voice_state(), crate::voice_chat::VoiceState::Hosting);
                                                                        let can_invite = is_hosting || matches!(voice_state(), crate::voice_chat::VoiceState::Active { .. });
                                                                        rsx! {
                                                                            button {
                                                                                class: if can_invite { "menu-item" } else { "menu-item disabled" },
                                                                                disabled: !can_invite,
                                                                                title: if can_invite { "Invite this user to your voice channel" } else { "Start a voice channel first" },
                                                                                onclick: {
                                                                                    let nick = user_nick.clone();
                                                                                    let profile_for_voice = user_profile.clone();
                                                                                    move |_| {
                                                                                        user_menu_open.set(None);
                                                                                        ctcp_submenu_open.set(false);
                                                                                        if !can_invite { return; }
                                                                                        
                                                                                        // Send voice channel invite using stored external IP
                                                                                        let external_ip = voice_external_ip();
                                                                                        let port = voice_local_port();
                                                                                        let session_id = voice_session_id().unwrap_or_else(|| "unknown".to_string());
                                                                                        
                                                                                        let ctcp_msg = crate::voice_chat::create_voice_call_ctcp(&external_ip, port, &session_id);
                                                                                        if let Some(core) = cores.read().get(&profile_for_voice) {
                                                                                            let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                target: nick.clone(),
                                                                                                message: ctcp_msg,
                                                                                            });
                                                                                        }
                                                                                        log::info!("Sent voice channel invite to {} at {}:{}", nick, external_ip, port);
                                                                                    }
                                                                                },
                                                                                "� Invite to Voice"
                                                                            }
                                                                        }
                                                                    }
                                                                    // Direct 1:1 Voice Call option
                                                                    {
                                                                        let can_call = matches!(voice_state(), crate::voice_chat::VoiceState::Idle);
                                                                        rsx! {
                                                                            button {
                                                                                class: if can_call { "menu-item" } else { "menu-item disabled" },
                                                                                disabled: !can_call,
                                                                                title: if can_call { "Start a direct voice call" } else { "Already in a call" },
                                                                                onclick: {
                                                                                    let nick = user_nick.clone();
                                                                                    let profile_for_call = user_profile.clone();
                                                                                    move |_| {
                                                                                        user_menu_open.set(None);
                                                                                        ctcp_submenu_open.set(false);
                                                                                        if !can_call { return; }
                                                                                        
                                                                                        // Generate session ID and get local IP
                                                                                        let session_id = crate::voice_chat::VoiceChatManager::generate_session_id();
                                                                                        // Start voice listener to get a port and external IP
                                                                                        let config = crate::voice_chat::VoiceConfig::default();
                                                                                        let muted_arc_clone = voice_muted_arc.read().clone();
                                                                                        
                                                                                        if let Some((external_ip, port, evt_rx, stop_flag, peer_tx)) = crate::voice_chat::start_voice_listener(config, muted_arc_clone) {
                                                                                            voice_external_ip.set(external_ip.clone());
                                                                                            voice_local_port.set(port);
                                                                                            voice_event_rx.set(Some(evt_rx));
                                                                                            voice_stop_flag.set(Some(stop_flag));
                                                                                            voice_peer_addr_tx.set(Some(peer_tx));
                                                                                            
                                                                                            // Update voice state - direct call (Outgoing)
                                                                                            voice_state.set(crate::voice_chat::VoiceState::Outgoing { peer: nick.clone() });
                                                                                            voice_session_id.set(Some(session_id.clone()));
                                                                                            voice_current_peer.set(Some(nick.clone()));
                                                                                            
                                                                                            // Send CTCP VOICE_CALL via IRC
                                                                                            let ctcp_msg = crate::voice_chat::create_voice_call_ctcp(&external_ip, port, &session_id);
                                                                                            if let Some(core) = cores.read().get(&profile_for_call) {
                                                                                                let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                    target: nick.clone(),
                                                                                                    message: ctcp_msg,
                                                                                                });
                                                                                            }
                                                                                            log::info!("Started voice call to {} at {}:{}", nick, external_ip, port);
                                                                                        } else {
                                                                                            log::error!("Failed to start voice listener");
                                                                                        }
                                                                                    }
                                                                                },
                                                                                "📞 Call"
                                                                            }
                                                                        }
                                                                    }
                                                                    // Invite to Channel option
                                                                    button {
                                                                        class: "menu-item",
                                                                        onclick: {
                                                                            let nick = user_nick.clone();
                                                                            let profile_for_invite = user_profile.clone();
                                                                            move |_| {
                                                                                user_menu_open.set(None);
                                                                                ctcp_submenu_open.set(false);
                                                                                
                                                                                // Add to pending invite probes (lowercase for case-insensitive matching)
                                                                                log::info!("Adding '{}' (lowercase: '{}') to pending_invite_probes for profile '{}'", nick, nick.to_lowercase(), profile_for_invite);
                                                                                pending_invite_probes.write().insert(nick.to_lowercase(), true);
                                                                                
                                                                                // Send VERSION probe to detect if they're a NAIS client
                                                                                // Use the profile where the user list is displayed, not the active profile
                                                                                if let Some(core) = cores.read().get(&profile_for_invite) {
                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                        target: nick.clone(),
                                                                                        message: "\x01VERSION\x01".to_string(),
                                                                                    });
                                                                                } else {
                                                                                    log::error!("No core found for profile '{}' to send VERSION probe", profile_for_invite);
                                                                                }
                                                                            }
                                                                        },
                                                                        "📨 Invite to Channel"
                                                                    }
                                                                    // Invite to Secure Channel option
                                                                    button {
                                                                        class: if !nsc_channels.read().is_empty() { "menu-item" } else { "menu-item disabled" },
                                                                        disabled: nsc_channels.read().is_empty(),
                                                                        title: if !nsc_channels.read().is_empty() { "Invite user to a secure encrypted channel" } else { "Create a secure channel first" },
                                                                        onclick: {
                                                                            let nick = user_nick.clone();
                                                                            let profile_for_nsc = user_profile.clone();
                                                                            move |_| {
                                                                                log::info!("Invite to Secure Channel clicked for user: {}", nick);
                                                                                user_menu_open.set(None);
                                                                                ctcp_submenu_open.set(false);
                                                                                // Open channel selection modal
                                                                                nsc_invite_modal.set(Some((nick.clone(), profile_for_nsc.clone())));
                                                                            }
                                                                        },
                                                                        "🔒 Invite to Secure Channel"
                                                                    }
                                                                    // Advanced options (hidden unless advanced mode is enabled)
                                                                    if *settings_show_advanced.read() {
                                                                        // Separator
                                                                        div {
                                                                            class: "menu-separator",
                                                                            style: "height: 1px; background: var(--border); margin: 4px 8px;"
                                                                        }
                                                                        // Whois option
                                                                        button {
                                                                            class: "menu-item",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let profile_for_whois = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    // Send /whois command directly
                                                                                    if let Some(core) = cores.read().get(&profile_for_whois) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Whois { nickname: nick.clone() });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "🔍 Whois"
                                                                        }
                                                                        // CTCP Submenu
                                                                        div {
                                                                            class: "menu-submenu-container",
                                                                            style: "position: relative;",
                                                                            button {
                                                                                class: "menu-item submenu-trigger",
                                                                                onclick: move |e: Event<MouseData>| {
                                                                                    e.stop_propagation();
                                                                                    ctcp_submenu_open.set(!ctcp_submenu_open());
                                                                                },
                                                                                "📡 CTCP"
                                                                                span {
                                                                                    style: "font-size: 10px; margin-left: auto;",
                                                                                    if ctcp_submenu_open() { "▲" } else { "▼" }
                                                                                }
                                                                            }
                                                                            if ctcp_submenu_open() {
                                                                                div {
                                                                                    class: "ctcp-submenu",
                                                                                    onclick: move |e: Event<MouseData>| {
                                                                                        e.stop_propagation();
                                                                                    },
                                                                                    // VERSION
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Request client name and version",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01VERSION\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "VERSION"
                                                                                    }
                                                                                    // PING
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Measure latency to user",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                let timestamp = chrono::Utc::now().timestamp().to_string();
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: format!("\x01PING {}\x01", timestamp),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "PING"
                                                                                    }
                                                                                    // TIME
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Request local time",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01TIME\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "TIME"
                                                                                    }
                                                                                    // FINGER
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Request user info and idle time",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01FINGER\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "FINGER"
                                                                                    }
                                                                                    // CLIENTINFO
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "List supported CTCP commands",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01CLIENTINFO\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "CLIENTINFO"
                                                                                    }
                                                                                    // SOURCE
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Request client source URL",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01SOURCE\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "SOURCE"
                                                                                    }
                                                                                    // USERINFO
                                                                                    button {
                                                                                        class: "menu-item",
                                                                                        title: "Request user-defined info string",
                                                                                        onclick: {
                                                                                            let nick = user_nick.clone();
                                                                                            let profile_for_ctcp = user_profile.clone();
                                                                                            move |_| {
                                                                                                user_menu_open.set(None);
                                                                                                ctcp_submenu_open.set(false);
                                                                                                if let Some(core) = cores.read().get(&profile_for_ctcp) {
                                                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                                                        target: nick.clone(),
                                                                                                        message: "\x01USERINFO\x01".to_string(),
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        "USERINFO"
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        // Separator before channel ops
                                                                        div {
                                                                            class: "menu-separator",
                                                                            style: "height: 1px; background: var(--border); margin: 4px 8px;"
                                                                        }
                                                                        // Op
                                                                        button {
                                                                            class: "menu-item",
                                                                            title: "Give operator status (+o)",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_mode = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    if let Some(core) = cores.read().get(&profile_for_mode) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Mode {
                                                                                            target: chan.clone(),
                                                                                            modes: "+o".to_string(),
                                                                                            args: Some(nick.clone()),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "👑 Op"
                                                                        }
                                                                        // Deop
                                                                        button {
                                                                            class: "menu-item",
                                                                            title: "Remove operator status (-o)",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_mode = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    if let Some(core) = cores.read().get(&profile_for_mode) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Mode {
                                                                                            target: chan.clone(),
                                                                                            modes: "-o".to_string(),
                                                                                            args: Some(nick.clone()),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "👑 Deop"
                                                                        }
                                                                        // Voice
                                                                        button {
                                                                            class: "menu-item",
                                                                            title: "Give voice (+v)",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_mode = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    if let Some(core) = cores.read().get(&profile_for_mode) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Mode {
                                                                                            target: chan.clone(),
                                                                                            modes: "+v".to_string(),
                                                                                            args: Some(nick.clone()),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "🎤 Voice"
                                                                        }
                                                                        // Devoice
                                                                        button {
                                                                            class: "menu-item",
                                                                            title: "Remove voice (-v)",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_mode = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    if let Some(core) = cores.read().get(&profile_for_mode) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Mode {
                                                                                            target: chan.clone(),
                                                                                            modes: "-v".to_string(),
                                                                                            args: Some(nick.clone()),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "🔇 Devoice"
                                                                        }
                                                                        // Separator before kick/ban
                                                                        div {
                                                                            class: "menu-separator",
                                                                            style: "height: 1px; background: var(--border); margin: 4px 8px;"
                                                                        }
                                                                        // Kick
                                                                        button {
                                                                            class: "menu-item danger",
                                                                            title: "Kick user from channel",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_kick = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    if let Some(core) = cores.read().get(&profile_for_kick) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Kick {
                                                                                            channel: chan.clone(),
                                                                                            user: nick.clone(),
                                                                                            reason: None,
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "🚪 Kick"
                                                                        }
                                                                        // Ban
                                                                        button {
                                                                            class: "menu-item danger",
                                                                            title: "Ban user from channel (+b)",
                                                                            onclick: {
                                                                                let nick = user_nick.clone();
                                                                                let chan = current_channel.clone();
                                                                                let profile_for_ban = user_profile.clone();
                                                                                move |_| {
                                                                                    user_menu_open.set(None);
                                                                                    ctcp_submenu_open.set(false);
                                                                                    let ban_mask = format!("{}!*@*", nick);
                                                                                    if let Some(core) = cores.read().get(&profile_for_ban) {
                                                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Mode {
                                                                                            target: chan.clone(),
                                                                                            modes: "+b".to_string(),
                                                                                            args: Some(ban_mask),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            },
                                                                            "🚫 Ban"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        }
                                    }
                                }
                            }
                        }
                        }  // Close the else block for NSC channel check
                    }
                }
            }
                }
            }

            // Voice chat incoming call notification
            if let Some((from, ext_ip, port, session_id, local_ip)) = voice_incoming_call() {
                div {
                    class: "voice-incoming-call",
                    style: "position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: var(--input-bg); border: 2px solid var(--accent-color); border-radius: 12px; padding: 24px; z-index: 1000; text-align: center; box-shadow: 0 8px 32px rgba(0,0,0,0.5);",
                    h3 {
                        style: "margin: 0 0 12px 0; color: var(--accent-color);",
                        "📞 Incoming Voice Call"
                    }
                    p {
                        style: "margin: 0 0 16px 0;",
                        "{from} wants to start a voice call"
                    }
                    div {
                        style: "display: flex; gap: 12px; justify-content: center;",
                        button {
                            style: "background: #4CAF50; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px;",
                            onclick: {
                                let from_user = from.clone();
                                let caller_ext_ip = ext_ip.clone();
                                let caller_local_ip = local_ip.clone();
                                let caller_port = port;
                                let sid = session_id.clone();
                                move |_| {
                                    // Accept the call using bidirectional connection
                                    // This handles double-NAT by trying both directions
                                    // Also handles same-LAN by using local IP when external IPs match
                                    let config = crate::voice_chat::VoiceConfig::default();
                                    let muted_arc_clone = voice_muted_arc.read().clone();
                                    
                                    log::info!("Accepting voice call from {} - using bidirectional connection", from_user);
                                    
                                    // Use bidirectional connection - it will resolve peer IP internally after getting our external IP
                                    if let Some((our_ip, our_port, evt_rx, stop_flag)) = crate::voice_chat::connect_voice_bidirectional(
                                        &caller_ext_ip,
                                        caller_local_ip.as_deref(),
                                        caller_port,
                                        config.clone(),
                                        muted_arc_clone.clone(),
                                    ) {
                                        voice_external_ip.set(our_ip.clone());
                                        voice_local_port.set(our_port);
                                        voice_event_rx.set(Some(evt_rx));
                                        voice_stop_flag.set(Some(stop_flag));
                                        
                                        // Send CTCP VOICE_ACCEPT with our external IP:port so caller can try connecting to us too
                                        let ctcp_msg = crate::voice_chat::create_voice_accept_ctcp(&our_ip, our_port, &sid);
                                        if let Some(core) = cores.read().get(&state.read().active_profile) {
                                            let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                target: from_user.clone(),
                                                message: ctcp_msg,
                                            });
                                        }
                                        log::info!("Sent VOICE_ACCEPT with our address {}:{}", our_ip, our_port);
                                        
                                        // Update state to active
                                        voice_state.set(crate::voice_chat::VoiceState::Active { peer: from_user.clone() });
                                        voice_current_peer.set(Some(from_user.clone()));
                                        voice_session_id.set(Some(sid.clone()));
                                        voice_incoming_call.set(None);
                                    } else {
                                        log::error!("Failed to set up bidirectional voice connection to {}:{}", caller_ext_ip, caller_port);
                                    }
                                }
                            },
                            "✓ Accept"
                        }
                        button {
                            style: "background: #f44336; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px;",
                            onclick: {
                                let from_user = from.clone();
                                let sid = session_id.clone();
                                move |_| {
                                    // Reject the call
                                    let ctcp_msg = crate::voice_chat::create_voice_reject_ctcp(&sid, "User declined");
                                    if let Some(core) = cores.read().get(&state.read().active_profile) {
                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                            target: from_user.clone(),
                                            message: ctcp_msg,
                                        });
                                    }
                                    
                                    voice_state.set(crate::voice_chat::VoiceState::Idle);
                                    voice_incoming_call.set(None);
                                }
                            },
                            "✗ Decline"
                        }
                    }
                }
            }

            // Voice chat active call overlay
            if let crate::voice_chat::VoiceState::Active { peer } = voice_state() {
                div {
                    class: "voice-active-call",
                    style: "position: fixed; bottom: 80px; right: 20px; background: var(--input-bg); border: 1px solid var(--accent-color); border-radius: 12px; padding: 16px; z-index: 999; min-width: 280px; box-shadow: 0 4px 16px rgba(0,0,0,0.3);",
                    div {
                        style: "display: flex; align-items: center; gap: 8px; margin-bottom: 12px;",
                        span {
                            style: "color: #4CAF50; animation: pulse 2s infinite;",
                            "●"
                        }
                        span {
                            style: "font-weight: bold;",
                            "Voice call with {peer}"
                        }
                    }
                    
                    // Audio Debug Panel
                    div {
                        style: "margin-bottom: 12px; border-top: 1px solid var(--border-color); padding-top: 12px;",
                        
                        // Collapsible header
                        div {
                            style: "display: flex; align-items: center; justify-content: space-between; cursor: pointer; margin-bottom: 8px;",
                            onclick: move |_| {
                                voice_debug_expanded.set(!voice_debug_expanded());
                            },
                            span {
                                style: "font-size: 12px; color: var(--text-muted); font-weight: bold;",
                                "🔧 Audio Debug"
                            }
                            span {
                                style: "font-size: 10px; color: var(--text-muted);",
                                if voice_debug_expanded() { "▼" } else { "▶" }
                            }
                        }
                        
                        if voice_debug_expanded() {
                            // Mic Input Level Meter
                            div {
                                style: "margin-bottom: 12px;",
                                div {
                                    style: "font-size: 11px; color: var(--text-muted); margin-bottom: 4px;",
                                    "Mic Input Level"
                                }
                                div {
                                    style: "background: #222; border-radius: 4px; height: 20px; position: relative; overflow: hidden;",
                                    // Level bar
                                    {
                                        let level = voice_mic_level();
                                        let width_pct = (level * 100.0).min(100.0);
                                        let color = if level > 0.8 {
                                            "#f44336" // Red for clipping
                                        } else if level > 0.5 {
                                            "#ff9800" // Orange for loud
                                        } else if level > 0.1 {
                                            "#4CAF50" // Green for good
                                        } else {
                                            "#666" // Gray for quiet
                                        };
                                        rsx! {
                                            div {
                                                style: "position: absolute; left: 0; top: 0; bottom: 0; width: {width_pct}%; background: {color}; transition: width 0.05s ease-out;"
                                            }
                                        }
                                    }
                                    // Level markers
                                    div {
                                        style: "position: absolute; top: 0; bottom: 0; left: 50%; width: 1px; background: #444;"
                                    }
                                    div {
                                        style: "position: absolute; top: 0; bottom: 0; left: 80%; width: 1px; background: #644;"
                                    }
                                }
                                // Level value
                                div {
                                    style: "font-size: 10px; color: var(--text-muted); margin-top: 2px; text-align: right;",
                                    {
                                        let level = voice_mic_level();
                                        let db = if level > 0.0 { (level * 100.0).log10() * 20.0 } else { -60.0 };
                                        format!("{:.1} dB", db.max(-60.0))
                                    }
                                }
                            }
                            
                            // Output Level Meter
                            div {
                                style: "margin-bottom: 12px;",
                                div {
                                    style: "font-size: 11px; color: var(--text-muted); margin-bottom: 4px;",
                                    "Output Level"
                                }
                                div {
                                    style: "background: #222; border-radius: 4px; height: 20px; position: relative; overflow: hidden;",
                                    // Level bar
                                    {
                                        let level = voice_output_level();
                                        let width_pct = (level * 100.0).min(100.0);
                                        let color = if level > 0.8 {
                                            "#f44336" // Red for clipping
                                        } else if level > 0.5 {
                                            "#ff9800" // Orange for loud
                                        } else if level > 0.1 {
                                            "#2196F3" // Blue for good (different from input)
                                        } else {
                                            "#666" // Gray for quiet
                                        };
                                        rsx! {
                                            div {
                                                style: "position: absolute; left: 0; top: 0; bottom: 0; width: {width_pct}%; background: {color}; transition: width 0.05s ease-out;"
                                            }
                                        }
                                    }
                                    // Level markers
                                    div {
                                        style: "position: absolute; top: 0; bottom: 0; left: 50%; width: 1px; background: #444;"
                                    }
                                    div {
                                        style: "position: absolute; top: 0; bottom: 0; left: 80%; width: 1px; background: #644;"
                                    }
                                }
                                // Level value
                                div {
                                    style: "font-size: 10px; color: var(--text-muted); margin-top: 2px; text-align: right;",
                                    {
                                        let level = voice_output_level();
                                        let db = if level > 0.0 { (level * 100.0).log10() * 20.0 } else { -60.0 };
                                        format!("{:.1} dB", db.max(-60.0))
                                    }
                                }
                            }
                            
                            // Network Statistics
                            div {
                                style: "border-top: 1px solid var(--border-color); padding-top: 8px; margin-top: 8px;",
                                div {
                                    style: "font-size: 11px; color: var(--text-muted); margin-bottom: 8px; font-weight: bold;",
                                    "📡 Network Stats"
                                }
                                
                                // TX/RX bytes
                                div {
                                    style: "display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 10px; margin-bottom: 8px;",
                                    div {
                                        style: "background: #1a2a1a; padding: 6px; border-radius: 4px;",
                                        div {
                                            style: "color: #4CAF50; font-weight: bold;",
                                            "⬆ TX"
                                        }
                                        div {
                                            style: "color: var(--text-color);",
                                            {
                                                let stats = voice_network_stats.read();
                                                crate::voice_chat::VoiceNetworkStats::format_bytes(stats.bytes_tx)
                                            }
                                        }
                                        div {
                                            style: "color: var(--text-muted);",
                                            {
                                                let stats = voice_network_stats.read();
                                                crate::voice_chat::VoiceNetworkStats::format_bitrate(stats.bitrate_tx)
                                            }
                                        }
                                    }
                                    div {
                                        style: "background: #1a1a2a; padding: 6px; border-radius: 4px;",
                                        div {
                                            style: "color: #2196F3; font-weight: bold;",
                                            "⬇ RX"
                                        }
                                        div {
                                            style: "color: var(--text-color);",
                                            {
                                                let stats = voice_network_stats.read();
                                                crate::voice_chat::VoiceNetworkStats::format_bytes(stats.bytes_rx)
                                            }
                                        }
                                        div {
                                            style: "color: var(--text-muted);",
                                            {
                                                let stats = voice_network_stats.read();
                                                crate::voice_chat::VoiceNetworkStats::format_bitrate(stats.bitrate_rx)
                                            }
                                        }
                                    }
                                }
                                
                                // Packet stats
                                div {
                                    style: "display: flex; justify-content: space-between; font-size: 10px; color: var(--text-muted);",
                                    div {
                                        {
                                            let stats = voice_network_stats.read();
                                            format!("Pkts: {}/{}", stats.packets_tx, stats.packets_rx)
                                        }
                                    }
                                    div {
                                        {
                                            let stats = voice_network_stats.read();
                                            let loss = stats.packet_loss_percent();
                                            let color = if loss > 5.0 { "#f44336" } else if loss > 1.0 { "#ff9800" } else { "#4CAF50" };
                                            rsx! {
                                                span {
                                                    style: "color: {color};",
                                                    "Loss: {loss:.1}%"
                                                }
                                            }
                                        }
                                    }
                                    div {
                                        {
                                            let stats = voice_network_stats.read();
                                            format!("Jitter: {}ms", stats.jitter_ms)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    div {
                        style: "display: flex; gap: 8px; justify-content: center;",
                        {
                            let mute_bg = if voice_muted() { "#f44336" } else { "#333" };
                            rsx! {
                                button {
                                    style: "background: {mute_bg}; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer;",
                                    onclick: move |_| {
                                        let new_muted = !voice_muted();
                                        voice_muted.set(new_muted);
                                        // Also update the Arc so audio capture knows about mute state
                                        if let Ok(mut m) = voice_muted_arc.read().lock() {
                                            *m = new_muted;
                                        }
                                    },
                                    if voice_muted() { "🔇 Unmute" } else { "🎤 Mute" }
                                }
                            }
                        }
                        button {
                            style: "background: #f44336; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer;",
                            onclick: {
                                let peer_nick = peer.clone();
                                move |_| {
                                    // End the call
                                    if let Some(sid) = voice_session_id() {
                                        let ctcp_msg = crate::voice_chat::create_voice_cancel_ctcp(&sid);
                                        if let Some(core) = cores.read().get(&state.read().active_profile) {
                                            let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                target: peer_nick.clone(),
                                                message: ctcp_msg,
                                            });
                                        }
                                    }
                                    
                                    // Stop the audio stream
                                    if let Some(stop_flag) = voice_stop_flag() {
                                        if let Ok(mut stopped) = stop_flag.lock() {
                                            *stopped = true;
                                        }
                                    }
                                    
                                    voice_state.set(crate::voice_chat::VoiceState::Idle);
                                    voice_current_peer.set(None);
                                    voice_session_id.set(None);
                                    voice_event_rx.set(None);
                                    voice_stop_flag.set(None);
                                }
                            },
                            "📵 End Call"
                        }
                    }
                }
            }

            // Voice chat outgoing call indicator
            if let crate::voice_chat::VoiceState::Outgoing { peer } = voice_state() {
                div {
                    class: "voice-outgoing-call",
                    style: "position: fixed; bottom: 80px; right: 20px; background: var(--input-bg); border: 1px solid var(--accent-color); border-radius: 12px; padding: 16px; z-index: 999; min-width: 200px; box-shadow: 0 4px 16px rgba(0,0,0,0.3);",
                    div {
                        style: "text-align: center;",
                        p {
                            style: "margin: 0 0 12px 0;",
                            "📞 Calling {peer}..."
                        }
                        button {
                            style: "background: #f44336; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer;",
                            onclick: {
                                let peer_nick = peer.clone();
                                move |_| {
                                    // Cancel the call
                                    if let Some(sid) = voice_session_id() {
                                        let ctcp_msg = crate::voice_chat::create_voice_cancel_ctcp(&sid);
                                        if let Some(core) = cores.read().get(&state.read().active_profile) {
                                            let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                target: peer_nick.clone(),
                                                message: ctcp_msg,
                                            });
                                        }
                                    }
                                    
                                    // Stop the audio stream
                                    if let Some(stop_flag) = voice_stop_flag() {
                                        if let Ok(mut stopped) = stop_flag.lock() {
                                            *stopped = true;
                                        }
                                    }
                                    
                                    voice_state.set(crate::voice_chat::VoiceState::Idle);
                                    voice_current_peer.set(None);
                                    voice_session_id.set(None);
                                    voice_event_rx.set(None);
                                    voice_stop_flag.set(None);
                                }
                            },
                            "Cancel"
                        }
                    }
                }
            }

            // WHOIS info popup
            if let Some(info) = whois_popup() {
                div {
                    class: "whois-popup-overlay",
                    onclick: move |_| {
                        whois_popup.set(None);
                    },
                    div {
                        class: "whois-popup",
                        onclick: move |e: Event<MouseData>| {
                            e.stop_propagation();
                        },
                        div {
                            class: "whois-popup-header",
                            h3 {
                                "🔍 {info.nick}"
                            }
                            button {
                                class: "whois-popup-close",
                                onclick: move |_| {
                                    whois_popup.set(None);
                                },
                                "✕"
                            }
                        }
                        div {
                            class: "whois-popup-content",
                            if let (Some(user), Some(host)) = (&info.user, &info.host) {
                                div {
                                    class: "whois-row",
                                    span { class: "whois-label", "Address" }
                                    span { class: "whois-value", "{user}@{host}" }
                                }
                            }
                            if let Some(realname) = &info.realname {
                                div {
                                    class: "whois-row",
                                    span { class: "whois-label", "Real Name" }
                                    span { class: "whois-value", "{realname}" }
                                }
                            }
                            if let Some(server) = &info.server {
                                div {
                                    class: "whois-row",
                                    span { class: "whois-label", "Server" }
                                    span { class: "whois-value", 
                                        "{server}"
                                        if let Some(server_info) = &info.server_info {
                                            span {
                                                style: "color: var(--muted); margin-left: 8px;",
                                                "({server_info})"
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(channels) = &info.channels {
                                div {
                                    class: "whois-row",
                                    span { class: "whois-label", "Channels" }
                                    span { class: "whois-value whois-channels", "{channels}" }
                                }
                            }
                            if let Some(idle_secs) = &info.idle_secs {
                                {
                                    let idle_num: u64 = idle_secs.parse().unwrap_or(0);
                                    let idle_display = if idle_num >= 3600 {
                                        format!("{}h {}m", idle_num / 3600, (idle_num % 3600) / 60)
                                    } else if idle_num >= 60 {
                                        format!("{}m {}s", idle_num / 60, idle_num % 60)
                                    } else {
                                        format!("{}s", idle_num)
                                    };
                                    rsx! {
                                        div {
                                            class: "whois-row",
                                            span { class: "whois-label", "Idle" }
                                            span { class: "whois-value", "{idle_display}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // CTCP response popup
            if let Some(info) = ctcp_response_popup() {
                div {
                    class: "ctcp-popup-overlay",
                    onclick: move |_| {
                        ctcp_response_popup.set(None);
                    },
                    div {
                        class: "ctcp-popup",
                        onclick: move |e: Event<MouseData>| {
                            e.stop_propagation();
                        },
                        div {
                            class: "ctcp-popup-header",
                            h3 {
                                "📡 CTCP {info.command}"
                            }
                            button {
                                class: "ctcp-popup-close",
                                onclick: move |_| {
                                    ctcp_response_popup.set(None);
                                },
                                "✕"
                            }
                        }
                        div {
                            class: "ctcp-popup-content",
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "From" }
                                span { class: "ctcp-value", "{info.from}" }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Command" }
                                span { class: "ctcp-value ctcp-command", "{info.command}" }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Response" }
                                span { class: "ctcp-value ctcp-response-text", "{info.response}" }
                            }
                        }
                    }
                }
            }

            // Channel invite popup
            if let Some(info) = channel_invite_popup() {
                {
                    // Collect available channels based on whether target is NAIS client
                    let channels: Vec<InviteChannelOption> = if info.is_nais_client {
                        // NAIS client: show all channels from all servers
                        let state_read = state.read();
                        state_read.servers.iter().flat_map(|(profile_name, server_state)| {
                            server_state.channels.iter()
                                .filter(|ch| ch.starts_with('#')) // Only real channels, not PMs
                                .map(|ch| {
                                    let is_nais = server_state.topics_by_channel.get(ch)
                                        .map(|t| crate::nais_channel::is_nais_topic(t))
                                        .unwrap_or(false);
                                    InviteChannelOption {
                                        display_name: if profile_name == &info.current_profile {
                                            ch.clone()
                                        } else {
                                            format!("{} ({})", ch, server_state.server)
                                        },
                                        channel: ch.clone(),
                                        profile: profile_name.clone(),
                                        server: server_state.server.clone(),
                                        is_nais,
                                    }
                                })
                                .collect::<Vec<_>>()
                        }).collect()
                    } else {
                        // Non-NAIS client: show only non-NAIS IRC channels on the same server
                        let state_read = state.read();
                        if let Some(server_state) = state_read.servers.get(&info.current_profile) {
                            server_state.channels.iter()
                                .filter(|ch| ch.starts_with('#')) // Only real channels
                                .filter(|ch| {
                                    // Exclude NAIS channels
                                    !server_state.topics_by_channel.get(*ch)
                                        .map(|t| crate::nais_channel::is_nais_topic(t))
                                        .unwrap_or(false)
                                })
                                .map(|ch| InviteChannelOption {
                                    display_name: ch.clone(),
                                    channel: ch.clone(),
                                    profile: info.current_profile.clone(),
                                    server: server_state.server.clone(),
                                    is_nais: false,
                                })
                                .collect()
                        } else {
                            Vec::new()
                        }
                    };
                    
                    rsx! {
                        div {
                            class: "channel-invite-overlay",
                            style: "position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 999; display: flex; align-items: center; justify-content: center;",
                            onclick: move |_| {
                                channel_invite_popup.set(None);
                            },
                            div {
                                class: "channel-invite-popup",
                                style: "background: var(--input-bg); border: 2px solid var(--accent-color); border-radius: 12px; padding: 20px; min-width: 350px; max-width: 500px; max-height: 70vh; display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,0.5);",
                                onclick: move |e: Event<MouseData>| {
                                    e.stop_propagation();
                                },
                                // Header
                                div {
                                    style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;",
                                    h3 {
                                        style: "margin: 0; color: var(--accent-color);",
                                        "📨 Invite {info.target_nick} to Channel"
                                    }
                                    button {
                                        style: "background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 18px;",
                                        onclick: move |_| {
                                            channel_invite_popup.set(None);
                                        },
                                        "✕"
                                    }
                                }
                                // Status indicator
                                div {
                                    style: "margin-bottom: 12px; padding: 8px 12px; background: var(--bg); border-radius: 6px; font-size: 13px;",
                                    if info.is_nais_client {
                                        span {
                                            style: "color: #4CAF50;",
                                            "✓ NAIS client detected - showing all channels across servers"
                                        }
                                    } else {
                                        span {
                                            style: "color: var(--text-muted);",
                                            "Standard IRC client - showing channels on this server"
                                        }
                                    }
                                }
                                // Channel list
                                div {
                                    style: "flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 4px;",
                                    if channels.is_empty() {
                                        div {
                                            style: "color: var(--text-muted); text-align: center; padding: 20px;",
                                            "No channels available to invite to"
                                        }
                                    } else {
                                        for channel_opt in channels.iter() {
                                            {
                                                let channel = channel_opt.channel.clone();
                                                let profile = channel_opt.profile.clone();
                                                let server = channel_opt.server.clone();
                                                let target_nick = info.target_nick.clone();
                                                let is_nais_channel = channel_opt.is_nais;
                                                let is_cross_server = profile != info.current_profile;
                                                let is_nais_client = info.is_nais_client;
                                                // For cross-server invites, send CTCP on the profile where we can reach the user
                                                let send_profile = info.current_profile.clone();
                                                
                                                rsx! {
                                                    button {
                                                        style: "display: flex; align-items: center; gap: 8px; padding: 10px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; text-align: left; width: 100%; transition: background 0.15s; color: var(--text);",
                                                        onclick: move |_| {
                                                            channel_invite_popup.set(None);
                                                            
                                                            if is_nais_client && (is_cross_server || is_nais_channel) {
                                                                // Send NAIS channel invite CTCP with full info
                                                                // Must send via the profile where we can reach the target user
                                                                let invite_msg = format!(
                                                                    "\x01NAIS_CHANNEL_INVITE {} {} {}\x01",
                                                                    channel,
                                                                    server,
                                                                    if is_nais_channel { "nais" } else { "irc" }
                                                                );
                                                                log::info!("Sending NAIS_CHANNEL_INVITE to {} via profile '{}': channel={}, server={}", 
                                                                    target_nick, send_profile, channel, server);
                                                                if let Some(core) = cores.read().get(&send_profile) {
                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                                                        target: target_nick.clone(),
                                                                        message: invite_msg,
                                                                    });
                                                                } else {
                                                                    log::error!("No core found for profile '{}' to send invite", send_profile);
                                                                }
                                                            } else {
                                                                // Standard IRC invite - always send on the user's current network
                                                                // so they actually receive it (not the channel's network)
                                                                if let Some(core) = cores.read().get(&send_profile) {
                                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Invite {
                                                                        nickname: target_nick.clone(),
                                                                        channel: channel.clone(),
                                                                    });
                                                                } else {
                                                                    log::error!("No core found for profile '{}' to send invite", send_profile);
                                                                }
                                                            }
                                                        },
                                                        span {
                                                            style: "font-size: 14px;",
                                                            if is_nais_channel { "🔒" } else { "#" }
                                                        }
                                                        div {
                                                            style: "flex: 1; display: flex; flex-direction: column;",
                                                            span {
                                                                style: "font-weight: 500;",
                                                                "{channel_opt.display_name}"
                                                            }
                                                            if is_cross_server {
                                                                span {
                                                                    style: "font-size: 11px; color: var(--text-muted);",
                                                                    "Cross-server invite via NAIS"
                                                                }
                                                            }
                                                        }
                                                        if is_nais_channel {
                                                            span {
                                                                style: "font-size: 11px; color: #4CAF50; background: rgba(76,175,80,0.1); padding: 2px 6px; border-radius: 4px;",
                                                                "NAIS"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cross-network invite popup
            if let Some(invite) = cross_network_invite() {
                div {
                    class: "modal-backdrop",
                    onclick: move |_| {
                        cross_network_invite.set(None);
                    },
                    div {
                        class: "ctcp-popup",
                        style: "max-width: 420px;",
                        onclick: move |e| e.stop_propagation(),
                        div {
                            class: "ctcp-popup-header",
                            div {
                                style: "display: flex; align-items: center; gap: 8px;",
                                span {
                                    style: "font-size: 20px;",
                                    if invite.is_nais { "🔒" } else { "📨" }
                                }
                                "Channel Invite"
                            }
                            button {
                                class: "close-button",
                                onclick: move |_| {
                                    cross_network_invite.set(None);
                                },
                                "×"
                            }
                        }
                        div {
                            class: "ctcp-popup-content",
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "From" }
                                span { class: "ctcp-value", "{invite.from_nick}" }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Channel" }
                                span { 
                                    class: "ctcp-value",
                                    style: if invite.is_nais { "color: #4CAF50;" } else { "" },
                                    "{invite.channel}"
                                    if invite.is_nais {
                                        span {
                                            style: "margin-left: 8px; font-size: 11px; background: rgba(76,175,80,0.1); padding: 2px 6px; border-radius: 4px;",
                                            "NAIS Encrypted"
                                        }
                                    }
                                }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Server" }
                                span { class: "ctcp-value", "{invite.server}" }
                            }
                            
                            // Show if this is a cross-network invite
                            {
                                let is_cross_network = {
                                    let state_read = state.read();
                                    !state_read.servers.values().any(|s| crate::profile::servers_match(&s.server, &invite.server))
                                };
                                
                                if is_cross_network {
                                    rsx! {
                                        div {
                                            style: "margin-top: 12px; padding: 10px; background: rgba(255,193,7,0.1); border: 1px solid rgba(255,193,7,0.3); border-radius: 6px;",
                                            div {
                                                style: "display: flex; align-items: center; gap: 8px; color: #FFB300;",
                                                span { style: "font-size: 16px;", "⚠️" }
                                                span { style: "font-weight: 500;", "New Network" }
                                            }
                                            p {
                                                style: "margin: 8px 0 0 0; font-size: 13px; color: var(--text-muted);",
                                                "Accepting will create a new profile and connect to this server."
                                            }
                                        }
                                    }
                                } else {
                                    rsx! { }
                                }
                            }
                            
                            // Buttons
                            div {
                                style: "display: flex; gap: 10px; margin-top: 16px;",
                                button {
                                    style: "flex: 1; padding: 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-size: 14px;",
                                    onclick: move |_| {
                                        cross_network_invite.set(None);
                                    },
                                    "Decline"
                                }
                                button {
                                    style: "flex: 1; padding: 10px; background: #4CAF50; border: none; border-radius: 6px; cursor: pointer; color: white; font-weight: 500; font-size: 14px;",
                                    onclick: {
                                        let invite_data = invite.clone();
                                        move |_| {
                                            // Accept the invite
                                            let server = invite_data.server.clone();
                                            let channel = invite_data.channel.clone();
                                            
                                            // Check if we already have a profile for this server
                                            // Use servers_match for fuzzy comparison (ignores port, case-insensitive)
                                            let existing_profile = {
                                                let profs = profiles.read();
                                                profs.iter().find(|p| crate::profile::servers_match(&p.server, &server)).cloned()
                                            };
                                            
                                            if let Some(profile) = existing_profile {
                                                // We already have a profile for this server
                                                // Check if already connected
                                                let is_connected = state.read().servers.get(&profile.name)
                                                    .map(|s| s.status == ConnectionStatus::Connected)
                                                    .unwrap_or(false);
                                                
                                                if is_connected {
                                                    // Just join the channel
                                                    if let Some(core) = cores.read().get(&profile.name) {
                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Join {
                                                            channel: channel.clone(),
                                                        });
                                                    }
                                                } else {
                                                    // Connect first, then join
                                                    // Create core if not exists
                                                    if !cores.read().contains_key(&profile.name) {
                                                        let core = irc_client::start_core();
                                                        register_shutdown_handle(&profile.name, core.cmd_tx.clone());
                                                        cores.write().insert(profile.name.clone(), core);
                                                    }
                                                    
                                                    if let Some(core) = cores.read().get(&profile.name) {
                                                        // Update state to show we're connecting
                                                        state.write().servers.entry(profile.name.clone())
                                                            .or_insert_with(|| irc_client::default_server_state(
                                                                profile.server.clone(),
                                                                profile.nickname.clone(),
                                                                channel.clone(),
                                                            ))
                                                            .status = ConnectionStatus::Connecting;
                                                        
                                                        // Connect to the server
                                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Connect {
                                                            server: profile.server.clone(),
                                                            nickname: profile.nickname.clone(),
                                                            channel: channel.clone(),
                                                            use_tls: profile.use_tls,
                                                            hide_host: profile.hide_host,
                                                        });
                                                    }
                                                }
                                                
                                                // Switch to that profile
                                                state.write().active_profile = profile.name.clone();
                                            } else {
                                                // No existing profile - create a new one
                                                let new_nickname = {
                                                    let profs = profiles.read();
                                                    profs.first().map(|p| p.nickname.clone())
                                                        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "nais".to_string()))
                                                };
                                                
                                                let new_profile_name = profile::profile_name(&server, &new_nickname, &channel);
                                                let new_profile = profile::Profile {
                                                    name: new_profile_name.clone(),
                                                    server: server.clone(),
                                                    nickname: new_nickname.clone(),
                                                    channel: channel.clone(),
                                                    use_tls: true, // Default to TLS
                                                    auto_connect: true,
                                                    enable_logging: true,
                                                    scrollback_limit: 1000,
                                                    log_buffer_size: 1000,
                                                    hide_host: true,
                                                };
                                                
                                                // Add profile
                                                {
                                                    let mut profs = profiles.write();
                                                    profs.push(new_profile.clone());
                                                }
                                                
                                                // Save profiles
                                                let store = profile::ProfileStore {
                                                    profiles: profiles.read().clone(),
                                                    last_used: last_used.read().clone(),
                                                    default_nickname: default_nick.read().clone(),
                                                    show_timestamps: *settings_show_timestamps.read(),
                                                    show_advanced: *settings_show_advanced.read(),
                                                };
                                                let _ = profile::save_store(&store);
                                                
                                                // Create server state
                                                state.write().servers.insert(
                                                    new_profile_name.clone(),
                                                    irc_client::default_server_state(
                                                        server.clone(),
                                                        new_nickname.clone(),
                                                        channel.clone(),
                                                    ),
                                                );
                                                
                                                // Create IRC core
                                                let core = irc_client::start_core();
                                                register_shutdown_handle(&new_profile_name, core.cmd_tx.clone());
                                                cores.write().insert(new_profile_name.clone(), core);
                                                
                                                // Connect
                                                if let Some(core) = cores.read().get(&new_profile_name) {
                                                    state.write().servers.get_mut(&new_profile_name)
                                                        .map(|s| s.status = ConnectionStatus::Connecting);
                                                    
                                                    let _ = core.cmd_tx.try_send(IrcCommandEvent::Connect {
                                                        server: server.clone(),
                                                        nickname: new_nickname,
                                                        channel: channel.clone(),
                                                        use_tls: true,
                                                        hide_host: true,
                                                    });
                                                }
                                                
                                                // Switch to the new profile
                                                state.write().active_profile = new_profile_name;
                                            }
                                            
                                            cross_network_invite.set(None);
                                        }
                                    },
                                    "Accept & Join"
                                }
                            }
                        }
                    }
                }
            }

            // Incoming IRC invite popup (standard IRC INVITE command)
            if let Some(invite) = incoming_irc_invite() {
                div {
                    class: "modal-backdrop",
                    onclick: move |_| {
                        incoming_irc_invite.set(None);
                    },
                    div {
                        class: "ctcp-popup",
                        style: "max-width: 400px;",
                        onclick: move |e| e.stop_propagation(),
                        div {
                            class: "ctcp-popup-header",
                            div {
                                style: "display: flex; align-items: center; gap: 8px;",
                                span {
                                    style: "font-size: 20px;",
                                    "📨"
                                }
                                "Channel Invite"
                            }
                            button {
                                class: "close-button",
                                onclick: move |_| {
                                    incoming_irc_invite.set(None);
                                },
                                "×"
                            }
                        }
                        div {
                            class: "ctcp-popup-content",
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "From" }
                                span { class: "ctcp-value", "{invite.from_nick}" }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Channel" }
                                span { class: "ctcp-value", "{invite.channel}" }
                            }
                            div {
                                class: "ctcp-row",
                                span { class: "ctcp-label", "Server" }
                                span { 
                                    class: "ctcp-value",
                                    style: "font-size: 12px; color: var(--text-muted);",
                                    "{invite.profile}"
                                }
                            }
                        }
                        div {
                            style: "display: flex; gap: 8px; padding: 12px; border-top: 1px solid var(--border); justify-content: flex-end;",
                            button {
                                class: "sidebar-button",
                                style: "padding: 6px 16px;",
                                onclick: move |_| {
                                    incoming_irc_invite.set(None);
                                },
                                "Decline"
                            }
                            button {
                                class: "action-button",
                                style: "padding: 6px 16px; background: var(--accent); color: white;",
                                onclick: move |_| {
                                    let channel = invite.channel.clone();
                                    let profile = invite.profile.clone();
                                    
                                    // Join the channel on the same server
                                    if let Some(core) = cores.read().get(&profile) {
                                        let _ = core.cmd_tx.try_send(IrcCommandEvent::Join {
                                            channel: channel.clone(),
                                        });
                                    }
                                    
                                    // Switch to that channel
                                    if let Some(server_state) = state.write().servers.get_mut(&profile) {
                                        if !server_state.channels.contains(&channel) {
                                            server_state.channels.push(channel.clone());
                                        }
                                        server_state.current_channel = channel;
                                    }
                                    
                                    incoming_irc_invite.set(None);
                                },
                                "Accept & Join"
                            }
                        }
                    }
                }
            }

            // Input composer
            div {
                class: "composer",
                input {
                    id: "chat-input",
                    class: "input",
                    r#type: "text",
                    placeholder: "Type message or /command...",
                    oninput: move |_evt| {
                        // Reset tab completion when user types (but not when we set value programmatically)
                        if *skip_tab_reset.read() {
                            skip_tab_reset.set(false);
                            return;
                        }
                        tab_completion_prefix.set(String::new());
                        tab_completion_matches.set(Vec::new());
                        tab_completion_index.set(0);
                    },
                    onkeydown: move |evt| {
                        match evt.key() {
                            Key::Tab => {
                                evt.prevent_default();
                                
                                let current_prefix = tab_completion_prefix.read().clone();
                                let current_matches = tab_completion_matches.read().clone();
                                let current_idx = *tab_completion_index.read();
                                
                                // Get users from current channel
                                let users = state.read()
                                    .servers
                                    .get(&state.read().active_profile)
                                    .and_then(|s| {
                                        let channel = &s.current_channel;
                                        s.users_by_channel.get(channel).cloned()
                                    })
                                    .unwrap_or_default();
                                
                                // Read current text from DOM and perform completion
                                spawn(async move {
                                    let result = document::eval(
                                        r#"dioxus.send(document.getElementById('chat-input').value)"#
                                    ).recv::<serde_json::Value>().await;
                                    let current_text = match result {
                                        Ok(v) => v.as_str().unwrap_or("").to_string(),
                                        Err(_) => return,
                                    };
                                    
                                    if current_prefix.is_empty() || current_matches.is_empty() {
                                        // Start new completion
                                        // Find the word being typed (from last space to end)
                                        let prefix = current_text
                                            .rsplit_once(' ')
                                            .map(|(_, word)| word)
                                            .unwrap_or(&current_text)
                                            .to_string();
                                        
                                        if prefix.is_empty() {
                                            return;
                                        }
                                        
                                        let prefix_lower = prefix.to_lowercase();
                                        
                                        // Find matching nicks (strip @ and + prefixes for matching)
                                        let matches: Vec<String> = users
                                            .iter()
                                            .filter_map(|u| {
                                                let nick = u.trim_start_matches(['@', '+']);
                                                if nick.to_lowercase().starts_with(&prefix_lower) {
                                                    Some(nick.to_string())
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect();
                                        
                                        if !matches.is_empty() {
                                            let completed_nick = &matches[0];
                                            let is_start_of_line = !current_text.contains(' ');
                                            let suffix = if is_start_of_line { ": " } else { " " };
                                            
                                            // Replace prefix with completed nick
                                            let new_text = if let Some((before, _)) = current_text.rsplit_once(' ') {
                                                format!("{} {}{}", before, completed_nick, suffix)
                                            } else {
                                                format!("{}{}", completed_nick, suffix)
                                            };
                                            
                                            skip_tab_reset.set(true);
                                            let escaped = new_text.replace('\\', "\\\\").replace('\'', "\\'");
                                            let _ = document::eval(&format!(
                                                r#"document.getElementById('chat-input').value = '{}'"#,
                                                escaped
                                            ));
                                            tab_completion_prefix.set(prefix);
                                            tab_completion_matches.set(matches);
                                            tab_completion_index.set(0);
                                        }
                                    } else {
                                        // Cycle to next match
                                        let next_idx = (current_idx + 1) % current_matches.len();
                                        let completed_nick = &current_matches[next_idx];
                                        
                                        // Find where the previous completion was inserted
                                        let prev_nick = &current_matches[current_idx];
                                        
                                        // Determine if completion was at start of line
                                        let is_start_of_line = current_text.starts_with(prev_nick);
                                        let suffix = if is_start_of_line { ": " } else { " " };
                                        
                                        // Replace the previous completion
                                        let new_text = if is_start_of_line {
                                            // Replace "nick: " at start
                                            let after = current_text.strip_prefix(prev_nick)
                                                .and_then(|s| s.strip_prefix(": "))
                                                .unwrap_or("");
                                            format!("{}{}{}", completed_nick, suffix, after)
                                        } else {
                                            // Find and replace "nick " in the text
                                            let search = format!("{} ", prev_nick);
                                            let replace = format!("{}{}", completed_nick, suffix);
                                            if let Some(pos) = current_text.rfind(&search) {
                                                let (before, after) = current_text.split_at(pos);
                                                let after = &after[search.len()..];
                                                format!("{}{}{}", before, replace, after)
                                            } else {
                                                current_text.clone()
                                            }
                                        };
                                        
                                        skip_tab_reset.set(true);
                                        let escaped = new_text.replace('\\', "\\\\").replace('\'', "\\'");
                                        let _ = document::eval(&format!(
                                            r#"document.getElementById('chat-input').value = '{}'"#,
                                            escaped
                                        ));
                                        tab_completion_index.set(next_idx);
                                    }
                                });
                            }
                            Key::Enter => {
                                // Read value directly from DOM for uncontrolled input
                                spawn(async move {
                                    let result = document::eval(
                                        r#"dioxus.send(document.getElementById('chat-input').value)"#
                                    ).recv::<serde_json::Value>().await;
                                    if let Ok(text) = result {
                                        if let Some(text_str) = text.as_str() {
                                            let text = text_str.to_string();
                                            // Reset tab completion on enter
                                            tab_completion_prefix.set(String::new());
                                            tab_completion_matches.set(Vec::new());
                                            tab_completion_index.set(0);
                                            // Clear the input
                                            let _ = document::eval(
                                                r#"document.getElementById('chat-input').value = ''"#
                                            );
                                            handle_send_message(
                                                text,
                                                state,
                                                input,
                                                history,
                                                history_index,
                                                cores,
                                                profiles,
                                                last_used,
                                                force_scroll_to_bottom,
                                                default_nick.read().clone(),
                                                voice_state,
                                                voice_session_id,
                                                voice_current_peer,
                                                voice_local_port,
                                                voice_external_ip,
                                                voice_muted_arc,
                                                voice_event_rx,
                                                voice_stop_flag,
                                                voice_peer_addr_tx,
                                                settings_show_timestamps,
                                                settings_show_advanced,
                                                nsc_current_channel,
                                                nsc_messages,
                                                nsc_fingerprint,
                                            );
                                        }
                                    }
                                });
                            }
                            Key::ArrowUp => {
                                evt.prevent_default();
                                let hist = history.read();
                                let current_idx = *history_index.read();
                                let next_idx = match current_idx {
                                    None => hist.len().saturating_sub(1),
                                    Some(idx) => idx.saturating_sub(1),
                                };
                                if next_idx < hist.len() {
                                    history_index.set(Some(next_idx));
                                    let value = hist[next_idx].clone();
                                    spawn(async move {
                                        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
                                        let _ = document::eval(&format!(
                                            r#"document.getElementById('chat-input').value = '{}'"#,
                                            escaped
                                        ));
                                    });
                                }
                            }
                            Key::ArrowDown => {
                                evt.prevent_default();
                                let hist = history.read();
                                let current_idx = *history_index.read();
                                if let Some(idx) = current_idx {
                                    if idx < hist.len() - 1 {
                                        let next_idx = idx + 1;
                                        history_index.set(Some(next_idx));
                                        let value = hist[next_idx].clone();
                                        spawn(async move {
                                            let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
                                            let _ = document::eval(&format!(
                                                r#"document.getElementById('chat-input').value = '{}'"#,
                                                escaped
                                            ));
                                        });
                                    } else {
                                        history_index.set(None);
                                        spawn(async move {
                                            let _ = document::eval(
                                                r#"document.getElementById('chat-input').value = ''"#
                                            );
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    },
                }
                if cfg!(feature = "desktop") {
                    {file_picker_button(input)}
                }
                button {
                    class: "send",
                    onclick: move |_| {
                        spawn(async move {
                            let result = document::eval(
                                r#"dioxus.send(document.getElementById('chat-input').value)"#
                            ).recv::<serde_json::Value>().await;
                            if let Ok(text) = result {
                                if let Some(text_str) = text.as_str() {
                                    let text = text_str.to_string();
                                    // Clear the input
                                    let _ = document::eval(
                                        r#"document.getElementById('chat-input').value = ''"#
                                    );
                                    handle_send_message(
                                        text,
                                        state,
                                        input,
                                        history,
                                        history_index,
                                        cores,
                                        profiles,
                                        last_used,
                                        force_scroll_to_bottom,
                                        default_nick.read().clone(),
                                        voice_state,
                                        voice_session_id,
                                        voice_current_peer,
                                        voice_local_port,
                                        voice_external_ip,
                                        voice_muted_arc,
                                        voice_event_rx,
                                        voice_stop_flag,
                                        voice_peer_addr_tx,
                                        settings_show_timestamps,
                                        settings_show_advanced,
                                        nsc_current_channel,
                                        nsc_messages,
                                        nsc_fingerprint,
                                    );
                                }
                            }
                        });
                    },
                    "Send"
                }
            }
        }

        // Modals
        // First-run setup modal (blocking)
        if show_first_run_setup.read().clone() {
            div {
                class: "modal-backdrop",
                style: "z-index: 10000;",
                div {
                    class: "modal",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "Welcome to NAIS IRC Client"
                    }
                    div {
                        class: "modal-body",
                        style: "text-align: center;",
                        p {
                            style: "margin-bottom: 20px; color: var(--text);",
                            "Choose a default nickname for IRC connections."
                        }
                        p {
                            style: "margin-bottom: 10px; font-size: 12px; color: var(--subtext);",
                            "If your nickname is taken, we'll try: {first_run_nick_input}_ and {first_run_nick_input}`"
                        }
                        input {
                            id: "first-run-nick-input",
                            class: "input",
                            r#type: "text",
                            placeholder: "Your nickname",
                            value: "{first_run_nick_input}",
                            style: "text-align: center; font-size: 16px; margin-bottom: 20px;",
                            oninput: move |evt| {
                                first_run_nick_input.set(evt.value());
                            },
                            onkeydown: move |evt| {
                                if evt.key() == Key::Enter {
                                    let nick = first_run_nick_input.read().trim().to_string();
                                    if !nick.is_empty() {
                                        let mut store_mut = profile::ProfileStore {
                                            profiles: profiles.read().clone(),
                                            last_used: last_used.read().clone(),
                                            default_nickname: Some(nick.clone()),
                                            show_timestamps: *settings_show_timestamps.read(),
                                            show_advanced: *settings_show_advanced.read(),
                                        };
                                        
                                        // Update all profiles with new nickname
                                        for profile in store_mut.profiles.iter_mut() {
                                            profile.nickname = nick.clone();
                                        }
                                        
                                        let _ = profile::save_store(&store_mut);
                                        profiles.set(store_mut.profiles.clone());
                                        
                                        // Update state with new nicknames
                                        for (_profile_name, server_state) in state.write().servers.iter_mut() {
                                            server_state.nickname = nick.clone();
                                        }
                                        
                                        show_first_run_setup.set(false);
                                        
                                        // Focus the chat input
                                        let _ = document::eval(
                                            r#"
                                            const input = document.getElementById('chat-input');
                                            if (input) input.focus();
                                            "#
                                        );
                                    }
                                }
                            },
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                let nick = first_run_nick_input.read().trim().to_string();
                                if !nick.is_empty() {
                                    let mut store_mut = profile::ProfileStore {
                                        profiles: profiles.read().clone(),
                                        last_used: last_used.read().clone(),
                                        default_nickname: Some(nick.clone()),
                                        show_timestamps: *settings_show_timestamps.read(),
                                        show_advanced: *settings_show_advanced.read(),
                                    };
                                    
                                    // Update all profiles with new nickname
                                    for profile in store_mut.profiles.iter_mut() {
                                        profile.nickname = nick.clone();
                                    }
                                    
                                    let _ = profile::save_store(&store_mut);
                                    profiles.set(store_mut.profiles.clone());
                                    
                                    // Update state with new nicknames
                                    for (_profile_name, server_state) in state.write().servers.iter_mut() {
                                        server_state.nickname = nick.clone();
                                    }
                                    
                                    show_first_run_setup.set(false);
                                    
                                    // Focus the chat input
                                    let _ = document::eval(
                                        r#"
                                        const input = document.getElementById('chat-input');
                                        if (input) input.focus();
                                        "#
                                    );
                                }
                            },
                            "Continue"
                        }
                    }
                }
            }
        }
        
        if show_new_profile.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_new_profile.set(false);
                },
                div {
                    class: "modal",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "New Profile"
                    }
                    div {
                        class: "modal-body",
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Server (e.g., irc.libera.chat)",
                            value: "{new_server_input}",
                            oninput: move |evt| {
                                new_server_input.set(evt.value());
                            },
                        }
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Nickname",
                            value: "{new_nick_input}",
                            oninput: move |evt| {
                                new_nick_input.set(evt.value());
                            },
                        }
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Channel (optional)",
                            value: "{new_channel_input}",
                            oninput: move |evt| {
                                new_channel_input.set(evt.value());
                            },
                        }
                        div {
                            class: "input",
                            style: "display: flex; align-items: center; gap: 10px;",
                            input {
                                r#type: "checkbox",
                                checked: "{new_tls_input}",
                                onchange: move |evt| {
                                    new_tls_input.set(evt.checked());
                                },
                            }
                            label {
                                "Use TLS/SSL"
                            }
                        }
                        if *settings_show_advanced.read() {
                            div {
                                class: "input",
                                style: "display: flex; align-items: center; gap: 10px;",
                                input {
                                    r#type: "checkbox",
                                    checked: "{new_hide_host_input}",
                                    onchange: move |evt| {
                                        new_hide_host_input.set(evt.checked());
                                    },
                                }
                                label {
                                    "Hide hostname (MODE +x)"
                                }
                            }
                        }
                        div {
                            class: "input",
                            style: "display: flex; align-items: center; gap: 10px;",
                            input {
                                r#type: "checkbox",
                                checked: "{new_auto_connect_input}",
                                onchange: move |evt| {
                                    new_auto_connect_input.set(evt.checked());
                                },
                            }
                            label {
                                "Auto-connect on startup"
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                show_new_profile.set(false);
                            },
                            "Cancel"
                        }
                        button {
                            class: "send",
                            onclick: move |_| {
                                let server = new_server_input.read().trim().to_string();
                                let nickname = new_nick_input.read().trim().to_string();
                                let channel = new_channel_input.read().trim().to_string();
                                let use_tls = *new_tls_input.read();
                                let auto_connect = *new_auto_connect_input.read();
                                let hide_host = *new_hide_host_input.read();

                                if server.is_empty() || nickname.is_empty() {
                                    return;
                                }

                                let name = profile::profile_name(&server, &nickname, &channel);
                                let prof = profile::Profile {
                                    name: name.clone(),
                                    server,
                                    nickname,
                                    channel,
                                    use_tls,
                                    auto_connect,
                                    enable_logging: true,
                                    scrollback_limit: 1000,
                                    log_buffer_size: 1000,
                                    hide_host,
                                };

                                let mut profs = profiles.write();
                                if !profs.iter().any(|p| p.name == prof.name) {
                                    profs.push(prof.clone());
                                }
                                drop(profs);

                                let mut state_mut = state.write();
                                state_mut.servers.insert(
                                    prof.name.clone(),
                                    irc_client::default_server_state(
                                        prof.server.clone(),
                                        prof.nickname.clone(),
                                        prof.channel.clone(),
                                    ),
                                );
                                drop(state_mut);

                                let store = profile::ProfileStore {
                                    profiles: profiles.read().clone(),
                                    last_used: last_used.read().clone(),
                                    default_nickname: default_nick.read().clone(),
                                    show_timestamps: *settings_show_timestamps.read(),
                                    show_advanced: *settings_show_advanced.read(),
                                };
                                let _ = profile::save_store(&store);

                                new_server_input.set(String::new());
                                new_nick_input.set(String::new());
                                new_channel_input.set(String::new());
                                new_tls_input.set(true);
                                new_auto_connect_input.set(true);
                                new_hide_host_input.set(true);
                                show_new_profile.set(false);
                            },
                            "Create"
                        }
                    }
                }
            }
        }

        if show_edit_profile.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_edit_profile.set(false);
                },
                div {
                    class: "modal",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "Edit Profile"
                    }
                    div {
                        class: "modal-body",
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Profile Name",
                            value: "{edit_name_input}",
                            oninput: move |evt| {
                                edit_name_input.set(evt.value());
                            },
                        }
                        if *settings_show_advanced.read() {
                            input {
                                class: "input",
                                r#type: "text",
                                placeholder: "Server",
                                value: "{edit_server_input}",
                                oninput: move |evt| {
                                    edit_server_input.set(evt.value());
                                },
                            }
                        }
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Nickname",
                            value: "{edit_nick_input}",
                            oninput: move |evt| {
                                edit_nick_input.set(evt.value());
                            },
                        }
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Channel",
                            value: "{edit_channel_input}",
                            oninput: move |evt| {
                                edit_channel_input.set(evt.value());
                            },
                        }
                        if *settings_show_advanced.read() {
                            div {
                                class: "input",
                                style: "display: flex; align-items: center; gap: 10px;",
                                input {
                                    r#type: "checkbox",
                                    checked: "{edit_tls_input}",
                                    onchange: move |evt| {
                                        edit_tls_input.set(evt.checked());
                                    },
                                }
                                label {
                                    "Use TLS/SSL"
                                }
                            }
                            div {
                                class: "input",
                                style: "display: flex; align-items: center; gap: 10px;",
                                input {
                                    r#type: "checkbox",
                                    checked: "{edit_hide_host_input}",
                                    onchange: move |evt| {
                                        edit_hide_host_input.set(evt.checked());
                                    },
                                }
                                label {
                                    "Hide hostname (MODE +x)"
                                }
                            }
                        }
                        div {
                            class: "input",
                            style: "display: flex; align-items: center; gap: 10px;",
                            input {
                                r#type: "checkbox",
                                checked: "{edit_auto_connect_input}",
                                onchange: move |evt| {
                                    edit_auto_connect_input.set(evt.checked());
                                },
                            }
                            label {
                                "Auto-connect on startup"
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                show_edit_profile.set(false);
                            },
                            "Cancel"
                        }
                        button {
                            class: "send",
                            onclick: move |_| {
                                let active_prof = state.read().active_profile.clone();
                                let new_name = edit_name_input.read().trim().to_string();
                                let server = edit_server_input.read().trim().to_string();
                                let nickname = edit_nick_input.read().trim().to_string();
                                let channel = edit_channel_input.read().trim().to_string();
                                let use_tls = *edit_tls_input.read();
                                let auto_connect = *edit_auto_connect_input.read();
                                let hide_host = *edit_hide_host_input.read();

                                if new_name.is_empty() || server.is_empty() || nickname.is_empty() {
                                    return;
                                }

                                let prof_idx_opt = profiles.read().iter().position(|p| p.name == active_prof);
                                if let Some(prof_idx) = prof_idx_opt {
                                    let old_name = active_prof.clone();
                                    let mut profs = profiles.write();
                                    profs[prof_idx].name = new_name.clone();
                                    profs[prof_idx].server = server.clone();
                                    profs[prof_idx].nickname = nickname.clone();
                                    profs[prof_idx].channel = channel.clone();
                                    profs[prof_idx].use_tls = use_tls;
                                    profs[prof_idx].auto_connect = auto_connect;
                                    profs[prof_idx].hide_host = hide_host;
                                    drop(profs);

                                    // Update server state with the new name and values
                                    let mut state_mut = state.write();
                                    if let Some(server_state) = state_mut.servers.remove(&old_name) {
                                        let mut updated_state = server_state;
                                        updated_state.server = server.clone();
                                        updated_state.nickname = nickname.clone();
                                        state_mut.servers.insert(new_name.clone(), updated_state);
                                    }
                                    
                                    // Update active profile if it was the one being edited
                                    if state_mut.active_profile == old_name {
                                        state_mut.active_profile = new_name.clone();
                                    }
                                    drop(state_mut);
                                    
                                    // Update cores map
                                    if old_name != new_name {
                                        let mut cores_mut = cores.write();
                                        if let Some(core_handle) = cores_mut.remove(&old_name) {
                                            cores_mut.insert(new_name.clone(), core_handle);
                                        }
                                        drop(cores_mut);
                                        
                                        // Update skip_reconnect map
                                        let mut skip_mut = skip_reconnect.write();
                                        if let Some(skip_val) = skip_mut.remove(&old_name) {
                                            skip_mut.insert(new_name.clone(), skip_val);
                                        }
                                        drop(skip_mut);
                                        
                                        // Update profile_status map
                                        let mut status_mut = profile_status.write();
                                        if let Some(status_val) = status_mut.remove(&old_name) {
                                            status_mut.insert(new_name.clone(), status_val);
                                        }
                                        drop(status_mut);
                                        
                                        // Update show_server_log map
                                        let mut log_mut = show_server_log.write();
                                        if let Some(log_val) = log_mut.remove(&old_name) {
                                            log_mut.insert(new_name.clone(), log_val);
                                        }
                                        drop(log_mut);
                                    }

                                    // Update last_used if it was the old name
                                    if last_used.read().as_ref() == Some(&old_name) {
                                        last_used.set(Some(new_name.clone()));
                                    }

                                    let store = profile::ProfileStore {
                                        profiles: profiles.read().clone(),
                                        last_used: last_used.read().clone(),
                                        default_nickname: default_nick.read().clone(),
                                        show_timestamps: *settings_show_timestamps.read(),
                                        show_advanced: *settings_show_advanced.read(),
                                    };
                                    let _ = profile::save_store(&store);
                                }

                                show_edit_profile.set(false);
                            },
                            "Save"
                        }
                    }
                }
            }
        }

        if show_import_modal.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_import_modal.set(false);
                },
                div {
                    class: "modal",
                    style: "width:min(500px, 90vw);",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "Import Network"
                    }
                    div {
                        class: "import-list",
                        for (label, server, channel, use_tls) in IMPORT_NETWORKS.iter() {
                            div {
                                class: "import-row",
                                div {
                                    class: "import-main",
                                    div {
                                        class: "import-name",
                                        "{label}"
                                    }
                                    div {
                                        class: "import-meta",
                                        if channel.is_empty() {
                                            "{server}"
                                        } else {
                                            "{server} {channel}"
                                        }
                                    }
                                }
                                button {
                                    class: "send",
                                    style: "padding:6px 10px; font-size:12px;",
                                    onclick: move |_| {
                                        let default_nick = "nais".to_string();
                                        let name = unique_profile_label(
                                            label,
                                            server,
                                            &default_nick,
                                            &profiles.read(),
                                        );
                                        let prof = profile::Profile {
                                            name,
                                            server: server.to_string(),
                                            nickname: default_nick.clone(),
                                            channel: channel.to_string(),
                                            use_tls: *use_tls,
                                            auto_connect: true,
                                            enable_logging: true,
                                            scrollback_limit: 1000,
                                            log_buffer_size: 1000,
                                            hide_host: true,
                                        };

                                        let mut profs = profiles.write();
                                        if !profs.iter().any(|p| p.name == prof.name) {
                                            profs.push(prof.clone());
                                        }
                                        drop(profs);

                                        let mut state_mut = state.write();
                                        state_mut.servers.insert(
                                            prof.name.clone(),
                                            irc_client::default_server_state(
                                                prof.server.clone(),
                                                prof.nickname.clone(),
                                                prof.channel.clone(),
                                            ),
                                        );
                                        drop(state_mut);

                                        let store = profile::ProfileStore {
                                            profiles: profiles.read().clone(),
                                            last_used: last_used.read().clone(),
                                            default_nickname: Some(default_nick.clone()),
                                            show_timestamps: *settings_show_timestamps.read(),
                                            show_advanced: *settings_show_advanced.read(),
                                        };
                                        let _ = profile::save_store(&store);

                                        show_import_modal.set(false);
                                    },
                                    "Import"
                                }
                            }
                        }
                    }
                }
            }
        }

        // Settings Modal
        if show_settings.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_settings.set(false);
                },
                div {
                    class: "modal settings-modal",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "⚙ Settings"
                    }
                    div {
                        class: "modal-body settings-body",
                        
                        // Global Settings Section
                        div {
                            class: "settings-section",
                            div {
                                class: "settings-section-title",
                                "Global Settings"
                            }
                            div {
                                class: "settings-row",
                                label {
                                    class: "settings-label",
                                    "Default Nickname"
                                }
                                input {
                                    class: "input settings-input",
                                    r#type: "text",
                                    placeholder: "Default nickname for new profiles",
                                    value: "{settings_default_nick}",
                                    oninput: move |evt| {
                                        settings_default_nick.set(evt.value());
                                    },
                                }
                            }
                        }
                        
                        // Profile Settings Section
                        div {
                            class: "settings-section",
                            div {
                                class: "settings-section-title",
                                "Profile Settings"
                            }
                            div {
                                class: "settings-profile-name",
                                "Active profile: {state.read().active_profile}"
                            }
                            
                            // Enable Logging
                            div {
                                class: "settings-row checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    checked: "{settings_enable_logging}",
                                    onchange: move |evt| {
                                        settings_enable_logging.set(evt.checked());
                                    },
                                }
                                label {
                                    class: "settings-label",
                                    "Enable Message Logging"
                                }
                            }
                            
                            // Show Timestamps
                            div {
                                class: "settings-row checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    checked: "{settings_show_timestamps}",
                                    onchange: move |evt| {
                                        settings_show_timestamps.set(evt.checked());
                                    },
                                }
                                label {
                                    class: "settings-label",
                                    "Show Timestamps"
                                }
                            }
                            
                            // Advanced Features
                            div {
                                class: "settings-row checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    checked: "{settings_show_advanced}",
                                    onchange: move |evt| {
                                        settings_show_advanced.set(evt.checked());
                                    },
                                }
                                label {
                                    class: "settings-label",
                                    "Advanced Features"
                                }
                            }
                            
                            // Scrollback Limit (advanced only)
                            if *settings_show_advanced.read() {
                                div {
                                    class: "settings-row",
                                    label {
                                        class: "settings-label",
                                        "Scrollback Limit"
                                    }
                                    input {
                                        class: "input settings-input-small",
                                        r#type: "number",
                                        min: "100",
                                        max: "100000",
                                    value: "{settings_scrollback_limit}",
                                    oninput: move |evt| {
                                        if let Ok(val) = evt.value().parse::<usize>() {
                                            settings_scrollback_limit.set(val.clamp(100, 100000));
                                        }
                                    },
                                }
                                span {
                                    class: "settings-hint",
                                    "messages"
                                }
                                }
                            
                                // Log Buffer Size (advanced only)
                                div {
                                    class: "settings-row",
                                    label {
                                        class: "settings-label",
                                        "Log Buffer Size"
                                    }
                                    input {
                                        class: "input settings-input-small",
                                        r#type: "number",
                                        min: "100",
                                        max: "100000",
                                        value: "{settings_log_buffer_size}",
                                        oninput: move |evt| {
                                            if let Ok(val) = evt.value().parse::<usize>() {
                                                settings_log_buffer_size.set(val.clamp(100, 100000));
                                            }
                                        },
                                    }
                                    span {
                                        class: "settings-hint",
                                        "messages"
                                    }
                                }
                            }
                        }
                        
                        // Audio Settings Section
                        div {
                            class: "settings-section",
                            div {
                                class: "settings-section-title",
                                "🎤 Audio Settings"
                            }
                            
                            // Input Device
                            div {
                                class: "settings-row",
                                label {
                                    class: "settings-label",
                                    "Input Device"
                                }
                                select {
                                    class: "input settings-select",
                                    onchange: move |evt| {
                                        let value = evt.value();
                                        let new_device = if value == "__default__" {
                                            None
                                        } else {
                                            Some(value)
                                        };
                                        voice_selected_device.set(new_device.clone());
                                        
                                        // Restart monitor with new device if active
                                        if voice_level_monitor.read().is_some() {
                                            if let Some(monitor) = crate::voice_chat::AudioLevelMonitor::start(new_device.as_deref()) {
                                                voice_level_monitor.set(Some(std::sync::Arc::new(monitor)));
                                            }
                                        }
                                    },
                                    option {
                                        value: "__default__",
                                        selected: voice_selected_device.read().is_none(),
                                        "System Default"
                                    }
                                    {
                                        voice_available_devices.read().iter().map(|device| {
                                            let name = device.name.clone();
                                            let is_selected = voice_selected_device.read().as_ref() == Some(&name);
                                            let display_name = if device.is_default {
                                                format!("{} (default)", name)
                                            } else {
                                                name.clone()
                                            };
                                            rsx! {
                                                option {
                                                    value: "{name}",
                                                    selected: is_selected,
                                                    "{display_name}"
                                                }
                                            }
                                        })
                                    }
                                }
                            }
                            
                            // Output Device
                            div {
                                class: "settings-row",
                                label {
                                    class: "settings-label",
                                    "Output Device"
                                }
                                select {
                                    class: "input settings-select",
                                    onchange: move |evt| {
                                        let value = evt.value();
                                        let new_device = if value == "__default__" {
                                            None
                                        } else {
                                            Some(value)
                                        };
                                        voice_selected_output_device.set(new_device);
                                    },
                                    option {
                                        value: "__default__",
                                        selected: voice_selected_output_device.read().is_none(),
                                        "System Default"
                                    }
                                    {
                                        voice_output_devices.read().iter().map(|device| {
                                            let name = device.name.clone();
                                            let is_selected = voice_selected_output_device.read().as_ref() == Some(&name);
                                            let display_name = if device.is_default {
                                                format!("{} (default)", name)
                                            } else {
                                                name.clone()
                                            };
                                            rsx! {
                                                option {
                                                    value: "{name}",
                                                    selected: is_selected,
                                                    "{display_name}"
                                                }
                                            }
                                        })
                                    }
                                }
                            }
                            
                            // Refresh Devices
                            div {
                                class: "settings-row",
                                label {
                                    class: "settings-label",
                                    ""
                                }
                                button {
                                    class: "send settings-refresh-btn",
                                    onclick: move |_| {
                                        let devices = crate::voice_chat::list_audio_input_devices();
                                        voice_available_devices.set(devices);
                                        let output_devices = crate::voice_chat::list_audio_output_devices();
                                        voice_output_devices.set(output_devices);
                                    },
                                    "🔄 Refresh Devices"
                                }
                            }
                        }
                        
                        // Noise Filtering Section (advanced only)
                        if *settings_show_advanced.read() {
                            div {
                                class: "settings-section",
                                div {
                                    class: "settings-section-title",
                                    "🔇 Noise Filtering"
                                }
                                
                                // Noise Suppression (AI)
                                div {
                                    class: "settings-row checkbox-row",
                                    input {
                                        r#type: "checkbox",
                                        checked: "{settings_noise_suppression}",
                                        onchange: move |evt| {
                                            settings_noise_suppression.set(evt.checked());
                                        },
                                    }
                                    label {
                                        class: "settings-label",
                                        "AI Noise Suppression (RNNoise)"
                                    }
                                }
                            
                            // Suppression Strength
                            if *settings_noise_suppression.read() {
                                div {
                                    class: "settings-row",
                                    label {
                                        class: "settings-label",
                                        "Suppression Strength"
                                    }
                                    input {
                                        class: "settings-slider",
                                        r#type: "range",
                                        min: "0",
                                        max: "100",
                                        value: "{(*settings_noise_suppression_strength.read() * 100.0) as i32}",
                                        oninput: move |evt| {
                                            if let Ok(val) = evt.value().parse::<f32>() {
                                                settings_noise_suppression_strength.set((val / 100.0).clamp(0.0, 1.0));
                                            }
                                        },
                                    }
                                    span {
                                        class: "settings-hint",
                                        "{(*settings_noise_suppression_strength.read() * 100.0) as i32}%"
                                    }
                                }
                            }
                            
                            // Noise Gate
                            div {
                                class: "settings-row checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    checked: "{settings_noise_gate}",
                                    onchange: move |evt| {
                                        settings_noise_gate.set(evt.checked());
                                    },
                                }
                                label {
                                    class: "settings-label",
                                    "Noise Gate (mutes low audio)"
                                }
                            }
                            
                            // Gate Threshold
                            if *settings_noise_gate.read() {
                                div {
                                    class: "settings-row",
                                    label {
                                        class: "settings-label",
                                        "Gate Threshold"
                                    }
                                    input {
                                        class: "settings-slider",
                                        r#type: "range",
                                        min: "0",
                                        max: "100",
                                        value: "{(*settings_noise_gate_threshold.read() * 1000.0) as i32}",
                                        oninput: move |evt| {
                                            if let Ok(val) = evt.value().parse::<f32>() {
                                                settings_noise_gate_threshold.set((val / 1000.0).clamp(0.001, 0.1));
                                            }
                                        },
                                    }
                                    span {
                                        class: "settings-hint",
                                        {
                                            let thresh = *settings_noise_gate_threshold.read();
                                            let db = if thresh > 0.0 { (thresh).log10() * 20.0 } else { -60.0 };
                                            format!("{:.0} dB", db)
                                        }
                                    }
                                }
                            }
                            
                            // High-pass Filter
                            div {
                                class: "settings-row checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    checked: "{settings_highpass_filter}",
                                    onchange: move |evt| {
                                        settings_highpass_filter.set(evt.checked());
                                    },
                                }
                                label {
                                    class: "settings-label",
                                    "High-pass Filter (removes rumble)"
                                }
                            }
                            
                            // Highpass Cutoff
                            if *settings_highpass_filter.read() {
                                div {
                                    class: "settings-row",
                                    label {
                                        class: "settings-label",
                                        "Cutoff Frequency"
                                    }
                                    input {
                                        class: "settings-slider",
                                        r#type: "range",
                                        min: "20",
                                        max: "300",
                                        value: "{*settings_highpass_cutoff.read() as i32}",
                                        oninput: move |evt| {
                                            if let Ok(val) = evt.value().parse::<f32>() {
                                                settings_highpass_cutoff.set(val.clamp(20.0, 300.0));
                                            }
                                        },
                                    }
                                    span {
                                        class: "settings-hint",
                                        "{*settings_highpass_cutoff.read() as i32} Hz"
                                    }
                                }
                            }
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                show_settings.set(false);
                            },
                            "Cancel"
                        }
                        button {
                            class: "send primary",
                            onclick: move |_| {
                                // Save global settings
                                let new_default_nick = settings_default_nick.read().trim().to_string();
                                let default_nick_opt = if new_default_nick.is_empty() {
                                    None
                                } else {
                                    Some(new_default_nick)
                                };
                                default_nick.set(default_nick_opt.clone());
                                
                                // Save active profile settings
                                let active = state.read().active_profile.clone();
                                let prof_idx_opt = profiles.read().iter().position(|p| p.name == active);
                                if let Some(prof_idx) = prof_idx_opt {
                                    let mut profs = profiles.write();
                                    profs[prof_idx].enable_logging = *settings_enable_logging.read();
                                    profs[prof_idx].scrollback_limit = *settings_scrollback_limit.read();
                                    profs[prof_idx].log_buffer_size = *settings_log_buffer_size.read();
                                    drop(profs);
                                }
                                
                                // Persist to disk
                                let store = profile::ProfileStore {
                                    profiles: profiles.read().clone(),
                                    last_used: last_used.read().clone(),
                                    default_nickname: default_nick_opt,
                                    show_timestamps: *settings_show_timestamps.read(),
                                    show_advanced: *settings_show_advanced.read(),
                                };
                                let _ = profile::save_store(&store);
                                
                                show_settings.set(false);
                            },
                            "Save"
                        }
                    }
                }
            }
        }

        // Channel Browser Modal
        // Nais Secure Channel modal
        if show_new_nsc_modal.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_new_nsc_modal.set(false);
                },
                div {
                    class: "modal",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "🔒 Secure Channels"
                    }
                    div {
                        class: "modal-body",
                        // Show identity fingerprint
                        div {
                            style: "margin-bottom: 16px; padding: 10px; background: rgba(99, 102, 241, 0.08); border-radius: 8px; font-size: 12px;",
                            div {
                                style: "color: var(--muted); margin-bottom: 4px;",
                                "Your Identity Fingerprint:"
                            }
                            div {
                                style: "font-family: monospace; word-break: break-all; color: var(--accent);",
                                "{nsc_fingerprint}"
                            }
                        }
                        
                        p {
                            style: "color: var(--muted); font-size: 13px; margin-bottom: 16px;",
                            "Create an end-to-end encrypted P2P channel. Messages never pass through IRC servers."
                        }
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Channel name (e.g., Private Chat)",
                            value: "{nsc_channel_name_input}",
                            disabled: *nsc_loading.read(),
                            oninput: move |evt| {
                                nsc_channel_name_input.set(evt.value());
                            },
                            onkeypress: move |evt| {
                                if evt.key() == Key::Enter && !*nsc_loading.read() {
                                    let name = nsc_channel_name_input.read().clone();
                                    let selected_network = nsc_selected_network.read().clone();
                                    // Use selected network or fall back to active profile
                                    let network = if selected_network.is_empty() {
                                        state.read().active_profile.clone()
                                    } else {
                                        selected_network
                                    };
                                    if !name.is_empty() && !network.is_empty() {
                                        nsc_loading.set(true);
                                        spawn(async move {
                                            let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                            let mgr = manager.read().await;
                                            match mgr.create_channel(name.clone(), network.clone()).await {
                                                Ok(info) => {
                                                    log::info!("Created NSC channel: {} ({}) on network '{}' with IRC discovery: {}", 
                                                        info.name, &info.channel_id[..8], info.network, &info.irc_channel);
                                                    
                                                    // Join the IRC channel for peer discovery on the selected network
                                                    let irc_channel = info.irc_channel.clone();
                                                    if let Some(core) = cores.read().get(&network) {
                                                        let _ = core.cmd_tx.try_send(irc_client::IrcCommandEvent::Join {
                                                            channel: irc_channel.clone(),
                                                        });
                                                        log::info!("Joined IRC discovery channel {} on network {}", irc_channel, network);
                                                    }
                                                    
                                                    // Refresh channel list
                                                    let channels = mgr.list_channels().await;
                                                    drop(mgr);
                                                    nsc_channels.set(channels);
                                                    nsc_channel_name_input.set(String::new());
                                                    show_new_nsc_modal.set(false);
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to create NSC channel: {}", e);
                                                }
                                            }
                                            nsc_loading.set(false);
                                        });
                                    }
                                }
                            },
                        }
                        
                        // Network selection dropdown
                        div {
                            style: "margin-top: 12px;",
                            div {
                                style: "color: var(--muted); font-size: 12px; margin-bottom: 4px;",
                                "IRC Network for Discovery:"
                            }
                            div {
                                style: "display: flex; flex-wrap: wrap; gap: 8px;",
                                for profile in profiles.read().iter().cloned() {
                                    {
                                        let profile_name = profile.name.clone();
                                        let is_selected = nsc_selected_network.read().clone() == profile_name || 
                                            (nsc_selected_network.read().is_empty() && state.read().active_profile == profile_name);
                                        rsx! {
                                            button {
                                                key: "{profile_name}",
                                                style: if is_selected {
                                                    "padding: 6px 12px; border-radius: 6px; background: var(--accent); color: white; border: none; cursor: pointer; font-size: 12px;"
                                                } else {
                                                    "padding: 6px 12px; border-radius: 6px; background: rgba(99, 102, 241, 0.1); color: var(--text); border: 1px solid rgba(99, 102, 241, 0.3); cursor: pointer; font-size: 12px;"
                                                },
                                                disabled: *nsc_loading.read(),
                                                onclick: move |_| {
                                                    nsc_selected_network.set(profile_name.clone());
                                                },
                                                "{profile.name}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Show existing secure channels
                        if !nsc_channels.read().is_empty() {
                            div {
                                style: "margin-top: 16px;",
                                div {
                                    style: "color: var(--muted); font-size: 12px; margin-bottom: 8px;",
                                    "Your Secure Channels:"
                                }
                                for channel in nsc_channels.read().iter().cloned() {
                                    {
                                        let channel_id = channel.channel_id.clone();
                                        let channel_id_for_button = channel.channel_id.clone();
                                        let irc_channel_display = channel.irc_channel.clone();
                                        let network_display = channel.network.clone();
                                        rsx! {
                                            div {
                                                key: "{channel_id}",
                                                style: "display: flex; flex-direction: column; padding: 8px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; margin-bottom: 4px;",
                                                div {
                                                    style: "display: flex; align-items: center; justify-content: space-between;",
                                                    div {
                                                        style: "display: flex; align-items: center; gap: 8px;",
                                                        span { "🔒" }
                                                        span { "{channel.name}" }
                                                        if channel.member_count > 1 {
                                                            span {
                                                                style: "color: var(--muted); font-size: 11px;",
                                                                "({channel.member_count} members)"
                                                            }
                                                        }
                                                    }
                                                    button {
                                                        style: "background: rgba(239, 68, 68, 0.2); color: #ef4444; border: none; padding: 4px 8px; border-radius: 4px; font-size: 11px; cursor: pointer;",
                                                        onclick: move |evt| {
                                                            evt.stop_propagation();
                                                            let cid = channel_id_for_button.clone();
                                                            log::info!("Leave button clicked for channel: {}", cid);
                                                            spawn(async move {
                                                                log::info!("Attempting to leave channel: {}", cid);
                                                                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                                let mgr = manager.read().await;
                                                                match mgr.leave_channel(&cid).await {
                                                                    Ok(()) => {
                                                                        log::info!("Successfully left channel: {}", cid);
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Failed to leave channel {}: {}", cid, e);
                                                                    }
                                                                }
                                                                // Always refresh channel list after leave attempt
                                                                let channels = mgr.list_channels().await;
                                                                log::info!("Refreshed channel list, {} channels remaining", channels.len());
                                                                drop(mgr);
                                                                nsc_channels.set(channels);
                                                                // Close the modal to give visual feedback
                                                                show_new_nsc_modal.set(false);
                                                            });
                                                        },
                                                        "Leave"
                                                    }
                                                }
                                                div {
                                                    style: "display: flex; align-items: center; gap: 6px; margin-top: 4px; padding-left: 24px;",
                                                    span {
                                                        style: "color: var(--muted); font-size: 11px;",
                                                        "Discovery:"
                                                    }
                                                    span {
                                                        style: "color: var(--accent); font-size: 11px; font-family: monospace;",
                                                        "{irc_channel_display}"
                                                    }
                                                    if !network_display.is_empty() {
                                                        span {
                                                            style: "color: var(--muted); font-size: 10px;",
                                                            "on"
                                                        }
                                                        span {
                                                            style: "color: var(--accent); font-size: 10px;",
                                                            "{network_display}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Show pending invites
                        if !nsc_pending_invites.read().is_empty() {
                            div {
                                style: "margin-top: 16px;",
                                div {
                                    style: "color: var(--muted); font-size: 12px; margin-bottom: 8px;",
                                    "Pending Invites:"
                                }
                                for invite in nsc_pending_invites.read().iter().cloned() {
                                    {
                                        let invite_id = invite.invite_id.clone();
                                        let invite_id_accept = invite.invite_id.clone();
                                        let invite_id_decline = invite.invite_id.clone();
                                        rsx! {
                                            div {
                                                key: "{invite_id}",
                                                style: "padding: 10px; background: rgba(76, 175, 80, 0.1); border: 1px solid rgba(76, 175, 80, 0.2); border-radius: 6px; margin-bottom: 4px;",
                                                div {
                                                    style: "display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;",
                                                    div {
                                                        style: "display: flex; align-items: center; gap: 8px;",
                                                        span { "📨" }
                                                        span { style: "font-weight: 500;", "{invite.from_nick}" }
                                                        span { style: "color: var(--muted);", "invites you to" }
                                                    }
                                                }
                                                div {
                                                    style: "display: flex; align-items: center; gap: 8px; margin-bottom: 8px;",
                                                    span { "🔒" }
                                                    span { style: "color: #4CAF50; font-weight: 500;", "{invite.channel_name}" }
                                                    if invite.member_count > 0 {
                                                        span {
                                                            style: "color: var(--muted); font-size: 11px;",
                                                            "({invite.member_count} members)"
                                                        }
                                                    }
                                                }
                                                if !invite.network.is_empty() {
                                                    div {
                                                        style: "margin-bottom: 8px; font-size: 11px; color: var(--muted);",
                                                        "Network: "
                                                        span { style: "color: var(--accent);", "{invite.network}" }
                                                    }
                                                }
                                                div {
                                                    style: "display: flex; gap: 8px;",
                                                    button {
                                                        style: "flex: 1; padding: 6px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 12px;",
                                                        onclick: move |_| {
                                                            let iid = invite_id_decline.clone();
                                                            spawn(async move {
                                                                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                                let mgr = manager.read().await;
                                                                match mgr.decline_invite(&iid).await {
                                                                    Ok((target_nick, ctcp_response)) => {
                                                                        // Send CTCP decline to inviter
                                                                        let active = state.read().active_profile.clone();
                                                                        if let Some(core) = cores.read().get(&active) {
                                                                            let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                                target: target_nick,
                                                                                message: ctcp_response,
                                                                            });
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Failed to decline invite: {}", e);
                                                                    }
                                                                }
                                                                let invites = mgr.get_pending_invites().await;
                                                                drop(mgr);
                                                                nsc_pending_invites.set(invites);
                                                            });
                                                        },
                                                        "Decline"
                                                    }
                                                    button {
                                                        style: "flex: 1; padding: 6px 12px; background: #4CAF50; border: none; border-radius: 4px; cursor: pointer; color: white; font-weight: 500; font-size: 12px;",
                                                        onclick: move |_| {
                                                            let iid = invite_id_accept.clone();
                                                            spawn(async move {
                                                                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                                let mgr = manager.read().await;
                                                                match mgr.accept_invite(&iid).await {
                                                                    Ok((target_nick, ctcp_response, irc_channel, network)) => {
                                                                        log::info!("Accepted invite, sending response to {} on network {}", target_nick, network);
                                                                        // Send CTCP response to inviter via the correct IRC network from the invite
                                                                        let profile_to_use = if !network.is_empty() {
                                                                            network.clone()
                                                                        } else {
                                                                            state.read().active_profile.clone()
                                                                        };
                                                                        if let Some(core) = cores.read().get(&profile_to_use) {
                                                                            // Send the accept response
                                                                            let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                                target: target_nick.clone(),
                                                                                message: ctcp_response,
                                                                            });
                                                                            // Join the IRC discovery channel for peer discovery on the correct network
                                                                            if !irc_channel.is_empty() {
                                                                                log::info!("Joining IRC discovery channel {} on network {}", irc_channel, profile_to_use);
                                                                                let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Join {
                                                                                    channel: irc_channel.clone(),
                                                                                });
                                                                            }
                                                                            
                                                                            // Probe the inviter directly to discover their peer info
                                                                            // Record pending probe so we can associate the response with this channel
                                                                            mgr.record_pending_probe(&target_nick, &irc_channel).await;
                                                                            let nsc_probe = mgr.create_probe_ctcp();
                                                                            if !nsc_probe.is_empty() {
                                                                                log::info!("Probing inviter {} for peer info (channel {})", target_nick, irc_channel);
                                                                                let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                                    target: target_nick.clone(),
                                                                                    message: nsc_probe.clone(),
                                                                                });
                                                                            }
                                                                            
                                                                            // Schedule discovery of all users in the IRC channel
                                                                            let irc_ch = irc_channel.clone();
                                                                            let profile_clone = profile_to_use.clone();
                                                                            let state_clone = state.clone();
                                                                            let cores_clone = cores.clone();
                                                                            spawn(async move {
                                                                                // Wait for NAMES to be received after joining
                                                                                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                                                                                
                                                                                // Get all users in the IRC channel and probe them
                                                                                let state_read = state_clone.read();
                                                                                let our_nick = state_read.servers.get(&profile_clone)
                                                                                    .map(|s| s.nickname.clone())
                                                                                    .unwrap_or_default();
                                                                                let users: Vec<String> = state_read.servers.get(&profile_clone)
                                                                                    .and_then(|s| s.users_by_channel.get(&irc_ch))
                                                                                    .map(|u| u.clone())
                                                                                    .unwrap_or_default();
                                                                                drop(state_read);
                                                                                
                                                                                if !users.is_empty() {
                                                                                    let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                                                    let mgr = manager.read().await;
                                                                                    
                                                                                    // Clean user list and record pending probes
                                                                                    let clean_users: Vec<String> = users.iter()
                                                                                        .map(|u| u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~').to_string())
                                                                                        .filter(|u| *u != our_nick)
                                                                                        .collect();
                                                                                    
                                                                                    mgr.record_pending_probes(&clean_users, &irc_ch).await;
                                                                                    let nsc_probe = mgr.create_probe_ctcp();
                                                                                    drop(mgr);
                                                                                    
                                                                                    if !nsc_probe.is_empty() {
                                                                                        if let Some(core) = cores_clone.read().get(&profile_clone) {
                                                                                            for clean_user in clean_users {
                                                                                                log::info!("Probing user {} in channel {} for peer discovery", clean_user, irc_ch);
                                                                                                let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                                                    target: clean_user.to_string(),
                                                                                                    message: nsc_probe.clone(),
                                                                                                });
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        } else {
                                                                            log::warn!("Network '{}' not connected, cannot send accept response", profile_to_use);
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Failed to accept invite: {}", e);
                                                                    }
                                                                }
                                                                let invites = mgr.get_pending_invites().await;
                                                                let channels = mgr.list_channels().await;
                                                                drop(mgr);
                                                                nsc_pending_invites.set(invites);
                                                                nsc_channels.set(channels);
                                                            });
                                                        },
                                                        "Accept"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Loading indicator
                        if *nsc_loading.read() {
                            div {
                                style: "text-align: center; padding: 10px; color: var(--muted);",
                                "Creating channel..."
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                show_new_nsc_modal.set(false);
                            },
                            "Close"
                        }
                        button {
                            class: "send primary",
                            disabled: *nsc_loading.read() || nsc_channel_name_input.read().is_empty(),
                            onclick: move |_| {
                                let name = nsc_channel_name_input.read().clone();
                                let selected_network = nsc_selected_network.read().clone();
                                // Use selected network or fall back to active profile
                                let network = if selected_network.is_empty() {
                                    state.read().active_profile.clone()
                                } else {
                                    selected_network
                                };
                                if !name.is_empty() && !network.is_empty() && !*nsc_loading.read() {
                                    nsc_loading.set(true);
                                    spawn(async move {
                                        let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                        let mgr = manager.read().await;
                                        match mgr.create_channel(name.clone(), network.clone()).await {
                                            Ok(info) => {
                                                log::info!("Created NSC channel: {} ({}) on network '{}'", info.name, &info.channel_id[..8], info.network);
                                                
                                                // Join the IRC discovery channel for peer discovery on the selected network
                                                let irc_channel = info.irc_channel.clone();
                                                if !irc_channel.is_empty() {
                                                    if let Some(core) = cores.read().get(&network) {
                                                        log::info!("Joining IRC discovery channel {} on network {}", irc_channel, network);
                                                        let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Join {
                                                            channel: irc_channel.clone(),
                                                        });
                                                        
                                                        // Schedule discovery of all users in the IRC channel
                                                        let irc_ch = irc_channel.clone();
                                                        let profile_clone = network.clone();
                                                        let state_clone = state.clone();
                                                        let cores_clone = cores.clone();
                                                        spawn(async move {
                                                            // Wait for NAMES to be received after joining
                                                            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                                                            
                                                            // Get all users in the IRC channel and probe them
                                                            let state_read = state_clone.read();
                                                            let our_nick = state_read.servers.get(&profile_clone)
                                                                .map(|s| s.nickname.clone())
                                                                .unwrap_or_default();
                                                            let users: Vec<String> = state_read.servers.get(&profile_clone)
                                                                .and_then(|s| s.users_by_channel.get(&irc_ch))
                                                                .map(|u| u.clone())
                                                                .unwrap_or_default();
                                                            drop(state_read);
                                                            
                                                            if !users.is_empty() {
                                                                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                                let mgr = manager.read().await;
                                                                
                                                                // Clean user list and record pending probes
                                                                let clean_users: Vec<String> = users.iter()
                                                                    .map(|u| u.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~').to_string())
                                                                    .filter(|u| *u != our_nick)
                                                                    .collect();
                                                                
                                                                mgr.record_pending_probes(&clean_users, &irc_ch).await;
                                                                let nsc_probe = mgr.create_probe_ctcp();
                                                                drop(mgr);
                                                                
                                                                if !nsc_probe.is_empty() {
                                                                    if let Some(core) = cores_clone.read().get(&profile_clone) {
                                                                        for clean_user in clean_users {
                                                                            log::info!("Probing user {} in channel {} for peer discovery (new channel)", clean_user, irc_ch);
                                                                            let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                                target: clean_user.to_string(),
                                                                                message: nsc_probe.clone(),
                                                                            });
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                                
                                                // Refresh channel list
                                                let channels = mgr.list_channels().await;
                                                drop(mgr);
                                                nsc_channels.set(channels);
                                                nsc_channel_name_input.set(String::new());
                                            }
                                            Err(e) => {
                                                log::error!("Failed to create NSC channel: {}", e);
                                            }
                                        }
                                        nsc_loading.set(false);
                                    });
                                }
                            },
                            "Create Channel"
                        }
                    }
                }
            }
        }

        // NSC Invite Channel Selection Modal
        if let Some((invite_nick, invite_profile)) = nsc_invite_modal.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    nsc_invite_modal.set(None);
                },
                div {
                    class: "modal",
                    style: "width: min(400px, 90vw);",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "🔒 Invite {invite_nick} to Secure Channel"
                    }
                    div {
                        class: "modal-body",
                        p {
                            style: "color: var(--muted); font-size: 13px; margin-bottom: 16px;",
                            "Select a channel to invite the user to:"
                        }
                        div {
                            style: "display: flex; flex-direction: column; gap: 8px;",
                            for channel in nsc_channels.read().iter().cloned() {
                                {
                                    let channel_id = channel.channel_id.clone();
                                    let channel_name = channel.name.clone();
                                    let nick_for_invite = invite_nick.clone();
                                    let profile_for_invite = invite_profile.clone();
                                    rsx! {
                                        button {
                                            key: "{channel_id}",
                                            class: "menu-item",
                                            style: "display: flex; align-items: center; gap: 8px; padding: 12px; background: rgba(99, 102, 241, 0.1); border-radius: 8px; border: 1px solid transparent; cursor: pointer; text-align: left; width: 100%;",
                                            onclick: move |_| {
                                                log::info!("Sending NSC invite to {} for channel '{}'", nick_for_invite, channel_name);
                                                let nick = nick_for_invite.clone();
                                                let profile = profile_for_invite.clone();
                                                let cid = channel_id.clone();
                                                let cname = channel_name.clone();
                                                let cores_clone = cores.clone();
                                                
                                                nsc_invite_modal.set(None);
                                                
                                                spawn(async move {
                                                    let manager = crate::nsc_manager::get_nsc_manager_async().await;
                                                    let mgr = manager.read().await;
                                                    
                                                    // Send probe first
                                                    let probe = mgr.create_probe_ctcp();
                                                    if !probe.is_empty() {
                                                        log::info!("Sending NSC probe to {}", nick);
                                                        if let Some(core) = cores_clone.read().get(&profile) {
                                                            let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                target: nick.clone(),
                                                                message: probe,
                                                            });
                                                        }
                                                    }
                                                    
                                                    // Create and send invite
                                                    match mgr.create_invite_ctcp(&nick, &cid).await {
                                                        Ok(invite_ctcp) => {
                                                            log::info!("Sending NSC invite CTCP to {}: {} chars", nick, invite_ctcp.len());
                                                            if let Some(core) = cores_clone.read().get(&profile) {
                                                                let _ = core.cmd_tx.try_send(crate::irc_client::IrcCommandEvent::Ctcp {
                                                                    target: nick.clone(),
                                                                    message: invite_ctcp,
                                                                });
                                                            }
                                                            log::info!("Sent NSC invite to {} for channel '{}'", nick, cname);
                                                        }
                                                        Err(e) => {
                                                            log::error!("Failed to create NSC invite: {}", e);
                                                        }
                                                    }
                                                });
                                            },
                                            span { "🔒" }
                                            div {
                                                style: "display: flex; flex-direction: column;",
                                                span {
                                                    style: "font-weight: 500;",
                                                    "{channel.name}"
                                                }
                                                if channel.member_count > 1 {
                                                    span {
                                                        style: "font-size: 11px; color: var(--muted);",
                                                        "{channel.member_count} members"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                nsc_invite_modal.set(None);
                            },
                            "Cancel"
                        }
                    }
                }
            }
        }

        if show_channel_browser.read().clone() {
            div {
                class: "modal-backdrop",
                onclick: move |_| {
                    show_channel_browser.set(false);
                },
                div {
                    class: "modal",
                    style: "width:min(700px, 90vw); max-height:80vh;",
                    onclick: move |evt| {
                        evt.stop_propagation();
                    },
                    div {
                        class: "modal-title",
                        "Browse Channels"
                    }
                    div {
                        class: "modal-body",
                        style: "display:flex; flex-direction:column; gap:12px;",
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Search channels...",
                            value: "{channel_search_input}",
                            oninput: move |evt| {
                                channel_search_input.set(evt.value());
                            },
                        }
                        if *list_loading.read() {
                            div {
                                style: "text-align:center; padding:20px; color:var(--muted);",
                                "Loading channel list..."
                            }
                        } else {
                            div {
                                style: "max-height:400px; overflow-y:auto;",
                                {
                                    let search_term = channel_search_input.read().to_lowercase();
                                    let mut filtered_channels: Vec<_> = channel_list.read()
                                        .iter()
                                        .filter(|(name, _, topic)| {
                                            if search_term.is_empty() {
                                                true
                                            } else {
                                                name.to_lowercase().contains(&search_term) ||
                                                topic.to_lowercase().contains(&search_term)
                                            }
                                        })
                                        .cloned()
                                        .collect();
                                    
                                    // Sort by user count descending
                                    filtered_channels.sort_by(|a, b| b.1.cmp(&a.1));
                                    
                                    rsx! {
                                        for (channel_name, user_count, topic) in filtered_channels.iter().take(100) {
                                            {
                                                let channel_name_clone = channel_name.clone();
                                                let channel_name_for_join = channel_name.clone();
                                                rsx! {
                                                    div {
                                                        key: "{channel_name}",
                                                        class: "import-row",
                                                        style: "cursor:pointer; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--panel);",
                                                        onclick: move |_| {
                                                            let active_profile_name = state.read().active_profile.clone();
                                                            
                                                            // Send JOIN command
                                                            let cores_read = cores.read();
                                                            if let Some(handle) = cores_read.get(&active_profile_name) {
                                                                let cmd_tx = handle.cmd_tx.clone();
                                                                let chan = channel_name_for_join.clone();
                                                                drop(cores_read);
                                                                spawn(async move {
                                                                    let _ = cmd_tx.send(irc_client::IrcCommandEvent::Join {
                                                                        channel: chan,
                                                                    }).await;
                                                                });
                                                            } else {
                                                                drop(cores_read);
                                                            }
                                                            
                                                            // Update profile to add this channel to autojoin list
                                                            let mut profs = profiles.write();
                                                            if let Some(prof) = profs.iter_mut().find(|p| p.name == active_profile_name) {
                                                                // Add channel to comma-separated list if not already present
                                                                let channels: Vec<&str> = prof.channel.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                                                                if !channels.contains(&channel_name_clone.as_str()) {
                                                                    if prof.channel.is_empty() {
                                                                        prof.channel = channel_name_clone.clone();
                                                                    } else {
                                                                        prof.channel = format!("{},{}", prof.channel, channel_name_clone);
                                                                    }
                                                                }
                                                            }
                                                            drop(profs);
                                                            
                                                            // Save the store
                                                            let store = profile::ProfileStore {
                                                                profiles: profiles.read().clone(),
                                                                last_used: last_used.read().clone(),
                                                                default_nickname: default_nick.read().clone(),
                                                                show_timestamps: *settings_show_timestamps.read(),
                                                                show_advanced: *settings_show_advanced.read(),
                                                            };
                                                            let _ = profile::save_store(&store);
                                                            
                                                            show_channel_browser.set(false);
                                                        },
                                                        div {
                                                            class: "import-main",
                                                            div {
                                                                style: "display:flex; justify-content:space-between; align-items:center;",
                                                                div {
                                                                    class: "import-name",
                                                                    style: "font-weight:600;",
                                                                    "{channel_name}"
                                                                }
                                                                div {
                                                                    style: "color:var(--muted); font-size:12px;",
                                                                    "{user_count} users"
                                                                }
                                                            }
                                                            if !topic.is_empty() {
                                                                div {
                                                                    class: "import-meta",
                                                                    style: "margin-top:4px; font-size:12px; color:var(--muted);",
                                                                    "{topic}"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if filtered_channels.is_empty() && !search_term.is_empty() {
                                            div {
                                                style: "text-align:center; padding:20px; color:var(--muted);",
                                                "No channels found matching \"{search_term}\""
                                            }
                                        }
                                        if filtered_channels.len() > 100 {
                                            div {
                                                style: "text-align:center; padding:12px; color:var(--muted); font-size:12px;",
                                                "Showing first 100 of {filtered_channels.len()} channels. Use search to refine."
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div {
                        class: "modal-actions",
                        button {
                            class: "send",
                            onclick: move |_| {
                                // Refresh channel list
                                let active_profile = state.read().active_profile.clone();
                                channel_list.set(Vec::new());
                                list_loading.set(true);
                                
                                let cores_read = cores.read();
                                if let Some(handle) = cores_read.get(&active_profile) {
                                    let cmd_tx = handle.cmd_tx.clone();
                                    drop(cores_read);
                                    spawn(async move {
                                        let _ = cmd_tx.send(irc_client::IrcCommandEvent::List).await;
                                    });
                                } else {
                                    drop(cores_read);
                                }
                            },
                            "Refresh"
                        }
                        button {
                            class: "send",
                            onclick: move |_| {
                                show_channel_browser.set(false);
                            },
                            "Close"
                        }
                    }
                }
            }
        }
    }
}

fn handle_send_message(
    text: String,
    mut state: Signal<irc_client::AppState>,
    mut input: Signal<String>,
    mut history: Signal<Vec<String>>,
    mut history_index: Signal<Option<usize>>,
    cores: Signal<HashMap<String, irc_client::CoreHandle>>,
    mut profiles: Signal<Vec<profile::Profile>>,
    last_used: Signal<Option<String>>,
    mut force_scroll_to_bottom: Signal<bool>,
    default_nick: Option<String>,
    mut voice_state: Signal<crate::voice_chat::VoiceState>,
    mut voice_session_id: Signal<Option<String>>,
    mut voice_current_peer: Signal<Option<String>>,
    mut voice_local_port: Signal<u16>,
    mut voice_external_ip: Signal<String>,
    voice_muted_arc: Signal<std::sync::Arc<std::sync::Mutex<bool>>>,
    mut voice_event_rx: Signal<Option<async_channel::Receiver<crate::voice_chat::VoiceEvent>>>,
    mut voice_stop_flag: Signal<Option<std::sync::Arc<std::sync::Mutex<bool>>>>,
    mut voice_peer_addr_tx: Signal<Option<async_channel::Sender<(String, u16)>>>,
    settings_show_timestamps: Signal<bool>,
    settings_show_advanced: Signal<bool>,
    nsc_current_channel: Signal<Option<String>>,
    mut nsc_messages: Signal<HashMap<String, Vec<(u64, String, String)>>>,
    nsc_fingerprint: Signal<String>,
) {
    let text = text.trim().to_string();
    if text.is_empty() {
        return;
    }

    {
        let mut items = history.write();
        if items.last().map(|last| last != &text).unwrap_or(true) {
            items.push(text.clone());
        }
    }
    history_index.set(None);

    // Handle NSC channel messages
    if let Some(channel_id) = nsc_current_channel.read().clone() {
        // For NSC channels, only handle regular messages (not commands)
        if !text.starts_with('/') {
            let text_clone = text.clone();
            let channel_id_clone = channel_id.clone();
            
            // Send via NSC transport layer
            spawn(async move {
                let manager = crate::nsc_manager::get_nsc_manager_async().await;
                let mgr = manager.read().await;
                
                // Initialize transport if not already done
                if !mgr.is_transport_running().await {
                    if let Err(e) = mgr.init_transport().await {
                        log::error!("Failed to init transport: {}", e);
                    }
                }
                
                // Send the message (this broadcasts to connected peers)
                match mgr.send_message(&channel_id_clone, text_clone.clone()).await {
                    Ok(msg) => {
                        // Add to local messages for display
                        let mut msgs = nsc_messages.write();
                        let channel_msgs = msgs.entry(channel_id_clone).or_insert_with(Vec::new);
                        channel_msgs.push((msg.timestamp, msg.sender, msg.text));
                    }
                    Err(e) => {
                        log::error!("Failed to send NSC message: {}", e);
                        // Still add locally so user sees their message
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let sender = nsc_fingerprint.read().clone();
                        let sender_short = if sender.len() > 8 { sender[..8].to_string() } else { sender };
                        let mut msgs = nsc_messages.write();
                        let channel_msgs = msgs.entry(channel_id_clone).or_insert_with(Vec::new);
                        channel_msgs.push((timestamp, sender_short, text_clone));
                    }
                }
                
                force_scroll_to_bottom.set(true);
            });
            
            input.set(String::new());
            return;
        }
    }

    let active_profile = state.read().active_profile.clone();
    let server_state = state.read().servers.get(&active_profile).cloned();
    let Some(server_state) = server_state else {
        return;
    };
    let channel = server_state.current_channel.clone();
    let nickname = server_state.nickname.clone();
    let handle = cores.read().get(&active_profile).cloned();

    if text.starts_with('/') {
        let mut parts = text.splitn(2, ' ');
        let command = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().unwrap_or("").trim().to_string();
        
        // NSC commands (work in any channel)
        if command == "/nsc" {
            let mut nsc_parts = arg.splitn(2, ' ');
            let subcommand = nsc_parts.next().unwrap_or("").to_lowercase();
            let subarg = nsc_parts.next().unwrap_or("").trim().to_string();
            
            match subcommand.as_str() {
                "info" | "status" => {
                    // Show NSC info
                    spawn(async move {
                        let manager = crate::nsc_manager::get_nsc_manager_async().await;
                        let mgr = manager.read().await;
                        
                        let peer_id = mgr.peer_id_hex();
                        let fingerprint = mgr.fingerprint();
                        let port = mgr.local_port().await;
                        let peer_count = mgr.connected_peer_count().await;
                        
                        let port_str = port.map(|p| p.to_string()).unwrap_or_else(|| "not running".to_string());
                        
                        // Add system message to current channel
                        let info = format!(
                            "NSC Info:\n  Fingerprint: {}\n  Peer ID: {}...\n  Listening: port {}\n  Connected peers: {}",
                            fingerprint, &peer_id[..16], port_str, peer_count
                        );
                        
                        // Display in NSC channel if selected, otherwise show in IRC channel
                        if let Some(nsc_ch) = nsc_current_channel.read().clone() {
                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let mut msgs = nsc_messages.write();
                            let channel_msgs = msgs.entry(nsc_ch).or_insert_with(Vec::new);
                            channel_msgs.push((timestamp, "System".to_string(), info));
                        } else {
                            let active_profile_local = state.read().active_profile.clone();
                            let channel_local = state.read().servers.get(&active_profile_local)
                                .map(|s| s.current_channel.clone())
                                .unwrap_or_default();
                            apply_event_with_config(
                                &mut state.write(),
                                &profiles.read(),
                                &active_profile_local,
                                IrcEvent::System {
                                    channel: channel_local,
                                    text: info,
                                },
                            );
                        }
                    });
                    input.set(String::new());
                    return;
                }
                "connect" => {
                    // Connect to a peer
                    if subarg.is_empty() {
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel,
                                text: "Usage: /nsc connect <ip:port> [peer_id]".to_string(),
                            },
                        );
                    } else {
                        let addr_str = subarg.clone();
                        spawn(async move {
                            let manager = crate::nsc_manager::get_nsc_manager_async().await;
                            let mgr = manager.read().await;
                            
                            // Parse address
                            let addr: std::net::SocketAddr = match addr_str.parse() {
                                Ok(a) => a,
                                Err(_) => {
                                    log::error!("Invalid address: {}", addr_str);
                                    return;
                                }
                            };
                            
                            // Use a placeholder peer ID for now (peer will identify itself)
                            let peer_id_placeholder = "0".repeat(64);
                            
                            match mgr.connect_to_peer(&peer_id_placeholder, addr).await {
                                Ok(_) => {
                                    log::info!("Connected to {}", addr);
                                    // Add system message
                                    if let Some(nsc_ch) = nsc_current_channel.read().clone() {
                                        let timestamp = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_secs())
                                            .unwrap_or(0);
                                        let mut msgs = nsc_messages.write();
                                        let channel_msgs = msgs.entry(nsc_ch).or_insert_with(Vec::new);
                                        channel_msgs.push((timestamp, "System".to_string(), format!("Connected to {}", addr)));
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to connect: {}", e);
                                }
                            }
                        });
                    }
                    input.set(String::new());
                    return;
                }
                "peers" => {
                    // List connected peers
                    spawn(async move {
                        let manager = crate::nsc_manager::get_nsc_manager_async().await;
                        let mgr = manager.read().await;
                        
                        let peer_count = mgr.connected_peer_count().await;
                        let addresses = mgr.get_peer_addresses().await;
                        
                        let mut info = format!("Connected peers: {}", peer_count);
                        for (peer_id, addr) in addresses.iter() {
                            info.push_str(&format!("\n  {} @ {}", &peer_id[..8], addr));
                        }
                        
                        if let Some(nsc_ch) = nsc_current_channel.read().clone() {
                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let mut msgs = nsc_messages.write();
                            let channel_msgs = msgs.entry(nsc_ch).or_insert_with(Vec::new);
                            channel_msgs.push((timestamp, "System".to_string(), info));
                        } else {
                            let active_profile_local = state.read().active_profile.clone();
                            let channel_local = state.read().servers.get(&active_profile_local)
                                .map(|s| s.current_channel.clone())
                                .unwrap_or_default();
                            apply_event_with_config(
                                &mut state.write(),
                                &profiles.read(),
                                &active_profile_local,
                                IrcEvent::System {
                                    channel: channel_local,
                                    text: info,
                                },
                            );
                        }
                    });
                    input.set(String::new());
                    return;
                }
                "help" | "" => {
                    let help_text = "NSC Commands:\n  /nsc info - Show your NSC info (fingerprint, port)\n  /nsc connect <ip:port> - Connect to a peer\n  /nsc peers - List connected peers";
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel: channel.clone(),
                            text: help_text.to_string(),
                        },
                    );
                    input.set(String::new());
                    return;
                }
                _ => {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Unknown NSC command: {}. Use /nsc help for available commands.", subcommand),
                        },
                    );
                    input.set(String::new());
                    return;
                }
            }
        }
        match command.as_str() {
            "/join" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /join #channel".to_string(),
                        },
                    );
                } else {
                    let target = if arg.starts_with('#') {
                        arg.clone()
                    } else {
                        format!("#{arg}")
                    };
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Join {
                            channel: target.clone(),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::Joined { channel: target.clone() },
                    );
                    
                    // Add channel to autojoin list
                    let mut profs_mut = profiles.write();
                    if let Some(prof) = profs_mut.iter_mut().find(|p| p.name == active_profile) {
                        let channels: Vec<&str> = prof.channel.split(',').map(|s: &str| s.trim()).filter(|s: &&str| !s.is_empty()).collect();
                        if !channels.contains(&target.as_str()) {
                            if prof.channel.is_empty() {
                                prof.channel = target.clone();
                            } else {
                                prof.channel = format!("{},{}", prof.channel, target);
                            }
                            // Save the updated profile
                            drop(profs_mut);
                            let store = profile::ProfileStore {
                                profiles: profiles.read().clone(),
                                last_used: last_used.read().clone(),
                                default_nickname: default_nick.clone(),
                                show_timestamps: *settings_show_timestamps.read(),
                                show_advanced: *settings_show_advanced.read(),
                            };
                            let _ = profile::save_store(&store);
                        } else {
                            drop(profs_mut);
                        }
                    } else {
                        drop(profs_mut);
                    }
                }
            }
            "/part" => {
                let mut part_parts = arg.splitn(2, ' ');
                let target_raw = part_parts.next().unwrap_or("").trim();
                let reason = part_parts.next().map(|val| val.trim().to_string());
                let target = if target_raw.is_empty() {
                    channel.clone()
                } else if target_raw.starts_with('#') {
                    target_raw.to_string()
                } else {
                    format!("#{target_raw}")
                };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Part {
                        channel: target.clone(),
                        reason: reason.clone(),
                    });
                }
                apply_event_with_config(
                    &mut state.write(),
                        &profiles.read(),
                    &active_profile,
                    IrcEvent::Parted { channel: target.clone() },
                );
                
                // Remove channel from autojoin list
                let mut profs_mut = profiles.write();
                if let Some(prof) = profs_mut.iter_mut().find(|p| p.name == active_profile) {
                    let channels: Vec<String> = prof.channel
                        .split(',')
                        .map(|s: &str| s.trim())
                        .filter(|s: &&str| !s.is_empty() && s != &target.as_str())
                        .map(|s: &str| s.to_string())
                        .collect();
                    prof.channel = channels.join(",");
                    drop(profs_mut);
                    // Save the updated profile
                    let store = profile::ProfileStore {
                        profiles: profiles.read().clone(),
                        last_used: last_used.read().clone(),
                        default_nickname: default_nick.clone(),
                        show_timestamps: *settings_show_timestamps.read(),
                        show_advanced: *settings_show_advanced.read(),
                    };
                    let _ = profile::save_store(&store);
                } else {
                    drop(profs_mut);
                }
            }
            "/nick" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /nick newname".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Nick {
                            nickname: arg.clone(),
                        });
                    }
                    if let Some(server_state) = state.write().servers.get_mut(&active_profile) {
                        server_state.nickname = arg.clone();
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Nickname set to {arg}."),
                        },
                    );
                }
            }
            "/me" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /me action".to_string(),
                        },
                    );
                } else {
                    let action = format!("\u{1}ACTION {arg}\u{1}");
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Send {
                            channel: channel.clone(),
                            text: action,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::Message {
                            channel,
                            user: nickname.clone(),
                            text: format!("* {nickname} {arg}"),
                        },
                    );
                }
            }
            "/whois" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /whois nickname".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Whois {
                            nickname: arg.clone(),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("WHOIS requested for {arg}..."),
                        },
                    );
                }
            }
            "/who" => {
                let target = if arg.is_empty() {
                    channel.clone()
                } else {
                    arg.clone()
                };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Who {
                        target: target.clone(),
                    });
                }
                apply_event_with_config(
                    &mut state.write(),
                        &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: format!("WHO requested for {target}..."),
                    },
                );
            }
            "/topic" => {
                let mut topic_parts = arg.splitn(2, ' ');
                let first = topic_parts.next().unwrap_or("").trim();
                let rest = topic_parts.next().map(|val| val.trim().to_string());
                let (target, topic) = if first.starts_with('#') {
                    let topic = rest.filter(|val| !val.is_empty());
                    (first.to_string(), topic)
                } else {
                    let topic = if arg.is_empty() { None } else { Some(arg.clone()) };
                    (channel.clone(), topic)
                };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Topic {
                        channel: target.clone(),
                        topic: topic.clone(),
                    });
                }
                let note = topic
                    .map(|value| format!("Topic set: {value}"))
                    .unwrap_or_else(|| "Topic requested.".to_string());
                apply_event_with_config(
                    &mut state.write(),
                        &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: format!("{target}: {note}"),
                    },
                );
            }
            "/msg" | "/query" => {
                let mut msg_parts = arg.splitn(2, ' ');
                let target = msg_parts.next().unwrap_or("").trim().to_string();
                let text = msg_parts.next().unwrap_or("").trim().to_string();
                
                if target.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /msg nickname message or /query nickname".to_string(),
                        },
                    );
                } else if text.is_empty() && command == "/query" {
                    // /query without message - just open PM window
                    {
                        let mut state_write = state.write();
                        if let Some(server) = state_write.servers.get_mut(&active_profile) {
                            if !server.channels.contains(&target) {
                                server.channels.push(target.clone());
                            }
                            server.current_channel = target.clone();
                        }
                    }
                    force_scroll_to_bottom.set(true);
                    // Focus the chat input
                    let _ = document::eval(
                        r#"
                        const input = document.getElementById('chat-input');
                        if (input) input.focus();
                        "#
                    );
                } else if text.is_empty() {
                    // /msg without message - show error
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /msg nickname message".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Msg {
                            target: target.clone(),
                            text: text.clone(),
                        });
                    }
                    // The event will be sent from the backend when message is sent
                }
            }
            "/notice" => {
                let mut notice_parts = arg.splitn(2, ' ');
                let target = notice_parts.next().unwrap_or("").trim().to_string();
                let text = notice_parts.next().unwrap_or("").trim().to_string();
                if target.is_empty() || text.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /notice target message".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Notice {
                            target,
                            text,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "NOTICE sent.".to_string(),
                        },
                    );
                }
            }
            "/kick" => {
                let mut kick_parts = arg.splitn(2, ' ');
                let user = kick_parts.next().unwrap_or("").trim().to_string();
                let reason = kick_parts.next().map(|val| val.trim().to_string());
                if user.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /kick user [reason]".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Kick {
                            channel: channel.clone(),
                            user,
                            reason,
                        });
                    }
                }
            }
            "/mode" => {
                let mut mode_parts = arg.splitn(2, ' ');
                let target_or_mode = mode_parts.next().unwrap_or("").trim().to_string();
                let rest = mode_parts.next().map(|val| val.trim().to_string());
                
                if target_or_mode.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /mode [target] modes [args]".to_string(),
                        },
                    );
                } else {
                    // If target_or_mode starts with # or is a single letter, determine target/modes
                    let (target, modes, args) = if target_or_mode.starts_with('#') {
                        // Target specified explicitly
                        if let Some(rest) = rest {
                            let mut parts = rest.splitn(2, ' ');
                            let modes = parts.next().unwrap_or("").to_string();
                            let args = parts.next().map(|s| s.to_string());
                            (target_or_mode, modes, args)
                        } else {
                            (target_or_mode, String::new(), None)
                        }
                    } else {
                        // No target, use current channel
                        (channel.clone(), target_or_mode, rest)
                    };
                    
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target,
                            modes,
                            args,
                        });
                    }
                }
            }
            "/invite" => {
                let mut invite_parts = arg.splitn(2, ' ');
                let user = invite_parts.next().unwrap_or("").trim().to_string();
                let target_channel = invite_parts.next().map(|val| val.trim().to_string());
                
                if user.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /invite user [#channel]".to_string(),
                        },
                    );
                } else {
                    let invite_channel = target_channel.unwrap_or_else(|| channel.clone());
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Invite {
                            nickname: user.clone(),
                            channel: invite_channel.clone(),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Inviting {user} to {invite_channel}..."),
                        },
                    );
                }
            }
            "/away" => {
                let message = if arg.is_empty() { None } else { Some(arg.clone()) };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Away {
                        message: message.clone(),
                    });
                }
                let status_text = if message.is_some() {
                    "Away status set.".to_string()
                } else {
                    "Away status cleared.".to_string()
                };
                apply_event_with_config(
                    &mut state.write(),
                        &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: status_text,
                    },
                );
            }
            "/voice" | "/call" => {
                // Voice call command: /voice <nickname>
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel: channel.clone(),
                            text: "Usage: /voice <nickname> - Start a voice call with a user".to_string(),
                        },
                    );
                } else {
                    let target_nick = arg.clone();
                    // Check if already in a call
                    let current_voice_state = voice_state();
                    if !matches!(current_voice_state, crate::voice_chat::VoiceState::Idle) {
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel: channel.clone(),
                                text: "Already in a voice call. End the current call first.".to_string(),
                            },
                        );
                    } else {
                        // Generate session ID
                        let session_id = crate::voice_chat::VoiceChatManager::generate_session_id();
                        
                        // Start voice listener to get a port and external IP
                        let config = crate::voice_chat::VoiceConfig::default();
                        let muted_arc_clone = voice_muted_arc.read().clone();
                        
                        if let Some((external_ip, port, evt_rx, stop_flag, peer_tx)) = crate::voice_chat::start_voice_listener(config, muted_arc_clone) {
                            voice_external_ip.set(external_ip.clone());
                            voice_local_port.set(port);
                            voice_event_rx.set(Some(evt_rx));
                            voice_stop_flag.set(Some(stop_flag));
                            voice_peer_addr_tx.set(Some(peer_tx));
                            
                            // Update voice state
                            voice_state.set(crate::voice_chat::VoiceState::Outgoing { peer: target_nick.clone() });
                            voice_session_id.set(Some(session_id.clone()));
                            voice_current_peer.set(Some(target_nick.clone()));
                            
                            // Send CTCP VOICE_CALL via IRC
                            let ctcp_msg = crate::voice_chat::create_voice_call_ctcp(&external_ip, port, &session_id);
                            if let Some(h) = handle.as_ref() {
                                let _ = h.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                    target: target_nick.clone(),
                                    message: ctcp_msg,
                                });
                            }
                            
                            apply_event_with_config(
                                &mut state.write(),
                                &profiles.read(),
                                &active_profile,
                                IrcEvent::System {
                                    channel: channel.clone(),
                                    text: format!("Calling {} at {}:{}...", target_nick, external_ip, port),
                                },
                            );
                        } else {
                            apply_event_with_config(
                                &mut state.write(),
                                &profiles.read(),
                                &active_profile,
                                IrcEvent::System {
                                    channel: channel.clone(),
                                    text: "Failed to start voice listener".to_string(),
                                },
                            );
                        }
                    }
                }
            }
            "/hangup" | "/endcall" => {
                // End current voice call
                let current_voice_state = voice_state();
                match current_voice_state {
                    crate::voice_chat::VoiceState::Active { peer } |
                    crate::voice_chat::VoiceState::Outgoing { peer } => {
                        // Send cancel CTCP
                        if let Some(sid) = voice_session_id() {
                            let ctcp_msg = crate::voice_chat::create_voice_cancel_ctcp(&sid);
                            if let Some(h) = handle.as_ref() {
                                let _ = h.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                    target: peer.clone(),
                                    message: ctcp_msg,
                                });
                            }
                        }
                        
                        // Stop the audio stream
                        if let Some(stop_flag) = voice_stop_flag() {
                            if let Ok(mut stopped) = stop_flag.lock() {
                                *stopped = true;
                            }
                        }
                        
                        voice_state.set(crate::voice_chat::VoiceState::Idle);
                        voice_current_peer.set(None);
                        voice_session_id.set(None);
                        voice_event_rx.set(None);
                        voice_stop_flag.set(None);
                        
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel: channel.clone(),
                                text: "Voice call ended.".to_string(),
                            },
                        );
                    }
                    _ => {
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel: channel.clone(),
                                text: "No active voice call.".to_string(),
                            },
                        );
                    }
                }
            }
            "/quit" | "/disconnect" => {
                let message = if arg.is_empty() { None } else { Some(arg.clone()) };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Quit {
                        message: message.clone(),
                    });
                }
                let quit_text = message
                    .map(|m| format!("Disconnecting: {}", m))
                    .unwrap_or_else(|| "Disconnecting...".to_string());
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: quit_text,
                    },
                );
            }
            "/list" => {
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::List);
                }
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: "Fetching channel list...".to_string(),
                    },
                );
            }
            "/ctcp" => {
                let mut ctcp_parts = arg.splitn(3, ' ');
                let target = ctcp_parts.next().unwrap_or("").trim().to_string();
                let ctcp_cmd = ctcp_parts.next().unwrap_or("").trim().to_uppercase();
                let ctcp_args = ctcp_parts.next().unwrap_or("").trim().to_string();
                
                if target.is_empty() || ctcp_cmd.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /ctcp <target> <command> [args]".to_string(),
                        },
                    );
                } else {
                    let ctcp_msg = if ctcp_args.is_empty() {
                        format!("\x01{}\x01", ctcp_cmd)
                    } else {
                        format!("\x01{} {}\x01", ctcp_cmd, ctcp_args)
                    };
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                            target: target.clone(),
                            message: ctcp_msg,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("CTCP {} sent to {}", ctcp_cmd, target),
                        },
                    );
                }
            }
            "/ping" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /ping <nickname>".to_string(),
                        },
                    );
                } else {
                    let timestamp = chrono::Utc::now().timestamp().to_string();
                    let ctcp_msg = format!("\x01PING {}\x01", timestamp);
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                            target: arg.clone(),
                            message: ctcp_msg,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("PING sent to {}...", arg),
                        },
                    );
                }
            }
            "/version" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /version <nickname>".to_string(),
                        },
                    );
                } else {
                    let ctcp_msg = "\x01VERSION\x01".to_string();
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                            target: arg.clone(),
                            message: ctcp_msg,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("VERSION request sent to {}...", arg),
                        },
                    );
                }
            }
            "/time" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /time <nickname>".to_string(),
                        },
                    );
                } else {
                    let ctcp_msg = "\x01TIME\x01".to_string();
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                            target: arg.clone(),
                            message: ctcp_msg,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("TIME request sent to {}...", arg),
                        },
                    );
                }
            }
            "/raw" | "/quote" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /raw <irc command>".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Raw {
                            command: arg.clone(),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Sent: {}", arg),
                        },
                    );
                }
            }
            "/op" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /op <nickname>".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "+o".to_string(),
                            args: Some(arg.clone()),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Giving operator status to {}...", arg),
                        },
                    );
                }
            }
            "/deop" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /deop <nickname>".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "-o".to_string(),
                            args: Some(arg.clone()),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Removing operator status from {}...", arg),
                        },
                    );
                }
            }
            "/devoice" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /devoice <nickname>".to_string(),
                        },
                    );
                } else {
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "-v".to_string(),
                            args: Some(arg.clone()),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Removing voice from {}...", arg),
                        },
                    );
                }
            }
            "/ban" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /ban <nick!user@host or nickname>".to_string(),
                        },
                    );
                } else {
                    // If it's just a nickname, convert to *!*@nick.* pattern
                    let ban_mask = if arg.contains('!') || arg.contains('@') {
                        arg.clone()
                    } else {
                        format!("{}!*@*", arg)
                    };
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "+b".to_string(),
                            args: Some(ban_mask.clone()),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Banning {}...", ban_mask),
                        },
                    );
                }
            }
            "/unban" => {
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /unban <nick!user@host or nickname>".to_string(),
                        },
                    );
                } else {
                    let ban_mask = if arg.contains('!') || arg.contains('@') {
                        arg.clone()
                    } else {
                        format!("{}!*@*", arg)
                    };
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "-b".to_string(),
                            args: Some(ban_mask.clone()),
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Unbanning {}...", ban_mask),
                        },
                    );
                }
            }
            "/kickban" | "/kb" => {
                let mut kb_parts = arg.splitn(2, ' ');
                let user = kb_parts.next().unwrap_or("").trim().to_string();
                let reason = kb_parts.next().map(|val| val.trim().to_string());
                
                if user.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /kickban <nickname> [reason]".to_string(),
                        },
                    );
                } else {
                    // Ban first
                    let ban_mask = format!("{}!*@*", user);
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: channel.clone(),
                            modes: "+b".to_string(),
                            args: Some(ban_mask),
                        });
                        // Then kick
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Kick {
                            channel: channel.clone(),
                            user: user.clone(),
                            reason,
                        });
                    }
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: format!("Kick-banning {}...", user),
                        },
                    );
                }
            }
            "/names" => {
                // Request names list for current or specified channel
                let target = if arg.is_empty() {
                    channel.clone()
                } else if arg.starts_with('#') {
                    arg.clone()
                } else {
                    format!("#{}", arg)
                };
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Raw {
                        command: format!("NAMES {}", target),
                    });
                }
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: format!("Requesting names for {}...", target),
                    },
                );
            }
            "/clear" => {
                // Clear messages for current channel
                {
                    let mut state_write = state.write();
                    if let Some(server) = state_write.servers.get_mut(&active_profile) {
                        server.messages.retain(|m| m.channel != channel);
                    }
                }
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: "Chat cleared.".to_string(),
                    },
                );
            }
            "/help" => {
                let help_text = if arg.is_empty() {
                    "Available commands: /join /part /nick /me /msg /query /notice /whois /who /topic /mode /kick /invite /away /quit /list /ctcp /ping /version /time /raw /op /deop /devoice /ban /unban /kickban /names /clear /voice /hangup /naiscreate /naisjoin /naisleave /naislist /naisprobe /help\n\nUse /help <command> for more info."
                } else {
                    match arg.trim_start_matches('/').to_lowercase().as_str() {
                        "join" => "/join <#channel> - Join a channel",
                        "part" => "/part [#channel] [reason] - Leave a channel",
                        "nick" => "/nick <newname> - Change your nickname",
                        "me" => "/me <action> - Send an action message",
                        "msg" | "query" => "/msg <target> <message> - Send a private message\n/query <target> - Open a private message window",
                        "notice" => "/notice <target> <message> - Send a notice",
                        "whois" => "/whois <nickname> - Get information about a user",
                        "who" => "/who [target] - List users in channel",
                        "topic" => "/topic [#channel] [new topic] - View or set channel topic",
                        "mode" => "/mode [target] <modes> [args] - Set channel/user modes",
                        "kick" => "/kick <nickname> [reason] - Kick a user from the channel",
                        "invite" => "/invite <nickname> [#channel] - Invite a user to a channel",
                        "away" => "/away [message] - Set/clear away status",
                        "quit" | "disconnect" => "/quit [message] - Disconnect from the server",
                        "list" => "/list - List available channels on the server",
                        "ctcp" => "/ctcp <target> <command> [args] - Send a CTCP command",
                        "ping" => "/ping <nickname> - Ping a user",
                        "version" => "/version <nickname> - Request client version from user",
                        "time" => "/time <nickname> - Request time from user",
                        "raw" | "quote" => "/raw <command> - Send a raw IRC command",
                        "op" => "/op <nickname> - Give operator status (+o)",
                        "deop" => "/deop <nickname> - Remove operator status (-o)",
                        "ban" => "/ban <mask> - Ban a user from the channel (+b)",
                        "unban" => "/unban <mask> - Remove a ban (-b)",
                        "kickban" | "kb" => "/kickban <nickname> [reason] - Ban and kick a user",
                        "names" => "/names [#channel] - List users in a channel",
                        "clear" => "/clear - Clear chat messages for current channel",
                        "voice" | "call" => "/voice <nickname> - Start a voice call\n(For channel voice mode, use: /mode +v nickname)",
                        "devoice" => "/devoice <nickname> - Remove voice mode (-v) from a user",
                        "hangup" | "endcall" => "/hangup - End the current voice call",
                        "naiscreate" => "/naiscreate [name] - Create a new NAIS secure P2P channel\nCreates a moderated IRC channel for discovery with encrypted P2P messaging",
                        "naisjoin" => "/naisjoin <#channel> - Join a NAIS secure channel\nJoins an existing NAIS channel and connects to peers",
                        "naisleave" => "/naisleave [channel_id] - Leave a NAIS secure channel",
                        "naislist" => "/naislist - List active NAIS channels and their peers",
                        "naisprobe" => "/naisprobe [#channel] - Manually probe users in channel for NAIS capability",
                        "help" => "/help [command] - Show help information",
                        _ => "Unknown command. Use /help for a list of commands.",
                    }
                };
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: help_text.to_string(),
                    },
                );
            }
            "/naiscreate" => {
                // Create a new NAIS secure P2P channel
                let channel_name = if arg.is_empty() { None } else { Some(arg.clone()) };
                let channel_id = crate::nais_channel::generate_channel_id();
                let irc_channel = crate::nais_channel::create_nais_irc_channel(&channel_id);
                let fingerprint = crate::nais_channel::generate_fingerprint();
                let topic = crate::nais_channel::create_nais_topic(&channel_id, &fingerprint);
                
                // Join the IRC channel
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Join {
                        channel: irc_channel.clone(),
                    });
                }
                
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel: channel.clone(),
                        text: format!("Creating NAIS channel: {} ({})", 
                            channel_name.as_deref().unwrap_or("unnamed"), 
                            irc_channel),
                    },
                );
                
                // Set the topic (this requires op status, which we should have as channel creator)
                // We'll set it after a short delay to allow JOIN to complete
                let irc_channel_clone = irc_channel.clone();
                let topic_clone = topic.clone();
                let handle_clone = handle.clone();
                spawn(async move {
                    Delay::new(Duration::from_millis(500)).await;
                    if let Some(handle) = handle_clone.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Topic {
                            channel: irc_channel_clone.clone(),
                            topic: Some(topic_clone),
                        });
                        // Set channel modes: +mnt (moderated, no external messages, topic lock)
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Mode {
                            target: irc_channel_clone,
                            modes: "+mnt".to_string(),
                            args: None,
                        });
                    }
                });
                
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel: channel.clone(),
                        text: format!("NAIS channel created. Channel ID: {}\nOther NAIS clients joining {} will auto-discover and connect P2P.", 
                            channel_id, irc_channel),
                    },
                );
            }
            "/naisjoin" => {
                // Join an existing NAIS channel
                if arg.is_empty() {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Usage: /naisjoin <#channel> - Join a NAIS P2P channel\nThe channel must have a NAIS topic (NAIS:v1:...)".to_string(),
                        },
                    );
                } else {
                    let target = if arg.starts_with('#') {
                        arg.clone()
                    } else {
                        format!("#{arg}")
                    };
                    
                    // Join the IRC channel to discover peers
                    if let Some(handle) = handle.as_ref() {
                        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Join {
                            channel: target.clone(),
                        });
                    }
                    
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel: channel.clone(),
                            text: format!("Joining {} to discover NAIS peers...\nIf this is a NAIS channel, peers will be probed automatically.", target),
                        },
                    );
                }
            }
            "/naisleave" => {
                // Leave a NAIS channel
                let target = if arg.is_empty() {
                    channel.clone()
                } else {
                    arg.clone()
                };
                
                // Part the IRC channel
                if let Some(handle) = handle.as_ref() {
                    let _ = handle.cmd_tx.try_send(IrcCommandEvent::Part {
                        channel: target.clone(),
                        reason: Some("Leaving NAIS channel".to_string()),
                    });
                }
                
                apply_event_with_config(
                    &mut state.write(),
                    &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel: channel.clone(),
                        text: format!("Left NAIS channel: {}", target),
                    },
                );
            }
            "/naislist" => {
                // List active NAIS channels
                // Check which channels have NAIS topics
                let server_state = state.read().servers.get(&active_profile).cloned();
                if let Some(ss) = server_state {
                    let mut nais_channels = Vec::new();
                    for (ch, topic) in &ss.topics_by_channel {
                        if crate::nais_channel::is_nais_topic(topic) {
                            if let Some((version, channel_id, _fingerprint)) = crate::nais_channel::parse_nais_topic(topic) {
                                let user_count = ss.users_by_channel.get(ch).map(|u| u.len()).unwrap_or(0);
                                nais_channels.push(format!("  {} [{}] - {} users (ID: {})", ch, version, user_count, &channel_id[..8.min(channel_id.len())]));
                            }
                        }
                    }
                    
                    let list_text = if nais_channels.is_empty() {
                        "No active NAIS channels.\n\nUse /naiscreate [name] to create a new NAIS channel\nUse /naisjoin #channel to join an existing NAIS channel".to_string()
                    } else {
                        format!("Active NAIS channels:\n{}", nais_channels.join("\n"))
                    };
                    
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: list_text,
                        },
                    );
                } else {
                    apply_event_with_config(
                        &mut state.write(),
                        &profiles.read(),
                        &active_profile,
                        IrcEvent::System {
                            channel,
                            text: "Not connected to server.".to_string(),
                        },
                    );
                }
            }
            "/naisprobe" => {
                // Manually probe users in current channel for NAIS capability
                let target_channel = if arg.is_empty() {
                    channel.clone()
                } else if arg.starts_with('#') {
                    arg.clone()
                } else {
                    format!("#{}", arg)
                };
                
                let server_state = state.read().servers.get(&active_profile).cloned();
                if let Some(ss) = server_state {
                    if let Some(users) = ss.users_by_channel.get(&target_channel) {
                        let our_nick = ss.nickname.clone();
                        let probe_msg = crate::nais_channel::create_probe_ctcp(&target_channel);
                        
                        let mut probed_count = 0;
                        for user in users {
                            // Strip mode prefixes
                            let clean_user = user.trim_start_matches(|c| c == '@' || c == '+' || c == '%' || c == '!' || c == '~');
                            if clean_user == our_nick {
                                continue;
                            }
                            
                            if let Some(handle) = handle.as_ref() {
                                let _ = handle.cmd_tx.try_send(IrcCommandEvent::Ctcp {
                                    target: clean_user.to_string(),
                                    message: probe_msg.clone(),
                                });
                                probed_count += 1;
                            }
                        }
                        
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel: channel.clone(),
                                text: format!("Probing {} users in {} for NAIS capability...", probed_count, target_channel),
                            },
                        );
                    } else {
                        apply_event_with_config(
                            &mut state.write(),
                            &profiles.read(),
                            &active_profile,
                            IrcEvent::System {
                                channel,
                                text: format!("No users found in {}", target_channel),
                            },
                        );
                    }
                }
            }
            _ => {
                apply_event_with_config(
                    &mut state.write(),
                        &profiles.read(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: "Unknown command.".to_string(),
                    },
                );
            }
        }
        input.set(String::new());
        
        // Force scroll to bottom after sending command
        force_scroll_to_bottom.set(true);
        return;
    }

    if let Some(handle) = handle.as_ref() {
        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Send {
            channel: channel.clone(),
            text: text.clone(),
        });
    }

    apply_event_with_config(
        &mut state.write(),
                        &profiles.read(),
        &active_profile,
        IrcEvent::Message {
            channel,
            user: nickname,
            text,
        },
    );

    input.set(String::new());
    
    // Force scroll to bottom after sending message
    force_scroll_to_bottom.set(true);
}

fn connect_profile(
    server: String,
    nickname: String,
    channel: String,
    use_tls: bool,
    hide_host: bool,
    profile_name: String,
    mut state: Signal<irc_client::AppState>,
    _profiles: Signal<Vec<profile::Profile>>,
    _last_used: Signal<Option<String>>,
    mut profile_status: Signal<HashMap<String, ConnectionStatus>>,
    mut cores: Signal<HashMap<String, irc_client::CoreHandle>>,
    mut skip_reconnect: Signal<HashMap<String, bool>>,
    mut show_server_log: Signal<HashMap<String, bool>>,
) {
    let core = irc_client::start_core();
    register_shutdown_handle(&profile_name, core.cmd_tx.clone());
    cores.write().insert(profile_name.clone(), core.clone());
    skip_reconnect.write().insert(profile_name.clone(), false);
    profile_status.write().insert(profile_name.clone(), ConnectionStatus::Connecting);
    
    // Auto-enable server log visibility during connection so user can see progress
    show_server_log.write().insert(profile_name.clone(), true);

    let cmd_tx = core.cmd_tx.clone();
    let _ = cmd_tx.try_send(IrcCommandEvent::Connect {
        server,
        nickname,
        channel,
        use_tls,
        hide_host,
    });

    let mut state_mut = state.write();
    if let Some(server_state) = state_mut.servers.get_mut(&profile_name) {
        server_state.status = ConnectionStatus::Connecting;
        // Switch to Server Log view to show connection progress
        server_state.current_channel = "Server Log".to_string();
    }
}

fn username_color(username: &str) -> &'static str {
    // 10 colors with good contrast on dark backgrounds
    const COLORS: [&str; 10] = [
        "#FF6B6B", // coral red
        "#4ECDC4", // turquoise
        "#FFE66D", // yellow
        "#A8E6CF", // mint green
        "#FF8B94", // pink
        "#95E1D3", // seafoam
        "#C7CEEA", // lavender
        "#FFDAC1", // peach
        "#B4A7D6", // purple
        "#9BDEAC", // green
    ];
    
    // Hash the username to get a consistent color
    let hash = username.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let index = (hash as usize) % COLORS.len();
    COLORS[index]
}

fn message_view(msg: ChatMessage, key: u64) -> Element {
    let system_class = if msg.is_system { " system" } else { "" };
    let action_class = if msg.is_action { " action" } else { "" };
    
    // Extract media content (images, videos, etc.) from the message text
    let media_items = extract_media_content(&msg.text);
    
    // Format timestamp for display
    let timestamp_str = {
        let dt = chrono::DateTime::from_timestamp(msg.timestamp, 0)
            .unwrap_or_else(|| chrono::Utc::now());
        dt.format("%H:%M:%S").to_string()
    };
    let timestamp_display = timestamp_str.clone();
    
    // State for showing timestamp on click
    let mut show_timestamp_clicked = use_signal(|| false);
    
    // Get global "always show timestamps" setting from context
    let always_show_timestamps = use_context::<Signal<bool>>();
    let show_timestamp = move || always_show_timestamps() || show_timestamp_clicked();
    
    rsx! {
        div {
            key: "{key}",
            class: format!("message{system_class}{action_class}"),
            // content-visibility: auto allows the browser to skip rendering off-screen messages
            // contain-intrinsic-size provides a placeholder size for scroll calculations
            style: "content-visibility: auto; contain-intrinsic-size: auto 60px;",
            onclick: move |_| {
                if !msg.is_system && !always_show_timestamps() {
                    show_timestamp_clicked.set(true);
                    // Auto-hide after 3 seconds
                    spawn(async move {
                        Delay::new(Duration::from_secs(3)).await;
                        show_timestamp_clicked.set(false);
                    });
                }
            },
            if msg.is_system {
                div {
                    class: "system-text",
                    {render_text_with_links(&msg.text)}
                }
            } else if msg.is_action {
                div {
                    class: "action-text",
                    if show_timestamp() {
                        span {
                            class: "timestamp",
                            style: "color: var(--text-dim); font-size: 11px; margin-right: 6px;",
                            "[{timestamp_display}]"
                        }
                    }
                    span {
                        class: "user",
                        style: "color: {username_color(&msg.user)};",
                        "* {msg.user}"
                    }
                    span {
                        " "
                        {render_text_with_links(&msg.text)}
                    }
                }
                if !media_items.is_empty() {
                    div {
                        class: "message-images",
                        for item in media_items {
                            {render_media_item(item)}
                        }
                    }
                }
            } else {
                div {
                    class: "message-meta",
                    if show_timestamp() {
                        span {
                            class: "timestamp",
                            style: "color: var(--text-dim); font-size: 11px; margin-right: 6px;",
                            "[{timestamp_str}]"
                        }
                    }
                    span {
                        class: "user",
                        style: "color: {username_color(&msg.user)};",
                        "{msg.user}"
                    }
                }
                div {
                    class: "message-text",
                    {render_text_with_links(&msg.text)}
                }
                if !media_items.is_empty() {
                    div {
                        class: "message-images",
                        for item in media_items {
                            {render_media_item(item)}
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum MediaItem {
    Image { source_url: String, image_url: String },
    YouTubeVideo { video_id: String, source_url: String },
    DiscoursePost { source_url: String, data: DiscourseData },
}

/// Represents a segment of text that may be plain, a clickable link, or a highlighted nick
#[derive(Clone, Debug)]
enum TextSegment {
    Plain(String),
    Link(String),
    Nick(String),
}

/// Parse text into segments, identifying URLs that should be clickable
#[allow(dead_code)]
fn parse_text_with_links(text: &str) -> Vec<TextSegment> {
    parse_text_with_links_and_nicks(text, &[])
}

/// Parse text into segments, identifying URLs and nick mentions
fn parse_text_with_links_and_nicks(text: &str, nicks: &[String]) -> Vec<TextSegment> {
    let mut segments = Vec::new();
    let mut current_plain = String::new();
    
    // Build a lowercase nick set for case-insensitive matching
    let nick_set: std::collections::HashSet<String> = nicks.iter()
        .map(|n| n.trim_start_matches(['@', '+', '%', '&', '~']).to_lowercase())
        .collect();
    
    for word in text.split_inclusive(|c: char| c.is_whitespace()) {
        // Check if this word contains a URL
        let trimmed = word.trim();
        let cleaned = trimmed
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim_end_matches(',')
            .trim_end_matches('.')
            .trim_end_matches(';')
            .trim_end_matches(')')
            .trim_start_matches('(');
        
        if cleaned.starts_with("http://") || cleaned.starts_with("https://") {
            // Found a URL - push any accumulated plain text first (checking for nicks)
            if !current_plain.is_empty() {
                segments.extend(split_plain_text_by_nicks(&current_plain, &nick_set, nicks));
                current_plain.clear();
            }
            
            // Handle prefix characters (like opening parentheses)
            let prefix_chars: String = trimmed.chars().take_while(|c| *c == '(' || *c == '<').collect();
            if !prefix_chars.is_empty() {
                segments.push(TextSegment::Plain(prefix_chars));
            }
            
            // Push the link
            segments.push(TextSegment::Link(cleaned.to_string()));
            
            // Handle suffix characters (punctuation after URL) and trailing whitespace
            let suffix_start = trimmed.find(cleaned).unwrap_or(0) + cleaned.len();
            let suffix = &trimmed[suffix_start..];
            let trailing_ws: String = word.chars().rev().take_while(|c| c.is_whitespace()).collect();
            if !suffix.is_empty() || !trailing_ws.is_empty() {
                current_plain.push_str(suffix);
                current_plain.push_str(&trailing_ws.chars().rev().collect::<String>());
            }
        } else {
            // Regular word, add to current plain text
            current_plain.push_str(word);
        }
    }
    
    // Push any remaining plain text (checking for nicks)
    if !current_plain.is_empty() {
        segments.extend(split_plain_text_by_nicks(&current_plain, &nick_set, nicks));
    }
    
    segments
}

/// Split plain text into segments, identifying nick mentions
/// Optimized to use O(n) word-based scanning instead of O(n*m) per-nick scanning
fn split_plain_text_by_nicks(
    text: &str, 
    nick_set: &std::collections::HashSet<String>,
    _original_nicks: &[String]
) -> Vec<TextSegment> {
    if nick_set.is_empty() || text.is_empty() {
        return vec![TextSegment::Plain(text.to_string())];
    }
    
    let mut segments = Vec::new();
    let mut current_plain = String::new();
    let mut chars = text.char_indices().peekable();
    
    while let Some((_start_idx, c)) = chars.next() {
        // Check if this starts a potential word (alphanumeric or underscore)
        if c.is_alphanumeric() || c == '_' {
            // Collect the entire word
            let mut word = String::new();
            word.push(c);
            
            while let Some(&(_idx, next_c)) = chars.peek() {
                if next_c.is_alphanumeric() || next_c == '_' {
                    word.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }
            
            // Check if word is a nick (case-insensitive)
            let word_lower = word.to_lowercase();
            if nick_set.contains(&word_lower) {
                // Found a nick! Push accumulated plain text first
                if !current_plain.is_empty() {
                    segments.push(TextSegment::Plain(std::mem::take(&mut current_plain)));
                }
                segments.push(TextSegment::Nick(word));
            } else {
                // Not a nick, add to plain text
                current_plain.push_str(&word);
            }
        } else {
            // Non-word character, add to plain text
            current_plain.push(c);
        }
    }
    
    // Push remaining plain text
    if !current_plain.is_empty() {
        segments.push(TextSegment::Plain(current_plain));
    }
    
    segments
}

/// Render text with clickable links and highlighted nick mentions
fn render_text_with_links(text: &str) -> Element {
    // Get channel users from context for nick highlighting
    let channel_users = use_context::<Signal<Vec<String>>>();
    let nicks = channel_users();
    let segments = parse_text_with_links_and_nicks(text, &nicks);
    
    rsx! {
        for segment in segments {
            match segment {
                TextSegment::Plain(txt) => rsx! { "{txt}" },
                TextSegment::Link(url) => rsx! {
                    a {
                        href: "{url}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        class: "chat-link",
                        "{url}"
                    }
                },
                TextSegment::Nick(nick) => {
                    let color = username_color(&nick);
                    rsx! {
                        span {
                            style: "color: {color}; font-weight: 500;",
                            "{nick}"
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscourseData {
    title: String,
    author: String,
    excerpt: String,
    category: Option<String>,
    site_name: String,
}

fn render_media_item(item: MediaItem) -> Element {
    match item {
        MediaItem::Image { source_url, image_url } => {
            // Get cached image or start downloading it
            let cached_url = get_or_download_image(&image_url);
            rsx! {
                a {
                    href: "{source_url}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    img {
                        src: "{cached_url}",
                        class: "embedded-image clickable",
                        loading: "lazy",
                        alt: "Embedded image",
                    }
                }
            }
        }
        MediaItem::YouTubeVideo { video_id, source_url } => {
            let thumbnail_url = format!("https://img.youtube.com/vi/{}/maxresdefault.jpg", video_id);
            // Cache YouTube thumbnails too
            let cached_url = get_or_download_image(&thumbnail_url);
            rsx! {
                a {
                    href: "{source_url}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    class: "video-preview",
                    img {
                        src: "{cached_url}",
                        class: "embedded-image clickable",
                        loading: "lazy",
                        alt: "YouTube video thumbnail",
                    }
                }
            }
        }
        MediaItem::DiscoursePost { source_url, data } => {
            rsx! {
                a {
                    href: "{source_url}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    class: "discourse-embed",
                    div {
                        class: "discourse-header",
                        span { class: "discourse-icon", "💬" }
                        span { class: "discourse-site", "{data.site_name}" }
                    }
                    div { class: "discourse-title", "{data.title}" }
                    div {
                        class: "discourse-meta",
                        span { class: "discourse-author", "by {data.author}" }
                        if let Some(ref category) = data.category {
                            span { class: "discourse-category", " • {category}" }
                        }
                    }
                    if !data.excerpt.is_empty() {
                        div { class: "discourse-excerpt", "{data.excerpt}" }
                    }
                }
            }
        }
    }
}

// Persistent cache structures
#[derive(Serialize, Deserialize, Clone)]
struct CacheEntry<T> {
    value: T,
    timestamp: u64,
    size: usize,
}

#[derive(Serialize, Deserialize)]
struct CacheMetadata {
    entries: HashMap<String, CacheEntry<()>>,  // Just metadata, not the actual data
    total_size: usize,
}

// Global cache for resolved pasteboard URLs with update counter
type UrlCache = Arc<Mutex<(HashMap<String, Option<String>>, u64)>>;
// Cache for downloaded image data (URL -> base64 data URI)
type ImageDataCache = Arc<Mutex<HashMap<String, String>>>;
type DiscourseCache = Arc<Mutex<(HashMap<String, Option<DiscourseData>>, u64)>>;

lazy_static::lazy_static! {
    static ref PASTEBOARD_CACHE: UrlCache = {
        let loaded = load_url_cache("pasteboard");
        Arc::new(Mutex::new((loaded, 0)))
    };
    static ref OG_IMAGE_CACHE: UrlCache = {
        let loaded = load_url_cache("og_image");
        Arc::new(Mutex::new((loaded, 0)))
    };
    static ref IMAGE_DATA_CACHE: ImageDataCache = {
        let loaded = load_image_data_cache();
        Arc::new(Mutex::new(loaded))
    };
    static ref DISCOURSE_CACHE: DiscourseCache = {
        let loaded = load_discourse_cache();
        Arc::new(Mutex::new((loaded, 0)))
    };
}

// Get cache directory path
fn get_cache_dir() -> PathBuf {
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(".cache"))
        .join("nais-client");
    
    // Create cache directory if it doesn't exist
    fs::create_dir_all(&cache_dir).ok();
    cache_dir
}

// Get current timestamp in seconds since epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Calculate size of a string in bytes
fn calculate_string_size(s: &str) -> usize {
    s.len()
}

// Calculate size of optional string
fn calculate_option_string_size(opt: &Option<String>) -> usize {
    opt.as_ref().map(|s| s.len()).unwrap_or(0) + 8  // Add some overhead
}

// Calculate size of DiscourseData
fn calculate_discourse_size(data: &Option<DiscourseData>) -> usize {
    match data {
        Some(d) => {
            d.title.len() + d.author.len() + d.excerpt.len() + 
            d.category.as_ref().map(|s| s.len()).unwrap_or(0) + 
            d.site_name.len() + 40  // overhead
        }
        None => 8,
    }
}

// Evict old entries if total cache size exceeds 1GB
const MAX_CACHE_SIZE: usize = 1024 * 1024 * 1024; // 1GB

fn evict_old_entries(cache_dir: &PathBuf, cache_type: &str) {
    let metadata_path = cache_dir.join(format!("{}_metadata.json", cache_type));
    
    if let Ok(data) = fs::read_to_string(&metadata_path) {
        if let Ok(mut metadata) = serde_json::from_str::<CacheMetadata>(&data) {
            if metadata.total_size > MAX_CACHE_SIZE {
                // Sort entries by timestamp (oldest first)
                let mut entries: Vec<_> = metadata.entries.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                entries.sort_by_key(|(_, entry)| entry.timestamp);
                
                // Remove oldest entries until we're under the limit
                let target_size = (MAX_CACHE_SIZE as f64 * 0.8) as usize; // Target 80% to avoid frequent evictions
                let mut keys_to_remove = Vec::new();
                
                for (key, entry) in entries {
                    if metadata.total_size <= target_size {
                        break;
                    }
                    
                    // Remove the cache file
                    let cache_file = cache_dir.join(format!("{}_{}.json", cache_type, 
                        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes())));
                    fs::remove_file(cache_file).ok();
                    
                    metadata.total_size -= entry.size;
                    keys_to_remove.push(key);
                }
                
                // Remove entries from metadata
                for key in keys_to_remove {
                    metadata.entries.remove(&key);
                }
                
                // Save updated metadata
                if let Ok(json) = serde_json::to_string(&metadata) {
                    fs::write(&metadata_path, json).ok();
                }
            }
        }
    }
}

// Save URL cache entry to disk
fn save_url_cache_entry(cache_type: &str, key: &str, value: &Option<String>) {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join(format!("{}_metadata.json", cache_type));
    
    // Load or create metadata
    let mut metadata = if let Ok(data) = fs::read_to_string(&metadata_path) {
        serde_json::from_str::<CacheMetadata>(&data).unwrap_or_else(|_| CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        })
    } else {
        CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        }
    };
    
    // Calculate size and update metadata
    let size = calculate_option_string_size(value);
    let timestamp = current_timestamp();
    
    // Remove old entry size if exists
    if let Some(old_entry) = metadata.entries.get(key) {
        metadata.total_size -= old_entry.size;
    }
    
    metadata.entries.insert(key.to_string(), CacheEntry {
        value: (),
        timestamp,
        size,
    });
    metadata.total_size += size;
    
    // Save metadata
    if let Ok(json) = serde_json::to_string(&metadata) {
        fs::write(&metadata_path, json).ok();
    }
    
    // Save cache entry
    let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
    let cache_file = cache_dir.join(format!("{}_{}.json", cache_type, encoded_key));
    if let Ok(json) = serde_json::to_string(value) {
        fs::write(cache_file, json).ok();
    }
    
    // Check if we need to evict old entries
    if metadata.total_size > MAX_CACHE_SIZE {
        evict_old_entries(&cache_dir, cache_type);
    }
}

// Load URL cache from disk
fn load_url_cache(cache_type: &str) -> HashMap<String, Option<String>> {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join(format!("{}_metadata.json", cache_type));
    
    let mut result = HashMap::new();
    
    if let Ok(data) = fs::read_to_string(&metadata_path) {
        if let Ok(metadata) = serde_json::from_str::<CacheMetadata>(&data) {
            for (key, _) in metadata.entries {
                let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
                let cache_file = cache_dir.join(format!("{}_{}.json", cache_type, encoded_key));
                
                if let Ok(data) = fs::read_to_string(&cache_file) {
                    if let Ok(value) = serde_json::from_str::<Option<String>>(&data) {
                        result.insert(key, value);
                    }
                }
            }
        }
    }
    
    result
}

// Save image data cache entry to disk
fn save_image_data_entry(key: &str, value: &str) {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join("image_data_metadata.json");
    
    // Load or create metadata
    let mut metadata = if let Ok(data) = fs::read_to_string(&metadata_path) {
        serde_json::from_str::<CacheMetadata>(&data).unwrap_or_else(|_| CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        })
    } else {
        CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        }
    };
    
    // Calculate size and update metadata
    let size = calculate_string_size(value);
    let timestamp = current_timestamp();
    
    // Remove old entry size if exists
    if let Some(old_entry) = metadata.entries.get(key) {
        metadata.total_size -= old_entry.size;
    }
    
    metadata.entries.insert(key.to_string(), CacheEntry {
        value: (),
        timestamp,
        size,
    });
    metadata.total_size += size;
    
    // Save metadata
    if let Ok(json) = serde_json::to_string(&metadata) {
        fs::write(&metadata_path, json).ok();
    }
    
    // Save cache entry
    let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
    let cache_file = cache_dir.join(format!("image_data_{}.json", encoded_key));
    if let Ok(json) = serde_json::to_string(value) {
        fs::write(cache_file, json).ok();
    }
    
    // Check if we need to evict old entries
    if metadata.total_size > MAX_CACHE_SIZE {
        evict_old_entries(&cache_dir, "image_data");
    }
}

// Load image data cache from disk
fn load_image_data_cache() -> HashMap<String, String> {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join("image_data_metadata.json");
    
    let mut result = HashMap::new();
    
    if let Ok(data) = fs::read_to_string(&metadata_path) {
        if let Ok(metadata) = serde_json::from_str::<CacheMetadata>(&data) {
            for (key, _) in metadata.entries {
                let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
                let cache_file = cache_dir.join(format!("image_data_{}.json", encoded_key));
                
                if let Ok(data) = fs::read_to_string(&cache_file) {
                    if let Ok(value) = serde_json::from_str::<String>(&data) {
                        result.insert(key, value);
                    }
                }
            }
        }
    }
    
    result
}

// Save discourse cache entry to disk
fn save_discourse_entry(key: &str, value: &Option<DiscourseData>) {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join("discourse_metadata.json");
    
    // Load or create metadata
    let mut metadata = if let Ok(data) = fs::read_to_string(&metadata_path) {
        serde_json::from_str::<CacheMetadata>(&data).unwrap_or_else(|_| CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        })
    } else {
        CacheMetadata {
            entries: HashMap::new(),
            total_size: 0,
        }
    };
    
    // Calculate size and update metadata
    let size = calculate_discourse_size(value);
    let timestamp = current_timestamp();
    
    // Remove old entry size if exists
    if let Some(old_entry) = metadata.entries.get(key) {
        metadata.total_size -= old_entry.size;
    }
    
    metadata.entries.insert(key.to_string(), CacheEntry {
        value: (),
        timestamp,
        size,
    });
    metadata.total_size += size;
    
    // Save metadata
    if let Ok(json) = serde_json::to_string(&metadata) {
        fs::write(&metadata_path, json).ok();
    }
    
    // Save cache entry
    let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
    let cache_file = cache_dir.join(format!("discourse_{}.json", encoded_key));
    if let Ok(json) = serde_json::to_string(value) {
        fs::write(cache_file, json).ok();
    }
    
    // Check if we need to evict old entries
    if metadata.total_size > MAX_CACHE_SIZE {
        evict_old_entries(&cache_dir, "discourse");
    }
}

// Load discourse cache from disk
fn load_discourse_cache() -> HashMap<String, Option<DiscourseData>> {
    let cache_dir = get_cache_dir();
    let metadata_path = cache_dir.join("discourse_metadata.json");
    
    let mut result = HashMap::new();
    
    if let Ok(data) = fs::read_to_string(&metadata_path) {
        if let Ok(metadata) = serde_json::from_str::<CacheMetadata>(&data) {
            for (key, _) in metadata.entries {
                let encoded_key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key.as_bytes());
                let cache_file = cache_dir.join(format!("discourse_{}.json", encoded_key));
                
                if let Ok(data) = fs::read_to_string(&cache_file) {
                    if let Ok(value) = serde_json::from_str::<Option<DiscourseData>>(&data) {
                        result.insert(key, value);
                    }
                }
            }
        }
    }
    
    result
}

async fn resolve_pasteboard_url_async(url: String) -> Option<String> {
    // Try to fetch the page and extract the direct image URL
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    
    let response = client.get(&url).send().await.ok()?;
    let html_content = response.text().await.ok()?;
    let document = Html::parse_document(&html_content);
    
    // Try multiple selectors to find the image
    // 1. Look for og:image or twitter:image meta tags
    if let Ok(selector) = Selector::parse("meta[property='og:image'], meta[name='twitter:image']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                return Some(content.to_string());
            }
        }
    }
    
    // 2. Look for img tag with id="paste-image" or class containing "image"
    if let Ok(selector) = Selector::parse("img.image, img[class*='paste']") {
        if let Some(element) = document.select(&selector).next() {
            // Check data-src first (pasteboard uses this)
            if let Some(src) = element.value().attr("data-src").or_else(|| element.value().attr("src")) {
                // Make sure it's an absolute URL
                if src.starts_with("http") {
                    return Some(src.to_string());
                } else if src.starts_with("//") {
                    return Some(format!("https:{}", src));
                } else if src.starts_with("/") {
                    return Some(format!("https://pasteboard.co{}", src));
                }
            }
        }
    }
    
    // 3. Look for any img tag with a reasonable size image
    if let Ok(selector) = Selector::parse("img[src], img[data-src]") {
        for element in document.select(&selector) {
            let src = element.value().attr("data-src").or_else(|| element.value().attr("src"));
            if let Some(src) = src {
                // Skip small images (icons, etc.)
                if src.contains("icon") || src.contains("logo") || src.contains("button") {
                    continue;
                }
                
                // Make sure it's an absolute URL
                if src.starts_with("http") {
                    return Some(src.to_string());
                } else if src.starts_with("//") {
                    return Some(format!("https:{}", src));
                } else if src.starts_with("/") {
                    return Some(format!("https://pasteboard.co{}", src));
                }
            }
        }
    }
    
    None
}

fn get_or_resolve_pasteboard_url(url: &str) -> Option<String> {
    // Check if this is a pasteboard.co URL
    if !url.contains("pasteboard.co") {
        return Some(url.to_string());
    }
    
    // Check cache first
    {
        let cache = PASTEBOARD_CACHE.lock().unwrap();
        if let Some(cached) = cache.0.get(url) {
            // Return cached result (Some = resolved URL, None = resolution failed)
            return cached.clone();
        }
    }
    
    // Not in cache, spawn async resolution task
    let url_clone = url.to_string();
    spawn(async move {
        let resolved = resolve_pasteboard_url_async(url_clone.clone()).await;
        let mut cache = PASTEBOARD_CACHE.lock().unwrap();
        cache.0.insert(url_clone.clone(), resolved.clone());
        cache.1 += 1; // Increment update counter
        drop(cache); // Release lock before saving to disk
        save_url_cache_entry("pasteboard", &url_clone, &resolved);
    });
    
    // Return None until resolved (will show on next render)
    None
}

async fn fetch_og_image_async(url: String) -> Option<String> {
    // Try to fetch the page and extract OG image
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0 (compatible; NAIS-client/0.1.0)")
        .build()
        .ok()?;
    
    let response = client.get(&url).send().await.ok()?;
    let html_content = response.text().await.ok()?;
    let document = Html::parse_document(&html_content);
    
    // Look for og:image meta tag
    if let Ok(selector) = Selector::parse("meta[property='og:image'], meta[property='og:image:secure_url'], meta[name='twitter:image']") {
        if let Some(element) = document.select(&selector).next() {
            if let Some(content) = element.value().attr("content") {
                // Make sure it's an absolute URL
                if content.starts_with("http") {
                    return Some(content.to_string());
                } else if content.starts_with("//") {
                    return Some(format!("https:{}", content));
                } else if content.starts_with("/") {
                    // Extract base URL from original URL
                    if let Ok(parsed_url) = url.parse::<url::Url>() {
                        if let Some(domain) = parsed_url.domain() {
                            let scheme = parsed_url.scheme();
                            return Some(format!("{}://{}{}", scheme, domain, content));
                        }
                    }
                }
            }
        }
    }
    
    None
}

fn get_or_fetch_og_image(url: &str) -> Option<String> {
    // Check cache first
    {
        let cache = OG_IMAGE_CACHE.lock().unwrap();
        if let Some(cached) = cache.0.get(url) {
            return cached.clone();
        }
    }
    
    // Not in cache, spawn async fetch task
    let url_clone = url.to_string();
    spawn(async move {
        let og_image = fetch_og_image_async(url_clone.clone()).await;
        let mut cache = OG_IMAGE_CACHE.lock().unwrap();
        cache.0.insert(url_clone.clone(), og_image.clone());
        cache.1 += 1; // Increment update counter
        drop(cache); // Release lock before saving to disk
        save_url_cache_entry("og_image", &url_clone, &og_image);
    });
    
    // Return None until fetched (will show on next render)
    None
}

// Download image data and convert to base64 data URI
async fn download_image_async(url: String) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (compatible; NAIS-client/0.1.0)")
        .build()
        .ok()?;
    
    let response = client.get(&url).send().await.ok()?;
    let content_type = response.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("image/png")
        .to_string();
    
    let bytes = response.bytes().await.ok()?;
    
    // Convert to base64 data URI
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    Some(format!("data:{};base64,{}", content_type, base64_data))
}

// Get cached image or download it
fn get_or_download_image(url: &str) -> String {
    // Check cache first
    {
        let cache = IMAGE_DATA_CACHE.lock().unwrap();
        if let Some(cached) = cache.get(url) {
            return cached.clone();
        }
    }
    
    // Not in cache, spawn async download task
    let url_clone = url.to_string();
    spawn(async move {
        if let Some(data_uri) = download_image_async(url_clone.clone()).await {
            let mut cache = IMAGE_DATA_CACHE.lock().unwrap();
            cache.insert(url_clone.clone(), data_uri.clone());
            drop(cache); // Release lock before saving to disk
            save_image_data_entry(&url_clone, &data_uri);
        }
    });
    
    // Return original URL until downloaded (browser will download it normally)
    url.to_string()
}


fn extract_youtube_id(url: &str) -> Option<String> {
    // Handle various YouTube URL formats
    if url.contains("youtube.com/watch?v=") {
        // https://www.youtube.com/watch?v=VIDEO_ID
        url.split("watch?v=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .map(|s| s.to_string())
    } else if url.contains("youtu.be/") {
        // https://youtu.be/VIDEO_ID
        url.split("youtu.be/")
            .nth(1)
            .and_then(|s| s.split('?').next())
            .map(|s| s.to_string())
    } else if url.contains("youtube.com/embed/") {
        // https://www.youtube.com/embed/VIDEO_ID
        url.split("embed/")
            .nth(1)
            .and_then(|s| s.split('?').next())
            .map(|s| s.to_string())
    } else {
        None
    }
}

// Upload image using simple file hosting (no API key needed)
#[allow(dead_code)]
async fn upload_simple_image(image_data: Vec<u8>) -> Option<String> {
    println!("Starting image upload, size: {} bytes", image_data.len());
    
    let client = reqwest::Client::builder()
        .user_agent("curl/7.68.0")
        .build()
        .ok()?;
    
    // Create multipart form
    let part = reqwest::multipart::Part::bytes(image_data)
        .file_name("image.png")
        .mime_str("image/png")
        .ok()?;
    
    let form = reqwest::multipart::Form::new()
        .part("file", part);
    
    // Upload to tmpfiles.org (simple, no auth required)
    println!("Uploading to tmpfiles.org...");
    let response = client
        .post("https://tmpfiles.org/api/v1/upload")
        .multipart(form)
        .send()
        .await;
    
    let response = match response {
        Ok(r) => {
            println!("Got response with status: {}", r.status());
            r
        }
        Err(e) => {
            println!("Upload failed: {}", e);
            return None;
        }
    };
    
    let text = response.text().await.ok()?;
    println!("Response: {}", text);
    
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    
    // Parse tmpfiles.org response: {"status":"success","data":{"url":"https://tmpfiles.org/..."}}
    let mut url = json.get("data")
        .and_then(|d| d.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    
    // Convert to direct download URL by adding /dl/
    // https://tmpfiles.org/23743089/image.png -> https://tmpfiles.org/dl/23743089/image.png
    if url.starts_with("https://tmpfiles.org/") && !url.contains("/dl/") {
        url = url.replace("https://tmpfiles.org/", "https://tmpfiles.org/dl/");
    }
    
    println!("Got URL: {:?}", url);
    Some(url)
}

// Extract icon URL from channel topic (looks for "Icon: <url>")
fn extract_icon_from_topic(topic: &str) -> Option<String> {
    // Case-insensitive search for "Icon:" followed by a URL
    let topic_lower = topic.to_lowercase();
    if let Some(icon_pos) = topic_lower.find("icon:") {
        let after_icon = &topic[icon_pos + 5..].trim_start();
        // Extract URL - look for http:// or https://
        for word in after_icon.split_whitespace() {
            if word.starts_with("http://") || word.starts_with("https://") {
                // Clean up potential trailing punctuation
                let url = word.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != ':' && c != '-' && c != '_' && c != '?' && c != '=' && c != '&');
                return Some(url.to_string());
            }
        }
    }
    None
}

// Detect if URL is a Discourse forum link
fn is_discourse_url(url: &str) -> bool {
    // Common Discourse domains
    let discourse_domains = [
        "discourse.ubuntu.com",
        "discourse.nixos.org",
        "discuss.python.org",
        "discuss.pytorch.org",
        "discuss.elastic.co",
        "discuss.gradle.org",
        "discuss.kotlinlang.org",
        "forum.obsidian.md",
        "community.openai.com",
        "community.home-assistant.io",
        "meta.discourse.org",
        "forum.julia.org",
        "forum.manjaro.org",
        "forum.sublimetext.com",
        "forum.freecodecamp.org",
    ];
    
    // Check if domain matches known Discourse sites
    if let Ok(parsed) = url.parse::<url::Url>() {
        if let Some(domain) = parsed.domain() {
            // Check known domains
            if discourse_domains.iter().any(|d| domain == *d || domain.ends_with(&format!(".{}", d))) {
                return true;
            }
            // Check for common Discourse URL patterns
            if url.contains("/t/") && url.matches('/').count() >= 4 {
                return true;
            }
        }
    }
    
    false
}

// Fetch Discourse post data via JSON API
async fn fetch_discourse_data_async(url: String) -> Option<DiscourseData> {
    // Discourse provides JSON API by appending .json to URLs
    let json_url = if url.contains('?') {
        format!("{}.json", url.split('?').next()?)
    } else {
        format!("{}.json", url.trim_end_matches('/'))
    };
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0 (compatible; NAIS-client/0.1.0)")
        .build()
        .ok()?;
    
    let response = client.get(&json_url).send().await.ok()?;
    let json: serde_json::Value = response.json().await.ok()?;
    
    // Extract topic data
    let title = json["title"].as_str()
        .or_else(|| json["fancy_title"].as_str())
        .unwrap_or("Discourse Post")
        .to_string();
    
    let author = json["details"]["created_by"]["username"].as_str()
        .or_else(|| json["post_stream"]["posts"][0]["username"].as_str())
        .unwrap_or("unknown")
        .to_string();
    
    // Get excerpt from first post
    let excerpt = json["post_stream"]["posts"][0]["cooked"].as_str()
        .and_then(|html| {
            let document = Html::parse_document(html);
            let text_selector = Selector::parse("p").ok()?;
            let text: String = document.select(&text_selector)
                .take(2)
                .map(|el| el.text().collect::<String>())
                .collect::<Vec<_>>()
                .join(" ");
            Some(text)
        })
        .unwrap_or_default();
    
    // Truncate excerpt
    let excerpt = if excerpt.len() > 200 {
        format!("{}...", &excerpt[..197])
    } else {
        excerpt
    };
    
    let category = json["category_id"].as_u64()
        .and_then(|_| json["details"]["category"]["name"].as_str())
        .or_else(|| json["category"]["name"].as_str())
        .map(|s| s.to_string());
    
    // Extract site name from URL
    let site_name = url.parse::<url::Url>()
        .ok()
        .and_then(|u| u.domain().map(|d| d.to_string()))
        .unwrap_or_else(|| "Discourse".to_string());
    
    Some(DiscourseData {
        title,
        author,
        excerpt,
        category,
        site_name,
    })
}

// Get cached Discourse data or fetch it
fn get_or_fetch_discourse_data(url: &str) -> Option<DiscourseData> {
    // Check cache first
    {
        let cache = DISCOURSE_CACHE.lock().unwrap();
        if let Some(cached) = cache.0.get(url) {
            return cached.clone();
        }
    }
    
    // Not in cache, spawn async fetch task
    let url_clone = url.to_string();
    spawn(async move {
        let discourse_data = fetch_discourse_data_async(url_clone.clone()).await;
        let mut cache = DISCOURSE_CACHE.lock().unwrap();
        cache.0.insert(url_clone.clone(), discourse_data.clone());
        cache.1 += 1; // Increment update counter
        drop(cache); // Release lock before saving to disk
        save_discourse_entry(&url_clone, &discourse_data);
    });
    
    // Return None until fetched (will show on next render)
    None
}

// Upload image to imgur and return the direct image URL
fn extract_media_content(text: &str) -> Vec<MediaItem> {
    let mut items = Vec::new();
    let image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"];
    
    // Simple URL extraction - look for http(s):// followed by non-whitespace
    for word in text.split_whitespace() {
        // Strip common punctuation/wrapping characters from URLs
        let cleaned_word = word
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim_end_matches(',')
            .trim_end_matches('.')
            .trim_end_matches(';')
            .trim_end_matches(')')
            .trim_start_matches('(');
        
        if cleaned_word.starts_with("http://") || cleaned_word.starts_with("https://") {
            // Check for YouTube videos first
            if cleaned_word.contains("youtube.com") || cleaned_word.contains("youtu.be") {
                if let Some(video_id) = extract_youtube_id(cleaned_word) {
                    items.push(MediaItem::YouTubeVideo {
                        video_id,
                        source_url: cleaned_word.to_string(),
                    });
                    continue;
                }
            }
            
            // Check if it's a pasteboard.co URL
            if cleaned_word.contains("pasteboard.co") {
                if let Some(resolved) = get_or_resolve_pasteboard_url(cleaned_word) {
                    items.push(MediaItem::Image {
                        source_url: cleaned_word.to_string(),
                        image_url: resolved,
                    });
                }
                continue;
            }
            
            // Check if it's a Discourse forum link
            if is_discourse_url(cleaned_word) {
                if let Some(data) = get_or_fetch_discourse_data(cleaned_word) {
                    items.push(MediaItem::DiscoursePost {
                        source_url: cleaned_word.to_string(),
                        data,
                    });
                }
                // Always skip OG image fetching for Discourse URLs, even if data not ready yet
                continue;
            }
            
            // Check if it's a tmpfiles.org URL and convert to /dl/ version
            let image_url = if cleaned_word.contains("tmpfiles.org/") && !cleaned_word.contains("/dl/") {
                cleaned_word.replace("tmpfiles.org/", "tmpfiles.org/dl/")
            } else {
                cleaned_word.to_string()
            };
            
            // For non-pasteboard URLs, check if it ends with an image extension
            let word_lower = cleaned_word.to_lowercase();
            if image_extensions.iter().any(|ext| word_lower.ends_with(ext)) {
                items.push(MediaItem::Image {
                    source_url: cleaned_word.to_string(),
                    image_url,
                });
            } else {
                // Not a direct image link - try to fetch OG image
                if let Some(og_image) = get_or_fetch_og_image(cleaned_word) {
                    items.push(MediaItem::Image {
                        source_url: cleaned_word.to_string(),
                        image_url: og_image,
                    });
                }
            }
        }
    }
    
    items
}

fn unique_profile_label(
    label: &str,
    _server: &str,
    _nickname: &str,
    existing_profiles: &[profile::Profile],
) -> String {
    let base_name = label.to_string();
    let mut name = base_name.clone();
    let mut counter = 1;
    while existing_profiles.iter().any(|p| p.name == name) {
        name = format!("{base_name} ({counter})");
        counter += 1;
    }
    name
}

// (label, server, channel, use_tls)
const IMPORT_NETWORKS: &[(&str, &str, &str, bool)] = &[
    ("Support", "irc.quakenet.org", "#nais", false),
    ("Libera.Chat", "irc.libera.chat", "", true),
    ("freenode", "irc.freenode.net", "", true),
    ("OFTC", "irc.oftc.net", "", true),
    ("Undernet", "irc.undernet.org", "", true),
    ("EFnet", "irc.efnet.org", "", true),
    ("IRCnet", "irc.ircnet.net", "", true),
    ("DALnet", "irc.dalnet.net", "", true),
    ("QuakeNet", "irc.quakenet.org", "", false),
    ("2600", "irc.2600.net", "", true),
];

const APP_STYLES: &str = r#"
:root {
    --bg: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
    --panel: rgba(20, 25, 45, 0.7);
    --border: rgba(100, 150, 255, 0.2);
    --text: #e0e7ff;
    --muted: #8892b0;
    --accent: #6366f1;
    --accent-dark: #4f46e5;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    --status-connected: #10b981;
    --status-connecting: #f59e0b;
    --status-disconnected: #ef4444;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
}

.top-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    backdrop-filter: blur(18px);
    gap: 16px;
}

.top-bar-left {
    display: flex;
    align-items: center;
    gap: 16px;
    flex: 1;
    min-width: 0;
}

.top-bar-right {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
}

.app-title {
    margin: 0;
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    white-space: nowrap;
}

.status-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
}

.status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    display: inline-block;
}

.status-dot.connected {
    background: var(--status-connected);
}

.status-dot.connecting {
    background: var(--status-connecting);
}

.status-dot.disconnected {
    background: var(--status-disconnected);
}

.compact-btn {
    padding: 6px 12px;
    font-size: 11px;
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid var(--accent);
    color: var(--accent);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    font-weight: 500;
    white-space: nowrap;
}

.compact-btn:hover {
    background: rgba(99, 102, 241, 0.25);
    transform: translateY(-1px);
}

/* Voice call button and dropdown */
.voice-btn.active {
    background: rgba(76, 175, 80, 0.3);
    border-color: #4CAF50;
    color: #4CAF50;
}

/* NSC (Nais Secure Channel) button */
.nsc-btn {
    background: rgba(99, 102, 241, 0.15);
    border-color: rgba(99, 102, 241, 0.4);
}

.nsc-btn:hover {
    background: rgba(99, 102, 241, 0.25);
    border-color: rgba(99, 102, 241, 0.6);
}

.voice-call-dropdown {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 4px;
    background: rgba(20, 25, 45, 0.98);
    border: 1px solid var(--border);
    border-radius: 8px;
    min-width: 200px;
    max-height: 300px;
    overflow: hidden;
    z-index: 1000;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(12px);
}

.voice-dropdown-header {
    padding: 10px 12px;
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
}

.voice-dropdown-empty {
    padding: 16px 12px;
    text-align: center;
    color: var(--muted);
    font-size: 12px;
}

.voice-dropdown-list {
    max-height: 250px;
    overflow-y: auto;
    padding: 4px;
}

.voice-dropdown-item {
    display: block;
    width: 100%;
    padding: 8px 12px;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
    text-align: left;
    font-size: 13px;
    border-radius: 4px;
    transition: background 0.2s;
}

.voice-dropdown-item:hover {
    background: rgba(99, 102, 241, 0.2);
}

.profile-search {
    flex: 1;
    max-width: 300px;
    padding: 6px 12px;
    font-size: 12px;
    background: rgba(30, 35, 55, 0.6);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    transition: all 0.2s;
}

.profile-search:focus {
    outline: none;
    border-color: var(--accent);
    background: rgba(30, 35, 55, 0.8);
}

.profile-search::placeholder {
    color: var(--muted);
}

.profiles-bar {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
}

.profiles-controls {
    display: flex;
    gap: 8px;
}

.profile-strip {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    padding: 10px 12px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    min-height: 48px;
}

.pill {
    padding: 6px 12px;
    background: rgba(99, 102, 241, 0.1);
    border: 1px solid var(--accent);
    color: var(--accent);
    border-radius: 20px;
    cursor: pointer;
    font-size: 12px;
    transition: all 0.2s;
}

.pill:hover {
    background: rgba(99, 102, 241, 0.2);
}

.pill.active {
    background: var(--accent);
    color: white;
}

.profile-name {
    display: flex;
    align-items: center;
    gap: 6px;
}

.profile-status {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

.profile-status.connected {
    background: var(--status-connected);
}

.profile-status.connecting {
    background: var(--status-connecting);
}

.profile-status.disconnected {
    background: var(--status-disconnected);
}

.menu-button {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0;
    font-size: 12px;
    margin-left: 4px;
}

.menu-button:hover {
    color: var(--text);
}

.menu-panel {
    position: absolute;
    top: 100%;
    left: 0;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 4px;
    min-width: 120px;
    z-index: 1000;
}

.menu-item {
    display: block;
    width: 100%;
    padding: 8px 12px;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
    text-align: left;
    font-size: 12px;
    transition: background 0.2s;
}

.menu-item:hover {
    background: rgba(99, 102, 241, 0.2);
}

.menu-item.disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.menu-item.disabled:hover {
    background: none;
}

/* User menu in userlist */
.user-row {
    position: relative;
}

.user-menu-btn {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: 2px 6px;
    font-size: 16px;
    font-weight: bold;
    opacity: 0;
    transition: opacity 0.2s, color 0.2s;
    line-height: 1;
}

.user-row:hover .user-menu-btn {
    opacity: 0.6;
}

.user-menu-btn:hover {
    opacity: 1 !important;
    color: var(--text);
}

.user-menu-panel {
    position: absolute;
    top: 100%;
    right: 0;
    background: rgba(20, 25, 45, 0.98);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 4px;
    min-width: 160px;
    z-index: 1000;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    overflow: visible;
}

/* CTCP Submenu styles */
.menu-submenu-container {
    position: relative;
    z-index: 1;
}

.submenu-trigger {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.ctcp-submenu {
    position: absolute;
    right: 0;
    top: 100%;
    margin-top: 4px;
    background: rgba(20, 25, 45, 0.98);
    border: 1px solid var(--accent);
    border-radius: 8px;
    padding: 4px;
    min-width: 140px;
    z-index: 9999;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

/* Danger menu items (kick/ban) */
.menu-item.danger {
    color: #ff6b6b;
}

.menu-item.danger:hover {
    background: rgba(255, 107, 107, 0.15);
    color: #ff5252;
}

/* WHOIS popup styles */
.whois-popup-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1001;
    backdrop-filter: blur(4px);
}

.whois-popup {
    background: rgba(20, 25, 45, 0.98);
    border: 1px solid var(--accent);
    border-radius: 16px;
    min-width: 360px;
    max-width: 500px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
    overflow: hidden;
}

.whois-popup-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    background: rgba(99, 102, 241, 0.1);
    border-bottom: 1px solid var(--border);
}

.whois-popup-header h3 {
    margin: 0;
    color: var(--accent);
    font-size: 18px;
    font-weight: 600;
}

.whois-popup-close {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 18px;
    padding: 4px 8px;
    border-radius: 4px;
    transition: all 0.2s;
}

.whois-popup-close:hover {
    color: var(--text);
    background: rgba(255, 255, 255, 0.1);
}

.whois-popup-content {
    padding: 16px 20px;
}

.whois-row {
    display: flex;
    align-items: flex-start;
    padding: 10px 0;
    border-bottom: 1px solid rgba(100, 150, 255, 0.1);
}

.whois-row:last-child {
    border-bottom: none;
}

.whois-label {
    min-width: 100px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.whois-value {
    flex: 1;
    color: var(--text);
    font-size: 14px;
    word-break: break-word;
}

.whois-channels {
    font-family: monospace;
    font-size: 13px;
}

/* CTCP response popup styles */
.ctcp-popup-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1001;
    backdrop-filter: blur(4px);
}

.ctcp-popup {
    background: rgba(20, 25, 45, 0.98);
    border: 1px solid #10b981;
    border-radius: 16px;
    min-width: 360px;
    max-width: 500px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
    overflow: hidden;
}

.ctcp-popup-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    background: rgba(16, 185, 129, 0.1);
    border-bottom: 1px solid var(--border);
}

.ctcp-popup-header h3 {
    margin: 0;
    color: #10b981;
    font-size: 18px;
    font-weight: 600;
}

.ctcp-popup-close {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 18px;
    padding: 4px 8px;
    border-radius: 4px;
    transition: all 0.2s;
}

.ctcp-popup-close:hover {
    color: var(--text);
    background: rgba(255, 255, 255, 0.1);
}

.ctcp-popup-content {
    padding: 16px 20px;
}

.ctcp-row {
    display: flex;
    align-items: flex-start;
    padding: 10px 0;
    border-bottom: 1px solid rgba(16, 185, 129, 0.1);
}

.ctcp-row:last-child {
    border-bottom: none;
}

.ctcp-label {
    min-width: 100px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.ctcp-value {
    flex: 1;
    color: var(--text);
    font-size: 14px;
    word-break: break-word;
}

.ctcp-command {
    font-family: monospace;
    color: #10b981;
    font-weight: 600;
}

.ctcp-response-text {
    font-family: monospace;
    font-size: 13px;
    background: rgba(16, 185, 129, 0.05);
    padding: 8px 12px;
    border-radius: 6px;
    white-space: pre-wrap;
}

.body {
    display: grid;
    grid-template-columns: 200px 1fr 200px;
    gap: 12px;
    flex: 1;
    overflow: hidden;
    min-height: 0;
}

.channels, .who {
    display: flex;
    flex-direction: column;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px;
    overflow: hidden;
    min-height: 0;
    max-height: 100%;
    transition: all 0.3s ease;
}

.channels.collapsed {
    padding: 8px 4px;
    align-items: center;
}

.channels.collapsed .section-title {
    flex-direction: column;
    align-items: center;
    margin-bottom: 12px;
}

.channels.collapsed ul {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
}

.channels.collapsed li {
    margin-bottom: 0;
}

.channels.collapsed .row {
    padding: 0;
    background: transparent;
    border: none;
    width: auto;
    display: flex;
    justify-content: center;
    align-items: center;
}

.channels.collapsed .row:hover {
    background: transparent;
}

.channel-icon {
    width: 42px;
    height: 42px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 16px;
    color: white;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    transition: all 0.2s;
}

.channel-icon-img {
    width: 80%;
    height: 80%;
    border-radius: 0;
    object-fit: contain;
}

.channel-icon:hover {
    transform: scale(1.1);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.row.active .channel-icon {
    box-shadow: 0 0 0 3px var(--accent);
}

.who.collapsed {
    padding: 8px 4px;
    align-items: center;
}

.who.collapsed .section-title {
    writing-mode: vertical-rl;
    text-orientation: mixed;
    margin-bottom: 0;
}

.collapse-btn {
    background: rgba(99, 102, 241, 0.1);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 4px 8px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    font-weight: bold;
    transition: all 0.2s;
}

.collapse-btn:hover {
    background: rgba(99, 102, 241, 0.2);
    transform: scale(1.05);
}

.section-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.channels ul, .who ul {
    list-style: none;
    padding: 0;
    margin: 0;
    flex: 1;
    overflow: auto;
}

.channels li, .who li {
    margin-bottom: 4px;
}

.row {
    display: block;
    width: 100%;
    padding: 6px 8px;
    background: rgba(99, 102, 241, 0.05);
    border: 1px solid transparent;
    color: var(--text);
    cursor: pointer;
    border-radius: 6px;
    font-size: 12px;
    text-align: left;
    transition: all 0.2s;
}

.row:hover {
    background: rgba(99, 102, 241, 0.15);
}

.row.active {
    background: var(--accent);
    color: white;
    border-color: var(--accent);
}

.chat {
    display: flex;
    flex-direction: column;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px;
    overflow: hidden;
    min-height: 0;
    max-height: 100%;
}

.chat-header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
}

.room {
    font-weight: 600;
    font-size: 14px;
    color: var(--accent);
    flex-shrink: 0;
}

.topic-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    background: linear-gradient(135deg, rgba(100, 150, 255, 0.08) 0%, rgba(100, 150, 255, 0.05) 100%);
    border-left: 3px solid var(--accent);
    border-radius: 6px;
    font-size: 12px;
    color: var(--text);
    line-height: 1.4;
    backdrop-filter: blur(4px);
    flex: 1;
    min-width: 0;
}

.topic-icon {
    font-size: 14px;
    flex-shrink: 0;
    opacity: 0.8;
}

.topic-icon.clickable {
    cursor: pointer;
    transition: opacity 0.2s, transform 0.2s;
}

.topic-icon.clickable:hover {
    opacity: 1;
    transform: scale(1.2);
}

.topic-text {
    flex: 1;
    word-wrap: break-word;
    overflow-wrap: break-word;
    word-break: break-word;
}

.messages {
    flex: 1;
    overflow: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.message {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13px;
    padding: 8px;
    border-radius: 6px;
    background: rgba(99, 102, 241, 0.05);
}

.message.system {
    background: rgba(249, 158, 11, 0.05);
    border-left: 2px solid var(--status-connecting);
}

.message-meta {
    font-size: 11px;
    color: var(--muted);
}

.user {
    color: var(--accent);
    font-weight: 600;
}

.message-text {
    color: var(--text);
    word-wrap: break-word;
}

.chat-link {
    color: var(--accent);
    text-decoration: underline;
    cursor: pointer;
    word-break: break-all;
}

.chat-link:hover {
    opacity: 0.8;
}

.system-text {
    color: var(--muted);
    font-style: italic;
    font-size: 12px;
}

.action-text {
    color: var(--text);
    font-style: italic;
    word-wrap: break-word;
}

.action-text .user {
    font-weight: 600;
}

.message-images {
    margin-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.message-images a {
    display: block;
    width: fit-content;
}

.embedded-image {
    max-width: 400px;
    max-height: 300px;
    border-radius: 8px;
    border: 1px solid var(--border);
    object-fit: contain;
    background: rgba(0, 0, 0, 0.2);
    transition: transform 0.2s, border-color 0.2s;
}

.embedded-image.clickable {
    cursor: pointer;
}

.embedded-image:hover {
    transform: scale(1.02);
    border-color: var(--accent);
}

.video-preview {
    position: relative;
    display: inline-block;
    max-width: 400px;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
    transition: transform 0.2s, box-shadow 0.2s;
}

.video-preview:hover {
    transform: scale(1.02);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.video-preview img {
    display: block;
    width: 100%;
    height: auto;
}

.discourse-embed {
    display: block;
    max-width: 500px;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    background: rgba(30, 35, 55, 0.6);
    transition: all 0.2s;
    text-decoration: none;
    color: var(--text);
    margin: 8px 0;
}

.discourse-embed:hover {
    background: rgba(40, 45, 65, 0.7);
    border-color: var(--accent);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.discourse-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    font-size: 11px;
    color: var(--subtext);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.discourse-icon {
    font-size: 14px;
}

.discourse-site {
    font-weight: 600;
}

.discourse-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 6px;
    line-height: 1.3;
}

.discourse-meta {
    display: flex;
    gap: 8px;
    font-size: 12px;
    color: var(--subtext);
    margin-bottom: 8px;
}

.discourse-author {
    color: var(--accent);
}

.discourse-category {
    color: var(--subtext);
}

.discourse-excerpt {
    font-size: 13px;
    color: rgba(255, 255, 255, 0.7);
    line-height: 1.4;
    overflow: hidden;
    text-overflow: ellipsis;
}

.composer {
    display: flex;
    gap: 8px;
}

.input {
    flex: 1;
    padding: 10px 12px;
    background: rgba(30, 35, 55, 0.8);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 8px;
    font-family: var(--font);
    font-size: 13px;
    transition: border 0.2s;
}

.input:focus {
    outline: none;
    border-color: var(--accent);
}

.input::placeholder {
    color: var(--muted);
}

.send {
    padding: 10px 16px;
    background: var(--accent);
    border: none;
    color: white;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    transition: all 0.2s;
}

.send:hover {
    background: var(--accent-dark);
    transform: translateY(-1px);
}

.send:active {
    transform: translateY(0);
}

.modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
}

.modal {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    max-width: 400px;
    width: 90vw;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.modal-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text);
}

.modal-body {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 16px;
}

.modal-body .input {
    width: 100%;
}

.modal-actions {
    display: flex;
    gap: 12px;
    justify-content: flex-end;
}

.modal-actions button {
    flex: 1;
}

.import-list {
    max-height: 400px;
    overflow: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.import-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px;
    background: rgba(99, 102, 241, 0.05);
    border: 1px solid var(--border);
    border-radius: 8px;
    gap: 12px;
}

.import-main {
    flex: 1;
}

.import-name {
    font-weight: 600;
    font-size: 13px;
    color: var(--text);
    margin-bottom: 4px;
}

.import-meta {
    font-size: 11px;
    color: var(--muted);
}

.import-row button {
    flex-shrink: 0;
}

/* Settings Modal Styles */
.settings-modal {
    max-width: 500px;
}

.settings-body {
    max-height: 60vh;
    overflow-y: auto;
}

.settings-section {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
}

.settings-section:last-child {
    margin-bottom: 0;
}

.settings-section-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--accent);
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}

.settings-profile-name {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 12px;
    padding: 8px;
    background: rgba(99, 102, 241, 0.1);
    border-radius: 6px;
}

.settings-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
}

.settings-row:last-child {
    margin-bottom: 0;
}

.settings-row.checkbox-row {
    gap: 8px;
}

.settings-label {
    font-size: 13px;
    color: var(--text);
    min-width: 140px;
    flex-shrink: 0;
}

.checkbox-row .settings-label {
    min-width: unset;
    cursor: pointer;
}

.settings-input {
    flex: 1;
    max-width: 240px;
}

.settings-input-small {
    width: 100px;
    text-align: center;
}

.settings-hint {
    font-size: 11px;
    color: var(--muted);
    min-width: 50px;
}

.settings-select {
    flex: 1;
    max-width: 240px;
    padding: 8px;
    background: var(--input);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 12px;
}

.settings-slider {
    flex: 1;
    max-width: 150px;
    height: 6px;
    -webkit-appearance: none;
    appearance: none;
    background: var(--border);
    border-radius: 3px;
    outline: none;
}

.settings-slider::-webkit-slider-thumb {
    -webkit-appearance: none;
    appearance: none;
    width: 16px;
    height: 16px;
    background: var(--accent);
    border-radius: 50%;
    cursor: pointer;
}

.settings-slider::-moz-range-thumb {
    width: 16px;
    height: 16px;
    background: var(--accent);
    border-radius: 50%;
    cursor: pointer;
    border: none;
}

.settings-refresh-btn {
    background: rgba(99, 102, 241, 0.1);
    padding: 6px 12px;
    font-size: 12px;
}

.settings-btn {
    background: rgba(99, 102, 241, 0.15);
}

.settings-btn:hover {
    background: rgba(99, 102, 241, 0.25);
}

.send.primary {
    background: var(--accent);
}

/* Scrollbar styling */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: transparent;
}

::-webkit-scrollbar-thumb {
    background: rgba(99, 102, 241, 0.3);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: rgba(99, 102, 241, 0.5);
}
"#;

