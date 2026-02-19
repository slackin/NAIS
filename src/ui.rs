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

pub fn run() {
    dioxus::launch(app);
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
    let default_nick = use_signal(|| store.default_nickname.clone());

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

    let mut input = use_signal(|| String::new());
    let history = use_signal(Vec::new);
    let mut history_index = use_signal(|| None::<usize>);

    let mut show_new_profile = use_signal(|| false);
    let mut show_edit_profile = use_signal(|| false);
    let mut show_import_modal = use_signal(|| false);
    let mut show_channel_browser = use_signal(|| false);
    let mut show_first_run_setup = use_signal(|| store.default_nickname.is_none());
    let mut profile_menu_open = use_signal(|| None::<String>);

    let mut new_server_input = use_signal(String::new);
    let mut new_nick_input = use_signal(String::new);
    let mut new_channel_input = use_signal(String::new);
    let mut new_tls_input = use_signal(|| true);
    let mut new_auto_connect_input = use_signal(|| true);
    
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

    let mut search_input = use_signal(String::new);
    let mut channel_list: Signal<Vec<(String, u32, String)>> = use_signal(Vec::new);
    let mut channel_search_input = use_signal(String::new);
    let mut list_loading = use_signal(|| false);
    let mut channels_collapsed = use_signal(|| false);
    let mut userlist_collapsed = use_signal(|| false);
    let mut topic_collapsed = use_signal(|| false);

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

    // Main event loop to poll cores for IRC events
    {
        let mut state_handle = state;
        let mut status_handle = profile_status;
        let mut channel_list_handle = channel_list;
        let mut list_loading_handle = list_loading;
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
                                _ => {}
                            }
                            
                            let mut state_mut = state_handle.write();
                            let profiles_read = profiles.read();
                            apply_event_with_config(&mut state_mut, &profiles_read, &profile_name, event.clone());
                            
                            // Update profile_status signal based on the event
                            if matches!(event, IrcEvent::Connected { .. }) {
                                status_handle.write().insert(profile_name.clone(), ConnectionStatus::Connected);
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
    }

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
                                prof_name,
                                state,
                                profiles,
                                last_used,
                                profile_status,
                                cores,
                                skip_reconnect,
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
                                                            prof_name_clone.clone(),
                                                            state,
                                                            profiles,
                                                            last_used,
                                                            profile_status,
                                                            cores,
                                                            skip_reconnect,
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
                                                    }
                                                    drop(profs);
                                                    
                                                    show_edit_profile.set(true);
                                                    profile_menu_open.set(None);
                                                },
                                                "Edit"
                                            }
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
                        // Server Log channel - only show if enabled for this profile
                        {
                            let active_profile = state.read().active_profile.clone();
                            let log_visible = show_server_log.read().get(&active_profile).copied().unwrap_or(false);
                            
                            if log_visible {
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
                        
                        // Regular channels
                        {
                            let channels = state.read()
                                .servers
                                .get(&state.read().active_profile)
                                .map(|s| s.channels.clone())
                                .unwrap_or_default();
                            
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
                    }
                }

                // Chat area
                div {
                    class: "chat",
                    div {
                        class: "chat-header",
                        div {
                            class: "room",
                            "{state.read().servers
                                .get(&state.read().active_profile)
                                .map(|s| s.current_channel.clone())
                                .unwrap_or_else(|| \"No channel\".to_string())}"
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
                            let current_channel = state.read().servers
                                .get(&state.read().active_profile)
                                .map(|s| s.current_channel.clone())
                                .unwrap_or_default();
                            
                            if current_channel == "Server Log" {
                                // Show server connection log
                                let log_entries = state.read()
                                    .servers
                                    .get(&state.read().active_profile)
                                    .map(|s| s.connection_log.clone())
                                    .unwrap_or_default();
                                
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
                            } else {
                                // Show regular chat messages
                                let messages = state.read()
                                    .servers
                                    .get(&state.read().active_profile)
                                    .map(|s| {
                                        s.messages.iter()
                                            .filter(|m| m.channel == current_channel)
                                            .cloned()
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default();
                                
                                rsx! {
                                    for msg in messages {
                                        {message_view(msg)}
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
                        let current_channel = state.read().servers
                            .get(&state.read().active_profile)
                            .map(|s| s.current_channel.clone())
                            .unwrap_or_default();

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
                        } else {
                            // Show regular users list
                            let mut users = state.read()
                                .servers
                                .get(&state.read().active_profile)
                                .and_then(|s| {
                                    s.users_by_channel.get(&current_channel).cloned()
                                })
                                .unwrap_or_default();
                            
                            // Sort users: ops (@) first, then voice (+), then regular users
                            users.sort_by(|a, b| {
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
                                            
                                            rsx! {
                                                li {
                                                    div {
                                                        class: "row",
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

            // Input composer
            div {
                class: "composer",
                input {
                    id: "chat-input",
                    class: "input",
                    r#type: "text",
                    placeholder: "Type message or /command...",
                    value: "{input}",
                    oninput: move |evt| {
                        input.set(evt.value());
                    },
                    onkeydown: move |evt| {
                        match evt.key() {
                            Key::Enter => {
                                let text = input.read().clone();
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
                                );
                            }
                            Key::ArrowUp => {
                                let hist = history.read();
                                let current_idx = *history_index.read();
                                let next_idx = match current_idx {
                                    None => hist.len().saturating_sub(1),
                                    Some(idx) => idx.saturating_sub(1),
                                };
                                if next_idx < hist.len() {
                                    history_index.set(Some(next_idx));
                                    input.set(hist[next_idx].clone());
                                }
                            }
                            Key::ArrowDown => {
                                let hist = history.read();
                                let current_idx = *history_index.read();
                                if let Some(idx) = current_idx {
                                    if idx < hist.len() - 1 {
                                        let next_idx = idx + 1;
                                        history_index.set(Some(next_idx));
                                        input.set(hist[next_idx].clone());
                                    } else {
                                        history_index.set(None);
                                        input.set(String::new());
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
                        let text = input.read().clone();
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
                        );
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
                                };
                                let _ = profile::save_store(&store);

                                new_server_input.set(String::new());
                                new_nick_input.set(String::new());
                                new_channel_input.set(String::new());
                                new_tls_input.set(true);
                                new_auto_connect_input.set(true);
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
                        input {
                            class: "input",
                            r#type: "text",
                            placeholder: "Server",
                            value: "{edit_server_input}",
                            oninput: move |evt| {
                                edit_server_input.set(evt.value());
                            },
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
                        for (label, server) in IMPORT_NETWORKS.iter() {
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
                                        "{server}"
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
                                            channel: String::new(),
                                            use_tls: true,
                                            auto_connect: true,
                                            enable_logging: true,
                                            scrollback_limit: 1000,
                                            log_buffer_size: 1000,
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

        // Channel Browser Modal
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
                if target.is_empty() || text.is_empty() {
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
    profile_name: String,
    mut state: Signal<irc_client::AppState>,
    _profiles: Signal<Vec<profile::Profile>>,
    _last_used: Signal<Option<String>>,
    mut profile_status: Signal<HashMap<String, ConnectionStatus>>,
    mut cores: Signal<HashMap<String, irc_client::CoreHandle>>,
    mut skip_reconnect: Signal<HashMap<String, bool>>,
) {
    let core = irc_client::start_core();
    cores.write().insert(profile_name.clone(), core.clone());
    skip_reconnect.write().insert(profile_name.clone(), false);
    profile_status.write().insert(profile_name.clone(), ConnectionStatus::Connecting);

    let cmd_tx = core.cmd_tx.clone();
    let _ = cmd_tx.try_send(IrcCommandEvent::Connect {
        server,
        nickname,
        channel,
        use_tls,
    });

    let mut state_mut = state.write();
    if let Some(server_state) = state_mut.servers.get_mut(&profile_name) {
        server_state.status = ConnectionStatus::Connecting;
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

fn message_view(msg: ChatMessage) -> Element {
    let system_class = if msg.is_system { " system" } else { "" };
    let action_class = if msg.is_action { " action" } else { "" };
    
    // Extract media content (images, videos, etc.) from the message text
    let media_items = extract_media_content(&msg.text);
    
    rsx! {
        div {
            class: format!("message{system_class}{action_class}"),
            if msg.is_system {
                div {
                    class: "system-text",
                    "{msg.text}"
                }
            } else if msg.is_action {
                div {
                    class: "action-text",
                    span {
                        class: "user",
                        style: "color: {username_color(&msg.user)};",
                        "* {msg.user}"
                    }
                    span {
                        " {msg.text}"
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
                    span {
                        class: "user",
                        style: "color: {username_color(&msg.user)};",
                        "{msg.user}"
                    }
                }
                div {
                    class: "message-text",
                    "{msg.text}"
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
    _label: &str,
    server: &str,
    nickname: &str,
    existing_profiles: &[profile::Profile],
) -> String {
    let base_name = profile::profile_name(server, nickname, "");
    let mut name = base_name.clone();
    let mut counter = 1;
    while existing_profiles.iter().any(|p| p.name == name) {
        name = format!("{base_name} ({counter})");
        counter += 1;
    }
    name
}

const IMPORT_NETWORKS: &[(&str, &str)] = &[
    ("Libera.Chat", "irc.libera.chat"),
    ("freenode", "irc.freenode.net"),
    ("OFTC", "irc.oftc.net"),
    ("Undernet", "irc.undernet.org"),
    ("EFnet", "irc.efnet.org"),
    ("IRCnet", "irc.ircnet.net"),
    ("DALnet", "irc.dalnet.net"),
    ("QuakeNet", "irc.quakenet.org"),
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

