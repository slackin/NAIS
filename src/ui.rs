use dioxus::events::Key;
use dioxus::prelude::*;
use futures_timer::Delay;
use std::collections::HashMap;
use std::time::Duration;

use crate::irc_client::{self, ChatMessage, ConnectionStatus, IrcCommandEvent, IrcEvent};
use crate::profile;

pub fn run() {
    dioxus::launch(app);
}

fn app() -> Element {
    let store = profile::load_store();
    let initial_profile = profile::select_profile(&store);

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
    let mut history = use_signal(Vec::new);
    let mut history_index = use_signal(|| None::<usize>);

    let mut show_new_profile = use_signal(|| false);
    let mut show_edit_profile = use_signal(|| false);
    let mut show_import_modal = use_signal(|| false);
    let mut show_channel_browser = use_signal(|| false);
    let mut profile_menu_open = use_signal(|| None::<String>);

    let mut new_server_input = use_signal(String::new);
    let mut new_nick_input = use_signal(String::new);
    let mut new_channel_input = use_signal(String::new);
    let mut new_tls_input = use_signal(|| true);
    let mut new_auto_connect_input = use_signal(|| true);

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

    // Auto-scroll messages to bottom when they change
    use_effect(move || {
        let _ = eval(
            r#"
            const messagesDiv = document.querySelector('.messages');
            if (messagesDiv) {
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            "#
        );
    });

    // Event loop to poll cores for IRC events
    {
        let mut state_handle = state;
        let mut status_handle = profile_status;
        let mut channel_list_handle = channel_list;
        let mut list_loading_handle = list_loading;
        spawn(async move {
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

                        while let Ok(event) = evt_rx.try_recv() {
                            // Handle channel list events separately
                            match &event {
                                IrcEvent::ChannelListItem { channel, user_count, topic } => {
                                    channel_list_handle.write().push((
                                        channel.clone(),
                                        *user_count,
                                        topic.clone(),
                                    ));
                                    continue;
                                }
                                IrcEvent::ChannelListEnd => {
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
                            irc_client::apply_event(&mut state_mut, &profile_name, event.clone());
                            
                            // Update profile_status signal based on the event
                            if matches!(event, IrcEvent::Connected { .. }) {
                                status_handle.write().insert(profile_name.clone(), ConnectionStatus::Connected);
                                
                                // Auto-refresh channel list 5 seconds after connection
                                let prof_name_clone = profile_name.clone();
                                let cores_clone = cores.clone();
                                let mut channel_list_clone = channel_list_handle.clone();
                                let mut list_loading_clone = list_loading_handle.clone();
                                spawn(async move {
                                    Delay::new(Duration::from_secs(5)).await;
                                    
                                    // Clear and start loading
                                    channel_list_clone.set(Vec::new());
                                    list_loading_clone.set(true);
                                    
                                    // Send LIST command
                                    let cores_read = cores_clone.read();
                                    if let Some(handle) = cores_read.get(&prof_name_clone) {
                                        let cmd_tx = handle.cmd_tx.clone();
                                        drop(cores_read);
                                        let _ = cmd_tx.send(irc_client::IrcCommandEvent::List).await;
                                    }
                                });
                            } else if matches!(event, IrcEvent::Disconnected) {
                                status_handle.write().insert(profile_name.clone(), ConnectionStatus::Disconnected);
                            }
                            drop(state_mut);
                        }
                    } else {
                        drop(cores_read);
                    }
                }

                Delay::new(Duration::from_millis(100)).await;
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

            // Header
            div {
                style: "display:flex; align-items:center; justify-content:space-between; padding:16px; background:var(--panel); border:1px solid var(--border); border-radius:16px; backdrop-filter:blur(18px);",
                h1 { style: "margin:0; font-size:24px;", "NAIS-client" }
                div {
                    style: "display:flex; gap:12px; align-items:center;",
                    div {
                        style: "font-size:12px; color:var(--muted);",
                        if let Some(server_state) = state.read().servers.get(&state.read().active_profile) {
                            match server_state.status {
                                ConnectionStatus::Connected => {
                                    rsx! {
                                        span {
                                            style: "width:8px; height:8px; border-radius:999px; display:inline-block; background:var(--status-connected); margin-right:6px;",
                                        }
                                        "Connected"
                                    }
                                }
                                ConnectionStatus::Connecting => {
                                    rsx! {
                                        span {
                                            style: "width:8px; height:8px; border-radius:999px; display:inline-block; background:var(--status-connecting); margin-right:6px;",
                                        }
                                        "Connecting"
                                    }
                                }
                                ConnectionStatus::Disconnected => {
                                    rsx! {
                                        span {
                                            style: "width:8px; height:8px; border-radius:999px; display:inline-block; background:var(--status-disconnected); margin-right:6px;",
                                        }
                                        "Disconnected"
                                    }
                                }
                            }
                        }
                    }
                    button {
                        class: "send",
                        style: "padding:8px 12px; font-size:12px;",
                        onclick: move |_| {
                            show_import_modal.set(true);
                        },
                        "Import"
                    }
                }
            }

            // Profiles bar
            div {
                class: "profiles-bar",
                div {
                    class: "profiles-controls",
                    input {
                        class: "profile-search compact",
                        r#type: "text",
                        placeholder: "Search profiles...",
                        value: "{search_input}",
                        oninput: move |evt| {
                            search_input.set(evt.value());
                        },
                    }
                    button {
                        class: "send",
                        style: "padding:6px 10px; font-size:12px;",
                        onclick: move |_| {
                            show_new_profile.set(true);
                        },
                        "New"
                    }
                }

                div {
                    class: "profile-strip",
                    { 
                        let profile_list: Vec<_> = profiles.read().iter().cloned().collect();
                        rsx! {
                            for (idx, prof) in profile_list.into_iter().enumerate() {
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

                                                        let mut store = profile::ProfileStore {
                                                            profiles: profiles.read().clone(),
                                                            last_used: last_used.read().clone(),
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
                                                    },
                                                    title: "{channel}",
                                                    if channels_collapsed() {
                                                        div {
                                                            class: "channel-icon",
                                                            style: "background: {color};",
                                                            "{first_letter}"
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
                    }

                    div {
                        class: "messages",
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
                                );
                            }
                            Key::ArrowUp => {
                                let mut hist = history.read();
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
                        );
                    },
                    "Send"
                }
            }
        }

        // Modals
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

                                let mut store = profile::ProfileStore {
                                    profiles: profiles.read().clone(),
                                    last_used: last_used.read().clone(),
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

                                    let mut store = profile::ProfileStore {
                                        profiles: profiles.read().clone(),
                                        last_used: last_used.read().clone(),
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
                                            nickname: default_nick,
                                            channel: String::new(),
                                            use_tls: true,
                                            auto_connect: true,
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

                                        let mut store = profile::ProfileStore {
                                            profiles: profiles.read().clone(),
                                            last_used: last_used.read().clone(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                irc_client::apply_event(
                    &mut state.write(),
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
                    };
                    let _ = profile::save_store(&store);
                } else {
                    drop(profs_mut);
                }
            }
            "/nick" => {
                if arg.is_empty() {
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                    irc_client::apply_event(
                        &mut state.write(),
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
                irc_client::apply_event(
                    &mut state.write(),
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
                irc_client::apply_event(
                    &mut state.write(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: format!("{target}: {note}"),
                    },
                );
            }
            _ => {
                irc_client::apply_event(
                    &mut state.write(),
                    &active_profile,
                    IrcEvent::System {
                        channel,
                        text: "Unknown command.".to_string(),
                    },
                );
            }
        }
        input.set(String::new());
        return;
    }

    if let Some(handle) = handle.as_ref() {
        let _ = handle.cmd_tx.try_send(IrcCommandEvent::Send {
            channel: channel.clone(),
            text: text.clone(),
        });
    }

    irc_client::apply_event(
        &mut state.write(),
        &active_profile,
        IrcEvent::Message {
            channel,
            user: nickname,
            text,
        },
    );

    input.set(String::new());
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
    rsx! {
        div {
            class: format!("message{system_class}"),
            if msg.is_system {
                div {
                    class: "system-text",
                    "{msg.text}"
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
            }
        }
    }
}

fn unique_profile_label(
    label: &str,
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

.profile-search {
    flex: 1;
    padding: 6px 10px;
    font-size: 12px;
    background: rgba(30, 35, 55, 0.8);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
}

.profile-search::placeholder {
    color: var(--muted);
}

.profile-strip {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
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
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
}

.room {
    font-weight: 600;
    font-size: 14px;
    color: var(--accent);
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

