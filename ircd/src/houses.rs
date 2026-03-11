//! Houses & Rooms System
//!
//! A "House" is a group of channels (rooms) under a single owner — like
//! a Discord server/guild but mapped onto IRC semantics.
//!
//! - Houses have an owner, roles, and members.
//! - Rooms are IRC channels within a house, with per-room permission overrides.
//! - Room IRC names are formatted as: #house.room (e.g., #myguild.general)
//! - Standalone IRC channels (#channel) still work outside the house system.

use crate::permissions::{
    HouseMember, PermissionOverride, Role, PermissionBits,
    PERM_READ_MESSAGES, PERM_SEND_MESSAGES,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Room (channel within a house)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomType {
    /// Standard text chat room
    Text,
    /// Voice chat room
    Voice,
    /// Announcement room (only certain roles can post)
    Announcement,
    /// Stage room (like voice but with speaker/audience model)
    Stage,
}

/// A room within a house. Maps to an IRC channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    /// Room ID (unique within house)
    pub id: String,
    /// Display name (e.g., "general", "off-topic")
    pub name: String,
    /// Room topic
    pub topic: String,
    /// Room type
    pub room_type: RoomType,
    /// Position for ordering in client UI
    pub position: i32,
    /// Category this room belongs to (for grouping in UI)
    pub category: Option<String>,
    /// Per-room permission overrides
    pub overrides: Vec<PermissionOverride>,
    /// Slowmode delay in seconds (0 = disabled)
    pub slowmode: u32,
    /// Whether the room is NSFW-flagged
    pub nsfw: bool,
    /// User limit (0 = no limit) — primarily for voice rooms
    pub user_limit: u32,
    /// Whether server-side persistent logging is enabled for this room
    /// (allows scrollback replay on join, like Discord). Off by default.
    /// Not possible on secure channels where messages bypass the server.
    pub logging: bool,
}

impl Room {
    /// Create a new text room.
    pub fn new_text(name: &str) -> Self {
        Room {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            topic: String::new(),
            room_type: RoomType::Text,
            position: 0,
            category: None,
            overrides: Vec::new(),
            slowmode: 0,
            nsfw: false,
            user_limit: 0,
            logging: false,
        }
    }

    /// Create a new voice room.
    pub fn new_voice(name: &str) -> Self {
        Room {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            topic: String::new(),
            room_type: RoomType::Voice,
            position: 0,
            category: None,
            overrides: Vec::new(),
            slowmode: 0,
            nsfw: false,
            user_limit: 0,
            logging: false,
        }
    }

    /// Create an announcement room (read-only for most, only specified roles can post).
    pub fn new_announcement(name: &str) -> Self {
        let mut room = Room::new_text(name);
        room.room_type = RoomType::Announcement;
        // Default override: deny SEND_MESSAGES for @everyone
        room.overrides.push(PermissionOverride {
            target: crate::permissions::OverrideTarget::Role("everyone".to_string()),
            allow: PERM_READ_MESSAGES,
            deny: PERM_SEND_MESSAGES,
        });
        room
    }

    /// The IRC channel name for this room within a house.
    pub fn irc_channel_name(&self, house_name: &str) -> String {
        format!("#{}.{}", house_name, self.name)
    }
}

// =============================================================================
// Category (grouping of rooms within a house)
// =============================================================================

/// A category groups rooms visually (like Discord channel categories).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub position: i32,
    /// Category-level permission overrides (inherited by rooms unless overridden)
    pub overrides: Vec<PermissionOverride>,
}

impl Category {
    pub fn new(name: &str) -> Self {
        Category {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            position: 0,
            overrides: Vec::new(),
        }
    }
}

// =============================================================================
// House (guild / server)
// =============================================================================

/// A House is a collection of rooms under a single owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct House {
    /// Unique house ID
    pub id: String,
    /// House name (used in IRC channel prefixes: #house.room)
    pub name: String,
    /// House description
    pub description: String,
    /// Owner's nickname
    pub owner: String,
    /// House icon URL (optional)
    pub icon: Option<String>,
    /// When the house was created
    pub created_at: i64,

    /// Roles defined in this house (keyed by role ID)
    pub roles: HashMap<String, Role>,
    /// Members of this house (keyed by nickname)
    pub members: HashMap<String, HouseMember>,
    /// Rooms in this house (keyed by room ID)
    pub rooms: HashMap<String, Room>,
    /// Categories for grouping rooms
    pub categories: HashMap<String, Category>,

    /// Banned users (nick -> reason)
    pub bans: HashMap<String, String>,
    /// Invite codes (code -> uses remaining, 0 = infinite)
    pub invites: HashMap<String, InviteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub code: String,
    pub creator: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: u32,
    pub uses: u32,
}

impl House {
    /// Create a new house with default rooms and roles.
    pub fn new(name: &str, owner: &str) -> Self {
        let mut roles = HashMap::new();
        let everyone = Role::everyone();
        roles.insert("everyone".to_string(), everyone);

        let mut members = HashMap::new();
        let owner_member = HouseMember::new(owner);
        // Owner doesn't need special roles — ownership itself grants ALL_PERMISSIONS
        members.insert(owner.to_string(), owner_member);

        // Create default rooms
        let mut rooms = HashMap::new();
        let general = Room::new_text("general");
        let voice_general = Room::new_voice("voice");
        rooms.insert(general.id.clone(), general);
        rooms.insert(voice_general.id.clone(), voice_general);

        // Default category
        let mut categories = HashMap::new();
        let text_cat = Category::new("Text Channels");
        let voice_cat = Category::new("Voice Channels");
        categories.insert(text_cat.id.clone(), text_cat);
        categories.insert(voice_cat.id.clone(), voice_cat);

        House {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            owner: owner.to_string(),
            icon: None,
            created_at: chrono::Utc::now().timestamp(),
            roles,
            members,
            rooms,
            categories,
            bans: HashMap::new(),
            invites: HashMap::new(),
        }
    }

    /// Check if a user is the owner.
    pub fn is_owner(&self, nick: &str) -> bool {
        self.owner.eq_ignore_ascii_case(nick)
    }

    /// Check if a user is a member.
    pub fn is_member(&self, nick: &str) -> bool {
        self.members.contains_key(nick)
    }

    /// Check if a user is banned.
    pub fn is_banned(&self, nick: &str) -> bool {
        self.bans.contains_key(nick)
    }

    /// Get a member's effective roles as Role references.
    pub fn get_member_roles(&self, nick: &str) -> Vec<&Role> {
        if let Some(member) = self.members.get(nick) {
            member.roles.iter()
                .filter_map(|rid| self.roles.get(rid))
                .collect()
        } else {
            vec![]
        }
    }

    /// Get a member's role IDs.
    pub fn get_member_role_ids(&self, nick: &str) -> Vec<String> {
        if let Some(member) = self.members.get(nick) {
            member.roles.clone()
        } else {
            vec![]
        }
    }

    /// Compute effective permissions for a user in a specific room.
    pub fn compute_room_permissions(&self, nick: &str, room_id: &str) -> PermissionBits {
        let is_owner = self.is_owner(nick);
        let roles = self.get_member_roles(nick);
        let role_ids = self.get_member_role_ids(nick);
        let overrides = if let Some(room) = self.rooms.get(room_id) {
            &room.overrides
        } else {
            return 0;
        };
        crate::permissions::compute_permissions(is_owner, &roles, overrides, &role_ids, nick)
    }

    /// Add a member to the house.
    pub fn add_member(&mut self, nick: &str) -> Result<(), &'static str> {
        if self.is_banned(nick) {
            return Err("User is banned from this house");
        }
        if self.is_member(nick) {
            return Err("User is already a member");
        }
        self.members.insert(nick.to_string(), HouseMember::new(nick));
        Ok(())
    }

    /// Remove a member from the house.
    pub fn remove_member(&mut self, nick: &str) -> Result<(), &'static str> {
        if self.is_owner(nick) {
            return Err("Cannot remove the house owner");
        }
        if self.members.remove(nick).is_some() {
            Ok(())
        } else {
            Err("User is not a member")
        }
    }

    /// Add a role to the house.
    pub fn add_role(&mut self, role: Role) -> Result<(), &'static str> {
        if self.roles.contains_key(&role.id) {
            return Err("Role ID already exists");
        }
        self.roles.insert(role.id.clone(), role);
        Ok(())
    }

    /// Remove a role from the house (cannot remove @everyone).
    pub fn remove_role(&mut self, role_id: &str) -> Result<(), &'static str> {
        if role_id == "everyone" {
            return Err("Cannot remove the @everyone role");
        }
        // Remove from all members
        for member in self.members.values_mut() {
            member.remove_role(role_id);
        }
        if self.roles.remove(role_id).is_some() {
            Ok(())
        } else {
            Err("Role not found")
        }
    }

    /// Add a room to the house.
    pub fn add_room(&mut self, room: Room) -> Result<String, &'static str> {
        let id = room.id.clone();
        // Check name uniqueness
        for existing in self.rooms.values() {
            if existing.name.eq_ignore_ascii_case(&room.name) {
                return Err("Room name already exists in this house");
            }
        }
        self.rooms.insert(id.clone(), room);
        Ok(id)
    }

    /// Remove a room from the house.
    pub fn remove_room(&mut self, room_id: &str) -> Result<(), &'static str> {
        if self.rooms.remove(room_id).is_some() {
            Ok(())
        } else {
            Err("Room not found")
        }
    }

    /// Find a room by name.
    pub fn find_room_by_name(&self, name: &str) -> Option<&Room> {
        self.rooms.values().find(|r| r.name.eq_ignore_ascii_case(name))
    }

    /// Find a room by name (mutable).
    pub fn find_room_by_name_mut(&mut self, name: &str) -> Option<&mut Room> {
        self.rooms.values_mut().find(|r| r.name.eq_ignore_ascii_case(name))
    }

    /// Generate an invite code.
    pub fn create_invite(&mut self, creator: &str, max_uses: u32, expires_secs: Option<i64>) -> String {
        let code: String = (0..8)
            .map(|_| {
                let idx = rand::random::<u8>() % 36;
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();

        let now = chrono::Utc::now().timestamp();
        let info = InviteInfo {
            code: code.clone(),
            creator: creator.to_string(),
            created_at: now,
            expires_at: expires_secs.map(|s| now + s),
            max_uses,
            uses: 0,
        };
        self.invites.insert(code.clone(), info);
        code
    }

    /// Use an invite code. Returns Ok(()) if successful.
    pub fn use_invite(&mut self, code: &str, nick: &str) -> Result<(), &'static str> {
        let now = chrono::Utc::now().timestamp();
        let invite = self.invites.get_mut(code).ok_or("Invalid invite code")?;

        if let Some(exp) = invite.expires_at {
            if now > exp {
                return Err("Invite has expired");
            }
        }
        if invite.max_uses > 0 && invite.uses >= invite.max_uses {
            return Err("Invite has reached max uses");
        }

        invite.uses += 1;
        self.add_member(nick)
    }

    /// Get all IRC channel names for this house.
    pub fn irc_channel_names(&self) -> Vec<String> {
        self.rooms.values()
            .map(|r| r.irc_channel_name(&self.name))
            .collect()
    }
}

// =============================================================================
// House Manager (part of server state)
// =============================================================================

/// Parse a channel name to see if it's a house room.  
/// Returns Some((house_name, room_name)) for "#house.room", None for plain channels.
pub fn parse_house_channel(channel: &str) -> Option<(&str, &str)> {
    let channel = channel.strip_prefix('#').or_else(|| channel.strip_prefix('&'))?;
    let dot = channel.find('.')?;
    if dot == 0 || dot == channel.len() - 1 {
        return None;
    }
    Some((&channel[..dot], &channel[dot + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_house() {
        let house = House::new("testguild", "owner_nick");
        assert_eq!(house.name, "testguild");
        assert!(house.is_owner("owner_nick"));
        assert!(house.is_member("owner_nick"));
        assert!(house.rooms.len() >= 2); // general + voice
    }

    #[test]
    fn test_parse_house_channel() {
        assert_eq!(parse_house_channel("#myguild.general"), Some(("myguild", "general")));
        assert_eq!(parse_house_channel("#myguild.voice"), Some(("myguild", "voice")));
        assert_eq!(parse_house_channel("#plainChannel"), None);
        assert_eq!(parse_house_channel("&#local.room"), Some(("#local", "room")));
    }

    #[test]
    fn test_invite_flow() {
        let mut house = House::new("testguild", "owner");
        let code = house.create_invite("owner", 5, None);
        assert!(house.use_invite(&code, "newuser").is_ok());
        assert!(house.is_member("newuser"));
        assert!(house.use_invite(&code, "newuser").is_err()); // already member
    }

    #[test]
    fn test_room_permissions() {
        let house = House::new("testguild", "owner_nick");
        let room_id = house.rooms.values().next().unwrap().id.clone();

        // Owner gets everything
        let perms = house.compute_room_permissions("owner_nick", &room_id);
        assert_eq!(perms, crate::permissions::ALL_PERMISSIONS);

        // Regular member gets default perms (through @everyone)
        let mut house2 = house.clone();
        house2.add_member("regular").unwrap();
        let perms = house2.compute_room_permissions("regular", &room_id);
        assert!(crate::permissions::has_permission(perms, PERM_READ_MESSAGES));
        assert!(crate::permissions::has_permission(perms, PERM_SEND_MESSAGES));
    }
}
