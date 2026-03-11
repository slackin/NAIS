//! Advanced Permissions System
//!
//! Discord-style role-based permissions with per-channel/room overrides.
//! Permissions are bitfield-based for efficient storage and checking.

use serde::{Deserialize, Serialize};

// =============================================================================
// Permission Bits
// =============================================================================

/// Permission bitfield type.
pub type PermissionBits = u64;

// -- General server permissions --
pub const PERM_ADMIN: u64              = 1 << 0;   // Full server admin (bypasses all checks)
pub const PERM_MANAGE_HOUSE: u64       = 1 << 1;   // Create/delete/edit house settings
pub const PERM_MANAGE_ROOMS: u64       = 1 << 2;   // Create/delete/rename rooms in a house
pub const PERM_MANAGE_ROLES: u64       = 1 << 3;   // Create/delete/edit roles
pub const PERM_MANAGE_MEMBERS: u64     = 1 << 4;   // Kick/ban members from house
pub const PERM_INVITE_MEMBERS: u64     = 1 << 5;   // Invite users to the house
pub const PERM_VIEW_AUDIT_LOG: u64     = 1 << 6;   // View house audit log

// -- Channel/room permissions --
pub const PERM_READ_MESSAGES: u64      = 1 << 10;  // View messages in a room
pub const PERM_SEND_MESSAGES: u64      = 1 << 11;  // Send messages in a room
pub const PERM_MANAGE_MESSAGES: u64    = 1 << 12;  // Delete others' messages
pub const PERM_EMBED_LINKS: u64        = 1 << 13;  // Post links that preview
pub const PERM_ATTACH_FILES: u64       = 1 << 14;  // Upload files/images
pub const PERM_MENTION_EVERYONE: u64   = 1 << 15;  // @everyone / @here
pub const PERM_USE_EXTERNAL_EMOJI: u64 = 1 << 16;  // Use emoji from other houses
pub const PERM_SET_TOPIC: u64          = 1 << 17;  // Change room topic

// -- Voice permissions --
pub const PERM_VOICE_CONNECT: u64      = 1 << 20;  // Connect to voice rooms
pub const PERM_VOICE_SPEAK: u64        = 1 << 21;  // Speak in voice rooms
pub const PERM_VOICE_MUTE: u64         = 1 << 22;  // Server-mute others
pub const PERM_VOICE_DEAFEN: u64       = 1 << 23;  // Server-deafen others
pub const PERM_VOICE_MOVE: u64         = 1 << 24;  // Move users between voice rooms
pub const PERM_VOICE_PRIORITY: u64     = 1 << 25;  // Priority speaker

// -- Moderation permissions --
pub const PERM_KICK: u64              = 1 << 30;  // Kick from room/house
pub const PERM_BAN: u64               = 1 << 31;  // Ban from house
pub const PERM_TIMEOUT: u64           = 1 << 32;  // Timeout (temp mute) a member
pub const PERM_MANAGE_LOGGING: u64    = 1 << 33;  // Toggle persistent message logging on a room

// -- IRC compatibility permissions --
pub const PERM_IRC_OPER: u64          = 1 << 40;  // IRC operator
pub const PERM_IRC_CHANOP: u64        = 1 << 41;  // Channel operator (@)
pub const PERM_IRC_HALFOP: u64        = 1 << 42;  // Half-operator (%)
pub const PERM_IRC_VOICE: u64         = 1 << 43;  // Voiced (+v)

/// Default permissions for @everyone in a newly created house.
pub const DEFAULT_EVERYONE_PERMS: u64 = PERM_READ_MESSAGES
    | PERM_SEND_MESSAGES
    | PERM_EMBED_LINKS
    | PERM_ATTACH_FILES
    | PERM_VOICE_CONNECT
    | PERM_VOICE_SPEAK;

/// All permissions (for owner/admin).
pub const ALL_PERMISSIONS: u64 = u64::MAX;

// =============================================================================
// Role
// =============================================================================

/// A named role with a permission set and display properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Permissions granted by this role
    pub permissions: PermissionBits,
    /// Position in hierarchy (higher = more authority). Owner is always top.
    pub position: i32,
    /// Color for display (IRC color code or hex)
    pub color: Option<String>,
    /// Whether this role is mentionable
    pub mentionable: bool,
    /// Whether this role is shown separately in member list
    pub hoist: bool,
}

impl Role {
    /// Create the built-in @everyone role for a house.
    pub fn everyone() -> Self {
        Role {
            id: "everyone".to_string(),
            name: "everyone".to_string(),
            permissions: DEFAULT_EVERYONE_PERMS,
            position: 0,
            color: None,
            mentionable: false,
            hoist: false,
        }
    }

    /// Create a moderator role template.
    pub fn moderator() -> Self {
        Role {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Moderator".to_string(),
            permissions: DEFAULT_EVERYONE_PERMS
                | PERM_MANAGE_MESSAGES
                | PERM_KICK
                | PERM_TIMEOUT
                | PERM_VOICE_MUTE
                | PERM_VOICE_DEAFEN
                | PERM_VOICE_MOVE
                | PERM_MENTION_EVERYONE
                | PERM_SET_TOPIC,
            position: 50,
            color: Some("#00ff00".to_string()),
            mentionable: true,
            hoist: true,
        }
    }

    /// Create an admin role template.
    pub fn admin() -> Self {
        Role {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Admin".to_string(),
            permissions: ALL_PERMISSIONS & !PERM_ADMIN, // everything except server admin
            position: 90,
            color: Some("#ff0000".to_string()),
            mentionable: true,
            hoist: true,
        }
    }

    pub fn has_permission(&self, perm: PermissionBits) -> bool {
        (self.permissions & PERM_ADMIN) != 0 || (self.permissions & perm) == perm
    }
}

// =============================================================================
// Permission Override (per-room)
// =============================================================================

/// A permission override for a specific role or user in a specific room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionOverride {
    /// Target: either a role ID or a user nick (prefixed with "user:" or "role:")
    pub target: OverrideTarget,
    /// Permissions explicitly allowed (ORed on top of role perms)
    pub allow: PermissionBits,
    /// Permissions explicitly denied (takes priority over allow)
    pub deny: PermissionBits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OverrideTarget {
    Role(String),
    User(String),
}

// =============================================================================
// Permission Computation
// =============================================================================

/// Compute effective permissions for a user given their roles and optional room overrides.
///
/// Algorithm (matches Discord's model):
/// 1. Start with @everyone base permissions.
/// 2. OR in all role permissions the user has.
/// 3. If user is house owner, return ALL_PERMISSIONS.
/// 4. If ADMIN bit is set, return ALL_PERMISSIONS.
/// 5. Apply role-level overrides for the room (allow/deny).
/// 6. Apply user-level overrides for the room (allow/deny, highest priority).
pub fn compute_permissions(
    is_owner: bool,
    roles: &[&Role],
    room_overrides: &[PermissionOverride],
    user_roles: &[String],
    username: &str,
) -> PermissionBits {
    // Owner bypasses everything
    if is_owner {
        return ALL_PERMISSIONS;
    }

    // 1. Start with base permissions from all roles
    let mut perms: PermissionBits = 0;
    for role in roles {
        perms |= role.permissions;
    }

    // 2. Admin bypass
    if (perms & PERM_ADMIN) != 0 {
        return ALL_PERMISSIONS;
    }

    // 3. Apply role overrides for this room
    let mut allow: PermissionBits = 0;
    let mut deny: PermissionBits = 0;
    for ov in room_overrides {
        match &ov.target {
            OverrideTarget::Role(role_id) => {
                if role_id == "everyone" || user_roles.contains(role_id) {
                    allow |= ov.allow;
                    deny |= ov.deny;
                }
            }
            _ => {}
        }
    }
    perms = (perms & !deny) | allow;

    // 4. Apply user-specific overrides (highest priority)
    let mut user_allow: PermissionBits = 0;
    let mut user_deny: PermissionBits = 0;
    for ov in room_overrides {
        if ov.target == OverrideTarget::User(username.to_string()) {
            user_allow |= ov.allow;
            user_deny |= ov.deny;
        }
    }
    perms = (perms & !user_deny) | user_allow;

    perms
}

/// Check a single permission bit.
pub fn has_permission(effective: PermissionBits, perm: PermissionBits) -> bool {
    (effective & perm) == perm
}

// =============================================================================
// Member in a House
// =============================================================================

/// A member's state within a house.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HouseMember {
    /// The user's nickname (must be registered/connected)
    pub nick: String,
    /// Role IDs this member holds in this house
    pub roles: Vec<String>,
    /// When they joined the house
    pub joined_at: i64,
    /// Optional timeout expiry (unix timestamp), 0 = not timed out
    pub timeout_until: i64,
    /// House-specific display name override
    pub house_nick: Option<String>,
}

impl HouseMember {
    pub fn new(nick: &str) -> Self {
        Self {
            nick: nick.to_string(),
            roles: vec!["everyone".to_string()],
            joined_at: chrono::Utc::now().timestamp(),
            timeout_until: 0,
            house_nick: None,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        self.timeout_until > 0 && chrono::Utc::now().timestamp() < self.timeout_until
    }

    pub fn has_role(&self, role_id: &str) -> bool {
        self.roles.contains(&role_id.to_string())
    }

    pub fn add_role(&mut self, role_id: &str) {
        if !self.has_role(role_id) {
            self.roles.push(role_id.to_string());
        }
    }

    pub fn remove_role(&mut self, role_id: &str) {
        self.roles.retain(|r| r != role_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_everyone_default_perms() {
        let role = Role::everyone();
        assert!(role.has_permission(PERM_READ_MESSAGES));
        assert!(role.has_permission(PERM_SEND_MESSAGES));
        assert!(!role.has_permission(PERM_KICK));
        assert!(!role.has_permission(PERM_ADMIN));
    }

    #[test]
    fn test_owner_gets_all() {
        let perms = compute_permissions(true, &[], &[], &[], "owner");
        assert_eq!(perms, ALL_PERMISSIONS);
    }

    #[test]
    fn test_role_deny_override() {
        let everyone = Role::everyone();
        let overrides = vec![PermissionOverride {
            target: OverrideTarget::Role("everyone".to_string()),
            allow: 0,
            deny: PERM_SEND_MESSAGES,
        }];
        let perms = compute_permissions(
            false,
            &[&everyone],
            &overrides,
            &["everyone".to_string()],
            "testuser",
        );
        assert!(has_permission(perms, PERM_READ_MESSAGES));
        assert!(!has_permission(perms, PERM_SEND_MESSAGES));
    }

    #[test]
    fn test_user_override_beats_role() {
        let everyone = Role::everyone();
        let overrides = vec![
            PermissionOverride {
                target: OverrideTarget::Role("everyone".to_string()),
                allow: 0,
                deny: PERM_SEND_MESSAGES,
            },
            PermissionOverride {
                target: OverrideTarget::User("specialuser".to_string()),
                allow: PERM_SEND_MESSAGES,
                deny: 0,
            },
        ];
        let perms = compute_permissions(
            false,
            &[&everyone],
            &overrides,
            &["everyone".to_string()],
            "specialuser",
        );
        assert!(has_permission(perms, PERM_SEND_MESSAGES));
    }
}
