//! IRC Protocol Parser & Types
//!
//! RFC 2812 compliant message parsing with extensions for NAIS features.

use std::fmt;

/// Maximum IRC message length (including CRLF)
pub const MAX_MSG_LEN: usize = 512;

/// Extended message length for NAIS capabilities
pub const MAX_MSG_LEN_EXTENDED: usize = 8192;

// =============================================================================
// IRC Message
// =============================================================================

/// A parsed IRC protocol message.
#[derive(Debug, Clone)]
pub struct Message {
    /// Optional message tags (IRCv3)
    pub tags: Option<String>,
    /// Source prefix (nick!user@host or server name)
    pub prefix: Option<String>,
    /// Command (PRIVMSG, JOIN, etc.)
    pub command: String,
    /// Command parameters
    pub params: Vec<String>,
}

impl Message {
    /// Parse a raw IRC line into a Message.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches("\r\n").trim_end_matches('\n');
        if line.is_empty() {
            return None;
        }

        let mut rest = line;
        
        // Parse IRCv3 tags (@key=value;key2=value2)
        let tags = if rest.starts_with('@') {
            let end = rest.find(' ')?;
            let t = rest[1..end].to_string();
            rest = rest[end..].trim_start();
            Some(t)
        } else {
            None
        };

        // Parse prefix (:nick!user@host)
        let prefix = if rest.starts_with(':') {
            let end = rest.find(' ')?;
            let p = rest[1..end].to_string();
            rest = rest[end..].trim_start();
            Some(p)
        } else {
            None
        };

        // Parse command
        let (command, remainder) = if let Some(idx) = rest.find(' ') {
            (rest[..idx].to_uppercase(), rest[idx..].trim_start())
        } else {
            (rest.to_uppercase(), "")
        };

        // Parse params
        let mut params = Vec::new();
        let mut rest = remainder;
        while !rest.is_empty() {
            if rest.starts_with(':') {
                // Trailing parameter (rest of line)
                params.push(rest[1..].to_string());
                break;
            }
            if let Some(idx) = rest.find(' ') {
                params.push(rest[..idx].to_string());
                rest = rest[idx..].trim_start();
            } else {
                params.push(rest.to_string());
                break;
            }
        }

        Some(Message {
            tags,
            prefix,
            command,
            params,
        })
    }

    /// Serialize the message to wire format.
    pub fn to_wire(&self) -> String {
        let mut out = String::with_capacity(512);

        if let Some(ref tags) = self.tags {
            out.push('@');
            out.push_str(tags);
            out.push(' ');
        }

        if let Some(ref prefix) = self.prefix {
            out.push(':');
            out.push_str(prefix);
            out.push(' ');
        }

        out.push_str(&self.command);

        for (i, param) in self.params.iter().enumerate() {
            out.push(' ');
            if i == self.params.len() - 1 && (param.contains(' ') || param.starts_with(':') || param.is_empty()) {
                out.push(':');
            }
            out.push_str(param);
        }

        out.push_str("\r\n");
        out
    }

    /// Create a new numeric reply from server to client.
    pub fn numeric(server_name: &str, numeric: u16, target: &str, text: &str) -> Self {
        Message {
            tags: None,
            prefix: Some(server_name.to_string()),
            command: format!("{:03}", numeric),
            params: vec![target.to_string(), text.to_string()],
        }
    }

    /// Create a server notice.
    pub fn server_notice(server_name: &str, target: &str, text: &str) -> Self {
        Message {
            tags: None,
            prefix: Some(server_name.to_string()),
            command: "NOTICE".to_string(),
            params: vec![target.to_string(), text.to_string()],
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_wire().trim_end())
    }
}

// =============================================================================
// IRC Numeric Replies
// =============================================================================

// Connection registration
pub const RPL_WELCOME: u16 = 1;
pub const RPL_YOURHOST: u16 = 2;
pub const RPL_CREATED: u16 = 3;
pub const RPL_MYINFO: u16 = 4;
pub const RPL_ISUPPORT: u16 = 5;

// User queries
pub const RPL_WHOISUSER: u16 = 311;
pub const RPL_WHOISSERVER: u16 = 312;
pub const RPL_WHOISOPERATOR: u16 = 313;
pub const RPL_ENDOFWHOIS: u16 = 318;
pub const RPL_WHOISCHANNELS: u16 = 319;
pub const RPL_WHOISACCOUNT: u16 = 330;

// Channel queries
pub const RPL_TOPIC: u16 = 332;
pub const RPL_TOPICWHOTIME: u16 = 333;
pub const RPL_NAMREPLY: u16 = 353;
pub const RPL_ENDOFNAMES: u16 = 366;

// MOTD
pub const RPL_MOTDSTART: u16 = 375;
pub const RPL_MOTD: u16 = 372;
pub const RPL_ENDOFMOTD: u16 = 376;

// Channel list
pub const RPL_LIST: u16 = 322;
pub const RPL_LISTEND: u16 = 323;

// Mode
pub const RPL_CHANNELMODEIS: u16 = 324;
pub const RPL_UMODEIS: u16 = 221;

// WHO
pub const RPL_WHOREPLY: u16 = 352;
pub const RPL_ENDOFWHO: u16 = 315;

// HOUSE custom numerics (use 800-899 range for NAIS extensions)
pub const RPL_HOUSELIST: u16 = 800;
pub const RPL_HOUSELISTEND: u16 = 801;
pub const RPL_HOUSEINFO: u16 = 802;
pub const RPL_HOUSEROOMLIST: u16 = 803;
pub const RPL_HOUSEROOMLISTEND: u16 = 804;
pub const RPL_HOUSEROLES: u16 = 805;
pub const RPL_HOUSEROLESEND: u16 = 806;
pub const RPL_HOUSEMEMBERS: u16 = 807;
pub const RPL_HOUSEMEMBERSEND: u16 = 808;

// Error numerics
pub const ERR_NOSUCHNICK: u16 = 401;
pub const ERR_NOSUCHCHANNEL: u16 = 403;
pub const ERR_CANNOTSENDTOCHAN: u16 = 404;
pub const ERR_UNKNOWNCOMMAND: u16 = 421;
pub const ERR_NONICKNAMEGIVEN: u16 = 431;
pub const ERR_ERRONEUSNICKNAME: u16 = 432;
pub const ERR_NICKNAMEINUSE: u16 = 433;
pub const ERR_USERNOTINCHANNEL: u16 = 441;
pub const ERR_NOTONCHANNEL: u16 = 442;
pub const ERR_NOTREGISTERED: u16 = 451;
pub const ERR_NEEDMOREPARAMS: u16 = 461;
pub const ERR_ALREADYREGISTRED: u16 = 462;
pub const ERR_PASSWDMISMATCH: u16 = 464;
pub const ERR_CHANNELISFULL: u16 = 471;
pub const ERR_INVITEONLYCHAN: u16 = 473;
pub const ERR_BANNEDFROMCHAN: u16 = 474;
pub const ERR_BADCHANNELKEY: u16 = 475;
pub const ERR_CHANOPRIVSNEEDED: u16 = 482;
pub const ERR_NOPRIVILEGES: u16 = 481;

// NAIS batch/fast protocol numerics (810-829)
// Used when client negotiates nais.dev/fast capability
pub const RPL_BATCHNAMES: u16 = 810;     // Batch NAMES: JSON array of {nick, prefix}
pub const RPL_BATCHLIST: u16 = 811;      // Batch LIST: JSON array of {name, count, topic}
pub const RPL_BATCHWHO: u16 = 812;       // Batch WHO: JSON array of who entries
pub const RPL_BATCHHOUSELIST: u16 = 813; // Batch HOUSE LIST: JSON array
pub const RPL_BATCHROOMLIST: u16 = 814;  // Batch HOUSE ROOM LIST: JSON array
pub const RPL_BATCHMEMBERS: u16 = 815;   // Batch HOUSE MEMBERS: JSON array
pub const RPL_BATCHROLES: u16 = 816;     // Batch HOUSE ROLE LIST: JSON array

// Scrollback replay
pub const RPL_SCROLLBACK: u16 = 820;     // Single scrollback history line
pub const RPL_SCROLLBACKEND: u16 = 821;  // End of scrollback replay
pub const RPL_BATCHSCROLLBACK: u16 = 822; // Batch scrollback: JSON array (fast clients)

// NAIS extension errors
pub const ERR_NOSUCHHOUSE: u16 = 900;
pub const ERR_HOUSEPERMDENIED: u16 = 901;
pub const ERR_NOTHOUSEMEMBER: u16 = 902;
pub const ERR_ALREADYHOUSEMEMBER: u16 = 903;
pub const ERR_NOSUCHROOM: u16 = 904;
pub const ERR_NOSUCHROLE: u16 = 905;

// =============================================================================
// Validation helpers
// =============================================================================

/// Check if a nickname is valid per IRC rules + NAIS extensions.
pub fn is_valid_nick(nick: &str) -> bool {
    if nick.is_empty() || nick.len() > 30 {
        return false;
    }
    let first = nick.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' && first != '[' && first != ']'
        && first != '{' && first != '}' && first != '\\' && first != '|' && first != '`'
    {
        return false;
    }
    nick.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '[' || c == ']'
            || c == '{' || c == '}' || c == '\\' || c == '|' || c == '`'
    })
}

/// Check if a channel name is valid.
pub fn is_valid_channel(name: &str) -> bool {
    if name.len() < 2 || name.len() > 50 {
        return false;
    }
    let prefix = name.chars().next().unwrap();
    if prefix != '#' && prefix != '&' {
        return false;
    }
    !name.contains(' ') && !name.contains(',') && !name.contains('\x07')
}

/// Check if a house name is valid (alphanumeric + hyphens/underscores).
pub fn is_valid_house_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 50 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let msg = Message::parse("NICK testuser\r\n").unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["testuser"]);
    }

    #[test]
    fn test_parse_with_prefix() {
        let msg = Message::parse(":nick!user@host PRIVMSG #channel :Hello World\r\n").unwrap();
        assert_eq!(msg.prefix.unwrap(), "nick!user@host");
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello World"]);
    }

    #[test]
    fn test_roundtrip() {
        let original = ":server PRIVMSG #test :hello world\r\n";
        let msg = Message::parse(original).unwrap();
        assert_eq!(msg.to_wire(), original);
    }

    #[test]
    fn test_valid_nick() {
        assert!(is_valid_nick("testuser"));
        assert!(is_valid_nick("_test_"));
        assert!(!is_valid_nick("123bad"));
        assert!(!is_valid_nick(""));
    }

    #[test]
    fn test_valid_channel() {
        assert!(is_valid_channel("#test"));
        assert!(is_valid_channel("&local"));
        assert!(!is_valid_channel("nochanprefix"));
        assert!(!is_valid_channel("#"));
    }
}
