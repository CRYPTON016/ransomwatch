//! Pattern matching module for ransomware detection
//!
//! Contains known ransomware file extensions, ransom note filenames,
//! and suspicious process names.

use std::collections::HashSet;
use std::path::Path;

/// Pattern matcher for detecting ransomware indicators
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// Known ransomware file extensions
    ransomware_extensions: HashSet<String>,

    /// Known ransom note filenames (case-insensitive)
    ransom_note_patterns: Vec<RansomNotePattern>,

    /// Suspicious process names that may indicate ransomware
    suspicious_processes: HashSet<String>,

    /// Commands that indicate backup deletion
    backup_deletion_commands: Vec<String>,
}

#[derive(Debug, Clone)]
struct RansomNotePattern {
    pattern: String,
    note_type: String,
    exact_match: bool,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    /// Create a new pattern matcher with default patterns
    pub fn new() -> Self {
        Self {
            ransomware_extensions: Self::default_ransomware_extensions(),
            ransom_note_patterns: Self::default_ransom_note_patterns(),
            suspicious_processes: Self::default_suspicious_processes(),
            backup_deletion_commands: Self::default_backup_deletion_commands(),
        }
    }

    /// Check if a file has a known ransomware extension
    pub fn is_ransomware_extension(&self, path: &Path) -> Option<String> {
        let extension = path.extension()?
            .to_str()?
            .to_lowercase();

        if self.ransomware_extensions.contains(&extension) {
            return Some(extension);
        }

        // Also check for double extensions like .pdf.locked
        let filename = path.file_name()?.to_str()?;
        for ext in &self.ransomware_extensions {
            if filename.to_lowercase().ends_with(&format!(".{}", ext)) {
                return Some(ext.clone());
            }
        }

        None
    }

    /// Check if a file appears to be a ransom note
    pub fn is_ransom_note(&self, path: &Path) -> Option<String> {
        let filename = path.file_name()?
            .to_str()?
            .to_lowercase();

        for pattern in &self.ransom_note_patterns {
            if pattern.exact_match {
                if filename == pattern.pattern.to_lowercase() {
                    return Some(pattern.note_type.clone());
                }
            } else if filename.contains(&pattern.pattern.to_lowercase()) {
                return Some(pattern.note_type.clone());
            }
        }

        None
    }

    /// Check if a process name is suspicious
    pub fn is_suspicious_process(&self, process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        self.suspicious_processes.iter().any(|p| name_lower.contains(p))
    }

    /// Check if a command line indicates backup deletion
    pub fn is_backup_deletion_command(&self, command: &str) -> Option<String> {
        let cmd_lower = command.to_lowercase();

        for pattern in &self.backup_deletion_commands {
            if cmd_lower.contains(pattern) {
                return Some(pattern.clone());
            }
        }

        None
    }

    /// Add a custom ransomware extension
    pub fn add_extension(&mut self, ext: impl Into<String>) {
        self.ransomware_extensions.insert(ext.into().to_lowercase());
    }

    /// Add a custom ransom note pattern
    pub fn add_ransom_note_pattern(&mut self, pattern: impl Into<String>, note_type: impl Into<String>, exact: bool) {
        self.ransom_note_patterns.push(RansomNotePattern {
            pattern: pattern.into(),
            note_type: note_type.into(),
            exact_match: exact,
        });
    }

    /// Default ransomware file extensions
    fn default_ransomware_extensions() -> HashSet<String> {
        [
            // LockBit variants
            "lockbit", "lockbit3", "lockbit2",
            // REvil/Sodinokibi
            "revil", "sodinokibi",
            // Ryuk
            "ryuk", "ryk",
            // Conti
            "conti",
            // Maze
            "maze",
            // DarkSide
            "darkside",
            // RansomEXX
            "ransomexx",
            // BlackCat/ALPHV
            "blackcat", "alphv",
            // Hive
            "hive",
            // Black Basta
            "basta",
            // Royal
            "royal",
            // Play
            "play",
            // Clop
            "clop", "ciop",
            // Akira
            "akira",
            // Generic encrypted extensions
            "encrypted", "enc", "crypted", "crypto", "crypt",
            "locked", "lock", "lok",
            "cerber", "cerber2", "cerber3",
            "locky", "zepto", "odin", "thor", "aesir",
            "wallet", "btc", "onion",
            "wncry", "wcry", "wanna",
            "petya", "notpetya",
            "bad", "dharma", "cesar", "arena", "cobra",
            "gandcrab", "gcrab",
            "globe", "purge", "globe2", "globe3",
            "spora",
            "shade", "troldesh",
            "jaff",
            "sage", "sage2",
            "mamba",
            "cry", "cryp1", "crypz",
            "xxx", "xyz", "zzz", "aaa", "abc",
            "ecc", "ezz", "exx",
            "vvv", "ttt", "micro",
            "mp3", // Some ransomware uses this
            "breaking_bad", "heisenberg",
            "osiris", "lukitus", "diablo6",
            "nochance", "nocry",
            "wasted", "payed", "pays",
            "evil", "devil", "demon",
            "madebyadam", "made_by_adam",
            "unknown", "noob", "hacked",
        ].iter().map(|s| s.to_string()).collect()
    }

    /// Default ransom note filename patterns
    fn default_ransom_note_patterns() -> Vec<RansomNotePattern> {
        vec![
            // Generic patterns
            RansomNotePattern { pattern: "readme".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "decrypt".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "recover".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "restore".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "how_to".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "howto".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "help_decrypt".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "help_recover".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "read_me".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "read-me".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "ransom".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "!read".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "_read".into(), note_type: "Generic".into(), exact_match: false },
            RansomNotePattern { pattern: "your_files".into(), note_type: "Generic".into(), exact_match: false },

            // Specific ransomware families
            RansomNotePattern { pattern: "lockbit".into(), note_type: "LockBit".into(), exact_match: false },
            RansomNotePattern { pattern: "restore-my-files.txt".into(), note_type: "LockBit".into(), exact_match: true },

            RansomNotePattern { pattern: "ryuk".into(), note_type: "Ryuk".into(), exact_match: false },
            RansomNotePattern { pattern: "ryukreadme".into(), note_type: "Ryuk".into(), exact_match: false },

            RansomNotePattern { pattern: "conti".into(), note_type: "Conti".into(), exact_match: false },
            RansomNotePattern { pattern: "conti_readme".into(), note_type: "Conti".into(), exact_match: false },

            RansomNotePattern { pattern: "wannacry".into(), note_type: "WannaCry".into(), exact_match: false },
            RansomNotePattern { pattern: "@wanadecryptor".into(), note_type: "WannaCry".into(), exact_match: false },
            RansomNotePattern { pattern: "@please_read_me".into(), note_type: "WannaCry".into(), exact_match: false },

            RansomNotePattern { pattern: "cerber".into(), note_type: "Cerber".into(), exact_match: false },
            RansomNotePattern { pattern: "# decrypt my files #".into(), note_type: "Cerber".into(), exact_match: false },

            RansomNotePattern { pattern: "locky".into(), note_type: "Locky".into(), exact_match: false },
            RansomNotePattern { pattern: "_locky_recover".into(), note_type: "Locky".into(), exact_match: false },

            RansomNotePattern { pattern: "gandcrab".into(), note_type: "GandCrab".into(), exact_match: false },
            RansomNotePattern { pattern: "krab-decrypt".into(), note_type: "GandCrab".into(), exact_match: false },

            RansomNotePattern { pattern: "darkside".into(), note_type: "DarkSide".into(), exact_match: false },

            RansomNotePattern { pattern: "blackcat".into(), note_type: "BlackCat".into(), exact_match: false },
            RansomNotePattern { pattern: "alphv".into(), note_type: "BlackCat".into(), exact_match: false },
            RansomNotePattern { pattern: "recover-".into(), note_type: "BlackCat".into(), exact_match: false },

            RansomNotePattern { pattern: "hive".into(), note_type: "Hive".into(), exact_match: false },

            RansomNotePattern { pattern: "akira".into(), note_type: "Akira".into(), exact_match: false },

            // Payment/contact indicators
            RansomNotePattern { pattern: "bitcoin".into(), note_type: "Payment".into(), exact_match: false },
            RansomNotePattern { pattern: "btc".into(), note_type: "Payment".into(), exact_match: false },
            RansomNotePattern { pattern: "monero".into(), note_type: "Payment".into(), exact_match: false },
            RansomNotePattern { pattern: "tor".into(), note_type: "Contact".into(), exact_match: false },
            RansomNotePattern { pattern: "onion".into(), note_type: "Contact".into(), exact_match: false },
        ]
    }

    /// Default suspicious process names
    fn default_suspicious_processes() -> HashSet<String> {
        [
            // Volume shadow copy deletion
            "vssadmin",
            "wmic",
            "shadowcopy",

            // Boot config modification
            "bcdedit",

            // Windows backup tools
            "wbadmin",

            // Disk management
            "diskpart",

            // Recovery disabling
            "recoveryenabled",

            // Windows Defender manipulation
            "mpcmdrun",

            // Network reconnaissance
            "nltest",
            "dsquery",
            "net.exe",

            // PowerShell encoded commands (suspicious)
            "powershell -e",
            "powershell -enc",
            "powershell -encodedcommand",

            // Certificate store manipulation
            "certutil",
        ].iter().map(|s| s.to_string()).collect()
    }

    /// Default backup deletion command patterns
    fn default_backup_deletion_commands() -> Vec<String> {
        vec![
            // Volume Shadow Copy deletion
            "vssadmin delete shadows".into(),
            "vssadmin.exe delete shadows".into(),
            "wmic shadowcopy delete".into(),

            // Windows backup deletion
            "wbadmin delete catalog".into(),
            "wbadmin delete systemstatebackup".into(),

            // Boot config modification
            "bcdedit /set {default} recoveryenabled no".into(),
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures".into(),

            // Recycle bin clearing
            "rd /s /q".into(),

            // Linux/Unix backup deletion
            "rm -rf /var/backups".into(),
            "rm -rf ~/.snapshots".into(),

            // Time Machine (macOS)
            "tmutil delete".into(),

            // Btrfs snapshots
            "btrfs subvolume delete".into(),

            // ZFS snapshots
            "zfs destroy".into(),
        ]
    }

    /// Get all known ransomware extensions
    pub fn get_extensions(&self) -> &HashSet<String> {
        &self.ransomware_extensions
    }

    /// Get count of known patterns
    pub fn pattern_count(&self) -> (usize, usize, usize) {
        (
            self.ransomware_extensions.len(),
            self.ransom_note_patterns.len(),
            self.suspicious_processes.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ransomware_extensions() {
        let matcher = PatternMatcher::new();

        assert!(matcher.is_ransomware_extension(&PathBuf::from("file.lockbit")).is_some());
        assert!(matcher.is_ransomware_extension(&PathBuf::from("document.pdf.encrypted")).is_some());
        assert!(matcher.is_ransomware_extension(&PathBuf::from("normal.pdf")).is_none());
        assert!(matcher.is_ransomware_extension(&PathBuf::from("IMPORTANT.RYUK")).is_some());
    }

    #[test]
    fn test_ransom_notes() {
        let matcher = PatternMatcher::new();

        assert!(matcher.is_ransom_note(&PathBuf::from("README.txt")).is_some());
        assert!(matcher.is_ransom_note(&PathBuf::from("DECRYPT_FILES.html")).is_some());
        assert!(matcher.is_ransom_note(&PathBuf::from("HOW_TO_RECOVER.txt")).is_some());
        assert!(matcher.is_ransom_note(&PathBuf::from("normal_document.txt")).is_none());
    }

    #[test]
    fn test_suspicious_processes() {
        let matcher = PatternMatcher::new();

        assert!(matcher.is_suspicious_process("vssadmin.exe"));
        assert!(matcher.is_suspicious_process("WMIC.exe"));
        assert!(matcher.is_suspicious_process("bcdedit"));
        assert!(!matcher.is_suspicious_process("notepad.exe"));
    }

    #[test]
    fn test_backup_deletion() {
        let matcher = PatternMatcher::new();

        assert!(matcher.is_backup_deletion_command("vssadmin delete shadows /all /quiet").is_some());
        assert!(matcher.is_backup_deletion_command("wmic shadowcopy delete").is_some());
        assert!(matcher.is_backup_deletion_command("notepad.exe").is_none());
    }
}
