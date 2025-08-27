use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeAttributes {
    pub inode: u64,
    pub file_type: FileType,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u16,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
    pub parent_inode: Option<u64>,
    pub name: String,
}

impl InodeAttributes {
    pub fn new_file(inode: u64, name: String, size: u64, parent_inode: Option<u64>) -> Self {
        let now = SystemTime::now();
        Self {
            inode,
            file_type: FileType::File,
            size,
            uid: 1000,
            gid: 1000,
            permissions: 0o644,
            created: now,
            modified: now,
            accessed: now,
            parent_inode,
            name,
        }
    }

    pub fn new_directory(inode: u64, name: String, parent_inode: Option<u64>) -> Self {
        let now = SystemTime::now();
        Self {
            inode,
            file_type: FileType::Directory,
            size: 4096,
            uid: 1000,
            gid: 1000,
            permissions: 0o755,
            created: now,
            modified: now,
            accessed: now,
            parent_inode,
            name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub modified: SystemTime,
    pub inode: u64,
}