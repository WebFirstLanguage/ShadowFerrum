use super::types::{DirectoryEntry, FileType, InodeAttributes};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Path not found: {0}")]
    NotFound(String),
    
    #[error("Path already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    
    #[error("Directory not empty: {0}")]
    DirectoryNotEmpty(String),
    
    #[error("Not a directory: {0}")]
    NotADirectory(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub struct StorageEngine {
    data_root: PathBuf,
    next_inode: Arc<RwLock<u64>>,
    path_to_inode: Arc<RwLock<HashMap<String, u64>>>,
}

impl StorageEngine {
    pub async fn new(data_root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&data_root).await?;
        fs::create_dir_all(data_root.join("inodes")).await?;
        fs::create_dir_all(data_root.join("content")).await?;
        
        let mut engine = Self {
            data_root,
            next_inode: Arc::new(RwLock::new(2)),
            path_to_inode: Arc::new(RwLock::new(HashMap::new())),
        };
        
        engine.ensure_root_exists().await?;
        engine.rebuild_path_cache().await?;
        
        Ok(engine)
    }
    
    async fn ensure_root_exists(&mut self) -> Result<()> {
        let root_inode_path = self.data_root.join("inodes").join("1.json");
        if !fs::try_exists(&root_inode_path).await.unwrap_or(false) {
            let root_attrs = InodeAttributes::new_directory(1, "/".to_string(), None);
            let json = serde_json::to_string_pretty(&root_attrs)?;
            fs::write(root_inode_path, json).await?;
            
            let mut path_cache = self.path_to_inode.write().await;
            path_cache.insert("/".to_string(), 1);
        }
        Ok(())
    }
    
    async fn rebuild_path_cache(&mut self) -> Result<()> {
        let inodes_dir = self.data_root.join("inodes");
        let mut entries = fs::read_dir(&inodes_dir).await?;
        let mut max_inode = 1u64;
        let mut path_cache = HashMap::new();
        
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".json") {
                    let inode_str = name.trim_end_matches(".json");
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        max_inode = max_inode.max(inode);
                        
                        let content = fs::read_to_string(entry.path()).await?;
                        if let Ok(attrs) = serde_json::from_str::<InodeAttributes>(&content) {
                            let path = self.build_path_from_inode(&attrs).await?;
                            path_cache.insert(path, inode);
                        }
                    }
                }
            }
        }
        
        *self.next_inode.write().await = max_inode + 1;
        *self.path_to_inode.write().await = path_cache;
        
        Ok(())
    }
    
    async fn build_path_from_inode(&self, attrs: &InodeAttributes) -> Result<String> {
        if attrs.inode == 1 {
            return Ok("/".to_string());
        }
        
        let mut path_components = vec![attrs.name.clone()];
        let mut current = attrs.parent_inode;
        
        while let Some(parent_inode) = current {
            if parent_inode == 1 {
                break;
            }
            
            let parent_attrs = self.load_inode_attributes(parent_inode).await?;
            path_components.push(parent_attrs.name.clone());
            current = parent_attrs.parent_inode;
        }
        
        path_components.reverse();
        Ok(format!("/{}", path_components.join("/")))
    }
    
    pub async fn get_next_inode(&self) -> u64 {
        let mut next = self.next_inode.write().await;
        let inode = *next;
        *next += 1;
        inode
    }
    
    pub async fn normalize_path(&self, path: &str) -> Result<String> {
        let path = path.trim();
        
        if path.is_empty() {
            return Ok("/".to_string());
        }
        
        let path = if !path.starts_with('/') {
            format!("/{}", path)
        } else {
            path.to_string()
        };
        
        let path = path.trim_end_matches('/');
        
        if path.is_empty() {
            Ok("/".to_string())
        } else if path.contains("..") || path.contains("./") || path.contains("//") {
            Err(StorageError::InvalidPath(path.to_string()))
        } else {
            Ok(path.to_string())
        }
    }
    
    async fn get_inode_for_path(&self, path: &str) -> Option<u64> {
        let path_cache = self.path_to_inode.read().await;
        path_cache.get(path).copied()
    }
    
    async fn load_inode_attributes(&self, inode: u64) -> Result<InodeAttributes> {
        let inode_path = self.data_root.join("inodes").join(format!("{}.json", inode));
        let content = fs::read_to_string(&inode_path).await
            .map_err(|_| StorageError::NotFound(format!("Inode {}", inode)))?;
        let attrs = serde_json::from_str(&content)?;
        Ok(attrs)
    }
    
    async fn save_inode_attributes(&self, attrs: &InodeAttributes) -> Result<()> {
        let inode_path = self.data_root.join("inodes").join(format!("{}.json", attrs.inode));
        let json = serde_json::to_string_pretty(&attrs)?;
        fs::write(inode_path, json).await?;
        Ok(())
    }
    
    pub async fn create_file(&self, path: &str, content: &[u8]) -> Result<()> {
        let path = self.normalize_path(path).await?;
        
        if let Some(_) = self.get_inode_for_path(&path).await {
            let inode = self.get_inode_for_path(&path).await.unwrap();
            let attrs = self.load_inode_attributes(inode).await?;
            if attrs.file_type == FileType::Directory {
                return Err(StorageError::NotADirectory(path));
            }
            
            let content_path = self.data_root.join("content").join(format!("{}", inode));
            fs::write(content_path, content).await?;
            
            let mut attrs = attrs;
            attrs.size = content.len() as u64;
            attrs.modified = std::time::SystemTime::now();
            self.save_inode_attributes(&attrs).await?;
        } else {
            let (parent_path, file_name) = self.split_path(&path)?;
            let parent_inode = self.ensure_parent_directory(&parent_path).await?;
            
            let inode = self.get_next_inode().await;
            let attrs = InodeAttributes::new_file(
                inode,
                file_name,
                content.len() as u64,
                Some(parent_inode),
            );
            
            self.save_inode_attributes(&attrs).await?;
            
            let content_path = self.data_root.join("content").join(format!("{}", inode));
            fs::write(content_path, content).await?;
            
            let mut path_cache = self.path_to_inode.write().await;
            path_cache.insert(path.clone(), inode);
        }
        
        Ok(())
    }
    
    pub async fn create_directory(&self, path: &str) -> Result<()> {
        let path = self.normalize_path(path).await?;
        
        if self.get_inode_for_path(&path).await.is_some() {
            return Err(StorageError::AlreadyExists(path));
        }
        
        let (parent_path, dir_name) = self.split_path(&path)?;
        let parent_inode = self.ensure_parent_directory(&parent_path).await?;
        
        let inode = self.get_next_inode().await;
        let attrs = InodeAttributes::new_directory(inode, dir_name, Some(parent_inode));
        
        self.save_inode_attributes(&attrs).await?;
        
        let mut path_cache = self.path_to_inode.write().await;
        path_cache.insert(path.clone(), inode);
        
        Ok(())
    }
    
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let path = self.normalize_path(path).await?;
        
        let inode = self.get_inode_for_path(&path).await
            .ok_or_else(|| StorageError::NotFound(path.clone()))?;
        
        let attrs = self.load_inode_attributes(inode).await?;
        
        if attrs.file_type != FileType::File {
            return Err(StorageError::NotADirectory(path));
        }
        
        let content_path = self.data_root.join("content").join(format!("{}", inode));
        let content = fs::read(&content_path).await?;
        
        Ok(content)
    }
    
    pub async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>> {
        let path = self.normalize_path(path).await?;
        
        let dir_inode = self.get_inode_for_path(&path).await
            .ok_or_else(|| StorageError::NotFound(path.clone()))?;
        
        let dir_attrs = self.load_inode_attributes(dir_inode).await?;
        
        if dir_attrs.file_type != FileType::Directory {
            return Err(StorageError::NotADirectory(path));
        }
        
        let mut entries = Vec::new();
        let path_cache = self.path_to_inode.read().await;
        
        for (_entry_path, &inode) in path_cache.iter() {
            if let Ok(attrs) = self.load_inode_attributes(inode).await {
                if attrs.parent_inode == Some(dir_inode) {
                    entries.push(DirectoryEntry {
                        name: attrs.name.clone(),
                        file_type: attrs.file_type,
                        size: attrs.size,
                        modified: attrs.modified,
                        inode: attrs.inode,
                    });
                }
            }
        }
        
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        
        Ok(entries)
    }
    
    pub async fn delete(&self, path: &str) -> Result<()> {
        let path = self.normalize_path(path).await?;
        
        let inode = self.get_inode_for_path(&path).await
            .ok_or_else(|| StorageError::NotFound(path.clone()))?;
        
        let attrs = self.load_inode_attributes(inode).await?;
        
        if attrs.file_type == FileType::Directory {
            let entries = self.list_directory(&path).await?;
            if !entries.is_empty() {
                return Err(StorageError::DirectoryNotEmpty(path));
            }
        } else {
            let content_path = self.data_root.join("content").join(format!("{}", inode));
            let _ = fs::remove_file(&content_path).await;
        }
        
        let inode_path = self.data_root.join("inodes").join(format!("{}.json", inode));
        fs::remove_file(&inode_path).await?;
        
        let mut path_cache = self.path_to_inode.write().await;
        path_cache.remove(&path);
        
        Ok(())
    }
    
    pub async fn get_attributes(&self, path: &str) -> Result<InodeAttributes> {
        let path = self.normalize_path(path).await?;
        
        let inode = self.get_inode_for_path(&path).await
            .ok_or_else(|| StorageError::NotFound(path.clone()))?;
        
        self.load_inode_attributes(inode).await
    }
    
    fn split_path(&self, path: &str) -> Result<(String, String)> {
        if path == "/" {
            return Err(StorageError::InvalidPath("Cannot split root path".to_string()));
        }
        
        let path = path.trim_end_matches('/');
        if let Some(pos) = path.rfind('/') {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let name = &path[pos + 1..];
            Ok((parent.to_string(), name.to_string()))
        } else {
            Err(StorageError::InvalidPath(path.to_string()))
        }
    }
    
    async fn ensure_parent_directory(&self, path: &str) -> Result<u64> {
        let path = self.normalize_path(path).await?;
        
        let inode = self.get_inode_for_path(&path).await
            .ok_or_else(|| StorageError::NotFound(format!("Parent directory: {}", path)))?;
        
        let attrs = self.load_inode_attributes(inode).await?;
        
        if attrs.file_type != FileType::Directory {
            return Err(StorageError::NotADirectory(path));
        }
        
        Ok(inode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    async fn create_test_engine() -> (StorageEngine, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let engine = StorageEngine::new(temp_dir.path().to_path_buf()).await.unwrap();
        (engine, temp_dir)
    }
    
    #[tokio::test]
    async fn test_create_and_read_file() {
        let (engine, _temp) = create_test_engine().await;
        
        let content = b"Hello, World!";
        engine.create_file("/test.txt", content).await.unwrap();
        
        let read_content = engine.read_file("/test.txt").await.unwrap();
        assert_eq!(read_content, content);
    }
    
    #[tokio::test]
    async fn test_create_directory() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/test_dir").await.unwrap();
        
        let attrs = engine.get_attributes("/test_dir").await.unwrap();
        assert_eq!(attrs.file_type, FileType::Directory);
        assert_eq!(attrs.name, "test_dir");
    }
    
    #[tokio::test]
    async fn test_create_nested_file() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/dir1").await.unwrap();
        engine.create_directory("/dir1/dir2").await.unwrap();
        engine.create_file("/dir1/dir2/file.txt", b"nested content").await.unwrap();
        
        let content = engine.read_file("/dir1/dir2/file.txt").await.unwrap();
        assert_eq!(content, b"nested content");
    }
    
    #[tokio::test]
    async fn test_list_directory() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/test_dir").await.unwrap();
        engine.create_file("/test_dir/file1.txt", b"content1").await.unwrap();
        engine.create_file("/test_dir/file2.txt", b"content2").await.unwrap();
        engine.create_directory("/test_dir/subdir").await.unwrap();
        
        let entries = engine.list_directory("/test_dir").await.unwrap();
        assert_eq!(entries.len(), 3);
        
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"file1.txt".to_string()));
        assert!(names.contains(&"file2.txt".to_string()));
        assert!(names.contains(&"subdir".to_string()));
    }
    
    #[tokio::test]
    async fn test_delete_file() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_file("/test.txt", b"content").await.unwrap();
        engine.delete("/test.txt").await.unwrap();
        
        let result = engine.read_file("/test.txt").await;
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }
    
    #[tokio::test]
    async fn test_delete_empty_directory() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/test_dir").await.unwrap();
        engine.delete("/test_dir").await.unwrap();
        
        let result = engine.get_attributes("/test_dir").await;
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }
    
    #[tokio::test]
    async fn test_delete_non_empty_directory_fails() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/test_dir").await.unwrap();
        engine.create_file("/test_dir/file.txt", b"content").await.unwrap();
        
        let result = engine.delete("/test_dir").await;
        assert!(matches!(result, Err(StorageError::DirectoryNotEmpty(_))));
    }
    
    #[tokio::test]
    async fn test_overwrite_existing_file() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_file("/test.txt", b"original").await.unwrap();
        engine.create_file("/test.txt", b"updated").await.unwrap();
        
        let content = engine.read_file("/test.txt").await.unwrap();
        assert_eq!(content, b"updated");
    }
    
    #[tokio::test]
    async fn test_create_duplicate_directory_fails() {
        let (engine, _temp) = create_test_engine().await;
        
        engine.create_directory("/test_dir").await.unwrap();
        let result = engine.create_directory("/test_dir").await;
        assert!(matches!(result, Err(StorageError::AlreadyExists(_))));
    }
    
    #[tokio::test]
    async fn test_get_attributes() {
        let (engine, _temp) = create_test_engine().await;
        
        let content = b"test content";
        engine.create_file("/test.txt", content).await.unwrap();
        
        let attrs = engine.get_attributes("/test.txt").await.unwrap();
        assert_eq!(attrs.file_type, FileType::File);
        assert_eq!(attrs.size, content.len() as u64);
        assert_eq!(attrs.name, "test.txt");
    }
    
    #[tokio::test]
    async fn test_path_normalization() {
        let (engine, _temp) = create_test_engine().await;
        
        assert_eq!(engine.normalize_path("").await.unwrap(), "/");
        assert_eq!(engine.normalize_path("/").await.unwrap(), "/");
        assert_eq!(engine.normalize_path("/test").await.unwrap(), "/test");
        assert_eq!(engine.normalize_path("/test/").await.unwrap(), "/test");
        assert_eq!(engine.normalize_path("test").await.unwrap(), "/test");
        
        assert!(engine.normalize_path("/test/../bad").await.is_err());
        assert!(engine.normalize_path("/test//bad").await.is_err());
        assert!(engine.normalize_path("./test").await.is_err());
    }
}