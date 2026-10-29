// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Persistent index state — shared by both LSP and MCP backends.
//!
//! Saves file content hashes to disk so incremental indexing survives
//! server restarts. Only changed files are re-parsed on next startup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Persistent index state for a project.
pub struct IndexState {
    /// Project slug (determines storage path)
    slug: String,
    /// File content hashes: path → FNV-1a hash
    hashes: HashMap<PathBuf, u64>,
    /// Optional volume identity, bound to the file hash it describes.
    volumes: HashMap<PathBuf, (u64, String)>,
    volumes_dirty: bool,
    /// Some when the workspace is ephemeral (test harness tempdir).
    /// Routes the state file to `<root>/.codegraph-state/index_state.json`
    /// instead of `~/.codegraph/projects/<slug>/` so we don't pollute
    /// the global registry.
    ephemeral_root: Option<PathBuf>,
}

impl IndexState {
    /// Create a new empty index state for a project.
    pub fn new(slug: &str) -> Self {
        Self {
            slug: slug.to_string(),
            hashes: HashMap::new(),
            volumes: HashMap::new(),
            volumes_dirty: false,
            ephemeral_root: None,
        }
    }

    /// Create state for a workspace, detecting whether the path is
    /// an ephemeral test-harness tempdir and routing state-file
    /// storage appropriately.
    pub fn for_workspace(slug: &str, workspace_path: &Path) -> Self {
        let ephemeral_root = if crate::memory::is_ephemeral_workspace(workspace_path) {
            Some(workspace_path.to_path_buf())
        } else {
            None
        };
        Self {
            slug: slug.to_string(),
            hashes: HashMap::new(),
            volumes: HashMap::new(),
            volumes_dirty: false,
            ephemeral_root,
        }
    }

    /// Path to the state file:
    /// - global:    `~/.codegraph/projects/<slug>/index_state.json`
    /// - ephemeral: `<workspace>/.codegraph-state/index_state.json`
    fn state_path(&self) -> PathBuf {
        if let Some(root) = &self.ephemeral_root {
            return root.join(".codegraph-state").join("index_state.json");
        }
        let base = crate::memory::codegraph_home_dir().unwrap_or_else(|_| PathBuf::from("/tmp/.codegraph"));
        base
            .join("projects")
            .join(&self.slug)
            .join("index_state.json")
    }

    fn invalidation_path(&self) -> PathBuf {
        self.state_path().with_extension("invalid")
    }

    /// Check if a saved state exists on disk.
    pub fn exists_on_disk(&self) -> bool {
        self.state_path().exists() && !self.invalidation_path().exists()
    }

    /// Load saved hashes from disk. Returns number of entries loaded.
    pub fn load(&mut self) -> usize {
        let path = self.state_path();
        if self.invalidation_path().exists() {
            self.hashes.clear();
            self.volumes.clear();
            tracing::warn!("Ignoring index state invalidated after graph persistence failure");
            return 0;
        }
        let json = match std::fs::read_to_string(&path) {
            Ok(j) => j,
            Err(_) => return 0,
        };

        let saved: HashMap<String, u64> = match serde_json::from_str(&json) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to parse index state: {}", e);
                return 0;
            }
        };

        self.hashes.clear();
        self.volumes.clear();
        self.volumes_dirty = false;
        for (path_str, hash) in &saved {
            self.hashes.insert(PathBuf::from(path_str), *hash);
        }
        if let Ok(json) = std::fs::read_to_string(path.with_extension("volumes.json")) {
            if let Ok(volumes) = serde_json::from_str::<HashMap<PathBuf, (u64, String)>>(&json) {
                self.volumes = volumes.into_iter().filter(|(path, (hash, _))| {
                    self.hashes.get(path) == Some(hash)
                }).collect();
            }
        }

        tracing::info!(
            "Loaded index state ({} files) from {:?}",
            self.hashes.len(),
            path
        );
        self.hashes.len()
    }

    /// Save current hashes to disk.
    pub fn save(&self) -> bool {
        if self.hashes.is_empty() {
            let state_removed = self.remove_state_file();
            let _ = std::fs::remove_file(self.state_path().with_extension("volumes.json"));
            let marker_removed = self.remove_invalidation_marker();
            return state_removed && marker_removed;
        }

        let state: HashMap<String, u64> = self
            .hashes
            .iter()
            .map(|(path, hash)| (path.display().to_string(), *hash))
            .collect();

        let path = self.state_path();
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!("Failed to create index state directory {:?}: {}", parent, e);
                return false;
            }
        }

        // Write volume metadata first. If the subsequent hash checkpoint fails,
        // hash matching on load prevents the metadata from authorizing pruning.
        let volume_path = path.with_extension("volumes.json");
        let volume_temp = path.with_extension(format!("volumes.{}.{}.tmp", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos()).unwrap_or_default()));
        let volumes = match serde_json::to_vec(&self.volumes) {
            Ok(volumes) => volumes,
            Err(error) => { tracing::warn!("Cannot serialize volume identities: {}", error); return false; }
        };
        if let Err(error) = std::fs::write(&volume_temp, volumes) {
            let _ = std::fs::remove_file(&volume_temp);
            tracing::warn!("Cannot save volume identities: {}", error);
            return false;
        }
        if let Err(error) = std::fs::rename(&volume_temp, &volume_path) {
            // On Windows rename cannot replace the old file. A missing sidecar
            // is safe: loading will conservatively keep unknown missing paths.
            if !volume_path.exists() || std::fs::remove_file(&volume_path).is_err()
                || std::fs::rename(&volume_temp, &volume_path).is_err() {
                let _ = std::fs::remove_file(&volume_temp);
                tracing::warn!("Cannot replace volume identities: {}", error);
                return false;
            }
        }

        match serde_json::to_string(&state) {
            Ok(json) => {
                let temp_path = path.with_extension(format!(
                    "json.{}.{}.tmp",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_nanos())
                        .unwrap_or_default()
                ));
                if let Err(e) = std::fs::write(&temp_path, json) {
                    tracing::warn!("Failed to write index state {:?}: {}", temp_path, e);
                    return false;
                }
                if let Err(e) = std::fs::rename(&temp_path, &path) {
                    // Windows does not replace an existing destination. It is
                    // safe to remove it here: graph persistence already
                    // succeeded, and a missing state only causes a rebuild.
                    if path.exists() {
                        if let Err(remove_error) = std::fs::remove_file(&path) {
                            let _ = std::fs::remove_file(&temp_path);
                            tracing::warn!(
                                "Failed to replace index state {:?}: {}; remove old state: {}",
                                path,
                                e,
                                remove_error
                            );
                            return false;
                        }
                    }
                    if let Err(rename_error) = std::fs::rename(&temp_path, &path) {
                        let _ = std::fs::remove_file(&temp_path);
                        tracing::warn!("Failed to save index state {:?}: {}", path, rename_error);
                        return false;
                    }
                }
                if !self.remove_invalidation_marker() {
                    return false;
                }
                tracing::info!("Saved index state ({} files)", state.len());
                true
            }
            Err(e) => {
                tracing::warn!("Failed to serialize index state: {}", e);
                false
            }
        }
    }

    fn remove_state_file(&self) -> bool {
        match std::fs::remove_file(self.state_path()) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => {
                tracing::warn!("Failed to remove empty index state: {}", error);
                false
            }
        }
    }

    fn remove_invalidation_marker(&self) -> bool {
        match std::fs::remove_file(self.invalidation_path()) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => {
                tracing::warn!(
                    "Failed to remove index state invalidation marker: {}",
                    error
                );
                false
            }
        }
    }

    /// Get the hash for a file path.
    pub fn get_hash(&self, path: &Path) -> Option<u64> {
        self.hashes.get(path).copied()
    }

    /// Set the hash for a file path.
    pub fn set_hash(&mut self, path: PathBuf, hash: u64) {
        if self.hashes.get(&path) != Some(&hash) { self.volumes.remove(&path); }
        self.hashes.insert(path, hash);
    }

    pub fn set_volume(&mut self, path: &Path, identity: String) {
        if let Some(hash) = self.hashes.get(path) {
            let value = (*hash, identity);
            if self.volumes.get(path) != Some(&value) {
                self.volumes.insert(path.to_path_buf(), value);
                self.volumes_dirty = true;
            }
        }
    }

    pub fn volumes_dirty(&self) -> bool { self.volumes_dirty }

    pub fn acknowledge_volumes_saved(&mut self) { self.volumes_dirty = false; }

    pub fn volume(&self, path: &Path) -> Option<&str> {
        self.volumes.get(path).and_then(|(hash, identity)|
            (self.hashes.get(path) == Some(hash)).then_some(identity.as_str()))
    }

    /// Remove a file from the state.
    pub fn remove(&mut self, path: &Path) {
        self.hashes.remove(path);
        self.volumes.remove(path);
    }

    /// Clear all hashes.
    pub fn clear(&mut self) {
        self.hashes.clear();
        self.volumes.clear();
    }

    /// Clear in-memory hashes and remove the durable checkpoint after graph
    /// persistence fails, so the next run cannot trust a mismatched graph.
    pub fn invalidate_saved_state(&mut self) -> bool {
        self.hashes.clear();
        self.volumes.clear();
        let path = self.state_path();
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(
                    "Failed to create index state directory for invalidation: {}",
                    e
                );
                return false;
            }
        }
        if let Err(e) = std::fs::write(self.invalidation_path(), b"graph persistence failed\n") {
            tracing::error!("Failed to write index state invalidation marker: {}", e);
            return false;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!("Invalidated index state after graph persistence failure"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("State invalidation marker protects {:?}: {}", path, e),
        }
        true
    }

    /// Get all hashes (for comparison).
    pub fn all_hashes(&self) -> &HashMap<PathBuf, u64> {
        &self.hashes
    }

    /// Number of tracked files.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Is the state empty?
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Merge from an existing HashMap (used by MCP backend's file_hashes).
    pub fn merge_from(&mut self, other: &HashMap<PathBuf, u64>) {
        for (path, hash) in other {
            self.hashes.insert(path.clone(), *hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_checkpoint_requires_matching_file_hash() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source.rs");
        let mut state = IndexState::for_workspace("volume-test", workspace.path());
        state.set_hash(source.clone(), 123);
        state.set_volume(&source, "mount-a".into());
        assert!(state.save());
        let mut loaded = IndexState::for_workspace("volume-test", workspace.path());
        assert_eq!(loaded.load(), 1);
        assert_eq!(loaded.volume(&source), Some("mount-a"));
        let changed = HashMap::from([(source.to_string_lossy().to_string(), 456_u64)]);
        std::fs::write(loaded.state_path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(loaded.load(), 1);
        assert_eq!(loaded.volume(&source), None);
    }

    #[test]
    fn invalidating_state_removes_checkpoint_and_clears_hashes() {
        let workspace = tempfile::tempdir().unwrap();
        let mut state = IndexState::for_workspace("state-test", workspace.path());
        state.set_hash(workspace.path().join("source.rs"), 123);
        assert!(state.save());

        assert!(state.exists_on_disk());
        assert!(state.invalidate_saved_state());
        assert!(state.is_empty());
        assert!(!state.exists_on_disk());
    }
}
