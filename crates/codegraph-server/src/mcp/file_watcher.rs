// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Filesystem watcher for MCP server — auto-indexes files on change.
//!
//! Watches all indexed workspace directories for file create/modify/delete
//! events. Debounces rapid changes (2s), then incrementally updates the
//! graph: removes old nodes, re-parses changed files, re-indexes dependents,
//! resolves cross-file imports, and rebuilds search indexes.

use crate::ai_query::QueryEngine;
use crate::indexer::{canonical_candidate, IndexConfig, Indexer, WorkspaceFilter};
use crate::parser_registry::ParserRegistry;
use crate::watcher::GraphUpdater;
use codegraph::{CodeGraph, NodeId};
use notify::event::ModifyKind;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify, RwLock};

/// Debounce interval — wait 2 seconds after last change before processing.
const DEBOUNCE_MS: u64 = 2000;

/// Watches workspace directories for file changes and auto-indexes them.
pub struct McpFileWatcher {
    _watcher: Arc<Mutex<RecommendedWatcher>>,
    #[cfg(test)]
    watched_directories: Arc<Mutex<HashSet<PathBuf>>>,
    #[cfg(test)]
    overflow_count: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
}

impl Drop for McpFileWatcher {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

/// Shared context for the watcher's async task.
struct WatcherCtx {
    graph: Arc<RwLock<CodeGraph>>,
    query_engine: Arc<QueryEngine>,
    indexer: Arc<Indexer>,
    persist_graph: Arc<dyn Fn(&CodeGraph) -> Result<(), String> + Send + Sync>,
    supported_extensions: Vec<String>,
    /// The indexer's exclusion rule, so a file kept out of the initial index
    /// cannot be let back in by a later write to it.
    filter: WorkspaceFilter,
    workspace_roots: Vec<PathBuf>,
    watcher: Arc<Mutex<RecommendedWatcher>>,
    watched_directories: Arc<Mutex<HashSet<PathBuf>>>,
    overflowed: Arc<AtomicBool>,
    overflow_notify: Arc<Notify>,
}

impl McpFileWatcher {
    /// Start watching the given directories for file changes.
    ///
    /// Spawns a background tokio task that processes file events with debouncing.
    pub async fn start(
        graph: Arc<RwLock<CodeGraph>>,
        parsers: Arc<ParserRegistry>,
        query_engine: Arc<QueryEngine>,
        indexer: Arc<Indexer>,
        persist_graph: Arc<dyn Fn(&CodeGraph) -> Result<(), String> + Send + Sync>,
        directories: &[PathBuf],
        config: &IndexConfig,
    ) -> Result<Self, notify::Error> {
        // Keep notify's synchronous callback non-blocking. If the bounded raw
        // queue fills, the graph worker performs a workspace reconciliation;
        // this preserves changes without blocking notify while `watch()` may
        // be waiting for its internal event thread.
        let (tx, mut raw_rx) = mpsc::channel::<Event>(100);
        let overflowed = Arc::new(AtomicBool::new(false));
        let overflow_notify = Arc::new(Notify::new());
        let overflow_count = Arc::new(AtomicUsize::new(0));
        let callback_overflowed = Arc::clone(&overflowed);
        let callback_overflow_notify = Arc::clone(&overflow_notify);
        let callback_overflow_count = Arc::clone(&overflow_count);

        let watcher = Arc::new(Mutex::new(RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
                        callback_overflowed.store(true, Ordering::Release);
                        callback_overflow_count.fetch_add(1, Ordering::Relaxed);
                        callback_overflow_notify.notify_one();
                    }
                }
            },
            Config::default(),
        )?));

        let watched_directories = Arc::new(Mutex::new(HashSet::new()));

        let supported_extensions: Vec<String> = parsers
            .supported_extensions()
            .iter()
            .map(|e| e.trim_start_matches('.').to_string())
            .collect();

        let filter = WorkspaceFilter::new(directories, config);
        let initial_extensions = supported_extensions.clone();
        let ctx = WatcherCtx {
            graph,
            query_engine,
            indexer,
            persist_graph,
            supported_extensions,
            filter: filter.clone(),
            workspace_roots: directories.to_vec(),
            watcher: Arc::clone(&watcher),
            watched_directories: Arc::clone(&watched_directories),
            overflowed: Arc::clone(&overflowed),
            overflow_notify: Arc::clone(&overflow_notify),
        };

        let (event_tx, mut event_rx) = mpsc::channel::<Event>(1000);
        let (shutdown_tx, _) = watch::channel(false);
        let mut forwarder_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = forwarder_shutdown.changed() => {
                        if changed.is_err() || *forwarder_shutdown.borrow() {
                            break;
                        }
                    }
                    event = raw_rx.recv() => match event {
                        Some(event) => if event_tx.send(event).await.is_err() { break; },
                        None => break,
                    }
                }
            }
        });

        let mut event_shutdown = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let debounce = Duration::from_millis(DEBOUNCE_MS);
            let mut pending: HashSet<PathBuf> = HashSet::new();
            let mut deleted: HashSet<PathBuf> = HashSet::new();
            let mut last_event: Option<Instant> = None;

            loop {
                tokio::select! {
                    changed = event_shutdown.changed() => {
                        if changed.is_err() || *event_shutdown.borrow() {
                            break;
                        }
                    }
                    event = event_rx.recv() => {
                        match event {
                            Some(event) => {
                                handle_watch_event(&ctx, event, &mut pending, &mut deleted).await;
                                if !pending.is_empty() || !deleted.is_empty() {
                                    last_event = Some(Instant::now());
                                }
                            }
                            None => break, // Channel closed
                        }
                    }
                    _ = ctx.overflow_notify.notified() => {
                        if ctx.overflowed.swap(false, Ordering::AcqRel) {
                            tracing::warn!("MCP watcher event queue overflowed; reconciling indexed workspaces");
                            pending.clear();
                            deleted.clear();
                            last_event = None;
                            reconcile_workspace(&ctx).await;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {
                        // Check debounce timer
                        if let Some(last) = last_event {
                            if last.elapsed() >= debounce && (!pending.is_empty() || !deleted.is_empty()) {
                                let changed: Vec<PathBuf> = pending.drain().collect();
                                let removed: Vec<PathBuf> = deleted.drain().collect();
                                last_event = None;

                                process_changes(&ctx, &changed, &removed).await;
                            }
                        }
                    }
                }
            }
        });

        // Let the receiver task start before registering even non-recursive
        // watches. Each allowed directory gets its own watch so excluded
        // descendants never allocate an OS watch.
        tokio::task::yield_now().await;
        for dir in directories {
            register_allowed_tree(
                dir,
                &filter,
                &initial_extensions,
                &watcher,
                &watched_directories,
                false,
            );
        }
        register_explicit_sources(
            &filter,
            &config.explicit_source_files,
            &initial_extensions,
            &watcher,
            &watched_directories,
        );

        let watch_count = watched_directories
            .lock()
            .map(|directories| directories.len())
            .unwrap_or(0);
        tracing::info!(
            "MCP file watcher started ({} allowed directories)",
            watch_count
        );

        Ok(McpFileWatcher {
            _watcher: watcher,
            #[cfg(test)]
            watched_directories,
            #[cfg(test)]
            overflow_count,
            shutdown: shutdown_tx,
        })
    }

    #[cfg(test)]
    fn watched_directories(&self) -> HashSet<PathBuf> {
        self.watched_directories
            .lock()
            .map(|directories| directories.clone())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn overflow_count(&self) -> usize {
        self.overflow_count.load(Ordering::Relaxed)
    }
}

/// Check if a path is a supported source file worth watching.
fn is_watchable(path: &Path, supported_extensions: &[String], filter: &WorkspaceFilter) -> bool {
    if path.is_dir() || !filter.admits(path) {
        return false;
    }

    // Check extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if ext == "json" && path.file_name().is_some_and(|n| n == "package-lock.json" || n == "npm-shrinkwrap.json") { return false; }
        if matches!(ext, "conf" | "dist") && !filter.is_explicit_file(path) { return false; }
        if ext == "dist" && !path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".conf.dist")) { return false; }
        supported_extensions.iter().any(|se| se == ext)
            || path
                .file_name()
                .is_some_and(|name| name == "CMakeLists.txt")
    } else {
        filter.is_explicit_file(path)
    }
}

/// Register each allowed directory separately. `notify`'s recursive mode
/// walks through excluded trees before the event filter ever sees a path;
/// non-recursive watches let the shared index filter prune the walk itself.
/// Files already present in a newly created subtree are returned for indexing
/// because their create events may have happened before its directories were
/// registered.
fn register_allowed_tree(
    root: &Path,
    filter: &WorkspaceFilter,
    supported_extensions: &[String],
    watcher: &Arc<Mutex<RecommendedWatcher>>,
    watched_directories: &Arc<Mutex<HashSet<PathBuf>>>,
    include_existing_files: bool,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![(root.to_path_buf(), HashSet::<PathBuf>::new())];
    let mut seen_paths = HashSet::new();

    while let Some((directory, ancestors)) = pending.pop() {
        if !directory.is_dir()
            || !filter.admits_directory(&directory)
            || !seen_paths.insert(directory.clone())
        {
            continue;
        }
        let canonical = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.clone());
        if ancestors.contains(&canonical) {
            continue;
        }
        let mut child_ancestors = ancestors;
        child_ancestors.insert(canonical);

        let registered = {
            let mut registered = match watched_directories.lock() {
                Ok(registered) => registered,
                Err(_) => continue,
            };
            if registered.contains(&directory) {
                true
            } else {
                let result = watcher
                    .lock()
                    .map_err(|_| notify::Error::generic("watcher lock poisoned"))
                    .and_then(|mut watcher| watcher.watch(&directory, RecursiveMode::NonRecursive));
                match result {
                    Ok(()) => {
                        registered.insert(directory.clone());
                        true
                    }
                    Err(error) => {
                        tracing::warn!(
                            "Failed to watch allowed directory {:?}: {}",
                            directory,
                            error
                        );
                        false
                    }
                }
            }
        };
        if !registered {
            continue;
        }

        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::debug!("Cannot scan watched directory {:?}: {}", directory, error);
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if filter.admits_directory(&path) {
                    pending.push((path, child_ancestors.clone()));
                }
            } else if include_existing_files && is_watchable(&path, supported_extensions, filter) {
                files.push(filter.indexed_form(&path));
            }
        }
    }
    files
}

/// Watch only the immediate parent directories needed for exact caller-owned
/// files. These watches are nonrecursive, and event admission still requires
/// an exact configured path in `WorkspaceFilter`.
fn register_explicit_sources(
    filter: &WorkspaceFilter,
    files: &[PathBuf],
    supported_extensions: &[String],
    watcher: &Arc<Mutex<RecommendedWatcher>>,
    watched_directories: &Arc<Mutex<HashSet<PathBuf>>>,
) -> Vec<PathBuf> {
    register_explicit_sources_under(
        filter,
        files,
        supported_extensions,
        watcher,
        watched_directories,
        None,
    )
}

fn register_explicit_sources_under(
    filter: &WorkspaceFilter,
    files: &[PathBuf],
    supported_extensions: &[String],
    watcher: &Arc<Mutex<RecommendedWatcher>>,
    watched_directories: &Arc<Mutex<HashSet<PathBuf>>>,
    under: Option<&Path>,
) -> Vec<PathBuf> {
    let under = under.and_then(canonical_candidate);
    let mut present_files = Vec::new();
    for file in files {
        let file = canonical_candidate(file);
        let Some(file) = file else { continue };
        if under
            .as_ref()
            .is_some_and(|directory| !file.starts_with(directory))
        {
            continue;
        }
        if !is_watchable(&file, supported_extensions, filter) {
            continue;
        }
        for directory in filter.explicit_watch_chain(&file) {
            let mut watched = watched_directories
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if watched.insert(directory.clone()) {
                match watcher
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .watch(&directory, RecursiveMode::NonRecursive)
                {
                    Ok(()) => {}
                    Err(error) => {
                        watched.remove(&directory);
                        tracing::warn!("Failed to watch explicit source path: {error}");
                    }
                }
            }
        }
        if file.is_file() {
            present_files.push(filter.indexed_form(&file));
        }
    }
    present_files
}

/// Recover changes that could not be represented individually because the
/// bounded callback queue filled. The watcher callback never blocks notify's
/// event thread: a full workspace scan discovers existing files and watches,
/// while graph paths absent from that scan are removed.
async fn reconcile_workspace(ctx: &WatcherCtx) {
    let mut present_files = HashSet::new();
    for root in &ctx.workspace_roots {
        present_files.extend(register_allowed_tree(
            root,
            &ctx.filter,
            &ctx.supported_extensions,
            &ctx.watcher,
            &ctx.watched_directories,
            true,
        ));
    }
    present_files.extend(register_explicit_sources(
        &ctx.filter,
        &ctx.filter.explicit_source_files(),
        &ctx.supported_extensions,
        &ctx.watcher,
        &ctx.watched_directories,
    ));

    let stale_directories: Vec<_> = ctx
        .watched_directories
        .lock()
        .map(|directories| {
            directories
                .iter()
                .filter(|directory| {
                    !directory.is_dir()
                        || (!ctx.filter.admits_directory(directory)
                            && !ctx.filter.admits_explicit_parent(directory))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    for directory in stale_directories {
        unwatch_allowed_tree(&directory, &ctx.watcher, &ctx.watched_directories);
    }

    let graph_files: HashSet<_> = {
        let graph = ctx.graph.read().await;
        graph
            .iter_nodes()
            .filter_map(|(_, node)| node.properties.get_string("path"))
            .map(PathBuf::from)
            .filter(|path| {
                ctx.workspace_roots
                    .iter()
                    .any(|root| path.starts_with(root))
            })
            .collect()
    };
    let removed: Vec<_> = graph_files.difference(&present_files).cloned().collect();
    let changed: Vec<_> = present_files.into_iter().collect();
    process_changes(ctx, &changed, &removed).await;
}

async fn handle_watch_event(
    ctx: &WatcherCtx,
    event: Event,
    pending: &mut HashSet<PathBuf>,
    deleted: &mut HashSet<PathBuf>,
) {
    let adds_or_moves_paths = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(_))
    );
    let removes_paths = matches!(
        event.kind,
        EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    );

    for path in event.paths {
        if adds_or_moves_paths && path.is_dir() {
            let allowed_directory = ctx.filter.admits_directory(&path);
            let explicit_ancestor = ctx.filter.admits_explicit_ancestor(&path);
            if !allowed_directory && !explicit_ancestor {
                continue;
            }
            let mut discovered = if allowed_directory {
                register_allowed_tree(
                    &path,
                    &ctx.filter,
                    &ctx.supported_extensions,
                    &ctx.watcher,
                    &ctx.watched_directories,
                    true,
                )
            } else {
                Vec::new()
            };
            if explicit_ancestor {
                discovered.extend(register_explicit_sources_under(
                    &ctx.filter,
                    &ctx.filter.explicit_source_files(),
                    &ctx.supported_extensions,
                    &ctx.watcher,
                    &ctx.watched_directories,
                    Some(&path),
                ));
            }
            for file in discovered {
                deleted.remove(&file);
                pending.insert(file);
            }
            continue;
        }

        let is_watched_directory = ctx
            .watched_directories
            .lock()
            .map(|directories| {
                directories
                    .iter()
                    .any(|directory| directory.starts_with(&path))
            })
            .unwrap_or(false);
        if removes_paths && !path.is_dir() && is_watched_directory {
            let descendants = graph_paths_under(&ctx.graph, &path).await;
            unwatch_allowed_tree(&path, &ctx.watcher, &ctx.watched_directories);
            for file in descendants {
                pending.remove(&file);
                deleted.insert(file);
            }
            continue;
        }

        if !is_watchable(&path, &ctx.supported_extensions, &ctx.filter) {
            continue;
        }
        let path = ctx.filter.indexed_form(&path);
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                deleted.remove(&path);
                pending.insert(path);
            }
            EventKind::Remove(_) => {
                pending.remove(&path);
                deleted.insert(path);
            }
            _ => {}
        }
    }
}

fn unwatch_allowed_tree(
    root: &Path,
    watcher: &Arc<Mutex<RecommendedWatcher>>,
    watched_directories: &Arc<Mutex<HashSet<PathBuf>>>,
) {
    let mut directories = match watched_directories.lock() {
        Ok(directories) => directories,
        Err(_) => return,
    };
    let mut removed: Vec<_> = directories
        .iter()
        .filter(|directory| directory.starts_with(root))
        .cloned()
        .collect();
    removed.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    let mut watcher = match watcher.lock() {
        Ok(watcher) => watcher,
        Err(_) => return,
    };
    for directory in removed {
        if let Err(error) = watcher.unwatch(&directory) {
            tracing::debug!(
                "Failed to unwatch removed directory {:?}: {}",
                directory,
                error
            );
        }
        directories.remove(&directory);
    }
}

async fn graph_paths_under(graph: &Arc<RwLock<CodeGraph>>, directory: &Path) -> HashSet<PathBuf> {
    let graph = graph.read().await;
    graph
        .iter_nodes()
        .filter_map(|(_, node)| node.properties.get_string("path"))
        .map(PathBuf::from)
        .filter(|path| path.starts_with(directory) && path != directory)
        .collect()
}

/// Every node in the graph, grouped by the file it came from.
///
/// Built once per batch. The previous code ran a full-graph
/// `query().property("path", ..)` scan for each deleted file, each vanished
/// file, each changed file's dependents, each changed file and each dependent,
/// so a burst of generated files multiplied whole-graph scans by the size of
/// the burst (issue #23). One pass answers all of them.
fn nodes_by_path(graph: &CodeGraph) -> HashMap<String, Vec<NodeId>> {
    let mut map: HashMap<String, Vec<NodeId>> = HashMap::new();
    for (id, node) in graph.iter_nodes() {
        if let Some(path) = node.properties.get_string("path") {
            map.entry(path.to_string()).or_default().push(id);
        }
    }
    map
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

/// Process accumulated file changes: re-index changed files, remove deleted files.
async fn process_changes(ctx: &WatcherCtx, changed: &[PathBuf], removed: &[PathBuf]) {
    tracing::info!(
        "[file-watcher] Processing {} changes ({} modified, {} deleted)",
        changed.len() + removed.len(),
        changed.len(),
        removed.len()
    );

    let by_path = {
        let graph = ctx.graph.read().await;
        nodes_by_path(&graph)
    };

    // macOS FSEvents sometimes reports a delete as a modification, so a
    // "changed" path that no longer exists is a delete.
    let (changed, vanished): (Vec<PathBuf>, Vec<PathBuf>) =
        changed.iter().cloned().partition(|p| p.exists());

    let mut graph_changed = false;
    let mut state_changed = false;
    let mut had_deletes = false;
    for path in removed.iter().chain(vanished.iter()) {
        // A file the index never held has nothing to remove. Skipping it here
        // keeps a burst of deletes of excluded or generated files from taking
        // the write lock at all.
        let Some(ids) = by_path.get(&path_key(path)) else {
            state_changed |= ctx.indexer.remove_file_hash(path).await;
            continue;
        };
        let mut graph = ctx.graph.write().await;
        for id in ids {
            let _ = graph.delete_node(*id);
        }
        state_changed |= ctx.indexer.remove_file_hash(path).await;
        graph_changed = true;
        had_deletes = true;
        tracing::info!(
            "[file-watcher] Removed {} nodes for deleted {:?}",
            ids.len(),
            path
        );
    }

    // Dependents are found before any changed file is re-parsed, while its old
    // nodes - and so their incoming edges - are still in the graph.
    let mut dependents: HashSet<PathBuf> = HashSet::new();
    if !changed.is_empty() {
        let graph = ctx.graph.read().await;
        for path in &changed {
            for node_id in by_path.get(&path_key(path)).into_iter().flatten() {
                let Ok(neighbors) = graph.get_neighbors(*node_id, codegraph::Direction::Incoming)
                else {
                    continue;
                };
                for neighbor_id in neighbors {
                    if let Ok(neighbor) = graph.get_node(neighbor_id) {
                        if let Some(dep_path) = neighbor.properties.get_string("path") {
                            let dep = PathBuf::from(dep_path);
                            if !changed.contains(&dep) && dep.exists() {
                                dependents.insert(dep);
                            }
                        }
                    }
                }
            }
        }
    }

    // One write lock per file covering both the removal and the re-parse. The
    // old code took them separately, leaving a window where a concurrent
    // search saw the file's symbols missing entirely.
    let mut indexed = 0;
    for path in changed.iter().chain(dependents.iter()) {
        // Force dependent files through the parser after an upstream symbol
        // change. The Indexer updates graph nodes and the in-memory hash as
        // one operation; the following snapshot gate commits both together.
        state_changed |= ctx.indexer.remove_file_hash(path).await;
        let had_nodes = by_path.contains_key(&path_key(path));
        match ctx.indexer.index_file(&ctx.graph, path).await {
            Ok(true) => {
                indexed += 1;
                graph_changed = true;
            }
            Ok(false) => {}
            Err(error) => {
                graph_changed |= had_nodes;
                tracing::warn!("[file-watcher] Failed to index {:?}: {}", path, error);
            }
        }
    }
    if !dependents.is_empty() {
        tracing::info!("[file-watcher] Re-indexed {} dependents", dependents.len());
    }

    // Deletions change the graph as much as edits do, so they rebuild the
    // indexes too. This used to sit inside the changed-files branch, so a batch
    // of pure deletions left the text index holding entries for nodes that no
    // longer existed until some later edit rebuilt it. Search did not show it -
    // results are resolved against the graph, where the nodes were already
    // gone - so this is index hygiene, not a visible correctness fix.
    graph_changed |= had_deletes;
    if !graph_changed && !state_changed {
        return;
    }
    if graph_changed {
        let mut graph = ctx.graph.write().await;
        GraphUpdater::resolve_cross_file_imports(&mut graph);
    }
    if graph_changed {
        ctx.query_engine.build_indexes().await;

        // Deleting a file and re-parsing one both leave vectors behind for node IDs
        // that no longer exist. One prune after all of it covers both; the old
        // per-file call ran before the nodes were deleted, so it could not see the
        // file it was meant for, and never ran at all after a re-parse.
        ctx.query_engine.prune_orphan_vectors().await;

        let reembed: Vec<String> = changed
            .iter()
            .chain(dependents.iter())
            .map(|p| path_key(p))
            .collect();
        ctx.query_engine.update_files_vectors(&reembed).await;
    }

    if let Err(error) = ctx
        .indexer
        .persist_graph_snapshot(&ctx.graph, |graph| (ctx.persist_graph)(graph))
        .await
    {
        tracing::error!(
            "[file-watcher] Failed to persist graph/index checkpoint: {}",
            error
        );
    }

    tracing::info!(
        "[file-watcher] Indexed {} files (incl. dependents), indexes rebuilt",
        indexed
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_extensionless_script_remains_watchable_when_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("bin")).unwrap();
        let script = root.join("bin/acore");
        std::fs::write(&script, "#!/bin/bash\necho hello\n").unwrap();
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![script.clone()];
        let filter = WorkspaceFilter::new(&[root.to_path_buf()], &config);
        assert!(is_watchable(&script, &[], &filter));
        std::fs::remove_file(&script).unwrap();
        assert!(is_watchable(&script, &[], &filter));
        assert!(!is_watchable(&root.join("bin/other"), &[], &filter));
    }

    #[test]
    fn configuration_watches_require_exact_inclusion() {
        let temp = tempfile::tempdir().unwrap(); let root = temp.path();
        let included = root.join("sample.conf.dist"); let other = root.join("private.conf");
        std::fs::write(&included, "Option = value\n").unwrap(); std::fs::write(&other, "Option = value\n").unwrap();
        let mut config = IndexConfig::default(); config.explicit_source_files = vec![included.clone()]; config.explicit_source_extensions = vec!["conf".into(), "dist".into()];
        let filter = WorkspaceFilter::new(&[root.to_path_buf()], &config);
        assert!(is_watchable(&included, &["dist".into()], &filter));
        assert!(!is_watchable(&other, &["conf".into()], &filter));
    }
    use crate::index_state::IndexState;
    use crate::indexer::IndexConfig;
    use std::time::Duration;

    fn test_indexer(root: &Path, parsers: &Arc<ParserRegistry>) -> Arc<Indexer> {
        let state = Arc::new(tokio::sync::Mutex::new(IndexState::for_workspace(
            "watcher-test",
            root,
        )));
        Arc::new(Indexer::new(Arc::clone(parsers), state))
    }

    fn test_graph_with_file(parsers: &ParserRegistry, path: &Path) -> Arc<RwLock<CodeGraph>> {
        let mut graph = CodeGraph::in_memory().unwrap();
        parsers.parse_file(path, &mut graph).unwrap();
        Arc::new(RwLock::new(graph))
    }

    async fn wait_for_name(graph: &Arc<RwLock<CodeGraph>>, name: &str, present: bool) {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let found = graph
                    .read()
                    .await
                    .iter_nodes()
                    .any(|(_, node)| node.properties.get_string("name") == Some(name));
                if found == present {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for watcher graph update");
    }

    fn test_config() -> IndexConfig {
        let mut config = IndexConfig::default();
        config.exclude_dirs.push("work".to_string());
        config.max_depth = 16;
        config
    }

    #[test]
    fn watcher_admits_only_the_cmake_special_filename_without_widening_txt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir_all(root.join("dist")).unwrap();
        let cmake = root.join("CMakeLists.txt");
        let readme = root.join("README.txt");
        let generated = root.join("dist/CMakeLists.txt");
        std::fs::write(&cmake, "project(sample)\n").unwrap();
        std::fs::write(&readme, "text\n").unwrap();
        std::fs::write(&generated, "project(generated)\n").unwrap();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &IndexConfig::default());
        let extensions = vec!["cmake".to_string(), "bats".to_string()];

        assert!(is_watchable(&cmake, &extensions, &filter));
        assert!(!is_watchable(&readme, &extensions, &filter));
        assert!(!is_watchable(&generated, &extensions, &filter));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn excluded_directories_are_not_watched_and_allowed_changes_are_indexed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let source_dir = root.join("src");
        let excluded = root.join("work/private");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&excluded).unwrap();
        let existing = source_dir.join("existing.rs");
        std::fs::write(&existing, "pub fn before_change() {}\n").unwrap();
        std::fs::write(excluded.join("secret.rs"), "pub fn must_not_index() {}\n").unwrap();

        let parsers = Arc::new(ParserRegistry::new());
        let indexer = test_indexer(&root, &parsers);
        let graph = test_graph_with_file(&parsers, &existing);
        let query_engine = Arc::new(QueryEngine::new(Arc::clone(&graph)));
        let persist_count = Arc::new(AtomicUsize::new(0));
        let callback_count = Arc::clone(&persist_count);
        let watcher = McpFileWatcher::start(
            Arc::clone(&graph),
            Arc::clone(&parsers),
            query_engine,
            indexer,
            Arc::new(move |_| {
                callback_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
            std::slice::from_ref(&root),
            &test_config(),
        )
        .await
        .unwrap();

        let watched = watcher.watched_directories();
        assert!(watched.contains(&root));
        assert!(watched.contains(&source_dir));
        assert!(!watched
            .iter()
            .any(|path| path.starts_with(root.join("work"))));
        assert!(!graph
            .read()
            .await
            .iter_nodes()
            .any(|(_, node)| { node.properties.get_string("name") == Some("must_not_index") }));

        // The root watch sees the new excluded directory, but the shared
        // workspace filter must keep the new subtree out of registration.
        std::fs::remove_dir_all(root.join("work")).unwrap();
        let newly_excluded = root.join("work/private");
        std::fs::create_dir_all(&newly_excluded).unwrap();
        std::fs::write(
            newly_excluded.join("new_secret.rs"),
            "pub fn newly_excluded_secret() {}\n",
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!watcher
            .watched_directories()
            .iter()
            .any(|path| path.starts_with(root.join("work"))));
        assert!(!graph.read().await.iter_nodes().any(|(_, node)| {
            node.properties.get_string("name") == Some("newly_excluded_secret")
        }));

        std::fs::write(&existing, "pub fn after_change() {}\n").unwrap();
        wait_for_name(&graph, "after_change", true).await;
        wait_for_name(&graph, "before_change", false).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while persist_count.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("watcher graph mutation did not reach its persistence callback");

        // The directory and its file are created before the event worker can
        // register the new directory. Registration scans the admitted subtree
        // and queues existing files, while the new non-recursive watches cover
        // subsequent edits.
        let created_dir = source_dir.join("new_area/deeper");
        std::fs::create_dir_all(&created_dir).unwrap();
        std::fs::write(created_dir.join("new.rs"), "pub fn created_tree() {}\n").unwrap();
        wait_for_name(&graph, "created_tree", true).await;
        assert!(watcher
            .watched_directories()
            .contains(&source_dir.join("new_area")));
        std::fs::remove_dir_all(source_dir.join("new_area")).unwrap();
        wait_for_name(&graph, "created_tree", false).await;
        let mut checkpoint = IndexState::for_workspace("watcher-test", &root);
        checkpoint.load();
        assert!(checkpoint.get_hash(&created_dir.join("new.rs")).is_none());
        drop(watcher);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_shell_include_stays_fresh_through_edit_delete_and_watcher_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let examples = root.join("apps/startup-scripts/src/examples");
        let dist_assets = root.join("module/testdeck/dist/assets");
        std::fs::create_dir_all(&examples).unwrap();
        std::fs::create_dir_all(&dist_assets).unwrap();
        let selected = examples.join("restarter.sh");
        let sibling = examples.join("unlisted.sh");
        let generated = dist_assets.join("bundle.js");
        std::fs::write(&selected, "function before_selected() { :; }\n").unwrap();
        std::fs::write(&sibling, "function sibling_must_stay_out() { :; }\n").unwrap();
        std::fs::write(&generated, "function generated_must_stay_out() {}\n").unwrap();

        let parsers = Arc::new(ParserRegistry::new());
        let indexer = test_indexer(&root, &parsers);
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![selected.clone()];
        config.explicit_source_extensions = parsers
            .supported_extensions()
            .iter()
            .map(|extension| extension.trim_start_matches('.').to_string())
            .collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let initial_filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(initial_filter.admits(&selected));
        assert!(!initial_filter.admits(&sibling));
        assert!(!initial_filter.admits(&generated));
        indexer
            .index_workspace(&graph, std::slice::from_ref(&root), &config)
            .await;
        wait_for_name(&graph, "before_selected", true).await;
        wait_for_name(&graph, "sibling_must_stay_out", false).await;

        let query_engine = Arc::new(QueryEngine::new(Arc::clone(&graph)));
        let persist_count = Arc::new(AtomicUsize::new(0));
        let callback_count = Arc::clone(&persist_count);
        let watcher = McpFileWatcher::start(
            Arc::clone(&graph),
            Arc::clone(&parsers),
            Arc::clone(&query_engine),
            Arc::clone(&indexer),
            Arc::new(move |_| {
                callback_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
            std::slice::from_ref(&root),
            &config,
        )
        .await
        .unwrap();
        assert!(watcher.watched_directories().contains(&examples));
        std::fs::write(&sibling, "function sibling_still_out() { :; }\n").unwrap();
        std::fs::write(&generated, "function generated_still_out() {}\n").unwrap();
        std::fs::write(&selected, "function after_edit_selected() { :; }\n").unwrap();
        wait_for_name(&graph, "after_edit_selected", true).await;
        wait_for_name(&graph, "before_selected", false).await;
        wait_for_name(&graph, "sibling_still_out", false).await;
        wait_for_name(&graph, "generated_still_out", false).await;

        // Removing the exact parent must remove the graph entry and its watch,
        // while the still-watched allowed ancestor remains ready to see the
        // directory return.
        std::fs::remove_dir_all(&examples).unwrap();
        wait_for_name(&graph, "after_edit_selected", false).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while watcher.watched_directories().contains(&examples) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("deleted explicit parent watch was not removed");

        std::fs::create_dir_all(&examples).unwrap();
        std::fs::write(
            &selected,
            "function after_parent_recreate_selected() { :; }\n",
        )
        .unwrap();
        std::fs::write(&sibling, "function recreated_sibling_stays_out() { :; }\n").unwrap();
        wait_for_name(&graph, "after_parent_recreate_selected", true).await;
        wait_for_name(&graph, "recreated_sibling_stays_out", false).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !watcher.watched_directories().contains(&examples) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("recreated exact parent was not watched again");

        // Force a real callback-queue overflow while the graph worker is
        // blocked registering newly created directories. Reconciliation must
        // retain only the exact shell include beneath the excluded parent.
        let watcher_lock = watcher._watcher.lock().unwrap();
        for index in 0..1200 {
            std::fs::create_dir(root.join(format!("overflow_{index:04}"))).unwrap();
        }
        assert!(watcher.overflow_count() > 0, "event queue did not overflow");
        drop(watcher_lock);
        std::fs::write(&generated, "function generated_after_overflow() {}\n").unwrap();
        std::fs::write(&selected, "function after_overflow_selected() { :; }\n").unwrap();
        wait_for_name(&graph, "after_overflow_selected", true).await;
        wait_for_name(&graph, "generated_after_overflow", false).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !watcher.watched_directories().contains(&examples) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("overflow reconciliation lost the exact parent watch");
        drop(watcher);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A new watcher reconstructs its exact-file registration from caller
        // configuration; edits after restart continue to update that one path.
        let callback_count = Arc::clone(&persist_count);
        let restarted = McpFileWatcher::start(
            Arc::clone(&graph),
            Arc::clone(&parsers),
            query_engine,
            indexer,
            Arc::new(move |_| {
                callback_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
            std::slice::from_ref(&root),
            &config,
        )
        .await
        .unwrap();
        assert!(restarted.watched_directories().contains(&examples));
        std::fs::write(&selected, "function after_restart_selected() { :; }\n").unwrap();
        wait_for_name(&graph, "after_restart_selected", true).await;
        assert!(persist_count.load(Ordering::Relaxed) >= 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_event_queues_resume_after_large_directory_create_burst() {
        const BURST: usize = 1200;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let indexer = test_indexer(&root, &parsers);
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let query_engine = Arc::new(QueryEngine::new(Arc::clone(&graph)));
        let watcher = McpFileWatcher::start(
            Arc::clone(&graph),
            Arc::clone(&parsers),
            query_engine,
            indexer,
            Arc::new(|_| Ok(())),
            std::slice::from_ref(&root),
            &test_config(),
        )
        .await
        .unwrap();

        // Hold the same lock that directory registration briefly takes. The
        // worker will stop draining Create events while the two bounded queues
        // fill. The callback must stay non-blocking and trigger reconciliation
        // so watcher registration can complete without dropping changes.
        let watcher_lock = watcher._watcher.lock().unwrap();
        for index in 0..BURST {
            let directory = root.join(format!("created_{index:04}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(
                directory.join("entry.rs"),
                format!("pub fn burst_entry_{index:04}() {{}}\n"),
            )
            .unwrap();
        }
        drop(watcher_lock);

        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let watched_count = watcher.watched_directories().len();
                let indexed_count = graph
                    .read()
                    .await
                    .iter_nodes()
                    .filter(|(_, node)| {
                        node.properties
                            .get_string("name")
                            .is_some_and(|name| name.starts_with("burst_entry_"))
                    })
                    .count();
                if watched_count >= BURST + 1 && indexed_count == BURST {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("watcher did not drain the bounded create-event burst");
        assert!(
            watcher.overflow_count() > 0,
            "burst did not exercise the bounded raw-queue overflow path"
        );
        drop(watcher);
    }

    #[test]
    fn nested_roots_use_their_own_exclusions_and_symlink_roots_remain_walkable() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let nested = outer.join("nested-root");
        std::fs::create_dir_all(nested.join("generated/deep")).unwrap();
        std::fs::create_dir_all(nested.join("source")).unwrap();
        std::fs::write(nested.join(".codegraphignore"), "generated\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&nested, tmp.path().join("nested-link")).unwrap();

        let roots = vec![outer.clone(), nested.clone()];
        let filter = WorkspaceFilter::new(&roots, &test_config());
        let parsers = ParserRegistry::new();
        let extensions: Vec<_> = parsers
            .supported_extensions()
            .iter()
            .map(|extension| extension.trim_start_matches('.').to_string())
            .collect();
        let watcher = Arc::new(Mutex::new(
            RecommendedWatcher::new(|_: Result<Event, notify::Error>| {}, Config::default())
                .unwrap(),
        ));
        let watched = Arc::new(Mutex::new(HashSet::new()));

        register_allowed_tree(&outer, &filter, &extensions, &watcher, &watched, false);
        register_allowed_tree(&nested, &filter, &extensions, &watcher, &watched, false);
        let watched = watched.lock().unwrap().clone();
        assert!(watched.contains(&outer));
        assert!(watched.contains(&nested));
        assert!(watched.contains(&nested.join("source")));
        assert!(!watched.contains(&nested.join("generated")));
        assert!(!watched.contains(&nested.join("generated/deep")));

        #[cfg(unix)]
        {
            let alias = tmp.path().join("nested-link");
            let alias_filter = WorkspaceFilter::new(std::slice::from_ref(&alias), &test_config());
            let alias_watched = Arc::new(Mutex::new(HashSet::new()));
            register_allowed_tree(
                &alias,
                &alias_filter,
                &extensions,
                &watcher,
                &alias_watched,
                false,
            );
            let alias_watched = alias_watched.lock().unwrap();
            assert!(alias_watched.contains(&alias));
            assert!(alias_watched.contains(&alias.join("source")));
            assert!(!alias_watched
                .iter()
                .any(|path| path.starts_with(alias.join("generated"))));
        }
    }
}
