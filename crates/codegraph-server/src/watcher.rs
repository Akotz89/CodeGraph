// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! File system watcher for incremental updates.

use crate::ai_query::QueryEngine;
use crate::embed_queue::EmbedQueue;
use crate::index::SymbolIndex;
use crate::memory::MemoryManager;
use crate::parser_registry::ParserRegistry;
use codegraph::CodeGraph;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tower_lsp::lsp_types::MessageType;
use tower_lsp::Client;

/// Default debounce interval in milliseconds.
const DEFAULT_DEBOUNCE_MS: u64 = 300;

/// File system watcher that triggers re-parsing on changes.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
}

impl FileWatcher {
    /// Create a new file watcher with debouncing.
    pub fn new(
        graph: Arc<RwLock<CodeGraph>>,
        parsers: Arc<ParserRegistry>,
        client: Client,
        memory_manager: Arc<MemoryManager>,
        symbol_index: Arc<SymbolIndex>,
        query_engine: Arc<QueryEngine>,
        embed_queue: EmbedQueue,
    ) -> Result<Self, notify::Error> {
        let (tx, mut rx) = mpsc::channel::<Event>(100);

        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    // Use blocking_send since this is called from a sync context
                    let _ = tx.blocking_send(event);
                }
            },
            Config::default(),
        )?;

        // Spawn event handler task with debouncing
        let graph_clone = Arc::clone(&graph);
        let parsers_clone = Arc::clone(&parsers);
        let client_clone = client.clone();
        let memory_clone = Arc::clone(&memory_manager);
        let symbol_index_clone = Arc::clone(&symbol_index);
        let query_engine_clone = Arc::clone(&query_engine);
        let embed_queue_clone = embed_queue.clone();

        tokio::spawn(async move {
            let debounce_duration = Duration::from_millis(DEFAULT_DEBOUNCE_MS);
            let mut pending_events: HashMap<PathBuf, (EventKind, Instant)> = HashMap::new();

            loop {
                // Use tokio::select to handle both incoming events and debounce timeouts
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(event) => {
                                // Accumulate events with debouncing
                                for path in event.paths {
                                    pending_events.insert(path, (event.kind, Instant::now()));
                                }
                            }
                            None => break, // Channel closed
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        // Process any events that have been pending long enough
                        let now = Instant::now();
                        let mut to_process = Vec::new();

                        pending_events.retain(|path, (kind, timestamp)| {
                            if now.duration_since(*timestamp) >= debounce_duration {
                                to_process.push((path.clone(), *kind));
                                false
                            } else {
                                true
                            }
                        });

                        // Process debounced events
                        for (path, kind) in to_process {
                            let event = Event {
                                kind,
                                paths: vec![path],
                                attrs: Default::default(),
                            };
                            Self::handle_event(
                                &graph_clone,
                                &parsers_clone,
                                &client_clone,
                                &memory_clone,
                                &symbol_index_clone,
                                &query_engine_clone,
                                &embed_queue_clone,
                                event,
                            )
                            .await;
                        }
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }

    /// Start watching a directory.
    pub fn watch(&mut self, path: &Path) -> Result<(), notify::Error> {
        self._watcher.watch(path, RecursiveMode::Recursive)
    }

    /// Stop watching a directory.
    pub fn unwatch(&mut self, path: &Path) -> Result<(), notify::Error> {
        self._watcher.unwatch(path)
    }

    /// Handle a file system event.
    #[allow(clippy::too_many_arguments)]
    async fn handle_event(
        graph: &Arc<RwLock<CodeGraph>>,
        parsers: &Arc<ParserRegistry>,
        client: &Client,
        memory_manager: &Arc<MemoryManager>,
        symbol_index: &Arc<SymbolIndex>,
        query_engine: &Arc<QueryEngine>,
        embed_queue: &EmbedQueue,
        event: Event,
    ) {
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                for path in event.paths {
                    // Skip non-parseable files
                    if !parsers.can_parse(&path) {
                        continue;
                    }

                    if let Err(e) = Self::handle_file_change(
                        graph,
                        parsers,
                        memory_manager,
                        symbol_index,
                        query_engine,
                        embed_queue,
                        &path,
                    )
                    .await
                    {
                        client
                            .log_message(
                                MessageType::WARNING,
                                format!("Error processing {}: {}", path.display(), e),
                            )
                            .await;
                    } else {
                        tracing::debug!("Re-indexed: {}", path.display());
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if let Err(e) = Self::handle_file_remove(
                        graph,
                        memory_manager,
                        symbol_index,
                        query_engine,
                        embed_queue,
                        &path,
                    )
                    .await
                    {
                        client
                            .log_message(
                                MessageType::WARNING,
                                format!("Error removing {}: {}", path.display(), e),
                            )
                            .await;
                    } else {
                        tracing::debug!("Removed from index: {}", path.display());
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle a file creation or modification.
    #[allow(clippy::too_many_arguments)]
    async fn handle_file_change(
        graph: &Arc<RwLock<CodeGraph>>,
        parsers: &Arc<ParserRegistry>,
        memory_manager: &Arc<MemoryManager>,
        symbol_index: &Arc<SymbolIndex>,
        query_engine: &Arc<QueryEngine>,
        embed_queue: &EmbedQueue,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        validate_call_scope_configuration()?;
        if !parsers.can_parse(path) {
            return Ok(());
        }
        // Read file content and select its parser from the same bytes.
        let content = tokio::fs::read_to_string(path).await?;
        let parser = match parsers.parser_for_source(&content, path) {
            Some(p) => p,
            None => return Ok(()),
        };

        let path_str = path.to_string_lossy().to_string();
        let node_id_strings: Vec<String>;
        let resolution;

        // Scope the graph lock
        {
            let mut graph = graph.write().await;

            // Collect node IDs before removal for memory invalidation
            node_id_strings = Self::collect_file_node_ids(&graph, path);

            // Remove existing nodes for this file
            Self::remove_file_nodes(&mut graph, path)?;
            // Parse and add new nodes
            let file_info = parser.parse_source(&content, path, &mut graph)?;

            // Resolve cross-file imports after parsing
            resolution = GraphUpdater::resolve_cross_file_imports(&mut graph);

            // Keep the LSP symbol index (hover/goto) in sync with the graph.
            symbol_index.add_file(path.to_path_buf(), &file_info, &graph);
        }

        // Refresh caller/callee/import indexes, then queue re-embedding.
        query_engine.build_indexes().await;
        embed_queue.enqueue(path.to_path_buf());

        // Auto-invalidate memories linked to changed nodes (after releasing graph lock)
        if !node_id_strings.is_empty() {
            let reason = format!("File modified: {}", path_str);
            if let Err(e) = memory_manager
                .invalidate_for_code_nodes(&node_id_strings, &reason)
                .await
            {
                tracing::warn!("Failed to invalidate memories for {}: {}", path_str, e);
            }
        }

        resolution?;
        Ok(())
    }

    /// Handle a file removal.
    async fn handle_file_remove(
        graph: &Arc<RwLock<CodeGraph>>,
        memory_manager: &Arc<MemoryManager>,
        symbol_index: &Arc<SymbolIndex>,
        query_engine: &Arc<QueryEngine>,
        embed_queue: &EmbedQueue,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        validate_call_scope_configuration()?;
        let path_str = path.to_string_lossy().to_string();
        let node_id_strings: Vec<String>;
        let resolution;

        // Scope the graph lock
        {
            let mut graph = graph.write().await;

            // Collect node IDs before removal for memory invalidation
            node_id_strings = Self::collect_file_node_ids(&graph, path);

            Self::remove_file_nodes(&mut graph, path)?;
            resolution = GraphUpdater::resolve_cross_file_imports(&mut graph);
        }

        query_engine.build_indexes().await;
        // Drop the file's symbols from the hover index; queue a pass to prune
        // the now-orphaned vectors (update_file_vectors finds nothing to add).
        symbol_index.remove_file(path);
        embed_queue.enqueue(path.to_path_buf());

        // Auto-invalidate memories linked to deleted nodes
        if !node_id_strings.is_empty() {
            let reason = format!("File deleted: {}", path_str);
            if let Err(e) = memory_manager
                .invalidate_for_code_nodes(&node_id_strings, &reason)
                .await
            {
                tracing::warn!("Failed to invalidate memories for {}: {}", path_str, e);
            }
        }

        resolution?;
        Ok(())
    }

    /// Collect all node IDs for a file (for memory invalidation).
    pub(crate) fn collect_file_node_ids(graph: &CodeGraph, path: &Path) -> Vec<String> {
        let path_str = path.to_string_lossy().to_string();
        if let Ok(nodes) = graph.query().property("path", path_str).execute() {
            nodes.iter().map(|n| n.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    /// Remove all nodes associated with a file from the graph.
    pub(crate) fn remove_file_nodes(
        graph: &mut CodeGraph,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path_str = path.to_string_lossy().to_string();

        // Query for all nodes with this file path
        if let Ok(nodes) = graph.query().property("path", path_str).execute() {
            for node_id in nodes {
                // Remove the node (edges are typically removed automatically)
                let _ = graph.delete_node(node_id);
            }
        }

        Ok(())
    }
}

/// Graph updater for batch operations.
pub struct GraphUpdater;

impl GraphUpdater {
    /// Batch update multiple files.
    pub async fn update_files(
        graph: &Arc<RwLock<CodeGraph>>,
        parsers: &Arc<ParserRegistry>,
        files: &[(PathBuf, String)],
    ) -> codegraph::Result<BatchUpdateResult> {
        validate_call_scope_configuration()?;
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        let mut graph_guard = graph.write().await;

        for (path, content) in files {
            if let Some(parser) = parsers.parser_for_source(content, path) {
                // Remove old nodes
                let path_str = path.to_string_lossy().to_string();
                if let Ok(nodes) = graph_guard.query().property("path", path_str).execute() {
                    for node_id in nodes {
                        let _ = graph_guard.delete_node(node_id);
                    }
                }

                // Parse new content
                match parser.parse_source(content, path, &mut graph_guard) {
                    Ok(info) => succeeded.push((path.clone(), info)),
                    Err(e) => failed.push((path.clone(), e.to_string())),
                }
            }
        }

        // Post-process: resolve cross-file import edges to actual symbol nodes
        Self::resolve_cross_file_imports(&mut graph_guard)?;

        Ok(BatchUpdateResult { succeeded, failed })
    }

    /// Resolve import edges to actual symbol nodes across files.
    ///
    /// After parsing all files, import edges may point to placeholder module nodes
    /// with relative path strings like "./toolManager". This function:
    /// 1. Finds all import edges with a `symbols` property
    /// 2. Looks up the actual symbol nodes by name in the graph
    /// 3. Creates direct import edges from the importing file to the symbol nodes
    ///
    /// This should be called after any parse operation to ensure cross-file
    /// imports are properly resolved.
    pub fn resolve_cross_file_imports(graph: &mut CodeGraph) -> codegraph::Result<()> {
        let scopes = configured_call_scopes()?;
        Self::resolve_cross_file_imports_with_scopes(graph, &scopes)
    }

    fn resolve_cross_file_imports_with_scopes(
        graph: &mut CodeGraph,
        call_scopes: &std::collections::HashMap<String, String>,
    ) -> codegraph::Result<()> {
        use codegraph::{EdgeType, NodeType, PropertyMap};

        // All nodes come from the in-memory graph iterator, avoiding silent
        // fallback to an empty map when a query fails.
        let file_nodes: Vec<_> = graph.iter_nodes().filter_map(|(id, node)|
            (node.node_type == NodeType::CodeFile).then_some(id)).collect();
        let mut symbol_map: std::collections::HashMap<String, codegraph::NodeId> = std::collections::HashMap::new();
        for (id, node) in graph.iter_nodes().filter(|(_, node)| node.node_type == NodeType::Function) {
            if let Some(name) = node.properties.get_string("name") {
                match symbol_map.get(name) {
                    Some(&existing) if symbol_weight(graph, id) <= symbol_weight(graph, existing) => {},
                    _ => { symbol_map.insert(name.to_string(), id); }
                }
            }
        }
        for kind in [NodeType::Class, NodeType::Interface] {
            for (id, node) in graph.iter_nodes().filter(|(_, node)| node.node_type == kind) {
                if let Some(name) = node.properties.get_string("name") {
                    symbol_map.insert(name.to_string(), id);
                }
            }
        }

        // Process import edges in one pass. `get_edges_between(source, target)`
        // scans all outgoing edges for the source; repeating it for each
        // neighbour of a bulk SQL file makes this loop quadratic.
        let mut edges_to_add: Vec<(codegraph::NodeId, codegraph::NodeId, PropertyMap)> = Vec::new();
        let file_node_ids: HashSet<_> = file_nodes.into_iter().collect();
        let mut linked_pairs: HashSet<_> = graph
            .iter_edges()
            .filter_map(|(_, edge)| {
                (edge.edge_type == EdgeType::Imports && file_node_ids.contains(&edge.source_id))
                    .then_some((edge.source_id, edge.target_id))
            })
            .collect();

        let mut desired_imports = HashSet::new();
        for (_, edge) in graph.iter_edges() {
            let file_id = edge.source_id;
            if edge.edge_type != EdgeType::Imports || !file_node_ids.contains(&file_id) {
                continue;
            }
            if let Some(symbols) = edge.properties.get_string_list_compat("symbols") {
                for symbol in &symbols {
                    let symbol = symbol.as_str();
                    if let Some(&symbol_id) = symbol_map.get(symbol) {
                        desired_imports.insert((file_id, symbol_id));
                        if linked_pairs.insert((file_id, symbol_id)) {
                            let props = PropertyMap::new()
                                .with("imported_symbol", symbol)
                                .with("resolved_by", "cross_file_resolution");
                            edges_to_add.push((file_id, symbol_id, props));
                        }
                    }
                }
            }
        }

        // A C-family call cannot bind directly to an unrelated Python/Rust
        // symbol merely because it has a higher complexity score. When there
        // is exactly one C-family function and no same-named C-family type,
        // prefer it over a non-C-family global winner. Keep the existing
        // resolver for ambiguous C-family names and possible FFI calls.
        let mut c_family_functions: std::collections::HashMap<String, Option<codegraph::NodeId>> = std::collections::HashMap::new();
        let mut c_family_types = HashSet::new();
        let mut scoped_functions: HashMap<(String, String), Option<codegraph::NodeId>> = HashMap::new();
        let mut scoped_types = HashSet::new();
        for (id, node) in graph.iter_nodes() {
            if !is_c_family_node(node) { continue; }
            let Some(name) = node.properties.get_string("name") else { continue; };
            let scope = node.properties.get_string("path")
                .and_then(|path| call_scope_for_path(path, call_scopes));
            if let Some(scope) = scope {
                let key = (scope.to_string(), name.to_string());
                match node.node_type {
                    NodeType::Function => { scoped_functions.entry(key).and_modify(|candidate| *candidate = None).or_insert(Some(id)); }
                    NodeType::Class | NodeType::Interface => { scoped_types.insert(key); }
                    _ => {}
                }
            }
            match node.node_type {
                NodeType::Function => {
                    c_family_functions.entry(name.to_string())
                        .and_modify(|candidate| *candidate = None)
                        .or_insert(Some(id));
                }
                NodeType::Class | NodeType::Interface => { c_family_types.insert(name.to_string()); }
                _ => {}
            }
        }

        // Remove only inferred calls whose selected target has changed. Keep
        // parser-authored calls and avoid rewriting unchanged edges on rescans.
        let desired_calls: HashSet<_> = graph.iter_nodes()
            .filter(|(_, node)| node.node_type == NodeType::Function)
            .flat_map(|(id, node)| {
                node.properties.get_string_list_compat("unresolved_calls")
                    .unwrap_or_default().into_iter()
                    .filter(|name| !name.is_empty())
                    .filter_map(|name| {
                        let target = symbol_map.get(name.as_str()).copied()?;
                        let caller_is_c = is_c_family_node(node);
                        if caller_is_c {
                            if let Some(scope) = node.properties.get_string("path").and_then(|path| call_scope_for_path(path, call_scopes)) {
                                let key = (scope.to_string(), name.clone());
                                if !scoped_types.contains(&key) {
                                    if let Some(Some(scoped)) = scoped_functions.get(&key) { return Some((id, *scoped)); }
                                }
                            }
                        }
                        let target_is_c = graph.get_node(target).ok().is_some_and(is_c_family_node);
                        if caller_is_c && !target_is_c && !c_family_types.contains(&name) {
                            if let Some(Some(local)) = c_family_functions.get(&name) { return Some((id, *local)); }
                        }
                        Some((id, target))
                    })
                    .collect::<Vec<_>>()
            }).collect();
        let obsolete_calls: Vec<_> = graph.iter_edges().filter_map(|(id, edge)| {
            (edge.edge_type == EdgeType::Calls
                && edge.properties.get_string("resolved_by") == Some("cross_file_resolution")
                && !desired_calls.contains(&(edge.source_id, edge.target_id)))
                .then_some(id)
        }).collect();
        let existing_calls: HashSet<_> = graph.iter_edges()
            .filter_map(|(_, edge)| (edge.edge_type == EdgeType::Calls)
                .then_some((edge.source_id, edge.target_id)))
            .collect();
        let call_edges_to_add: Vec<_> = desired_calls.difference(&existing_calls)
            .map(|&(from_id, to_id)| (from_id, to_id, EdgeType::Calls,
                PropertyMap::new().with("resolved_by", "cross_file_resolution").with("is_direct", "true")))
            .collect();
        let resolved_call_count = call_edges_to_add.len();
        // Resolve type references without mutating the graph while planning.
        let mut existing_refs: HashSet<_> = graph.iter_edges().filter_map(|(_, edge)|
            (edge.edge_type == EdgeType::References).then_some((edge.source_id, edge.target_id))).collect();
        let mut ref_edges_to_add = Vec::new();
        let mut desired_refs = HashSet::new();
        for (func_id, node) in graph.iter_nodes().filter(|(_, node)| node.node_type == NodeType::Function) {
            if let Some(unresolved) = node.properties.get_string_list_compat("unresolved_type_refs") {
                for name in unresolved {
                    if let Some(&type_id) = symbol_map.get(name.as_str()) {
                        desired_refs.insert((func_id, type_id));
                        if existing_refs.insert((func_id, type_id)) {
                            ref_edges_to_add.push((func_id, type_id, EdgeType::References,
                                PropertyMap::new().with("resolved_by", "cross_file_resolution")));
                        }
                    }
                }
            }
        }
        let scopes = Self::sql_scope_map();
        let (sql_obsolete, sql_additions) = Self::plan_sql_table_references(graph, &scopes);
        let mut obsolete = obsolete_calls;
        obsolete.extend(graph.iter_edges().filter_map(|(id, edge)| {
            if edge.properties.get_string("resolved_by") != Some("cross_file_resolution") {
                return None;
            }
            let pair = (edge.source_id, edge.target_id);
            match edge.edge_type {
                EdgeType::Imports if !desired_imports.contains(&pair) => Some(id),
                EdgeType::References if !desired_refs.contains(&pair) => Some(id),
                _ => None,
            }
        }));
        obsolete.extend(sql_obsolete);
        let mut additions: Vec<_> = edges_to_add.into_iter()
            .map(|(from, to, props)| (from, to, EdgeType::Imports, props)).collect();
        additions.extend(call_edges_to_add);
        additions.extend(ref_edges_to_add);
        additions.extend(sql_additions);
        graph.replace_edges_batch(&obsolete, additions)?;
        if resolved_call_count > 0 {
            tracing::info!("[resolve_cross_file] Resolved {} cross-file call edges", resolved_call_count);
        }
        Ok(())
    }

    /// Link unqualified SQL references only within an unambiguous database scope.
    pub fn resolve_sql_table_references(graph: &mut CodeGraph) -> codegraph::Result<()> {
        let (obsolete, additions) = Self::plan_sql_table_references(graph, &Self::sql_scope_map());
        graph.replace_edges_batch(&obsolete, additions)?;
        Ok(())
    }

    fn sql_scope_map() -> std::collections::HashMap<String, String> {
        match std::env::var("CODEGRAPH_SQL_SCOPE_MAP") {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|_| {
                tracing::warn!("Invalid SQL scope map; cross-root links are disabled");
                Default::default()
            }),
            Err(_) => Default::default(),
        }
    }

    #[cfg(test)]
    fn resolve_sql_table_references_with_scopes(
        graph: &mut CodeGraph,
        scopes: &std::collections::HashMap<String, String>,
    ) -> codegraph::Result<()> {
        let (obsolete, additions) = Self::plan_sql_table_references(graph, scopes);
        graph.replace_edges_batch(&obsolete, additions)?;
        Ok(())
    }

    fn plan_sql_table_references(
        graph: &CodeGraph,
        scopes: &std::collections::HashMap<String, String>,
    ) -> (Vec<codegraph::EdgeId>, Vec<(codegraph::NodeId, codegraph::NodeId, codegraph::EdgeType, codegraph::PropertyMap)>) {
        use codegraph::{EdgeType, NodeId, PropertyMap};
        use std::collections::HashMap;

        fn identity(path: &str, name: &str) -> Option<(String, String, String, bool)> {
            let (root, tail) = path.split_once("/data/sql/")?;
            let mut parts = tail.split('/');
            let first = parts.next()?;
            let second = parts.next()?;
            let (stage, database) = if matches!(first, "base" | "updates" | "archive" | "old") {
                (first, second.strip_prefix("pending_").unwrap_or(second))
            } else {
                let database = match first {
                    "world" | "db-world" => "db_world", "auth" | "db-auth" => "db_auth",
                    "characters" | "db-characters" => "db_characters", "playerbots" => "db_playerbots",
                    _ => return None,
                };
                (if second.ends_with(".sql") { "updates" } else { second }, database)
            };
            if !matches!(stage, "base" | "updates" | "archive" | "old") ||
                !matches!(database, "db_world" | "db_auth" | "db_characters" | "db_playerbots") { return None; }
            let name = name.trim_matches('`').to_ascii_lowercase();
            if name.is_empty() || name.contains('.') || name.contains('`') { return None; }
            Some((root.to_owned(), database.to_owned(), name, stage == "base"))
        }

        let mut additions = Vec::new();

        let mut definitions: HashMap<(String, String, String), Vec<NodeId>> = HashMap::new();
        let mut references = Vec::new();
        for (id, node) in graph.iter_nodes() {
            let (Some(kind), Some(path), Some(name)) = (node.properties.get_string("kind"), node.properties.get_string("path"), node.properties.get_string("name")) else { continue; };
            if !matches!(kind, "table" | "table_reference") { continue; }
            let Some((root, database, name, base)) = identity(path, name) else { continue; };
            let scope = match scopes.get(&root) {
                Some(group) if !group.is_empty() => format!("group:{group}"),
                _ => format!("root:{root}"),
            };
            let key = (scope, database, name);
            if kind == "table" && base { definitions.entry(key).or_default().push(id); }
            else if kind == "table_reference" || (kind == "table" && !base) { references.push((id, key)); }
        }
        for (reference, key) in references {
            if let Some([definition]) = definitions.get(&key).map(Vec::as_slice) {
                additions.push((reference, *definition, EdgeType::References,
                    PropertyMap::new().with("resolved_by", "sql_database_scope")));
            }
        }

        let mut tables: HashMap<(String, String), Vec<NodeId>> = HashMap::new();
        for ((scope, _, name), ids) in &definitions {
            tables.entry((scope.clone(), name.clone())).or_default().extend(ids);
        }
        let mut links = HashSet::new();
        let mut prepared_links = HashSet::new();
        let mut prepared: HashMap<(String, String), Vec<Vec<String>>> = HashMap::new();
        let mut prepared_users = Vec::new();
        for (id, node) in graph.iter_nodes() {
            if node.node_type != codegraph::NodeType::Function { continue; }
            let Some(path) = node.properties.get_string("path") else { continue; };
            let root = scopes.keys().filter(|root| path.strip_prefix(root.as_str()).is_some_and(|rest| rest.starts_with('/'))).max_by_key(|root| root.len()).map(String::as_str)
                .or_else(|| path.split_once("/src/").map(|(root, _)| root));
            let Some(root) = root else { continue; };
            let scope = match scopes.get(root) { Some(group) if !group.is_empty() => format!("group:{group}"), _ => format!("root:{root}") };
            if let Some(names) = node.properties.get_string_list("sql_literal_tables") {
                for name in names {
                    if let Some([table]) = tables.get(&(scope.clone(), name.clone())).map(Vec::as_slice) {
                        links.insert((id, *table));
                    }
                }
            }
            if let Some(definitions) = node.properties.get_string_list("sql_prepared_definitions") {
                for definition in definitions {
                    let mut fields = definition.split('\t');
                    if let Some(key) = fields.next() {
                        prepared.entry((scope.clone(), key.to_owned())).or_default().push(fields.map(str::to_owned).collect());
                    }
                }
            }
            if let Some(uses) = node.properties.get_string_list("sql_prepared_uses") {
                for key in uses { prepared_users.push((id, scope.clone(), key.clone())); }
            }
        }
        for (user, scope, key) in prepared_users {
            if let Some([names]) = prepared.get(&(scope.clone(), key)).map(Vec::as_slice) {
                for name in names {
                    if let Some([table]) = tables.get(&(scope.clone(), name.clone())).map(Vec::as_slice) {
                        prepared_links.insert((user, *table));
                    }
                }
            }
        }
        for (function, table) in &links {
            additions.push((*function, *table, EdgeType::References, PropertyMap::new().with("resolved_by", "code_sql_literal")));
        }
        for (function, table) in prepared_links.difference(&links) {
            additions.push((*function, *table, EdgeType::References, PropertyMap::new().with("resolved_by", "code_sql_prepared")));
        }
        let desired: HashSet<_> = additions.iter().map(|(source, target, _, props)|
            (*source, *target, props.get_string("resolved_by").unwrap().to_owned())).collect();
        let mut existing = HashSet::new();
        let obsolete: Vec<_> = graph.iter_edges().filter_map(|(id, edge)| {
            let method = edge.properties.get_string("resolved_by")?;
            if !matches!(method, "sql_database_scope" | "code_sql_literal" | "code_sql_prepared") { return None; }
            let key = (edge.source_id, edge.target_id, method.to_owned());
            (!desired.contains(&key) || !existing.insert(key)).then_some(id)
        }).collect();
        additions.retain(|(source, target, _, props)| {
            existing.insert((*source, *target, props.get_string("resolved_by").unwrap().to_owned()))
        });
        (obsolete, additions)
    }
}

pub fn validate_call_scope_configuration() -> codegraph::Result<()> {
    configured_call_scopes().map(|_| ())
}

fn configured_call_scopes() -> codegraph::Result<HashMap<String, String>> {
    match std::env::var("CODEGRAPH_CALL_SCOPE_MAP") {
        Ok(raw) => parse_call_scope_map(&raw),
        Err(std::env::VarError::NotPresent) => Ok(HashMap::new()),
        Err(_) => Err(codegraph::GraphError::InvalidOperation {
            message: "CODEGRAPH_CALL_SCOPE_MAP is not valid Unicode".to_string(),
        }),
    }
}

fn parse_call_scope_map(raw: &str) -> codegraph::Result<HashMap<String, String>> {
    let parsed: HashMap<String, String> = serde_json::from_str(raw).map_err(|error|
        codegraph::GraphError::InvalidOperation { message: format!("Invalid CODEGRAPH_CALL_SCOPE_MAP: {error}") })?;
    let mut scopes = HashMap::new();
    for (root, group) in parsed {
        let path = Path::new(&root);
        if !path.is_absolute() || group.trim().is_empty() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(codegraph::GraphError::InvalidOperation {
                message: "CODEGRAPH_CALL_SCOPE_MAP requires absolute roots without parent components and nonempty groups".to_string(),
            });
        }
        let normalized: PathBuf = path.components().collect();
        let normalized = normalized.to_str().ok_or_else(|| codegraph::GraphError::InvalidOperation {
            message: "CODEGRAPH_CALL_SCOPE_MAP contains a non-Unicode root".to_string(),
        })?.to_string();
        if scopes.insert(normalized, group).is_some() {
            return Err(codegraph::GraphError::InvalidOperation {
                message: "CODEGRAPH_CALL_SCOPE_MAP contains duplicate normalized roots".to_string(),
            });
        }
    }
    Ok(scopes)
}

fn call_scope_for_path<'a>(path: &str, scopes: &'a HashMap<String, String>) -> Option<&'a str> {
    scopes.iter()
        .filter(|(root, _)| Path::new(path).strip_prefix(Path::new(root)).is_ok())
        .max_by_key(|(root, _)| Path::new(root).components().count())
        .map(|(_, group)| group.as_str())
}

fn is_c_family_node(node: &codegraph::Node) -> bool {
    if let Some(language) = node.properties.get_string("language") {
        return matches!(language.to_ascii_lowercase().as_str(), "c" | "cpp" | "c++");
    }
    let Some(path) = node.properties.get_string("path") else { return false; };
    let path = path.to_ascii_lowercase();
    path.ends_with(".cpp.inc") || path.ends_with(".h.in") ||
        std::path::Path::new(&path).extension().and_then(|ext| ext.to_str())
            .is_some_and(|ext| matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx"))
}

/// Weight a symbol for deduplication: prefer non-stub implementations.
/// Returns a score based on complexity and line count — stubs (empty body,
/// single-line return) get low scores, real implementations get high scores.
fn symbol_weight(graph: &codegraph::CodeGraph, node_id: codegraph::NodeId) -> u32 {
    let node = match graph.get_node(node_id) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    let complexity = node.properties.get_int("complexity").unwrap_or(1) as u32;
    let lines = {
        let start = node.properties.get_int("line_start").unwrap_or(0) as u32;
        let end = node.properties.get_int("line_end").unwrap_or(0) as u32;
        end.saturating_sub(start) + 1
    };
    // Complexity is the primary signal, lines break ties
    complexity * 100 + lines
}

/// Result of a batch update operation.
pub struct BatchUpdateResult {
    pub succeeded: Vec<(PathBuf, codegraph_parser_api::FileInfo)>,
    pub failed: Vec<(PathBuf, String)>,
}

impl BatchUpdateResult {
    /// Check if all files were updated successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get the success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.succeeded.len() + self.failed.len();
        if total == 0 {
            1.0
        } else {
            self.succeeded.len() as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    fn parsed_function(graph: &mut codegraph::CodeGraph, source: &str) -> codegraph::NodeId {
        use codegraph_parser_api::CodeParser;
        codegraph_cpp::CppParser::new().parse_source(source, std::path::Path::new("/repo/src/f.cpp"), graph).unwrap().functions[0]
    }

    #[test]
    fn cpp_sql_query_references_unique_table_definition() {
        use codegraph::{CodeGraph, NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let source = format!("void f() {{ {} db.Query(\"SELECT receiver FROM mail\"); }}", "int n = 1; ".repeat(110));
        let function = parsed_function(&mut graph, &source);
        let node = graph.get_node(function).unwrap();
        assert!(!node.properties.get_string("body_prefix").unwrap().contains("SELECT"));
        assert_eq!(node.properties.get_string_list("sql_literal_tables").unwrap(), &["mail".to_string()]);
        let table = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("name", "mail").with("kind", "table")
            .with("path", "/repo/data/sql/base/db_characters/mail.sql")).unwrap();
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert_eq!(graph.get_edges_between(function, table).unwrap().len(), 1);
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert_eq!(graph.get_edges_between(function, table).unwrap().len(), 1);
        let duplicate = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("name", "mail").with("kind", "table")
            .with("path", "/repo/data/sql/base/db_world/mail.sql")).unwrap();
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert!(graph.get_edges_between(function, table).unwrap().is_empty());
        assert!(graph.get_edges_between(function, duplicate).unwrap().is_empty());
    }

    #[test]
    fn cpp_sql_ignores_comments_unrelated_strings_ctes_and_other_roots() {
        use codegraph::{CodeGraph, NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let function = parsed_function(&mut graph, r#"void f() { /* db.Query("SELECT * FROM mail"); */ log("SELECT * FROM mail"); db.Query("WITH mail AS (SELECT 1) SELECT * FROM mail"); db.Query("SELECT * FROM other"); }"#);
        let local = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("name", "mail").with("kind", "table")
            .with("path", "/repo/data/sql/base/db_characters/mail.sql")).unwrap();
        let foreign = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("name", "other").with("kind", "table")
            .with("path", "/different/data/sql/base/db_characters/other.sql")).unwrap();
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert!(graph.get_edges_between(function, local).unwrap().is_empty());
        assert!(graph.get_edges_between(function, foreign).unwrap().is_empty());
    }

    #[test]
    fn cpp_prepared_statement_users_link_to_their_sql_table() {
        use codegraph::{CodeGraph, NodeType, PropertyMap};
        use codegraph_parser_api::CodeParser;
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = codegraph_cpp::CppParser::new();
        parser.parse_source(r#"void define() { PrepareStatement(DEL_MAIL, "DELETE FROM mail WHERE id = ?", 0); }"#, std::path::Path::new("/repo/src/database.cpp"), &mut graph).unwrap();
        let user = parser.parse_source(r#"void user() { auto s = db.GetPreparedStatement(DEL_MAIL); db.Execute(s); }"#, std::path::Path::new("/repo/src/user.cpp"), &mut graph).unwrap().functions[0];
        let table = graph.add_node(NodeType::Generic, PropertyMap::new().with("name", "mail").with("kind", "table").with("path", "/repo/data/sql/base/db_characters/mail.sql")).unwrap();
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert_eq!(graph.get_edges_between(user, table).unwrap().len(), 1);
        let edge = graph.get_edges_between(user, table).unwrap()[0];
        assert_eq!(graph.get_edge(edge).unwrap().properties.get_string("resolved_by"), Some("code_sql_prepared"));
        parser.parse_source(r#"void other() { PrepareStatement(DEL_MAIL, dynamic_sql, 0); }"#, std::path::Path::new("/repo/src/other.cpp"), &mut graph).unwrap();
        super::GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert!(graph.get_edges_between(user, table).unwrap().is_empty());
    }
    use super::*;
    use crate::domain::node_props;

    #[test]
    fn sql_links_are_scoped_unambiguous_and_reconciled() {
        use codegraph::{EdgeType, NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let mut node = |kind: &str, path: &str, name: &str| graph.add_node(NodeType::Generic,
            PropertyMap::new().with("kind", kind).with("path", path).with("name", name)).unwrap();
        let world = node("table", "/repo/data/sql/base/db_world/things.sql", "`things`");
        let auth = node("table", "/repo/data/sql/base/db_auth/things.sql", "`things`");
        let reference = node("table_reference", "/repo/data/sql/updates/db_world/001.sql", "`things`");
        let other_root = node("table_reference", "/other/data/sql/updates/db_world/001.sql", "things");
        let qualified = node("table_reference", "/repo/data/sql/updates/db_world/002.sql", "auth.things");
        let unknown = node("table_reference", "/repo/data/sql/custom/db_world/003.sql", "things");
        let pending = node("table_reference", "/repo/data/sql/updates/pending_db_world/004.sql", "things");
        let bots = node("table", "/module/data/sql/playerbots/base/things.sql", "things");
        let bot_ref = node("table_reference", "/module/data/sql/playerbots/updates/001.sql", "things");
        let module_world = node("table_reference", "/module/data/sql/world/updates/001.sql", "things");
        let hyphen_world = node("table", "/module/data/sql/db-world/base/things.sql", "things");
        let hyphen_ref = node("table_reference", "/module/data/sql/db-world/updates/001.sql", "things");
        let direct_ref = node("table_reference", "/module/data/sql/db-world/update.sql", "things");
        let update_definition = node("table", "/module/data/sql/db-world/updates/002.sql", "things");
        GraphUpdater::resolve_sql_table_references(&mut graph).unwrap();
        let original = graph.get_edges_between(reference, world).unwrap();
        GraphUpdater::resolve_sql_table_references(&mut graph).unwrap();
        let edges = graph.get_edges_between(reference, world).unwrap();
        assert_eq!(edges, original, "unchanged SQL links retain their edge IDs");
        assert_eq!(edges.len(), 1);
        assert_eq!(graph.get_edge(edges[0]).unwrap().edge_type, EdgeType::References);
        assert!(graph.get_edges_between(reference, auth).unwrap().is_empty());
        assert!(graph.get_edges_between(other_root, world).unwrap().is_empty());
        assert!(graph.get_edges_between(qualified, world).unwrap().is_empty());
        assert!(graph.get_edges_between(unknown, world).unwrap().is_empty());
        assert_eq!(graph.get_edges_between(pending, world).unwrap().len(), 1);
        assert_eq!(graph.get_edges_between(bot_ref, bots).unwrap().len(), 1);
        assert!(graph.get_edges_between(module_world, bots).unwrap().is_empty());
        assert_eq!(graph.get_edges_between(hyphen_ref, hyphen_world).unwrap().len(), 1);
        assert_eq!(graph.get_edges_between(module_world, hyphen_world).unwrap().len(), 1);
        assert_eq!(graph.get_edges_between(direct_ref, hyphen_world).unwrap().len(), 1);
        assert_eq!(graph.get_edges_between(update_definition, hyphen_world).unwrap().len(), 1);
        let scopes = std::collections::HashMap::from([
            ("/repo".to_string(), "project".to_string()),
            ("/other".to_string(), "project".to_string()),
        ]);
        GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &scopes).unwrap();
        assert_eq!(graph.get_edges_between(other_root, world).unwrap().len(), 1);
        assert!(graph.get_edges_between(other_root, auth).unwrap().is_empty());
        GraphUpdater::resolve_sql_table_references_with_scopes(&mut graph, &std::collections::HashMap::new()).unwrap();
        assert!(graph.get_edges_between(other_root, world).unwrap().is_empty());
        let duplicate = graph.add_node(NodeType::Generic, PropertyMap::new().with("kind", "table")
            .with("path", "/repo/data/sql/base/db_world/other.sql").with("name", "things")).unwrap();
        GraphUpdater::resolve_sql_table_references(&mut graph).unwrap();
        assert!(graph.get_edges_between(reference, world).unwrap().is_empty());
        graph.delete_node(duplicate).unwrap();
        GraphUpdater::resolve_sql_table_references(&mut graph).unwrap();
        assert_eq!(graph.get_edges_between(reference, world).unwrap().len(), 1);
    }

    // Helper to create a mock FileInfo using GraphUpdater
    async fn create_file_info_via_update(
        path: &str,
        content: &str,
    ) -> codegraph_parser_api::FileInfo {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());
        let files = vec![(PathBuf::from(path), content.to_string())];
        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();
        result.succeeded.into_iter().next().unwrap().1
    }

    #[test]
    fn test_batch_update_result_all_succeeded_empty() {
        let result = BatchUpdateResult {
            succeeded: vec![],
            failed: vec![],
        };
        assert!(result.all_succeeded());
    }

    #[test]
    fn test_batch_update_result_has_failures() {
        let result = BatchUpdateResult {
            succeeded: vec![],
            failed: vec![(PathBuf::from("bad.py"), "parse error".to_string())],
        };
        assert!(!result.all_succeeded());
    }

    #[test]
    fn test_success_rate_empty() {
        let result = BatchUpdateResult {
            succeeded: vec![],
            failed: vec![],
        };
        assert!((result.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_success_rate_all_failure() {
        let result = BatchUpdateResult {
            succeeded: vec![],
            failed: vec![
                (PathBuf::from("a.py"), "error".to_string()),
                (PathBuf::from("b.py"), "error".to_string()),
            ],
        };
        assert!((result.success_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_batch_update_result_all_succeeded_with_files() {
        let info = create_file_info_via_update("a.py", "def foo(): pass").await;
        let result = BatchUpdateResult {
            succeeded: vec![(PathBuf::from("a.py"), info)],
            failed: vec![],
        };
        assert!(result.all_succeeded());
    }

    #[tokio::test]
    async fn test_batch_update_result_mixed() {
        let info = create_file_info_via_update("a.py", "def foo(): pass").await;
        let result = BatchUpdateResult {
            succeeded: vec![(PathBuf::from("a.py"), info)],
            failed: vec![(PathBuf::from("bad.py"), "parse error".to_string())],
        };
        assert!(!result.all_succeeded());
    }

    #[tokio::test]
    async fn test_success_rate_all_success() {
        let info1 = create_file_info_via_update("a.py", "def a(): pass").await;
        let info2 = create_file_info_via_update("b.py", "def b(): pass").await;
        let result = BatchUpdateResult {
            succeeded: vec![
                (PathBuf::from("a.py"), info1),
                (PathBuf::from("b.py"), info2),
            ],
            failed: vec![],
        };
        assert!((result.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_success_rate_half() {
        let info = create_file_info_via_update("a.py", "def foo(): pass").await;
        let result = BatchUpdateResult {
            succeeded: vec![(PathBuf::from("a.py"), info)],
            failed: vec![(PathBuf::from("b.py"), "error".to_string())],
        };
        assert!((result.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_success_rate_two_thirds() {
        let info1 = create_file_info_via_update("a.py", "def a(): pass").await;
        let info2 = create_file_info_via_update("b.py", "def b(): pass").await;
        let result = BatchUpdateResult {
            succeeded: vec![
                (PathBuf::from("a.py"), info1),
                (PathBuf::from("b.py"), info2),
            ],
            failed: vec![(PathBuf::from("c.py"), "error".to_string())],
        };
        // 2/3 = 0.6666...
        assert!((result.success_rate() - (2.0 / 3.0)).abs() < 0.0001);
    }

    #[tokio::test]
    async fn batch_header_uses_buffer_not_stale_disk_content() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mixed.h");
        std::fs::write(&path, "struct OldC { int value; };\n").unwrap();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());
        let result = GraphUpdater::update_files(&graph, &parsers, &[(path.clone(), "class EditedCpp {};".into())]).await.unwrap();
        assert!(result.all_succeeded());
        assert!(graph.read().await.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("EditedCpp")));
        std::fs::write(&path, "class DiskCpp {};\n").unwrap();
        let result = GraphUpdater::update_files(&graph, &parsers, &[(path, "struct EditedC { int value; };".into())]).await.unwrap();
        assert!(result.all_succeeded());
        let graph = graph.read().await;
        assert!(graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("EditedC")));
        assert!(!graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("EditedCpp")));
    }

    #[tokio::test]
    async fn test_graph_updater_update_files_python() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        let files = vec![(
            PathBuf::from("test.py"),
            "def foo():\n    pass\n".to_string(),
        )];

        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();

        assert!(result.all_succeeded());
        assert_eq!(result.succeeded.len(), 1);
        assert!(result.failed.is_empty());
    }

    #[tokio::test]
    async fn test_graph_updater_update_multiple_files() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        let files = vec![
            (PathBuf::from("a.py"), "def a(): pass".to_string()),
            (PathBuf::from("b.rs"), "fn b() {}".to_string()),
            (PathBuf::from("c.ts"), "function c() {}".to_string()),
        ];

        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();

        assert!(result.all_succeeded());
        assert_eq!(result.succeeded.len(), 3);
    }

    #[tokio::test]
    async fn test_graph_updater_unsupported_file_skipped() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        let files = vec![(PathBuf::from("readme.txt"), "hello world".to_string())];

        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();

        // Unsupported files are silently skipped, not considered failures
        assert!(result.all_succeeded());
        assert!(result.succeeded.is_empty());
        assert!(result.failed.is_empty());
    }

    #[tokio::test]
    async fn test_graph_updater_mixed_files() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        let files = vec![
            (PathBuf::from("valid.py"), "def foo(): pass".to_string()),
            (PathBuf::from("readme.md"), "# Hello".to_string()), // unsupported
            (PathBuf::from("valid.rs"), "fn bar() {}".to_string()),
        ];

        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();

        // Only parseable files are tracked
        assert!(result.all_succeeded());
        assert_eq!(result.succeeded.len(), 2); // Python and Rust
    }

    #[tokio::test]
    async fn test_graph_updater_updates_remove_old_nodes() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        // First update
        let files1 = vec![(
            PathBuf::from("test.py"),
            "def old_function(): pass".to_string(),
        )];
        GraphUpdater::update_files(&graph, &parsers, &files1).await.unwrap();

        // Second update with new content (should replace old)
        let files2 = vec![(
            PathBuf::from("test.py"),
            "def new_function(): pass".to_string(),
        )];
        let result = GraphUpdater::update_files(&graph, &parsers, &files2).await.unwrap();

        assert!(result.all_succeeded());
    }

    #[tokio::test]
    async fn test_cross_file_import_resolution() {
        use codegraph::{Direction, EdgeType, NodeType};

        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsers = Arc::new(ParserRegistry::new());

        // Create two TypeScript files:
        // 1. utils.ts defines a class MyClass
        // 2. main.ts imports { MyClass } from './utils'
        let files = vec![
            (
                PathBuf::from("/src/utils.ts"),
                r#"
                export class MyClass {
                    constructor() {}
                    doSomething() {}
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("/src/main.ts"),
                r#"
                import { MyClass } from './utils';

                const instance = new MyClass();
                instance.doSomething();
                "#
                .to_string(),
            ),
        ];

        let result = GraphUpdater::update_files(&graph, &parsers, &files).await.unwrap();
        assert!(result.all_succeeded());

        // Now check if the import edge was resolved correctly
        let graph_guard = graph.read().await;

        // Find the MyClass node
        let class_nodes: Vec<_> = graph_guard
            .query()
            .node_type(NodeType::Class)
            .execute()
            .unwrap_or_default();

        let my_class_id = class_nodes.iter().find(|&id| {
            graph_guard
                .get_node(*id)
                .map(|n| node_props::name(n) == "MyClass")
                .unwrap_or(false)
        });

        assert!(my_class_id.is_some(), "MyClass should exist in the graph");

        let my_class_id = my_class_id.unwrap();

        // Check if MyClass has incoming import edges
        let incoming_neighbors = graph_guard
            .get_neighbors(*my_class_id, Direction::Incoming)
            .unwrap_or_default();

        let has_import_edge = incoming_neighbors.iter().any(|neighbor_id| {
            graph_guard
                .get_edges_between(*neighbor_id, *my_class_id)
                .map(|edges| {
                    edges.iter().any(|e| {
                        graph_guard
                            .get_edge(*e)
                            .map(|edge| edge.edge_type == EdgeType::Imports)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });

        assert!(
            has_import_edge,
            "MyClass should have an incoming import edge from main.ts"
        );
    }

    #[test]
    fn test_same_file_calls_edges_preserved() {
        use codegraph::{Direction, EdgeType};
        // Verify that the mapper creates same-file Calls edges
        // and they survive through parse_file
        let source = r#"
struct Foo;

impl Foo {
    fn caller(&self) {
        Self::target();
        self.instance_target();
        standalone();
    }
    fn target() {}
    fn instance_target(&self) {}
}

fn standalone() {}
"#;
        let mut graph = CodeGraph::in_memory().unwrap();
        let parsers = ParserRegistry::new();
        let result = parsers.parse_source(source, std::path::Path::new("test.rs"), &mut graph);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        // Find the "caller" function node
        let all_funcs = graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap();
        let caller_id = all_funcs
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "caller")
                    .unwrap_or(false)
            })
            .expect("Should find 'caller' function");

        // Collect callees via Calls edges
        let callees: Vec<String> = graph
            .get_neighbors(*caller_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter(|&&nid| {
                graph
                    .get_edges_between(*caller_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::Calls)
                            .unwrap_or(false)
                    })
            })
            .filter_map(|&nid| {
                graph
                    .get_node(nid)
                    .ok()
                    .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
            })
            .collect();

        eprintln!("Callees of 'caller': {:?}", callees);
        assert!(
            callees.contains(&"target".to_string()),
            "Missing Calls edge: caller -> target (Self::target())"
        );
        assert!(
            callees.contains(&"instance_target".to_string()),
            "Missing Calls edge: caller -> instance_target (self.instance_target())"
        );
        assert!(
            callees.contains(&"standalone".to_string()),
            "Missing Calls edge: caller -> standalone"
        );
    }

    #[test]
    fn test_parse_real_file_calls_edges() {
        use codegraph::{Direction, EdgeType};
        // Parse the actual watcher.rs and check if new -> handle_event edge exists
        let mut graph = CodeGraph::in_memory().unwrap();
        let parsers = ParserRegistry::new();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/watcher.rs");
        if !path.exists() {
            eprintln!("Skipping: {:?} not found", path);
            return;
        }
        let result = parsers.parse_file(&path, &mut graph);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let all_funcs = graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap();

        // Print all functions and their Calls edges
        for &fid in &all_funcs {
            let node = graph.get_node(fid).unwrap();
            let name = node.properties.get_string("name").unwrap_or("?");

            let callees: Vec<String> = graph
                .get_neighbors(fid, Direction::Outgoing)
                .unwrap_or_default()
                .iter()
                .filter_map(|&nid| {
                    let has_call = graph
                        .get_edges_between(fid, nid)
                        .unwrap_or_default()
                        .iter()
                        .any(|&eid| {
                            graph
                                .get_edge(eid)
                                .map(|e| e.edge_type == EdgeType::Calls)
                                .unwrap_or(false)
                        });
                    if has_call {
                        graph
                            .get_node(nid)
                            .ok()
                            .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            let unresolved = node.properties.get_string("unresolved_calls").unwrap_or("");

            if !callees.is_empty() || !unresolved.is_empty() {
                eprintln!(
                    "  {} -> resolved: {:?}, unresolved: [{}]",
                    name, callees, unresolved
                );
            }
        }

        // Check that new -> handle_event exists
        let new_id = all_funcs
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "new")
                    .unwrap_or(false)
            })
            .expect("Should find 'new' function");

        let new_callees: Vec<String> = graph
            .get_neighbors(*new_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter_map(|&nid| {
                let has_call = graph
                    .get_edges_between(*new_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::Calls)
                            .unwrap_or(false)
                    });
                if has_call {
                    graph
                        .get_node(nid)
                        .ok()
                        .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .collect();

        eprintln!("new callees: {:?}", new_callees);
        assert!(
            new_callees.contains(&"handle_event".to_string()),
            "new -> handle_event Calls edge should exist"
        );
    }

    #[test]
    fn test_typescript_this_method_calls_edges() {
        use codegraph::{Direction, EdgeType};

        let source = r#"
export class ToolManager {
    private formatResult(data: any): string {
        return JSON.stringify(data);
    }

    private formatCallGraph(response: any, summary: boolean): string {
        return this.formatResult(response);
    }

    async handleTool(name: string): Promise<string> {
        const result = await this.getResult(name);
        return this.formatCallGraph(result, false);
    }

    private async getResult(name: string): Promise<any> {
        return { name };
    }
}
"#;

        let mut graph = CodeGraph::in_memory().unwrap();
        let parsers = ParserRegistry::new();
        let result = parsers.parse_source(source, std::path::Path::new("test.ts"), &mut graph);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        // Print all functions and their Calls edges for diagnosis
        let all_funcs = graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap();

        eprintln!("=== TypeScript this.method() Calls edges ===");
        for &fid in &all_funcs {
            let node = graph.get_node(fid).unwrap();
            let name = node.properties.get_string("name").unwrap_or("?");

            let callees: Vec<String> = graph
                .get_neighbors(fid, Direction::Outgoing)
                .unwrap_or_default()
                .iter()
                .filter_map(|&nid| {
                    let has_call = graph
                        .get_edges_between(fid, nid)
                        .unwrap_or_default()
                        .iter()
                        .any(|&eid| {
                            graph
                                .get_edge(eid)
                                .map(|e| e.edge_type == EdgeType::Calls)
                                .unwrap_or(false)
                        });
                    if has_call {
                        graph
                            .get_node(nid)
                            .ok()
                            .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            let unresolved = node.properties.get_string("unresolved_calls").unwrap_or("");
            eprintln!(
                "  {} -> resolved: {:?}, unresolved: [{}]",
                name, callees, unresolved
            );
        }

        // Check: handleTool should call formatCallGraph and getResult
        let handle_id = all_funcs
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "handleTool")
                    .unwrap_or(false)
            })
            .expect("Should find 'handleTool' function");

        let handle_callees: Vec<String> = graph
            .get_neighbors(*handle_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter_map(|&nid| {
                let has_call = graph
                    .get_edges_between(*handle_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::Calls)
                            .unwrap_or(false)
                    });
                if has_call {
                    graph
                        .get_node(nid)
                        .ok()
                        .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .collect();

        eprintln!("handleTool callees: {:?}", handle_callees);
        assert!(
            handle_callees.contains(&"formatCallGraph".to_string()),
            "handleTool -> formatCallGraph Calls edge should exist (this.formatCallGraph())"
        );
        assert!(
            handle_callees.contains(&"getResult".to_string()),
            "handleTool -> getResult Calls edge should exist (this.getResult())"
        );

        // Check: formatCallGraph should call formatResult
        let format_id = all_funcs
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "formatCallGraph")
                    .unwrap_or(false)
            })
            .expect("Should find 'formatCallGraph' function");

        let format_callees: Vec<String> = graph
            .get_neighbors(*format_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter_map(|&nid| {
                let has_call = graph
                    .get_edges_between(*format_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::Calls)
                            .unwrap_or(false)
                    });
                if has_call {
                    graph
                        .get_node(nid)
                        .ok()
                        .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .collect();

        eprintln!("formatCallGraph callees: {:?}", format_callees);
        assert!(
            format_callees.contains(&"formatResult".to_string()),
            "formatCallGraph -> formatResult Calls edge should exist (this.formatResult())"
        );
    }

    #[test]
    fn test_typescript_type_references_edges() {
        use codegraph::{Direction, EdgeType};

        let source = r#"
interface DependencyGraphParams {
    uri: string;
    depth: number;
}

interface DependencyNode {
    id: string;
    label: string;
}

function buildGraph(params: DependencyGraphParams): DependencyNode[] {
    return [];
}
"#;

        let mut graph = CodeGraph::in_memory().unwrap();
        let parsers = ParserRegistry::new();
        let result = parsers.parse_source(source, std::path::Path::new("test.ts"), &mut graph);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let all_funcs = graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap();

        let build_id = all_funcs
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "buildGraph")
                    .unwrap_or(false)
            })
            .expect("Should find 'buildGraph'");

        // Check References edges from buildGraph
        let refs: Vec<String> = graph
            .get_neighbors(*build_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter_map(|&nid| {
                let has_ref = graph
                    .get_edges_between(*build_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::References)
                            .unwrap_or(false)
                    });
                if has_ref {
                    graph
                        .get_node(nid)
                        .ok()
                        .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .collect();

        eprintln!("buildGraph References: {:?}", refs);
        assert!(
            refs.contains(&"DependencyGraphParams".to_string()),
            "buildGraph should reference DependencyGraphParams via param type"
        );
        assert!(
            refs.contains(&"DependencyNode".to_string()),
            "buildGraph should reference DependencyNode via return type"
        );

        // DependencyGraphParams should have incoming References edge
        let all_ifaces = graph
            .query()
            .node_type(codegraph::NodeType::Interface)
            .execute()
            .unwrap();

        let dgp_id = all_ifaces
            .iter()
            .find(|&&id| {
                graph
                    .get_node(id)
                    .map(|n| node_props::name(n) == "DependencyGraphParams")
                    .unwrap_or(false)
            })
            .expect("Should find DependencyGraphParams");

        let incoming: Vec<String> = graph
            .get_neighbors(*dgp_id, Direction::Incoming)
            .unwrap_or_default()
            .iter()
            .filter_map(|&nid| {
                let has_ref = graph
                    .get_edges_between(nid, *dgp_id)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::References)
                            .unwrap_or(false)
                    });
                if has_ref {
                    graph
                        .get_node(nid)
                        .ok()
                        .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .collect();

        eprintln!("DependencyGraphParams referenced by: {:?}", incoming);
        assert!(
            incoming.contains(&"buildGraph".to_string()),
            "DependencyGraphParams should have incoming References from buildGraph"
        );
    }

    #[test]
    fn test_parse_real_ts_file_calls_edges() {
        use codegraph::{Direction, EdgeType};

        let mut graph = CodeGraph::in_memory().unwrap();
        let parsers = ParserRegistry::new();

        // Parse the actual toolManager.ts
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("src/ai/toolManager.ts");
        if !path.exists() {
            eprintln!("Skipping: {:?} not found", path);
            return;
        }

        let result = parsers.parse_file(&path, &mut graph);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let all_funcs = graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap();

        eprintln!("=== toolManager.ts functions with Calls edges ===");
        let mut format_call_graph_has_callers = false;
        for &fid in &all_funcs {
            let node = graph.get_node(fid).unwrap();
            let name = node.properties.get_string("name").unwrap_or("?");

            // Check outgoing Calls
            let callees: Vec<String> = graph
                .get_neighbors(fid, Direction::Outgoing)
                .unwrap_or_default()
                .iter()
                .filter_map(|&nid| {
                    let has_call = graph
                        .get_edges_between(fid, nid)
                        .unwrap_or_default()
                        .iter()
                        .any(|&eid| {
                            graph
                                .get_edge(eid)
                                .map(|e| e.edge_type == EdgeType::Calls)
                                .unwrap_or(false)
                        });
                    if has_call {
                        graph
                            .get_node(nid)
                            .ok()
                            .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            // Check incoming Calls (callers)
            let callers: Vec<String> = graph
                .get_neighbors(fid, Direction::Incoming)
                .unwrap_or_default()
                .iter()
                .filter_map(|&nid| {
                    let has_call = graph
                        .get_edges_between(nid, fid)
                        .unwrap_or_default()
                        .iter()
                        .any(|&eid| {
                            graph
                                .get_edge(eid)
                                .map(|e| e.edge_type == EdgeType::Calls)
                                .unwrap_or(false)
                        });
                    if has_call {
                        graph
                            .get_node(nid)
                            .ok()
                            .and_then(|n| n.properties.get_string("name").map(|s| s.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            if name == "formatCallGraph" {
                format_call_graph_has_callers = !callers.is_empty();
            }

            let unresolved = node.properties.get_string("unresolved_calls").unwrap_or("");
            if !callees.is_empty() || !callers.is_empty() || !unresolved.is_empty() {
                eprintln!(
                    "  {} -> callees: {:?}, callers: {:?}, unresolved: [{}]",
                    name, callees, callers, unresolved
                );
            }
        }

        eprintln!(
            "\nformatCallGraph has callers: {}",
            format_call_graph_has_callers
        );
    }

    /// Integration test that simulates the full server pipeline for cross-file resolution.
    ///
    /// Scenario (using inline C source):
    /// 1. Batch-parse caller.c and callee.c into the graph
    /// 2. resolve_cross_file_imports → Calls edges created
    /// 3. Simulate did_open(caller.c): remove + re-parse + resolve
    /// 4. Verify cross-file Calls edges survive the did_open cycle
    ///
    #[test]
    fn test_cross_file_resolution_after_didopen() {
        let caller_source = r#"
void main_func(void) {
    int val = 42;
    if (val > 0) {
        helper_func(val);
    }
}
"#;
        let callee_source = r#"
void helper_func(int x) {
    int result = x * 2;
}
"#;
        let caller_path = std::path::Path::new("/test/caller.c");
        let callee_path = std::path::Path::new("/test/callee.c");

        let parsers = ParserRegistry::new();
        let parser = parsers
            .parser_for_path(caller_path)
            .expect("No C parser found");
        let mut graph = CodeGraph::in_memory().unwrap();

        // --- Phase 1: Batch-parse both files ---
        let r = parser.parse_source(caller_source, caller_path, &mut graph);
        assert!(r.is_ok(), "Failed to parse caller.c: {:?}", r.err());
        let r = parser.parse_source(callee_source, callee_path, &mut graph);
        assert!(r.is_ok(), "Failed to parse callee.c: {:?}", r.err());

        let main_id = find_function_node(&graph, "main_func");
        assert!(main_id.is_some(), "main_func not found after batch parse");
        let main_id = main_id.unwrap();

        let helper_id = find_function_node(&graph, "helper_func");
        assert!(
            helper_id.is_some(),
            "helper_func not found after batch parse"
        );

        // --- Phase 2: resolve_cross_file_imports ---
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();

        let edge_count_after_batch = count_calls_edges_from(&graph, main_id);
        assert!(
            edge_count_after_batch > 0,
            "Expected Calls edges after batch resolve, got 0"
        );
        assert!(
            has_calls_edge(&graph, main_id, helper_id.unwrap()),
            "Expected Calls edge main_func -> helper_func after batch resolve"
        );

        // --- Phase 3: Simulate did_open(caller.c) ---
        // 3a. Remove caller.c nodes
        let path_str = caller_path.to_string_lossy().to_string();
        if let Ok(nodes) = graph.query().property("path", path_str).execute() {
            for node_id in nodes {
                let _ = graph.delete_node(node_id);
            }
        }
        assert!(
            find_function_node(&graph, "main_func").is_none(),
            "main_func should be gone after removal"
        );

        // 3b. Re-parse caller.c
        let r = parser.parse_source(caller_source, caller_path, &mut graph);
        assert!(r.is_ok(), "Failed to re-parse caller.c: {:?}", r.err());
        let fi = r.unwrap();
        // graph.query() doesn't see nodes added after deletion in the
        // in-memory backend, so use FileInfo directly for the new ID.
        assert!(
            !fi.functions.is_empty(),
            "Re-parse should produce at least one function"
        );
        let main_id_new = fi.functions[0];

        // 3c. resolve after re-parse
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();

        let helper_id_final = find_function_node(&graph, "helper_func");
        assert!(
            helper_id_final.is_some(),
            "helper_func not found after re-resolve"
        );
        assert!(
            has_calls_edge(&graph, main_id_new, helper_id_final.unwrap()),
            "Expected Calls edge main_func -> helper_func after did_open cycle"
        );
    }

    #[tokio::test]
    async fn invalid_scope_config_rejects_library_update_before_mutation() {
        const MARKER: &str = "CODEGRAPH_TEST_INVALID_SCOPE_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "watcher::tests::invalid_scope_config_rejects_library_update_before_mutation"])
                .env(MARKER, "1").env("CODEGRAPH_CALL_SCOPE_MAP", "invalid-json")
                .output().unwrap();
            assert!(result.status.success(), "child failed: {}", String::from_utf8_lossy(&result.stderr));
            return;
        }
        use codegraph::{NodeType, PropertyMap};
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let path = PathBuf::from("/test/unchanged.cpp");
        let id = graph.write().await.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "original").with("path", path.to_string_lossy().to_string())).unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        assert!(GraphUpdater::update_files(&graph, &parsers, &[(path, "void replacement() {}".into())]).await.is_err());
        let g = graph.read().await;
        assert_eq!(g.get_node(id).unwrap().properties.get_string("name"), Some("original"));
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn call_scope_configuration_rejects_malformed_or_unsafe_roots() {
        assert!(parse_call_scope_map("not-json").is_err());
        assert!(parse_call_scope_map(r#"{"relative":"group"}"#).is_err());
        assert!(parse_call_scope_map(r#"{"/repo":""}"#).is_err());
        assert!(parse_call_scope_map(r#"{"/repo":"a","/repo/":"b"}"#).is_err());
        assert!(parse_call_scope_map(r#"{"/repo/../other":"a"}"#).is_err());
        let scopes = parse_call_scope_map(r#"{"/":"all","/repo/":"project"}"#).unwrap();
        assert_eq!(call_scope_for_path("/repo/src/file.cpp", &scopes), Some("project"));
        assert_eq!(call_scope_for_path("/repo-other/file.cpp", &scopes), Some("all"));
    }

    #[test]
    fn parsed_cpp_scope_keeps_module_calls_on_their_source_copy() {
        use codegraph_parser_api::CodeParser;
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = codegraph_cpp::CppParser::new();
        let caller = parser.parse_source("int module_caller() { return GameTime::GetGameTime(); }", Path::new("/repo/module/src/caller.cpp"), &mut graph).unwrap().functions[0];
        let candidate = parser.parse_source("namespace GameTime { int GetGameTime() { return 1; } }", Path::new("/repo/candidate/src/time.cpp"), &mut graph).unwrap().functions[0];
        let old = parser.parse_source("namespace GameTime { int GetGameTime() { if (true) { return 2; } return 0; } }", Path::new("/repo/old/src/time.cpp"), &mut graph).unwrap().functions[0];
        let scopes = HashMap::from([
            ("/repo/module".to_string(), "candidate".to_string()),
            ("/repo/candidate".to_string(), "candidate".to_string()),
            ("/repo/old".to_string(), "old".to_string()),
        ]);
        GraphUpdater::resolve_cross_file_imports_with_scopes(&mut graph, &scopes).unwrap();
        assert!(has_calls_edge(&graph, caller, candidate));
        assert!(!has_calls_edge(&graph, caller, old));
    }

    #[test]
    fn configured_source_scopes_separate_duplicate_cpp_definitions() {
        use codegraph::{NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "caller")
            .with("path", "/repo/candidate/src/caller.cpp")
            .with("unresolved_calls", vec!["GameTime::GetGameTime".to_string()])).unwrap();
        let target = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "GameTime::GetGameTime")
            .with("path", "/repo/candidate/src/time.cpp").with("complexity", 1_i64)).unwrap();
        let fixture = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "GameTime::GetGameTime")
            .with("path", "/repo/fixtures/time.cpp").with("complexity", 99_i64)).unwrap();
        let scopes = HashMap::from([
            ("/repo".to_string(), "other".to_string()),
            ("/repo/candidate".to_string(), "candidate".to_string()),
            ("/repo/fixtures".to_string(), "fixtures".to_string()),
        ]);
        GraphUpdater::resolve_cross_file_imports_with_scopes(&mut graph, &scopes).unwrap();
        assert!(has_calls_edge(&graph, caller, target));
        assert!(!has_calls_edge(&graph, caller, fixture));
        assert_eq!(call_scope_for_path("/repo/candidate-old/a.cpp", &scopes), Some("other"));
    }

    #[test]
    fn parsed_cpp_call_prefers_cpp_definition_over_unrelated_python() {
        use codegraph_parser_api::CodeParser;
        let mut graph = CodeGraph::in_memory().unwrap();
        let cpp = codegraph_cpp::CppParser::new();
        let python = codegraph_python::PythonParser::new();
        let caller = cpp.parse_source("void caller() { helper(); }", Path::new("/repo/src/caller.cpp"), &mut graph).unwrap().functions[0];
        let target = cpp.parse_source("void helper() {}", Path::new("/repo/src/helper.cpp"), &mut graph).unwrap().functions[0];
        let foreign = python.parse_source("def helper():\n    if True:\n        if True:\n            return 1\n    return 0\n", Path::new("/repo/tests/helper.py"), &mut graph).unwrap().functions[0];
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, target));
        assert!(!has_calls_edge(&graph, caller, foreign));
    }

    #[test]
    fn cpp_call_does_not_choose_a_same_named_python_function() {
        use codegraph::{NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("path", "/repo/src/caller.cpp")
            .with("unresolved_calls", vec!["helper".to_string()])).unwrap();
        let cpp = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/repo/src/helper.cpp")
            .with("complexity", 1_i64)).unwrap();
        let python = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/repo/tests/helper.py")
            .with("complexity", 99_i64)).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, cpp));
        assert!(!has_calls_edge(&graph, caller, python));
    }

    #[test]
    fn cpp_cross_language_call_remains_when_no_c_family_candidate_exists() {
        use codegraph::{NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("path", "/repo/caller.cpp")
            .with("unresolved_calls", vec!["foreign".to_string()])).unwrap();
        let foreign = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "foreign").with("path", "/repo/ffi.rs")).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, foreign));
    }

    #[test]
    fn c_family_detection_honors_language_and_template_paths() {
        use codegraph::{Node, NodeType, PropertyMap};
        let node = |props| Node::new(1, NodeType::Function, props);
        assert!(!is_c_family_node(&node(PropertyMap::new().with("language", "python").with("path", "/repo/f.cpp"))));
        assert!(is_c_family_node(&node(PropertyMap::new().with("language", "cpp").with("path", "/repo/template.unknown"))));
        assert!(is_c_family_node(&node(PropertyMap::new().with("path", "/repo/unit.cpp.inc"))));
        assert!(is_c_family_node(&node(PropertyMap::new().with("path", "/repo/build.h.in"))));
    }

    #[test]
    fn c_caller_prefers_unique_family_function_using_language_metadata() {
        use codegraph::{NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("language", "c").with("path", "/repo/caller.py")
            .with("unresolved_calls", vec!["helper".to_string()])).unwrap();
        let c_target = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("language", "cpp").with("path", "/repo/helper.py")).unwrap();
        let foreign = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("language", "python").with("path", "/repo/helper.cpp")
            .with("complexity", 99_i64)).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, c_target));
        assert!(!has_calls_edge(&graph, caller, foreign));
    }

    #[test]
    fn c_family_class_remains_constructor_candidate() {
        use codegraph::{NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("path", "/repo/caller.cpp")
            .with("unresolved_calls", vec!["Widget".to_string()])).unwrap();
        graph.add_node(NodeType::Function, PropertyMap::new().with("name", "Widget").with("path", "/repo/widget.cpp")).unwrap();
        let class = graph.add_node(NodeType::Class, PropertyMap::new().with("name", "Widget").with("path", "/repo/widget.hpp")).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, class));
    }

    #[test]
    fn inferred_calls_are_replaced_when_resolution_changes() {
        use codegraph::{EdgeType, NodeType, PropertyMap};
        let mut graph = CodeGraph::in_memory().unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("path", "/candidate/caller.cpp")
            .with("language", "cpp").with("unresolved_calls", vec!["helper".to_string()])
            .with("unresolved_type_refs", vec!["helper".to_string()])).unwrap();
        let direct = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "direct").with("path", "/candidate/caller.cpp").with("language", "cpp")).unwrap();
        let first = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/candidate/helper.cpp").with("language", "cpp")).unwrap();
        graph.add_edge(caller, direct, EdgeType::Calls, PropertyMap::new()).unwrap();
        let file = graph.add_node(NodeType::CodeFile, PropertyMap::new().with("name", "file")).unwrap();
        let placeholder = graph.add_node(NodeType::Module, PropertyMap::new().with("name", "module")).unwrap();
        graph.add_edge(file, placeholder, EdgeType::Imports, PropertyMap::new()
            .with("symbols", vec!["helper".to_string()])).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, first));
        assert_eq!(graph.get_edges_between(file, first).unwrap().len(), 1);
        assert!(graph.get_edges_between(caller, first).unwrap().iter()
            .any(|id| graph.get_edge(*id).unwrap().edge_type == EdgeType::References));
        let initial_edges = graph.get_edges_between(caller, first).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert_eq!(graph.get_edges_between(caller, first).unwrap(), initial_edges);
        let second = graph.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/fixtures/helper.cpp")
            .with("language", "cpp").with("complexity", 99_i64)).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(!has_calls_edge(&graph, caller, first));
        assert!(graph.get_edges_between(caller, first).unwrap().is_empty());
        assert!(graph.get_edges_between(file, first).unwrap().is_empty());
        assert_eq!(graph.get_edges_between(file, second).unwrap().len(), 1);
        assert!(graph.get_edges_between(caller, second).unwrap().iter()
            .any(|id| graph.get_edge(*id).unwrap().edge_type == EdgeType::References));
        assert!(has_calls_edge(&graph, caller, second));
        assert!(has_calls_edge(&graph, caller, direct));
        graph.delete_node(second).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, first));
        assert!(has_calls_edge(&graph, caller, direct));
    }

    #[test]
    fn inferred_call_replacement_reports_failure_and_retries() {
        use codegraph::{NodeType, PropertyMap, GraphError};
        use codegraph::storage::{BatchOperation, KeyValue, MemoryBackend, StorageBackend};
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        struct FailingBatch { inner: MemoryBackend, fail: Arc<AtomicBool> }
        impl StorageBackend for FailingBatch {
            fn put(&mut self, k: &[u8], v: &[u8]) -> codegraph::Result<()> { self.inner.put(k, v) }
            fn get(&self, k: &[u8]) -> codegraph::Result<Option<Vec<u8>>> { self.inner.get(k) }
            fn delete(&mut self, k: &[u8]) -> codegraph::Result<()> { self.inner.delete(k) }
            fn exists(&self, k: &[u8]) -> codegraph::Result<bool> { self.inner.exists(k) }
            fn scan_prefix(&self, k: &[u8]) -> codegraph::Result<Vec<KeyValue>> { self.inner.scan_prefix(k) }
            fn write_batch(&mut self, ops: Vec<BatchOperation>) -> codegraph::Result<()> {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(GraphError::Storage { message: "injected failure".into(), source: None });
                }
                self.inner.write_batch(ops)
            }
            fn flush(&mut self) -> codegraph::Result<()> { self.inner.flush() }
        }
        let fail = Arc::new(AtomicBool::new(false));
        let mut graph = CodeGraph::with_backend(Box::new(FailingBatch { inner: MemoryBackend::new(), fail: fail.clone() })).unwrap();
        let caller = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "caller")
            .with("unresolved_calls", vec!["helper".to_string()])).unwrap();
        let first = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "helper")).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(has_calls_edge(&graph, caller, first));
        let second = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "helper")
            .with("complexity", 99_i64)).unwrap();
        let file = graph.add_node(NodeType::CodeFile, PropertyMap::new().with("name", "file")).unwrap();
        let placeholder = graph.add_node(NodeType::Module, PropertyMap::new().with("name", "module")).unwrap();
        let imported = graph.add_node(NodeType::Function, PropertyMap::new().with("name", "imported")).unwrap();
        graph.add_edge(file, placeholder, codegraph::EdgeType::Imports,
            PropertyMap::new().with("symbols", vec!["imported".to_string()])).unwrap();
        fail.store(true, Ordering::SeqCst);
        assert!(GraphUpdater::resolve_cross_file_imports(&mut graph).is_err());
        assert!(has_calls_edge(&graph, caller, first));
        assert!(!has_calls_edge(&graph, caller, second));
        assert!(graph.get_edges_between(file, imported).unwrap().is_empty());
        fail.store(false, Ordering::SeqCst);
        GraphUpdater::resolve_cross_file_imports(&mut graph).unwrap();
        assert!(!has_calls_edge(&graph, caller, first));
        assert!(has_calls_edge(&graph, caller, second));
        assert_eq!(graph.get_edges_between(file, imported).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn lsp_file_removal_reresolves_calls_and_refreshes_query_index() {
        use codegraph::{NodeType, PropertyMap};
        let mut initial = CodeGraph::in_memory().unwrap();
        let caller = initial.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "caller").with("path", "/candidate/caller.cpp")
            .with("unresolved_calls", vec!["helper".to_string()])).unwrap();
        let fallback = initial.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/candidate/fallback.cpp")).unwrap();
        let removed = initial.add_node(NodeType::Function, PropertyMap::new()
            .with("name", "helper").with("path", "/candidate/removed.cpp")
            .with("complexity", 99_i64)).unwrap();
        GraphUpdater::resolve_cross_file_imports(&mut initial).unwrap();
        assert!(has_calls_edge(&initial, caller, removed));
        let graph = Arc::new(RwLock::new(initial));
        let engine = Arc::new(QueryEngine::new(graph.clone()));
        engine.build_indexes().await;
        let memory = Arc::new(MemoryManager::new(None));
        let symbols = Arc::new(SymbolIndex::new());
        let queue = EmbedQueue::new(engine.clone());
        FileWatcher::handle_file_remove(&graph, &memory, &symbols, &engine, &queue,
            Path::new("/candidate/removed.cpp")).await.unwrap();
        let calls = engine.get_callees(caller, 1).await;
        assert!(calls.iter().any(|call| call.node_id == fallback));
        assert!(!calls.iter().any(|call| call.node_id == removed));
    }

    fn find_function_node(graph: &CodeGraph, name: &str) -> Option<codegraph::NodeId> {
        graph
            .query()
            .node_type(codegraph::NodeType::Function)
            .execute()
            .unwrap_or_default()
            .into_iter()
            .find(|&id| {
                graph
                    .get_node(id)
                    .ok()
                    .map(|n| node_props::name(n) == name)
                    .unwrap_or(false)
            })
    }

    fn count_calls_edges_from(graph: &CodeGraph, node_id: codegraph::NodeId) -> usize {
        use codegraph::{Direction, EdgeType};
        graph
            .get_neighbors(node_id, Direction::Outgoing)
            .unwrap_or_default()
            .iter()
            .filter(|&&nid| {
                graph
                    .get_edges_between(node_id, nid)
                    .unwrap_or_default()
                    .iter()
                    .any(|&eid| {
                        graph
                            .get_edge(eid)
                            .map(|e| e.edge_type == EdgeType::Calls)
                            .unwrap_or(false)
                    })
            })
            .count()
    }

    fn has_calls_edge(graph: &CodeGraph, from: codegraph::NodeId, to: codegraph::NodeId) -> bool {
        use codegraph::EdgeType;
        graph
            .get_edges_between(from, to)
            .unwrap_or_default()
            .iter()
            .any(|&eid| {
                graph
                    .get_edge(eid)
                    .map(|e| e.edge_type == EdgeType::Calls)
                    .unwrap_or(false)
            })
    }
}
