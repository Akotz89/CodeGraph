// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Caller/callee graph traversal — transport-agnostic.
//!
//! Extracts the shared pattern from MCP get_callers/get_callees handlers.

use crate::ai_query::{CallInfo, QueryEngine};
use crate::domain::node_props;
use codegraph::{CodeGraph, NodeId};
use serde::Serialize;
use tokio::sync::RwLock;

// ============================================================
// Response Types
// ============================================================

/// Diagnostic info emitted when no callers/callees are found.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiagnosticInfo {
    pub node_found: bool,
    pub node_id: String,
    pub symbol_name: String,
    pub total_edges_in_graph: usize,
    pub note: String,
}

/// Result of `get_callers`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CallersResult {
    pub callers: Vec<CallInfo>,
    pub symbol_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<DiagnosticInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_message: Option<String>,
}

/// Result of `get_callees`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CalleesResult {
    pub callees: Vec<CallInfo>,
    pub symbol_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<DiagnosticInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_message: Option<String>,
}

// ============================================================
// Domain Functions
// ============================================================

/// Get all callers of a symbol at the given depth.
///
/// Returns `CallersResult` matching the MCP codegraph_get_callers response shape.
pub(crate) async fn get_callers(
    graph: &RwLock<CodeGraph>,
    query_engine: &QueryEngine,
    node_id: NodeId,
    depth: u32,
    used_fallback: bool,
    requested_line: Option<u32>,
) -> CallersResult {
    let symbol_name = {
        let g = graph.read().await;
        g.get_node(node_id)
            .ok()
            .map(|n| node_props::name(n).to_string())
            .unwrap_or_default()
    };

    // Node IDs identify individual definitions, including copies in separate
    // workspaces. A same-name definition is not evidence for this node.
    let result = query_engine.get_callers(node_id, depth).await;

    let diagnostic = if result.is_empty() {
        let edge_count = {
            let g = graph.read().await;
            g.edge_count()
        };
        Some(DiagnosticInfo {
            node_found: true,
            node_id: node_id.to_string(),
            symbol_name: symbol_name.clone(),
            total_edges_in_graph: edge_count,
            note: "No callers found. This may indicate: (1) the function is not called \
                   anywhere, (2) the language parser doesn't extract call relationships, \
                   or (3) indexes need to be rebuilt."
                .to_string(),
        })
    } else {
        None
    };

    let (used_fallback_field, fallback_message) =
        build_fallback(used_fallback, requested_line, &symbol_name);

    CallersResult {
        callers: result,
        symbol_name,
        diagnostic,
        used_fallback: used_fallback_field,
        fallback_message,
    }
}

/// Get all callees of a symbol at the given depth.
///
/// Returns `CalleesResult` matching the MCP codegraph_get_callees response shape.
pub(crate) async fn get_callees(
    graph: &RwLock<CodeGraph>,
    query_engine: &QueryEngine,
    node_id: NodeId,
    depth: u32,
    used_fallback: bool,
    requested_line: Option<u32>,
) -> CalleesResult {
    let symbol_name = {
        let g = graph.read().await;
        g.get_node(node_id)
            .ok()
            .map(|n| node_props::name(n).to_string())
            .unwrap_or_default()
    };

    let result = query_engine.get_callees(node_id, depth).await;

    let diagnostic = if result.is_empty() {
        let edge_count = {
            let g = graph.read().await;
            g.edge_count()
        };
        Some(DiagnosticInfo {
            node_found: true,
            node_id: node_id.to_string(),
            symbol_name: symbol_name.clone(),
            total_edges_in_graph: edge_count,
            note: "No callees found. This may indicate: (1) the function doesn't call \
                   other functions, (2) the language parser doesn't extract call \
                   relationships, or (3) indexes need to be rebuilt."
                .to_string(),
        })
    } else {
        None
    };

    let (used_fallback_field, fallback_message) =
        build_fallback(used_fallback, requested_line, &symbol_name);

    CalleesResult {
        callees: result,
        symbol_name,
        diagnostic,
        used_fallback: used_fallback_field,
        fallback_message,
    }
}

// ============================================================
// Private Helpers
// ============================================================

fn build_fallback(
    used_fallback: bool,
    requested_line: Option<u32>,
    symbol_name: &str,
) -> (Option<bool>, Option<String>) {
    if used_fallback {
        (
            Some(true),
            Some(format!(
                "No symbol at line {}. Using nearest symbol '{}' instead.",
                requested_line.unwrap_or(0),
                symbol_name
            )),
        )
    } else {
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph::{EdgeType, NodeType, PropertyMap};
    use std::sync::Arc;

    #[tokio::test]
    async fn exact_symbol_does_not_borrow_edges_from_same_named_copy() {
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let (requested, other, caller, callee) = {
            let mut g = graph.write().await;
            let requested = g.add_node(NodeType::Function, PropertyMap::new().with("name", "helper").with("path", "/candidate/helper.cpp")).unwrap();
            let other = g.add_node(NodeType::Function, PropertyMap::new().with("name", "helper").with("path", "/fixture/helper.cpp")).unwrap();
            let caller = g.add_node(NodeType::Function, PropertyMap::new().with("name", "caller")).unwrap();
            let callee = g.add_node(NodeType::Function, PropertyMap::new().with("name", "callee")).unwrap();
            g.add_edge(caller, other, EdgeType::Calls, PropertyMap::new()).unwrap();
            g.add_edge(other, callee, EdgeType::Calls, PropertyMap::new()).unwrap();
            (requested, other, caller, callee)
        };
        let engine = QueryEngine::new(Arc::clone(&graph));
        engine.build_indexes().await;
        assert!(get_callers(&graph, &engine, requested, 1, false, None).await.callers.is_empty());
        assert!(get_callees(&graph, &engine, requested, 1, false, None).await.callees.is_empty());
        assert_eq!(get_callers(&graph, &engine, other, 1, false, None).await.callers[0].node_id, caller);
        assert_eq!(get_callees(&graph, &engine, other, 1, false, None).await.callees[0].node_id, callee);
    }
}
