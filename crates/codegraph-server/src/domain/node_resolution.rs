// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Node resolution — unified find_nearest_node.

use codegraph::{CodeGraph, NodeId};

use crate::domain::node_props;

/// Find the nearest function/symbol node at or near a given line in a file.
///
/// Strategy:
/// 1. Exact containment: find nodes whose line range contains target_line (prefer tightest fit)
/// 2. Fallback: find nearest node by proximity (prefer forward-looking, penalize backward)
///
/// Returns (node_id, used_fallback) where used_fallback is true if no exact containment was found.
pub(crate) fn find_nearest_node(
    graph: &CodeGraph,
    file_path: &str,
    target_line: u32,
) -> Option<(NodeId, bool)> {
    // MCP and LSP lines are zero-based; stored source locations are one-based.
    let target_line = target_line.saturating_add(1);
    // Strategy 1: Exact containment (prefer tightest — smallest range)
    let mut best_exact: Option<(NodeId, u32)> = None; // (id, range_size)

    for (&node_id, node) in graph.nodes_iter() {
        if node_props::path(node) != file_path {
            continue;
        }
        let start = node_props::line_start(node);
        let end = node_props::line_end_opt(node).unwrap_or(start);
        if target_line >= start && target_line <= end {
            let range_size = end.saturating_sub(start);
            if best_exact.is_none() || range_size < best_exact.unwrap().1 {
                best_exact = Some((node_id, range_size));
            }
        }
    }
    if let Some((id, _)) = best_exact {
        return Some((id, false));
    }

    // Strategy 2: Nearest by proximity (prefer forward, penalize backward)
    let mut best_fallback: Option<(NodeId, i64)> = None;
    for (&node_id, node) in graph.nodes_iter() {
        if node_props::path(node) != file_path {
            continue;
        }
        let start = node_props::line_start(node) as i64;
        let end = node_props::line_end_opt(node).unwrap_or(start as u32) as i64;
        let target = target_line as i64;

        let distance = if start > target {
            start - target // Forward — preferred
        } else {
            (target - end) + 1000 // Backward — penalized
        };

        if best_fallback.is_none() || distance < best_fallback.unwrap().1 {
            best_fallback = Some((node_id, distance));
        }
    }

    best_fallback.map(|(id, _)| (id, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph::{NodeType, PropertyMap};

    #[test]
    fn resolves_zero_based_lines_and_single_line_symbols() {
        let mut graph = CodeGraph::in_memory().unwrap();
        let single = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("path", "/test.sql")
            .with("line_start", 23_i64)).unwrap();
        let later = graph.add_node(NodeType::Generic, PropertyMap::new()
            .with("path", "/test.sql")
            .with("line_start", 41_i64)).unwrap();
        assert_eq!(find_nearest_node(&graph, "/test.sql", 22), Some((single, false)));
        assert_eq!(find_nearest_node(&graph, "/test.sql", 40), Some((later, false)));
        assert_eq!(find_nearest_node(&graph, "/test.sql", 23), Some((later, true)));
    }
}
