// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! AutoHotkey v2 structural indexing. Values and source bodies are not stored.
use codegraph::{CodeGraph, EdgeType, NodeId, NodeType, PropertyMap};
use codegraph_parser_api::{CodeParser, FileInfo, ParserConfig, ParserError, ParserMetrics};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::Path,
    sync::Mutex,
    time::Instant,
};

const COVERAGE: &str = "Partial AutoHotkey v2 index: declarations and some unshadowed same-file function calls; member calls, dynamic targets, runtime effects, values and source bodies are not resolved.";

pub(crate) struct AutoHotkeyParser {
    config: ParserConfig,
    metrics: Mutex<ParserMetrics>,
}

impl AutoHotkeyParser {
    pub(crate) fn with_config(config: ParserConfig) -> Self {
        Self {
            config,
            metrics: Mutex::new(ParserMetrics::default()),
        }
    }
}

impl CodeParser for AutoHotkeyParser {
    fn language(&self) -> &str {
        "autohotkey"
    }
    fn file_extensions(&self) -> &[&str] {
        &[".ahk"]
    }
    fn config(&self) -> &ParserConfig {
        &self.config
    }
    fn metrics(&self) -> ParserMetrics {
        self.metrics.lock().unwrap().clone()
    }
    fn reset_metrics(&mut self) {
        *self.metrics.lock().unwrap() = ParserMetrics::default();
    }

    fn parse_file(&self, path: &Path, graph: &mut CodeGraph) -> Result<FileInfo, ParserError> {
        let start = Instant::now();
        let data = (|| {
            let mut file = std::fs::File::open(path)
                .map_err(|e| ParserError::IoError(path.to_path_buf(), e))?;
            let size = file
                .metadata()
                .map_err(|e| ParserError::IoError(path.to_path_buf(), e))?
                .len();
            if size > self.config.max_file_size as u64 {
                return Err(ParserError::FileTooLarge(
                    path.to_path_buf(),
                    usize::try_from(size).unwrap_or(usize::MAX),
                ));
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take((self.config.max_file_size as u64).saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|e| ParserError::IoError(path.to_path_buf(), e))?;
            if bytes.len() > self.config.max_file_size {
                return Err(ParserError::FileTooLarge(path.to_path_buf(), bytes.len()));
            }
            String::from_utf8(bytes).map_err(|e| {
                ParserError::IoError(
                    path.to_path_buf(),
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                )
            })
        })();
        let result = data.and_then(|source| self.parse_source(&source, path, graph));
        let mut metrics = self.metrics.lock().unwrap();
        metrics.files_attempted += 1;
        metrics.total_parse_time += start.elapsed();
        match &result {
            Ok(info) => {
                metrics.files_succeeded += 1;
                metrics.total_entities += info.entity_count();
            }
            Err(_) => metrics.files_failed += 1,
        }
        result
    }

    fn parse_source(
        &self,
        source: &str,
        path: &Path,
        graph: &mut CodeGraph,
    ) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size {
            return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len()));
        }
        let start = Instant::now();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_autohotkey::LANGUAGE.into())
            .map_err(|e| ParserError::ParseError(path.to_path_buf(), e.to_string()))?;
        let tree = parser.parse(source, None).ok_or_else(|| {
            ParserError::ParseError(path.to_path_buf(), "AutoHotkey parser failed".into())
        })?;
        if tree.root_node().has_error() {
            return Err(ParserError::ParseError(
                path.to_path_buf(),
                "AutoHotkey syntax tree contains errors".into(),
            ));
        }
        let error = |e: codegraph::GraphError| ParserError::GraphError(e.to_string());
        let file = graph
            .add_node(
                NodeType::CodeFile,
                PropertyMap::new()
                    .with(
                        "name",
                        path.file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("<script>"),
                    )
                    .with("path", path.to_string_lossy().to_string())
                    .with("language", "autohotkey")
                    .with("coverage", "partial")
                    .with("coverage_diagnostic", COVERAGE),
            )
            .map_err(error)?;
        let mut functions = Vec::new();
        let mut classes = Vec::new();
        let mut definitions: HashMap<(NodeId, String), Vec<NodeId>> = HashMap::new();
        let mut scopes: HashMap<NodeId, (NodeId, HashSet<String>)> = HashMap::new();
        let mut calls = Vec::new();
        let mut shadowed = HashSet::new();
        // Collect bindings in one lexical scope. Nested bodies belong to their own
        // scopes, while their names can shadow globals in the enclosing scope.
        fn identifiers(node: tree_sitter::Node, source: &str, out: &mut HashSet<String>) {
            if node.kind() == "identifier" {
                if let Ok(name) = node.utf8_text(source.as_bytes()) {
                    out.insert(name.to_ascii_lowercase());
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                identifiers(child, source, out);
            }
        }
        fn parameter_names(node: tree_sitter::Node, source: &str, out: &mut HashSet<String>) {
            match node.kind() {
                "identifier" => identifiers(node, source, out),
                "default_param" | "optional_param" | "variadic_param" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        identifiers(name, source, out);
                    }
                }
                "param_sequence" | "byref_param" => {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        parameter_names(child, source, out);
                    }
                }
                _ => {}
            }
        }
        fn bindings(node: tree_sitter::Node, source: &str, out: &mut HashSet<String>, root: bool) {
            if !root
                && matches!(
                    node.kind(),
                    "function_declaration"
                        | "method_declaration"
                        | "class_declaration"
                        | "function_expression"
                        | "fat_arrow_function"
                )
            {
                if node.kind() != "function_declaration" {
                    if let Some(name) = node.child_by_field_name("name") {
                        identifiers(name, source, out);
                    }
                }
                return;
            }
            match node.kind() {
                "fat_arrow_function" => {
                    if let Some(head) = node
                        .child_by_field_name("head")
                        .filter(|n| n.kind() == "identifier")
                    {
                        identifiers(head, source, out);
                    }
                }
                "assignment_operation" => {
                    if let Some(left) = node
                        .child_by_field_name("left")
                        .filter(|n| n.kind() == "identifier")
                    {
                        identifiers(left, source, out);
                    }
                }
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        identifiers(name, source, out);
                    }
                }
                "param_sequence" => parameter_names(node, source, out),
                "for_statement" => {
                    let mut cursor = node.walk();
                    for iterator in node.children_by_field_name("iterator", &mut cursor) {
                        identifiers(iterator, source, out);
                    }
                }
                "catch_clause" => {
                    if let Some(variable) = node.child_by_field_name("variable") {
                        identifiers(variable, source, out);
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                bindings(child, source, out, false);
            }
        }
        let mut root_cursor = tree.root_node().walk();
        for child in tree.root_node().named_children(&mut root_cursor) {
            if !matches!(child.kind(), "function_declaration" | "class_declaration") {
                bindings(child, source, &mut shadowed, true);
            }
        }
        scopes.insert(file, (file, shadowed));
        fn collect(
            node: tree_sitter::Node,
            source: &str,
            path: &Path,
            graph: &mut CodeGraph,
            parent: NodeId,
            file: NodeId,
            active_function: Option<NodeId>,
            functions: &mut Vec<NodeId>,
            classes: &mut Vec<NodeId>,
            definitions: &mut HashMap<(NodeId, String), Vec<NodeId>>,
            calls: &mut Vec<(NodeId, String)>,
            scopes: &mut HashMap<NodeId, (NodeId, HashSet<String>)>,
        ) -> Result<(), ParserError> {
            let mut owner = parent;
            let mut active = active_function;
            let kind = match node.kind() {
                "function_declaration"
                | "method_declaration"
                | "function_expression"
                | "fat_arrow_function" => Some(NodeType::Function),
                "class_declaration" => Some(NodeType::Class),
                _ => None,
            };
            if let Some(kind) = kind {
                if node.child_by_field_name("name").is_some()
                    || matches!(node.kind(), "function_expression" | "fat_arrow_function")
                {
                    let name = match node.child_by_field_name("name") {
                        Some(name_node) => name_node
                            .utf8_text(source.as_bytes())
                            .map_err(|e| {
                                ParserError::ParseError(path.to_path_buf(), e.to_string())
                            })?
                            .to_string(),
                        None => format!(
                            "<anonymous@{}:{}>",
                            node.start_position().row + 1,
                            node.start_position().column + 1
                        ),
                    };
                    let id = graph
                        .add_node(
                            kind,
                            PropertyMap::new()
                                .with("name", name.as_str())
                                .with("path", path.to_string_lossy().to_string())
                                .with("language", "autohotkey")
                                .with("line_start", (node.start_position().row + 1) as i64)
                                .with("line_end", (node.end_position().row + 1) as i64)
                                .with("coverage", "partial")
                                .with("coverage_diagnostic", COVERAGE),
                        )
                        .map_err(|e| ParserError::GraphError(e.to_string()))?;
                    graph
                        .add_edge(parent, id, EdgeType::Contains, PropertyMap::new())
                        .map_err(|e| ParserError::GraphError(e.to_string()))?;
                    if kind == NodeType::Function {
                        functions.push(id);
                        if node.kind() == "function_declaration" {
                            definitions
                                .entry((active_function.unwrap_or(file), name.to_ascii_lowercase()))
                                .or_default()
                                .push(id);
                        }
                        let mut local = HashSet::new();
                        bindings(node, source, &mut local, true);
                        scopes.insert(id, (active_function.unwrap_or(file), local));
                        active = Some(id);
                    } else {
                        classes.push(id);
                        active = None;
                    }
                    owner = id;
                }
            } else if matches!(node.kind(), "function_call" | "call_statement") {
                if let Some(name) = node
                    .child_by_field_name("function")
                    .filter(|n| n.kind() == "identifier")
                {
                    if let (Some(caller), Ok(text)) = (active, name.utf8_text(source.as_bytes())) {
                        calls.push((caller, text.to_ascii_lowercase()));
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect(
                    child,
                    source,
                    path,
                    graph,
                    owner,
                    file,
                    active,
                    functions,
                    classes,
                    definitions,
                    calls,
                    scopes,
                )?;
            }
            Ok(())
        }
        collect(
            tree.root_node(),
            source,
            path,
            graph,
            file,
            file,
            None,
            &mut functions,
            &mut classes,
            &mut definitions,
            &mut calls,
            &mut scopes,
        )?;
        for (caller, name) in calls {
            let mut scope = caller;
            while let Some((parent_scope, local)) = scopes.get(&scope) {
                if local.contains(&name) {
                    break;
                }
                if let Some(ids) = definitions.get(&(scope, name.clone())) {
                    if ids.len() == 1 {
                        graph
                            .add_edge(caller, ids[0], EdgeType::Calls, PropertyMap::new())
                            .map_err(|e| ParserError::GraphError(e.to_string()))?;
                    }
                    break;
                }
                if *parent_scope == scope {
                    break;
                }
                scope = *parent_scope;
            }
        }
        Ok(FileInfo {
            file_path: path.to_path_buf(),
            file_id: file,
            functions,
            classes,
            traits: Vec::new(),
            imports: Vec::new(),
            parse_time: start.elapsed(),
            line_count: source.lines().count(),
            byte_count: source.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_functions_and_local_calls_without_values() {
        let source = "Caller() {\n secret := \"SYNTHETIC_PRIVATE_VALUE_7821\"\n helper()\n}\nHelper() {\n return 1\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        let info = parser
            .parse_source(source, Path::new("example.ahk"), &mut graph)
            .unwrap();
        assert_eq!(info.functions.len(), 2);
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            1
        );
        assert!(graph
            .iter_nodes()
            .all(|(_, node)| !format!("{:?}", node.properties)
                .contains("SYNTHETIC_PRIVATE_VALUE_7821")));
    }

    #[test]
    fn rejects_syntax_errors_without_indexing() {
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        assert!(parser
            .parse_source("Broken( {", Path::new("broken.ahk"), &mut graph)
            .is_err());
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn indexes_methods_and_statement_calls_without_file_call_edges() {
        let source = "Helper(\"top\")\nclass C {\n Method() {\n Helper \"arg\"\n }\n}\nHelper(x) {\n return x\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        let info = parser
            .parse_source(source, Path::new("example.ahk"), &mut graph)
            .unwrap();
        assert_eq!(info.classes.len(), 1);
        assert_eq!(info.functions.len(), 2);
        let method = graph
            .iter_nodes()
            .find(|(_, n)| n.properties.get_string("name") == Some("Method"))
            .unwrap()
            .0;
        assert!(graph
            .iter_edges()
            .any(|(_, e)| e.source_id == info.classes[0]
                && e.target_id == method
                && e.edge_type == EdgeType::Contains));
        let calls: Vec<_> = graph
            .iter_edges()
            .filter(|(_, e)| e.edge_type == EdgeType::Calls)
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.source_id, method);
    }

    #[test]
    fn rejects_oversized_file_before_indexing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.ahk");
        std::fs::write(&path, "x".repeat(32)).unwrap();
        let config = ParserConfig {
            max_file_size: 4,
            ..ParserConfig::default()
        };
        let parser = AutoHotkeyParser::with_config(config);
        let mut graph = CodeGraph::in_memory().unwrap();
        assert!(matches!(
            parser.parse_file(&path, &mut graph),
            Err(ParserError::FileTooLarge(_, _))
        ));
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn does_not_resolve_ambiguous_case_insensitive_names() {
        let source = "Caller() {\n helper()\n}\nHelper() {\n}\nhelper() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("duplicate.ahk"), &mut graph)
            .unwrap();
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            0
        );
    }

    #[test]
    fn does_not_link_shadowed_nested_function_to_global() {
        let source = "Outer() {\n Inner() {\n }\n Inner()\n}\nInner() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("shadow.ahk"), &mut graph)
            .unwrap();
        let inner = graph
            .iter_nodes()
            .find(|(_, node)| {
                node.properties.get_string("name") == Some("Inner")
                    && node.properties.get_int("line_start") == Some(2)
            })
            .unwrap()
            .0;
        let calls: Vec<_> = graph
            .iter_edges()
            .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.target_id, inner);
    }

    #[test]
    fn does_not_link_shadowed_variable_or_parameter_to_global() {
        let source = "Caller(Target) {\n Target()\n}\nOther() {\n Target := Func(\"elsewhere\")\n Target()\n}\nTarget() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("shadow.ahk"), &mut graph)
            .unwrap();
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            0
        );
    }

    #[test]
    fn resolves_loop_calls_and_unrelated_function_scopes() {
        let source = "Shadowed(Helper) {\n Helper()\n}\nCaller() {\n for item in items {\n Helper()\n }\n}\nHelper() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("scopes.ahk"), &mut graph)
            .unwrap();
        let caller = graph
            .iter_nodes()
            .find(|(_, n)| n.properties.get_string("name") == Some("Caller"))
            .unwrap()
            .0;
        let calls: Vec<_> = graph
            .iter_edges()
            .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.source_id, caller);
    }

    #[test]
    fn anonymous_function_owns_its_calls() {
        let source = "Caller() {\n cb := (*) => Helper()\n}\nHelper() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("lambda.ahk"), &mut graph)
            .unwrap();
        let lambda = graph
            .iter_nodes()
            .find(|(_, n)| {
                n.properties
                    .get_string("name")
                    .is_some_and(|name| name.starts_with("<anonymous@"))
            })
            .unwrap()
            .0;
        let calls: Vec<_> = graph
            .iter_edges()
            .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.source_id, lambda);
    }

    #[test]
    fn anonymous_parameter_shadows_global() {
        let source = "Caller() {\n cb := Helper => Helper()\n}\nHelper() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("lambda.ahk"), &mut graph)
            .unwrap();
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            0
        );
    }

    #[test]
    fn resolves_calls_in_default_parameters_and_indexed_assignments() {
        let source = "Caller(x := Helper()) {\n items[GetIndex()] := 1\n}\nHelper() {\n}\nGetIndex() {\n return 1\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("expressions.ahk"), &mut graph)
            .unwrap();
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            2
        );
    }

    #[test]
    fn second_loop_iterator_shadows_global_call_target() {
        let source = "Caller() {\n for key, Target in items {\n Target()\n }\n}\nTarget() {\n}\n";
        let mut graph = CodeGraph::in_memory().unwrap();
        let parser = AutoHotkeyParser::with_config(ParserConfig::default());
        parser
            .parse_source(source, Path::new("loop.ahk"), &mut graph)
            .unwrap();
        assert_eq!(
            graph
                .iter_edges()
                .filter(|(_, edge)| edge.edge_type == EdgeType::Calls)
                .count(),
            0
        );
    }
}
