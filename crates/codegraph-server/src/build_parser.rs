// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Small source-location reader for CMake build commands and Bats test cases.
//!
//! shortcut: command extraction is static and partial; it does not evaluate
//! CMake variables, conditions, functions, generator expressions, or shell.

use codegraph::{CodeGraph, EdgeType, NodeId, NodeType, PropertyMap};
use codegraph_parser_api::{CodeParser, FileInfo, ParserConfig, ParserError, ParserMetrics};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

const BUILD_EXTENSIONS: &[&str] = &[".cmake", ".bats", ".bat", ".html", ".am", ".ac", ".rc", ".json", ".conf", ".dist"];
const CMAKE_COVERAGE: &str = "Partial lexical CMake index: commands are source-located; full syntax validation, other command semantics, variable expansion, conditions, macro/function execution, generator expressions, and toolchain resolution are not modeled.";
const BATS_COVERAGE: &str = "Bats test declarations are indexed; shell execution, setup/teardown effects, and dynamic test generation are not modeled.";
const BATCH_COVERAGE: &str = "Batch labels and literal program references are indexed; command execution, expansion, control flow, and dynamic paths are not modeled.";
const HTML_COVERAGE: &str = "Literal script and link targets are indexed; HTML validation, DOM behavior, dynamic URLs, and inline script semantics are not modeled.";
const LEGACY_BUILD_COVERAGE: &str = "Static legacy build declarations are indexed; variable values, macro execution, preprocessing and build effects are not modeled.";
const JSON_COVERAGE: &str = "Selected JSON/JSON-lines field names only; values, arbitrary keys, array positions, source lines, and runtime effects are not modeled.";
const CONFIG_COVERAGE: &str = "Static non-sensitive option names only; option values, sensitive names, overrides and runtime effects are not modeled.";

pub(crate) struct BuildParser {
    config: ParserConfig,
    metrics: Mutex<ParserMetrics>,
}

impl BuildParser {
    pub(crate) fn with_config(config: ParserConfig) -> Self {
        Self {
            config,
            metrics: Mutex::new(ParserMetrics::default()),
        }
    }

    fn parse_cmake(
        &self,
        source: &str,
        path: &Path,
        graph: &mut CodeGraph,
    ) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size {
            return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len()));
        }
        let start = Instant::now();
        let file_id = add_file_node(graph, path, "cmake", source, CMAKE_COVERAGE)?;
        let mut classes = Vec::new();
        let mut definitions = std::collections::HashMap::<String, NodeId>::new();

        for command in cmake_commands(source) {
            let line_start = line_at(source, command.start);
            let line_end = line_at(source, command.end);
            let arguments = cmake_arguments(command.arguments);
            let command_id = graph
                .add_node(
                    NodeType::Generic,
                    PropertyMap::new()
                        .with("name", format!("cmake.{}@{}", command.name, line_start))
                        .with("path", path.to_string_lossy().to_string())
                        .with("language", "cmake")
                        .with("symbol_kind", "build_command")
                        .with("command", command.name.as_str())
                        .with("line_start", line_start as i64)
                        .with("line_end", line_end as i64)
                        .with("coverage", "partial")
                        .with("coverage_diagnostic", CMAKE_COVERAGE),
                )
                .map_err(graph_error)?;
            graph
                .add_edge(file_id, command_id, EdgeType::Contains, PropertyMap::new())
                .map_err(graph_error)?;

            match command.name.as_str() {
                "project" | "add_library" | "add_executable" | "add_custom_target" => {
                    if let Some(name) = arguments.first().and_then(|arg| safe_target(arg)) {
                        let target_kind = if command.name == "project" {
                            "project"
                        } else {
                            command.name.strip_prefix("add_").unwrap_or("target")
                        };
                        let target_id = graph
                            .add_node(
                                NodeType::Module,
                                PropertyMap::new()
                                    .with("name", name)
                                    .with("path", path.to_string_lossy().to_string())
                                    .with("language", "cmake")
                                    .with("symbol_kind", "build_target")
                                    .with("target_kind", target_kind)
                                    .with("line_start", line_start as i64)
                                    .with("line_end", line_end as i64)
                                    .with("coverage", "partial")
                                    .with("coverage_diagnostic", CMAKE_COVERAGE),
                            )
                            .map_err(graph_error)?;
                        graph
                            .add_edge(command_id, target_id, EdgeType::Defines, PropertyMap::new())
                            .map_err(graph_error)?;
                        graph
                            .add_edge(file_id, target_id, EdgeType::Contains, PropertyMap::new())
                            .map_err(graph_error)?;
                        definitions.insert(name.to_string(), target_id);
                        classes.push(target_id);
                    }
                }
                "add_subdirectory" | "include" | "find_package" => {
                    if let Some(reference) = arguments.first().and_then(|arg| safe_reference(arg)) {
                        let reference_id = add_reference(
                            graph,
                            path,
                            &command.name,
                            reference,
                            line_start,
                            line_end,
                            CMAKE_COVERAGE,
                        )?;
                        graph
                            .add_edge(
                                command_id,
                                reference_id,
                                EdgeType::References,
                                PropertyMap::new().with("relation", command.name.as_str()),
                            )
                            .map_err(graph_error)?;
                    }
                }
                "target_sources" | "target_link_libraries" => {
                    let Some(target) = arguments.first().and_then(|arg| safe_target(arg)) else {
                        continue;
                    };
                    let dependencies = arguments.iter().skip(1).filter_map(|arg| {
                        if matches!(
                            arg.to_ascii_uppercase().as_str(),
                            "PRIVATE"
                                | "PUBLIC"
                                | "INTERFACE"
                                | "BEFORE"
                                | "AFTER"
                                | "SYSTEM"
                                | "DEBUG"
                                | "OPTIMIZED"
                                | "GENERAL"
                        ) {
                            None
                        } else {
                            safe_reference(arg)
                        }
                    });
                    for dependency in dependencies {
                        let reference_id = add_reference(
                            graph,
                            path,
                            &command.name,
                            dependency,
                            line_start,
                            line_end,
                            CMAKE_COVERAGE,
                        )?;
                        graph
                            .add_edge(
                                command_id,
                                reference_id,
                                EdgeType::References,
                                PropertyMap::new()
                                    .with("relation", command.name.as_str())
                                    .with("target", target),
                            )
                            .map_err(graph_error)?;
                        if let Some(target_id) = definitions.get(target) {
                            graph
                                .add_edge(
                                    *target_id,
                                    reference_id,
                                    EdgeType::Uses,
                                    PropertyMap::new().with("relation", command.name.as_str()),
                                )
                                .map_err(graph_error)?;
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(FileInfo {
            file_path: path.to_path_buf(),
            file_id,
            functions: Vec::new(),
            classes,
            traits: Vec::new(),
            imports: Vec::new(),
            parse_time: start.elapsed(),
            line_count: source.lines().count(),
            byte_count: source.len(),
        })
    }

    fn parse_bats(
        &self,
        source: &str,
        path: &Path,
        graph: &mut CodeGraph,
    ) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size {
            return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len()));
        }
        let start = Instant::now();
        let file_id = add_file_node(graph, path, "bats", source, BATS_COVERAGE)?;
        let mut functions = Vec::new();
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            let Some(description) = bats_description(trimmed) else {
                continue;
            };
            let name = sanitize_test_name(description);
            let line_number = index + 1;
            let test_id = graph
                .add_node(
                    NodeType::Function,
                    PropertyMap::new()
                        .with("name", name)
                        .with("path", path.to_string_lossy().to_string())
                        .with("language", "bats")
                        .with("signature", "@test")
                        .with("is_test", true)
                        .with("line_start", line_number as i64)
                        .with("line_end", line_number as i64)
                        .with("coverage", "partial")
                        .with("coverage_diagnostic", BATS_COVERAGE),
                )
                .map_err(graph_error)?;
            graph
                .add_edge(file_id, test_id, EdgeType::Contains, PropertyMap::new())
                .map_err(graph_error)?;
            functions.push(test_id);
        }
        Ok(FileInfo {
            file_path: path.to_path_buf(),
            file_id,
            functions,
            classes: Vec::new(),
            traits: Vec::new(),
            imports: Vec::new(),
            parse_time: start.elapsed(),
            line_count: source.lines().count(),
            byte_count: source.len(),
        })
    }

    fn parse_references(&self, source: &str, path: &Path, graph: &mut CodeGraph, language: &str) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size { return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len())); }
        let start = Instant::now();
        let diagnostic = match language { "html" => HTML_COVERAGE, "batch" => BATCH_COVERAGE, _ => LEGACY_BUILD_COVERAGE };
        let file_id = add_file_node(graph, path, language, source, diagnostic)?;
        let label = regex::Regex::new(r"^:([A-Za-z_][A-Za-z0-9_-]*)\s*$").unwrap();
        let batch_ref = regex::Regex::new(r"(?i)(?:^|\s)([A-Za-z0-9_.-]+\.(?:exe|bat|py))(?:\s|$)").unwrap();
        let html_ref = regex::Regex::new(r#"(?i)<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*[\"']([^\"'<>\s]+)[\"'][^>]*>"#).unwrap();
        let assignment = regex::Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+|:|\?)?=").unwrap();
        let macro_name = regex::Regex::new(r"^((?:AC|AM|LT)_[A-Z0-9_]+)(?:\s*\(|\s*$)").unwrap();
        let include = regex::Regex::new(r#"^#\s*include\s*[\"<]([A-Za-z0-9_./-]+)[\">]"#).unwrap();
        let mut functions = Vec::new();
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if language == "batch" && (trimmed.starts_with("::") || trimmed.to_ascii_lowercase().starts_with("rem ")) { continue; }
            let mut entities = Vec::new();
            if language == "batch" {
                if let Some(c) = label.captures(trimmed) { entities.push((c[1].to_string(), "batch_label", NodeType::Function)); }
                for c in batch_ref.captures_iter(trimmed) { entities.push((c[1].to_string(), "batch_program_reference", NodeType::Generic)); }
            } else if language == "html" {
                for c in html_ref.captures_iter(line) { entities.push((c[1].to_string(), "html_resource_reference", NodeType::Generic)); }
            } else if language == "automake" || language == "makefile" {
                if let Some(c) = assignment.captures(trimmed) { entities.push((c[1].to_string(), "automake_variable", NodeType::Generic)); }
            } else if language == "autoconf" {
                if let Some(c) = macro_name.captures(trimmed) { entities.push((c[1].to_string(), "autoconf_macro", NodeType::Generic)); }
            } else if let Some(c) = include.captures(trimmed) {
                entities.push((c[1].to_string(), "resource_include", NodeType::Generic));
            }
            for (name, kind, node_type) in entities {
                // Keep only static identifiers and relative/local URLs, never query strings or credentials.
                if name.contains(['?', '#', '@', '%', '$']) || name.contains("://") { continue; }
                let id = graph.add_node(node_type, PropertyMap::new().with("name", name).with("path", path.to_string_lossy().to_string())
                    .with("language", language).with("symbol_kind", kind).with("line_start", (index + 1) as i64)
                    .with("line_end", (index + 1) as i64).with("coverage", "partial").with("coverage_diagnostic", diagnostic)).map_err(graph_error)?;
                graph.add_edge(file_id, id, EdgeType::Contains, PropertyMap::new()).map_err(graph_error)?;
                if kind == "batch_label" { functions.push(id); }
            }
        }
        Ok(FileInfo { file_path: path.to_path_buf(), file_id, functions, classes: Vec::new(), traits: Vec::new(), imports: Vec::new(), parse_time: start.elapsed(), line_count: source.lines().count(), byte_count: source.len() })
    }

    fn parse_json_fields(&self, source: &str, path: &Path, graph: &mut CodeGraph) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size { return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len())); }
        let start = Instant::now();
        let normalized = strip_json_comments(source).ok_or_else(|| ParserError::ParseError(path.to_path_buf(), "unterminated JSON comment".to_string()))?;
        let values = match serde_json::from_slice::<serde_json::Value>(&normalized) {
            Ok(value) => vec![value],
            Err(_) => {
                let stream = serde_json::Deserializer::from_slice(&normalized).into_iter::<serde_json::Value>();
                let values: Vec<_> = stream.collect::<Result<_, _>>().map_err(|e| ParserError::SyntaxError(path.to_path_buf(), e.line(), e.column(), "invalid JSON or JSON lines with comments".to_string()))?;
                if values.is_empty() && !source.trim_start().starts_with('#') {
                    return Err(ParserError::ParseError(path.to_path_buf(), "empty JSON input".to_string()));
                }
                values
            }
        };
        let file_id = add_file_node(graph, path, "json", source, JSON_COVERAGE)?;
        // Whitelist field names; never retain arbitrary keys or any JSON values.
        const FIELDS: &[&str] = &["name", "version", "description", "type", "schema", "scripts", "dependencies", "devDependencies", "peerDependencies", "engines", "compilerOptions", "include", "exclude", "files", "scenarios", "scenario", "actions", "events", "conditions", "steps", "actors", "roles", "map", "route", "position", "targets", "expected", "settings", "config"];
        let mut stack: Vec<_> = values.iter().map(|value| (value, 0usize)).collect();
        let mut seen = std::collections::HashSet::new();
        while let Some((current, depth)) = stack.pop() {
            if depth >= 64 { continue; }
            match current {
                serde_json::Value::Object(fields) => for (key, child) in fields {
                    if FIELDS.contains(&key.as_str()) && seen.insert(key.clone()) {
                        let id = graph.add_node(NodeType::Generic, PropertyMap::new().with("name", key.as_str()).with("path", path.to_string_lossy().to_string()).with("language", "json").with("symbol_kind", "json_field").with("coverage", "partial").with("coverage_diagnostic", JSON_COVERAGE)).map_err(graph_error)?;
                        graph.add_edge(file_id, id, EdgeType::Contains, PropertyMap::new()).map_err(graph_error)?;
                    }
                    stack.push((child, depth + 1));
                },
                serde_json::Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
                _ => {}
            }
        }
        Ok(FileInfo { file_path: path.to_path_buf(), file_id, functions: Vec::new(), classes: Vec::new(), traits: Vec::new(), imports: Vec::new(), parse_time: start.elapsed(), line_count: source.lines().count(), byte_count: source.len() })
    }

    fn parse_config_options(&self, source: &str, path: &Path, graph: &mut CodeGraph) -> Result<FileInfo, ParserError> {
        if source.len() > self.config.max_file_size { return Err(ParserError::FileTooLarge(path.to_path_buf(), source.len())); }
        let start = Instant::now();
        let file_id = add_file_node(graph, path, "config", source, CONFIG_COVERAGE)?;
        let assignment = regex::Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_.-]{0,127})\s*=").unwrap();
        let sensitive = regex::Regex::new(r"(?i)(password|passwd|secret|token|credential|api.?key|private.?key)").unwrap();
        for (index, line) in source.lines().enumerate() {
            let Some(c) = assignment.captures(line) else { continue; };
            let name = &c[1];
            if sensitive.is_match(name) { continue; }
            let id = graph.add_node(NodeType::Generic, PropertyMap::new().with("name", name).with("path", path.to_string_lossy().to_string()).with("language", "config").with("symbol_kind", "config_option").with("line_start", (index + 1) as i64).with("line_end", (index + 1) as i64).with("coverage", "partial").with("coverage_diagnostic", CONFIG_COVERAGE)).map_err(graph_error)?;
            graph.add_edge(file_id, id, EdgeType::Contains, PropertyMap::new()).map_err(graph_error)?;
        }
        Ok(FileInfo { file_path: path.to_path_buf(), file_id, functions: Vec::new(), classes: Vec::new(), traits: Vec::new(), imports: Vec::new(), parse_time: start.elapsed(), line_count: source.lines().count(), byte_count: source.len() })
    }

    fn record(&self, success: bool, elapsed: std::time::Duration, entities: usize, edges: usize) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.files_attempted += 1;
            if success {
                metrics.files_succeeded += 1;
                metrics.total_entities += entities;
                metrics.total_relationships += edges;
            } else {
                metrics.files_failed += 1;
            }
            metrics.total_parse_time += elapsed;
        }
    }
}

impl CodeParser for BuildParser {
    fn language(&self) -> &str {
        "build"
    }

    fn file_extensions(&self) -> &[&str] {
        BUILD_EXTENSIONS
    }

    fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .is_some_and(|name| name == "CMakeLists.txt")
            || path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "cmake" | "bats" | "bat" | "html" | "am" | "rc") || (ext == "json" && !path.file_name().is_some_and(|n| n == "package-lock.json" || n == "npm-shrinkwrap.json")))
            || path.file_name().is_some_and(|name| name == "configure.ac" || name == "Makefile")
            || path.extension().is_some_and(|ext| ext == "conf")
            || path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.ends_with(".conf.dist"))
    }

    fn parse_file(&self, path: &Path, graph: &mut CodeGraph) -> Result<FileInfo, ParserError> {
        let start = Instant::now();
        let metadata = std::fs::metadata(path)
            .map_err(|error| ParserError::IoError(path.to_path_buf(), error))?;
        if metadata.len() > self.config.max_file_size as u64 {
            return Err(ParserError::FileTooLarge(
                path.to_path_buf(),
                usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            ));
        }
        let before_nodes = graph.node_count();
        let before_edges = graph.edge_count();
        let source = std::fs::read_to_string(path)
            .map_err(|error| ParserError::IoError(path.to_path_buf(), error))?;
        let result = self.parse_source(&source, path, graph);
        self.record(
            result.is_ok(),
            start.elapsed(),
            graph.node_count().saturating_sub(before_nodes),
            graph.edge_count().saturating_sub(before_edges),
        );
        result
    }

    fn parse_source(
        &self,
        source: &str,
        file_path: &Path,
        graph: &mut CodeGraph,
    ) -> Result<FileInfo, ParserError> {
        if is_cmake(file_path) {
            self.parse_cmake(source, file_path, graph)
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("bats") {
            self.parse_bats(source, file_path, graph)
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("bat") {
            self.parse_references(source, file_path, graph, "batch")
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("html") {
            self.parse_references(source, file_path, graph, "html")
        } else if file_path.file_name().is_some_and(|name| name == "configure.ac") {
            self.parse_references(source, file_path, graph, "autoconf")
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("am") {
            self.parse_references(source, file_path, graph, "automake")
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("rc") {
            self.parse_references(source, file_path, graph, "winresource")
        } else if file_path.extension().and_then(|ext| ext.to_str()) == Some("json") && self.can_parse(file_path) {
            self.parse_json_fields(source, file_path, graph)
        } else if file_path.extension().is_some_and(|ext| ext == "conf") || file_path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".conf.dist")) {
            self.parse_config_options(source, file_path, graph)
        } else if crate::parser_registry::extensionless_source_kind(file_path) == Some("makefile") {
            self.parse_references(source, file_path, graph, "makefile")
        } else {
            Err(ParserError::UnsupportedFeature(
                file_path.to_path_buf(),
                "unsupported build-file type".to_string(),
            ))
        }
    }

    fn config(&self) -> &ParserConfig {
        &self.config
    }

    fn metrics(&self) -> ParserMetrics {
        self.metrics
            .lock()
            .map(|metrics| metrics.clone())
            .unwrap_or_default()
    }

    fn reset_metrics(&mut self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            *metrics = ParserMetrics::default();
        }
    }
}

fn is_cmake(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "CMakeLists.txt")
        || path.extension().and_then(|ext| ext.to_str()) == Some("cmake")
}

fn add_file_node(
    graph: &mut CodeGraph,
    path: &Path,
    language: &str,
    source: &str,
    diagnostic: &str,
) -> Result<NodeId, ParserError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<build-file>");
    graph
        .add_node(
            NodeType::CodeFile,
            PropertyMap::new()
                .with("name", name)
                .with("path", path.to_string_lossy().to_string())
                .with("language", language)
                .with("coverage", "partial")
                .with("coverage_diagnostic", diagnostic)
                .with("line_count", source.lines().count() as i64),
        )
        .map_err(graph_error)
}

fn add_reference(
    graph: &mut CodeGraph,
    path: &Path,
    command: &str,
    reference: &str,
    line_start: usize,
    line_end: usize,
    diagnostic: &str,
) -> Result<NodeId, ParserError> {
    graph
        .add_node(
            NodeType::Generic,
            PropertyMap::new()
                .with("name", reference)
                .with("path", path.to_string_lossy().to_string())
                .with("language", "cmake")
                .with("symbol_kind", "build_reference")
                .with("command", command)
                .with("line_start", line_start as i64)
                .with("line_end", line_end as i64)
                .with("resolution", "unresolved")
                .with("coverage", "partial")
                .with("coverage_diagnostic", diagnostic),
        )
        .map_err(graph_error)
}

fn graph_error(error: impl std::fmt::Display) -> ParserError {
    ParserError::GraphError(error.to_string())
}

/// Remove line and block comments without touching quoted strings or line positions.
fn strip_json_comments(source: &str) -> Option<Vec<u8>> {
    let mut out = source.as_bytes().to_vec();
    let (mut i, mut quoted, mut escaped) = (0, false, false);
    while i < out.len() {
        let b = out[i];
        if quoted {
            if escaped { escaped = false; } else if b == b'\\' { escaped = true; } else if b == b'"' { quoted = false; }
            i += 1; continue;
        }
        if b == b'"' { quoted = true; i += 1; continue; }
        if b == b'#' || (b == b'/' && out.get(i + 1) == Some(&b'/')) {
            while i < out.len() && out[i] != b'\n' { out[i] = b' '; i += 1; }
        } else if b == b'/' && out.get(i + 1) == Some(&b'*') {
            out[i] = b' '; out[i + 1] = b' '; i += 2;
            let mut closed = false;
            while i < out.len() {
                if out[i] == b'*' && out.get(i + 1) == Some(&b'/') { out[i] = b' '; out[i + 1] = b' '; i += 2; closed = true; break; }
                if out[i] != b'\n' { out[i] = b' '; } i += 1;
            }
            if !closed { return None; }
        } else { i += 1; }
    }
    Some(out)
}

fn safe_target(value: &str) -> Option<&str> {
    let lower = value.to_ascii_lowercase();
    (!value.starts_with('$')
        && !value.is_empty()
        && ![
            "secret",
            "password",
            "credential",
            "token",
            "private",
            ".env",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-:".contains(&byte)))
    .then_some(value)
}

fn safe_reference(value: &str) -> Option<&str> {
    let lower = value.to_ascii_lowercase();
    (!value.starts_with('$')
        && !value.starts_with('/')
        && !value.is_empty()
        && !value.contains("..")
        && ![
            "secret",
            "password",
            "credential",
            "token",
            "private",
            ".env",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./+-:".contains(&byte)))
    .then_some(value)
}

fn sanitize_test_name(description: &str) -> String {
    let lower = description.to_ascii_lowercase();
    if ["secret", "password", "credential", "token", "api_key"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        "redacted Bats test description".to_string()
    } else {
        description.to_string()
    }
}

fn bats_description(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("@test")?.trim_start();
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let end = rest.as_bytes()[1..]
        .iter()
        .enumerate()
        .find_map(|(index, byte)| {
            (*byte == quote && rest.as_bytes()[index] != b'\\').then_some(index + 1)
        })?;
    Some(&rest[1..end])
}

struct CMakeCommand<'a> {
    name: String,
    arguments: &'a str,
    start: usize,
    end: usize,
}

fn cmake_commands(source: &str) -> Vec<CMakeCommand<'_>> {
    let bytes = source.as_bytes();
    let mut commands = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'#' {
            cursor = skip_comment(bytes, cursor);
            continue;
        }
        if !bytes[cursor].is_ascii_alphabetic() && bytes[cursor] != b'_' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        let name_end = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'(') {
            cursor = name_end;
            continue;
        }
        let args_start = cursor + 1;
        if let Some(end) = cmake_close_paren(bytes, cursor) {
            commands.push(CMakeCommand {
                name: source[start..name_end].to_ascii_lowercase(),
                arguments: &source[args_start..end],
                start,
                end: end + 1,
            });
            cursor = end + 1;
        } else {
            break;
        }
    }
    commands
}

fn cmake_close_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut cursor = open + 1;
    let mut quoted = false;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(bytes.len()),
            b'"' => {
                quoted = !quoted;
                cursor += 1;
            }
            b'#' if !quoted => cursor = skip_comment(bytes, cursor),
            b'[' if !quoted => {
                if let Some((equals, body_start)) = bracket_open(bytes, cursor) {
                    if let Some(body_end) = bracket_close(bytes, body_start, equals) {
                        cursor = body_end;
                    } else {
                        return None;
                    }
                } else {
                    cursor += 1;
                }
            }
            b'(' if !quoted => {
                depth += 1;
                cursor += 1;
            }
            b')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(cursor);
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }
    None
}

fn cmake_arguments(raw: &str) -> Vec<String> {
    let bytes = raw.as_bytes();
    let mut args = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b';')
        {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        if bytes[cursor] == b'#' {
            cursor = skip_comment(bytes, cursor);
            continue;
        }
        let start = cursor;
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'"' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            args.push(raw[start + 1..cursor.saturating_sub(1)].to_string());
        } else if let Some((equals, body_start)) = bracket_open(bytes, cursor) {
            if let Some(end) = bracket_close(bytes, body_start, equals) {
                args.push(raw[body_start..end - (equals + 2)].to_string());
                cursor = end;
            } else {
                break;
            }
        } else {
            while cursor < bytes.len()
                && !bytes[cursor].is_ascii_whitespace()
                && bytes[cursor] != b';'
            {
                if bytes[cursor] == b'#' {
                    break;
                }
                cursor += 1;
            }
            if cursor > start {
                args.push(raw[start..cursor].to_string());
            } else {
                cursor += 1;
            }
        }
    }
    args
}

fn bracket_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if bytes.get(start) != Some(&b'[') {
        return None;
    }
    let mut cursor = start + 1;
    while bytes.get(cursor) == Some(&b'=') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'[')).then_some((cursor - start - 1, cursor + 1))
}

fn bracket_close(bytes: &[u8], start: usize, equals: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor + equals + 1 < bytes.len() {
        if bytes[cursor] == b']'
            && bytes[cursor + 1..cursor + equals + 1]
                .iter()
                .all(|byte| *byte == b'=')
            && bytes[cursor + equals + 1] == b']'
        {
            return Some(cursor + equals + 2);
        }
        cursor += 1;
    }
    None
}

fn line_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| start + offset + 1)
}

fn skip_comment(bytes: &[u8], start: usize) -> usize {
    if let Some((equals, body_start)) = bracket_open(bytes, start + 1) {
        bracket_close(bytes, body_start, equals).unwrap_or(bytes.len())
    } else {
        line_end(bytes, start)
    }
}

fn line_at(source: &str, offset: usize) -> usize {
    source.as_bytes()[..offset.min(source.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_and_html_static_references_are_source_located_and_partial() {
        let parser = BuildParser::with_config(ParserConfig::default());
        let mut graph = CodeGraph::in_memory().unwrap();
        parser.parse_source("@echo off\n:MENU\nstart /b /w map_extractor.exe\nrem ignored.exe\n%PYEXE% launch.py %*\n", Path::new("extractor.bat"), &mut graph).unwrap();
        parser.parse_source("<script type=\"module\" src=\"/src/main.tsx\"></script>\n<link href=\"/icon.svg?token=secret\">", Path::new("index.html"), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();
        for (name, line) in [("MENU", 2), ("map_extractor.exe", 3), ("launch.py", 5), ("/src/main.tsx", 1)] {
            assert!(nodes.iter().any(|n| n.properties.get_string("name") == Some(name) && n.properties.get_int("line_start") == Some(line) && n.properties.get_string("coverage") == Some("partial")), "missing {name}");
        }
        assert!(!nodes.iter().any(|n| n.properties.get_string("name").is_some_and(|s| s.contains("secret") || s == "ignored.exe")));
    }

    #[test]
    fn legacy_build_declarations_are_partial_without_values() {
        let parser = BuildParser::with_config(ParserConfig::default());
        let mut graph = CodeGraph::in_memory().unwrap();
        parser.parse_source("SUBDIRS = libmpq bindings\nPASSWORD = secret\n", Path::new("Makefile.am"), &mut graph).unwrap();
        parser.parse_source("AC_INIT(libmpq, 0.4.2)\n", Path::new("configure.ac"), &mut graph).unwrap();
        parser.parse_source("#include \"resource.h\"\n", Path::new("worldserver.rc"), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();
        for name in ["SUBDIRS", "AC_INIT", "resource.h"] { assert!(nodes.iter().any(|n| n.properties.get_string("name") == Some(name) && n.properties.get_string("coverage") == Some("partial"))); }
        assert!(!nodes.iter().any(|n| n.properties.get_string("name").is_some_and(|s| s.contains("secret"))));
        assert!(!parser.can_parse(Path::new("env.ac")));
    }

    #[test]
    fn json_graph_contains_only_whitelisted_field_names_not_values_or_arbitrary_keys() {
        let parser = BuildParser::with_config(ParserConfig::default());
        let mut graph = CodeGraph::in_memory().unwrap();
        let json = r#"{"name":"sensitive-value-987", "secret-arbitrary-123":"hidden", "settings":{"type":"private-text"}}"#;
        parser.parse_source(json, Path::new("settings.json"), &mut graph).unwrap();
        let names: Vec<_> = graph.iter_nodes().filter_map(|(_, n)| n.properties.get_string("name")).collect();
        assert!(names.contains(&"name") && names.contains(&"settings") && names.contains(&"type"));
        assert!(!names.iter().any(|n| n.contains("sensitive-value") || n.contains("secret-arbitrary") || n.contains("private-text")));
        assert!(!parser.can_parse(Path::new("package-lock.json")));
        assert!(parser.parse_source("{\"name\":", Path::new("broken.json"), &mut graph).is_err());
        assert!(parser.parse_source("# comment\n{\"name\":\"https://example/#fragment\", // note\n\"type\":1}", Path::new("commented.json"), &mut graph).is_ok());
        assert!(parser.parse_source("# JSON lines\n{\"name\":\"one\"}\n{\"type\":\"two\"}\n", Path::new("lines.json"), &mut graph).is_ok());
        assert!(parser.parse_source("{\"name\":1} /* unfinished", Path::new("broken.json"), &mut graph).is_err());
    }

    #[test]
    fn config_graph_contains_safe_option_names_without_values() {
        let parser = BuildParser::with_config(ParserConfig::default());
        let mut graph = CodeGraph::in_memory().unwrap();
        parser.parse_source("# comment\nFeature.Enabled = FAKEVALUEQZJ\nDatabase.Password = FAKEPASSWORDQZJ\n", Path::new("world.conf.dist"), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, n)| n).collect();
        assert!(nodes.iter().any(|n| n.properties.get_string("name") == Some("Feature.Enabled") && n.properties.get_int("line_start") == Some(2) && n.properties.get_string("coverage") == Some("partial")));
        assert!(!nodes.iter().any(|n| n.properties.get_string("name").is_some_and(|s| s.contains("Password") || s.contains("FAKEVALUE") || s.contains("FAKEPASSWORD"))));
        assert!(!parser.can_parse(Path::new("conf.sh.dist")));
    }

    #[test]
    fn real_config_corpus_indexes_without_retaining_values() {
        let Ok(corpus) = std::env::var("CPI420_CONFIG_CORPUS") else { return; };
        let paths: Vec<String> = serde_json::from_str(&std::fs::read_to_string(corpus).unwrap()).unwrap();
        assert!(!paths.is_empty());
        let parser = BuildParser::with_config(ParserConfig::default()); let mut graph = CodeGraph::in_memory().unwrap();
        for path in &paths { parser.parse_file(Path::new(path), &mut graph).unwrap_or_else(|e| panic!("failed to parse {path}: {e}")); }
        assert_eq!(graph.iter_nodes().filter(|(_, n)| n.node_type == NodeType::CodeFile).count(), paths.len());
    }

    #[test]
    fn real_json_corpus_indexes_without_retaining_values() {
        let Ok(corpus) = std::env::var("CPI420_JSON_CORPUS") else { return; };
        let paths: Vec<String> = serde_json::from_str(&std::fs::read_to_string(corpus).unwrap()).unwrap();
        assert!(!paths.is_empty());
        let parser = BuildParser::with_config(ParserConfig::default());
        let mut graph = CodeGraph::in_memory().unwrap();
        for path in &paths { parser.parse_file(Path::new(path), &mut graph).unwrap_or_else(|e| panic!("failed to parse {path}: {e}")); }
        assert_eq!(graph.iter_nodes().filter(|(_, n)| n.node_type == NodeType::CodeFile).count(), paths.len());
        println!("Indexed {} actual JSON files in memory; no input copies written", paths.len());
    }
    use crate::index_state::IndexState;
    use crate::indexer::{IndexConfig, Indexer, WorkspaceFilter};
    use crate::parser_registry::ParserRegistry;
    use codegraph::{Direction, PropertyValue};
    use std::sync::Arc;

    #[test]
    fn cmake_commands_keep_locations_and_mark_unresolved_build_semantics() {
        let source = "# ignored add_executable(hidden)\nproject(AzerothCore LANGUAGES CXX C)\nadd_subdirectory(\"src/server\")\nadd_library(core STATIC core.cpp)\ntarget_link_libraries(core PUBLIC common)\n";
        let path = Path::new("CMakeLists.txt");
        let mut graph = CodeGraph::in_memory().unwrap();
        let info = BuildParser::with_config(ParserConfig::default())
            .parse_cmake(source, path, &mut graph)
            .unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();

        assert_eq!(info.line_count, 5);
        assert!(nodes.iter().any(|node| {
            node.properties.get_string("name") == Some("AzerothCore")
                && node.properties.get_string("target_kind") == Some("project")
                && node.properties.get_int("line_start") == Some(2)
        }));
        assert!(nodes.iter().any(|node| {
            node.properties.get_string("name") == Some("core")
                && node.properties.get_string("target_kind") == Some("library")
                && node.properties.get_int("line_start") == Some(4)
        }));
        assert!(!nodes
            .iter()
            .any(|node| node.properties.get_string("name") == Some("hidden")));
        assert!(nodes.iter().any(|node| {
            node.properties.get_string("name") == Some("src/server")
                && node.properties.get_string("resolution") == Some("unresolved")
                && node.properties.get_int("line_start") == Some(3)
        }));
        let references = nodes
            .iter()
            .filter(|node| node.properties.get_string("symbol_kind") == Some("build_reference"))
            .count();
        assert!(references >= 2);
        let file = graph.get_node(info.file_id).unwrap();
        assert_eq!(file.properties.get_string("coverage"), Some("partial"));
        assert!(file.properties.get_string("coverage_diagnostic").is_some());
        assert!(
            graph
                .get_neighbors_by_edge_type(info.file_id, Direction::Outgoing, EdgeType::Contains)
                .unwrap()
                .len()
                >= 4
        );
    }

    #[test]
    fn bats_test_declarations_are_source_located_without_retaining_bodies_or_secrets() {
        let source = "@test \"runs a normal case\" {\n  run command\n}\n@test \"uses password=sentinel-secret\" {\n  run command\n}\n";
        let path = Path::new("tests.bats");
        let mut graph = CodeGraph::in_memory().unwrap();
        let info = BuildParser::with_config(ParserConfig::default())
            .parse_bats(source, path, &mut graph)
            .unwrap();
        let tests: Vec<_> = info
            .functions
            .iter()
            .map(|id| graph.get_node(*id).unwrap())
            .collect();
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].properties.get_int("line_start"), Some(1));
        assert_eq!(tests[0].properties.get_bool("is_test"), Some(true));
        assert_eq!(
            tests[0].properties.get_string("name"),
            Some("runs a normal case")
        );
        assert_eq!(
            tests[1].properties.get_string("name"),
            Some("redacted Bats test description")
        );
        for (_, node) in graph.iter_nodes() {
            for (_, value) in node.properties.iter() {
                if let PropertyValue::String(value) = value {
                    assert!(!value.contains("sentinel-secret"));
                }
            }
        }
        let file = graph.get_node(info.file_id).unwrap();
        assert_eq!(file.properties.get_string("coverage"), Some("partial"));
    }

    #[test]
    fn real_azerothcore_cmake_and_bats_files_produce_located_partial_nodes() {
        let Some(root) =
            std::env::var_os("CODEGRAPH_TEST_SOURCE_ROOT").map(std::path::PathBuf::from)
        else {
            eprintln!("skipping real-source fixture: CODEGRAPH_TEST_SOURCE_ROOT is unset");
            return;
        };
        let registry = crate::parser_registry::ParserRegistry::new();
        let mut graph = CodeGraph::in_memory().unwrap();
        for relative in [
            "CMakeLists.txt",
            "src/cmake/showoptions.cmake",
            "modules/CMakeLists.txt",
        ] {
            let path = root.join(relative);
            let info = registry.parse_file(&path, &mut graph).unwrap();
            let file = graph.get_node(info.file_id).unwrap();
            assert_eq!(file.properties.get_string("coverage"), Some("partial"));
            assert!(info.line_count > 0);
            assert!(graph
                .nodes_by_path(&path.to_string_lossy())
                .iter()
                .any(|id| graph
                    .get_node(*id)
                    .unwrap()
                    .properties
                    .get_int("line_start")
                    .is_some()));
        }
        let bats = root.join("apps/compiler/test/test_compiler.bats");
        let info = registry.parse_file(&bats, &mut graph).unwrap();
        assert_eq!(info.functions.len(), 19);
        let descriptions: Vec<_> = info
            .functions
            .iter()
            .filter_map(|id| {
                graph
                    .get_node(*id)
                    .ok()?
                    .properties
                    .get_string("name")
                    .map(str::to_string)
            })
            .collect();
        assert!(descriptions
            .iter()
            .any(|name| name == "compiler: should show help with --help argument"));
        assert_eq!(
            graph
                .get_node(info.file_id)
                .unwrap()
                .properties
                .get_string("coverage"),
            Some("partial")
        );
    }

    #[test]
    fn cmake_special_filename_and_bats_extension_are_recognized_only_as_build_inputs() {
        let parser = BuildParser::with_config(ParserConfig::default());
        assert!(parser.can_parse(Path::new("CMakeLists.txt")));
        assert!(parser.can_parse(Path::new("src/options.cmake")));
        assert!(parser.can_parse(Path::new("test.bats")));
        assert!(!parser.can_parse(Path::new("README.txt")));
        assert_eq!(parser.file_extensions(), &[".cmake", ".bats", ".bat", ".html", ".am", ".ac", ".rc", ".json", ".conf", ".dist"]);
    }

    #[tokio::test]
    async fn directory_walk_indexes_cmakelists_but_keeps_generated_and_secret_dirs_excluded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir_all(root.join("examples")).unwrap();
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(root.join("CMakeLists.txt"), "project(sample)\n").unwrap();
        std::fs::write(root.join("examples/CMakeLists.txt"), "project(example)\n").unwrap();
        std::fs::write(root.join("dist/CMakeLists.txt"), "project(generated)\n").unwrap();
        std::fs::write(root.join("private/CMakeLists.txt"), "project(secret)\n").unwrap();

        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(tokio::sync::Mutex::new(IndexState::for_workspace(
            "cmake-walk-test",
            &root,
        )));
        let indexer = Indexer::new(Arc::clone(&parsers), state);
        let mut config = IndexConfig::default();
        config.exclude_dirs.push("private".to_string());
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&root.join("CMakeLists.txt")));
        assert!(!filter.admits(&root.join("examples/CMakeLists.txt")));
        assert!(!filter.admits(&root.join("dist/CMakeLists.txt")));
        assert!(!filter.admits(&root.join("private/CMakeLists.txt")));

        let graph = Arc::new(tokio::sync::RwLock::new(CodeGraph::in_memory().unwrap()));
        let (total, parsed, _, _, _) = indexer
            .index_directory(
                &graph,
                &root,
                &config,
                0,
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            )
            .await;
        assert_eq!((total, parsed), (1, 1));
        assert!(graph
            .read()
            .await
            .iter_nodes()
            .any(|(_, node)| node.properties.get_string("name") == Some("sample")));
        assert!(!graph.read().await.iter_nodes().any(|(_, node)| {
            node.properties
                .get_string("name")
                .is_some_and(|name| matches!(name, "example" | "generated" | "secret"))
        }));
    }
}
