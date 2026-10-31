// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! MySQL SQL parser adapter for CodeGraph's generic entity graph.

use codegraph::{CodeGraph, EdgeType, NodeId, NodeType, PropertyMap, PropertyValue};
use codegraph_parser_api::{
    CodeParser, FileInfo, ParserConfig, ParserError, ParserMetrics, ParserResult,
};
use sqlparser::ast::{ObjectName, Spanned, Statement, Use, Visit, Visitor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

const EXTENSIONS: &[&str] = &[".sql"];
pub(crate) const MAX_SQL_FILE_SIZE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SQL_STATEMENT_BYTES: usize = 1024 * 1024;
const MAX_SQL_PRELUDE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SQL_LINE_BYTES: usize = 64 * 1024;

pub(crate) fn is_sql_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
}

pub(crate) struct SqlParser {
    config: ParserConfig,
    metrics: Mutex<ParserMetrics>,
}

impl SqlParser {
    pub(crate) fn with_config(config: ParserConfig) -> Self {
        Self {
            config,
            metrics: Mutex::new(ParserMetrics::default()),
        }
    }

    fn parse(
        &self,
        source: &str,
        file_path: &Path,
        graph: &mut CodeGraph,
    ) -> ParserResult<FileInfo> {
        let started = Instant::now();
        if source.len() > self.config.max_file_size {
            return Err(ParserError::FileTooLarge(
                file_path.to_path_buf(),
                source.len(),
            ));
        }

        let normalized_source = normalize_mysql_delimiters(source, file_path)?;
        let (normalized_source, database_options) =
            strip_mysql_database_encryption(&normalized_source);
        let (normalized_source, partial_triggers) = strip_mysql_trigger_declarations(&normalized_source);
        let (normalized_source, signal_procedures, signal_triggers, procedure_key_directive) =
            strip_mysql_procedure_signals(&normalized_source);
        if procedure_key_directive {
            return Err(ParserError::UnsupportedFeature(file_path.to_path_buf(),
                "procedure-local ENABLE/DISABLE KEYS cannot yet retain its table relationship".to_string()));
        }
        let (normalized_source, stored_functions) = strip_mysql_function_bodies(&normalized_source);
        let (normalized_source, dynamic_statements) =
            strip_mysql_dynamic_statements(&normalized_source);
        let (normalized_source, multi_table_updates) =
            strip_mysql_multi_table_updates(&normalized_source);
        let (normalized_source, privilege_statements) =
            strip_mysql_privilege_statements(&normalized_source);
        let (normalized_source, persistent_settings, constraint_options) =
            strip_mysql_persist_and_check_alters(&normalized_source);
        let identity_line_map: Vec<_> = (1..=source.lines().count()).collect();
        let (normalized_source, key_directives) =
            strip_mysql_key_directives(&normalized_source, &identity_line_map);
        let (normalized_source, mut table_options) =
            strip_mysql_drop_rename_comment_alters(&normalized_source);
        table_options.extend(constraint_options);
        let (normalized_source, engine_options) = strip_mysql_engine_options(&normalized_source);
        table_options.extend(engine_options);
        let normalized_source = normalize_quoted_create_table_options(&normalized_source);
        let statements =
            Parser::parse_sql(&MySqlDialect {}, &normalized_source).map_err(|error| {
                let message = error.to_string();
                let (line, column) = error_location(&message);
                ParserError::SyntaxError(file_path.to_path_buf(), line, column, message)
            })?;

        // Keep schema context per statement; a later USE must never change an
        // earlier definition's identity.
        let mut current_schema = None::<String>;
        let mut statement_schemas = Vec::with_capacity(statements.len());
        let mut schema_changes = Vec::new();
        for statement in &statements {
            if let Statement::Use(use_expr) = statement {
                current_schema = match use_expr {
                    Use::Object(name) | Use::Database(name) | Use::Schema(name) => {
                        Some(simple_sql_identifier(&name.to_string()).unwrap_or_default())
                    }
                    _ => Some(String::new()),
                };
                schema_changes.push((statement_line(statement, &normalized_source), current_schema.clone()));
            }
            statement_schemas.push(current_schema.clone());
        }

        let file_name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<sql>");
        let file_id = graph
            .add_node(
                NodeType::CodeFile,
                PropertyMap::new()
                    .with("name", file_name)
                    .with("path", file_path.to_string_lossy().to_string())
                    .with("language", "sql"),
            )
            .map_err(|error| ParserError::GraphError(error.to_string()))?;

        // First create definitions so references can resolve to local objects
        // regardless of declaration order in the migration file.
        let definitions: Vec<_> = statements
            .iter()
            .enumerate()
            .filter_map(|(index, statement)| {
                definition(statement).map(|(kind, name)| (index, kind, name))
            })
            .collect();
        let mut defined_nodes = HashMap::<String, Option<NodeId>>::new();
        let mut statement_nodes = HashMap::<usize, NodeId>::new();
        for (index, kind, name) in &definitions {
            let line = statement_line(&statements[*index], &normalized_source);
            let schema = statement_schemas[*index].as_deref();
            let mut properties = sql_relation_properties(file_path, name, kind, line, schema);
            if *kind == "trigger" {
                let mut unsupported = Vec::new();
                if partial_triggers.contains(&normalize_procedure_name(name)) {
                    unsupported.push("trigger local declaration semantics are not modeled");
                }
                if signal_triggers.contains(&normalize_procedure_name(name)) {
                    unsupported.push("SIGNAL statement semantics");
                }
                if !unsupported.is_empty() {
                    properties = properties.with("coverage", "partial")
                        .with("unsupported_constructs", unsupported.join(", "));
                }
            }
            if *kind == "stored_procedure" {
                let mut unsupported = Vec::new();
                if source.to_ascii_uppercase().contains("IF NOT EXISTS")
                    || source.to_ascii_uppercase().contains("END IF")
                {
                    unsupported.push("conditional control flow");
                }
                if source.to_ascii_uppercase().contains("PREPARE ") {
                    unsupported.push("dynamic SQL PREPARE");
                }
                if signal_procedures.contains(&normalize_procedure_name(name)) {
                    unsupported.push("SIGNAL statement semantics");
                }
                if source.to_ascii_uppercase().contains("DECLARE ")
                    || source.to_ascii_uppercase().contains("LEAVE ")
                    || regex::Regex::new(r"(?im)^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*BEGIN")
                        .is_ok_and(|label| label.is_match(source))
                {
                    unsupported.push("local declarations or labelled control flow");
                }
                if !unsupported.is_empty() {
                    properties = properties
                        .with("coverage", "partial")
                        .with("unsupported_constructs", unsupported.join(", "));
                } else {
                    properties = properties.with("coverage", "parsed");
                }
            }
            let node_id = graph
                .add_node(NodeType::Generic, properties)
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(file_id, node_id, EdgeType::Defines, PropertyMap::new())
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            let key = sql_relation_key(name, schema);
            defined_nodes.entry(key).and_modify(|entry| *entry = None).or_insert(Some(node_id));
            statement_nodes.insert(*index, node_id);
        }

        for (name, value, version, line) in database_options {
            let node = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(file_path, &name, "mysql_database_encryption_option", line)
                        .with("value", value.as_str())
                        .with("version_guard", version.as_str())
                        .with("coverage", "partial")
                        .with(
                            "unsupported_constructs",
                            "database encryption effects are not modeled",
                        ),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(file_id, node, EdgeType::Contains, PropertyMap::new())
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }

        for function in stored_functions {
            let function_id = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(
                        file_path,
                        &function.name,
                        "mysql_stored_function",
                        function.line,
                    )
                    .with("coverage", "partial")
                    .with(
                        "unsupported_constructs",
                        "MySQL function body control flow, side effects, and return semantics are not fully modeled",
                    ),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(file_id, function_id, EdgeType::Defines, PropertyMap::new())
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            for (table, line) in function.table_references {
                let schema = sql_schema_at_line(&schema_changes, line);
                let normalized = sql_relation_key(&table, schema);
                let table_id = if let Some(Some(id)) = defined_nodes.get(&normalized).filter(|_| schema != Some("")) {
                    *id
                } else {
                    let id = graph
                        .add_node(
                            NodeType::Generic,
                            sql_relation_properties(file_path, &table, "table_reference", line, schema),
                        )
                        .map_err(|error| ParserError::GraphError(error.to_string()))?;
                    if schema != Some("") { defined_nodes.entry(normalized).or_insert(Some(id)); }
                    id
                };
                graph
                    .add_edge(
                        function_id,
                        table_id,
                        EdgeType::References,
                        PropertyMap::new().with("relation", "sql_table"),
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
            }
        }

        for directive in key_directives {
            let directive_id = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(
                        file_path,
                        &format!("ALTER TABLE {} {} KEYS", directive.table, directive.action),
                        "mysql_key_directive",
                        directive.line,
                    )
                    .with("action", format!("{}_keys", directive.action)),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(
                    file_id,
                    directive_id,
                    EdgeType::Contains,
                    PropertyMap::new(),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            let schema = sql_schema_at_line(&schema_changes, directive.line);
            let table_key = sql_relation_key(&directive.table, schema);
            let table_id = if let Some(Some(id)) = defined_nodes.get(&table_key).filter(|_| schema != Some("")) {
                *id
            } else {
                let id = graph
                    .add_node(
                        NodeType::Generic,
                        sql_relation_properties(
                            file_path,
                            &directive.table,
                            "table_reference",
                            directive.line,
                            schema,
                        ),
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
                if schema != Some("") { defined_nodes.entry(table_key).or_insert(Some(id)); }
                id
            };
            graph
                .add_edge(
                    directive_id,
                    table_id,
                    EdgeType::References,
                    PropertyMap::new().with("relation", "sql_table"),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }

        add_mysql_dynamic_statement_nodes(graph, file_id, file_path, dynamic_statements)?;
        add_mysql_multi_table_update_nodes(
            graph,
            file_id,
            file_path,
            multi_table_updates,
            &mut defined_nodes,
            &schema_changes,
        )?;
        add_mysql_privilege_statement_nodes(graph, file_id, file_path, privilege_statements)?;
        for (name, line) in persistent_settings {
            let node = graph.add_node(NodeType::Generic,
                sql_node_properties(file_path, &name, "mysql_persistent_setting", line)
                    .with("coverage", "partial")
                    .with("unsupported_constructs", "setting value and server effects are not modeled"))
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph.add_edge(file_id, node, EdgeType::Contains, PropertyMap::new())
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }

        for option in table_options {
            let option_id = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(
                        file_path,
                        &format!(
                            "ALTER TABLE {} {} {}",
                            option.table, option.option, option.value
                        ),
                        "mysql_table_option",
                        option.line,
                    )
                    .with("option", option.option.as_str())
                    .with("value", option.value.as_str())
                    .with("coverage", option.coverage)
                    .with(
                        "unsupported_constructs",
                        option.unsupported_constructs.as_str(),
                    ),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(file_id, option_id, EdgeType::Contains, PropertyMap::new())
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            let schema = sql_schema_at_line(&schema_changes, option.line);
            let normalized = sql_relation_key(&option.table, schema);
            let target_id = if let Some(Some(id)) = defined_nodes.get(&normalized).filter(|_| schema != Some("")) {
                *id
            } else {
                let id = graph
                    .add_node(
                        NodeType::Generic,
                        sql_relation_properties(
                            file_path,
                            &option.table,
                            "table_reference",
                            option.line,
                            schema,
                        ),
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
                if schema != Some("") { defined_nodes.entry(normalized).or_insert(Some(id)); }
                id
            };
            graph
                .add_edge(
                    option_id,
                    target_id,
                    EdgeType::References,
                    PropertyMap::new().with("relation", "sql_table"),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }

        for (index, statement) in statements.iter().enumerate() {
            let schema = statement_schemas[index].as_deref();
            let statement_id = if let Some(id) = statement_nodes.get(&index) {
                *id
            } else {
                let mut properties = sql_node_properties(
                    file_path,
                    &format!("{} statement {}", statement_kind(statement), index + 1),
                    "statement",
                    statement_line(statement, &normalized_source),
                );
                if matches!(statement, Statement::Use(_)) {
                    properties = properties.with("sql_use", true)
                        .with("sql_schema", schema.unwrap_or(""));
                }
                let id = graph
                    .add_node(
                        NodeType::Generic,
                        properties,
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
                graph
                    .add_edge(file_id, id, EdgeType::Contains, PropertyMap::new())
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
                id
            };
            let mut relation_visitor = RelationCollector::default();
            let _ = statement.visit(&mut relation_visitor);
            if let Statement::CreateTrigger(trigger) = statement {
                relation_visitor.relations.push((trigger.table_name.to_string(), statement_line(statement, &normalized_source)));
            }
            let own_definition = definition(statement).map(|(_, name)| sql_relation_key(&name, schema));
            let mut seen_relations = std::collections::HashSet::new();
            for (name, line) in relation_visitor.relations {
                let normalized = sql_relation_key(&name, schema);
                if own_definition.as_deref() == Some(normalized.as_str())
                    || !seen_relations.insert(normalized.clone())
                {
                    continue;
                }
                let target_id = if let Some(Some(id)) = defined_nodes.get(&normalized).filter(|_| schema != Some("")) {
                    *id
                } else {
                    let id = graph
                        .add_node(
                            NodeType::Generic,
                            sql_relation_properties(file_path, &name, "table_reference", line, schema),
                        )
                        .map_err(|error| ParserError::GraphError(error.to_string()))?;
                    id
                };
                graph
                    .add_edge(
                        statement_id,
                        target_id,
                        EdgeType::References,
                        PropertyMap::new().with("relation", "sql_table"),
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
            }
        }

        Ok(FileInfo {
            file_path: file_path.to_path_buf(),
            file_id,
            functions: Vec::new(),
            classes: Vec::new(),
            traits: Vec::new(),
            imports: Vec::new(),
            parse_time: started.elapsed(),
            line_count: source.lines().count(),
            byte_count: source.len(),
        })
    }

    /// Parse a large insert-only data tail without retaining its row AST.
    /// Small DDL statements before the tail still go through sqlparser in full.
    fn parse_large_bulk_file(&self, path: &Path, graph: &mut CodeGraph) -> ParserResult<FileInfo> {
        let started = Instant::now();
        let file = std::fs::File::open(path)
            .map_err(|error| ParserError::IoError(path.to_path_buf(), error))?;
        let mut reader = BufReader::new(file);
        let mut prelude = Vec::new();
        let mut prelude_line_map = vec![1usize];
        let mut statement = Vec::new();
        let mut line_buffer = Vec::new();
        let mut state = SqlLexState::Normal;
        let mut delimiter = ";".to_string();
        let mut line_count = 0usize;
        let mut byte_count = 0usize;
        let mut statement_line = 1usize;
        let mut statement_has_token = false;
        let mut bulk_header = None;
        let mut bulk_summaries = Vec::new();
        let mut bulk_state = SqlLexState::Normal;
        let mut bulk_depth = 0usize;
        let mut bulk_rows = 0u64;
        let mut bulk_ended = false;
        let mut trailing_statement = false;

        loop {
            line_buffer.clear();
            let read = read_limited_sql_line(&mut reader, &mut line_buffer).map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    ParserError::UnsupportedFeature(
                        path.to_path_buf(),
                        format!(
                            "SQL line exceeds the streaming limit of {MAX_SQL_LINE_BYTES} bytes"
                        ),
                    )
                } else {
                    ParserError::IoError(path.to_path_buf(), error)
                }
            })?;
            if read == 0 {
                break;
            }
            byte_count = byte_count.saturating_add(read);
            if byte_count as u64 > MAX_SQL_FILE_SIZE_BYTES {
                return Err(ParserError::FileTooLarge(
                    path.to_path_buf(),
                    usize::try_from(byte_count as u64).unwrap_or(usize::MAX),
                ));
            }
            line_count += 1;

            if bulk_header.is_some() && bulk_ended {
                if trailing_statement {
                    return Err(ParserError::UnsupportedFeature(
                        path.to_path_buf(),
                        "streaming mode requires each bulk INSERT to end before the next statement"
                            .to_string(),
                    ));
                }
                let (table_name, insert_line) = bulk_header.take().unwrap();
                bulk_summaries.push((table_name, insert_line, bulk_rows));
                bulk_state = SqlLexState::Normal;
                bulk_depth = 0;
                bulk_rows = 0;
                bulk_ended = false;
                trailing_statement = false;
                state = SqlLexState::Normal;
                statement_has_token = false;
            }

            if bulk_header.is_some() {
                scan_bulk_line(
                    &line_buffer,
                    &mut bulk_state,
                    &mut bulk_depth,
                    &mut bulk_rows,
                    &mut bulk_ended,
                    &mut trailing_statement,
                    path,
                )?;
                continue;
            }

            if matches!(state, SqlLexState::Normal) && !statement_has_token {
                if let Some(value) = delimiter_command(&line_buffer) {
                    delimiter = value.map_err(|message| {
                        ParserError::UnsupportedFeature(path.to_path_buf(), message)
                    })?;
                    let directive_line: Vec<_> = line_buffer
                        .iter()
                        .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
                        .collect();
                    append_prelude_chunk(
                        &mut prelude,
                        &mut prelude_line_map,
                        &directive_line,
                        line_count,
                        line_count,
                    );
                    continue;
                }
            }

            let mut cursor = 0;
            while cursor < line_buffer.len() {
                let start = cursor;
                let custom_terminator = matches!(state, SqlLexState::Normal)
                    && delimiter != ";"
                    && line_buffer[cursor..].starts_with(delimiter.as_bytes());
                let event = if custom_terminator {
                    cursor += delimiter.len();
                    SqlLexEvent::Terminator
                } else if delimiter != ";"
                    && matches!(state, SqlLexState::Normal)
                    && line_buffer[cursor] == b';'
                {
                    cursor += 1;
                    SqlLexEvent::Normal(b';')
                } else {
                    next_lex_event(&line_buffer, &mut cursor, &mut state)
                };
                if !statement_has_token {
                    if let SqlLexEvent::Normal(byte) = event {
                        if !byte.is_ascii_whitespace() && byte != b';' {
                            statement_line = line_count;
                            statement_has_token = true;
                        }
                    }
                }
                if custom_terminator {
                    statement.push(b';');
                } else {
                    statement.extend_from_slice(&line_buffer[start..cursor]);
                }
                match event {
                    SqlLexEvent::Terminator => {
                        append_prelude_chunk(
                            &mut prelude,
                            &mut prelude_line_map,
                            &statement,
                            statement_line,
                            line_count,
                        );
                        statement.clear();
                        statement_has_token = false;
                        if prelude.len() > MAX_SQL_PRELUDE_BYTES {
                            return Err(ParserError::UnsupportedFeature(
                                path.to_path_buf(),
                                format!("SQL prelude exceeds {MAX_SQL_PRELUDE_BYTES} bytes"),
                            ));
                        }
                    }
                    SqlLexEvent::Normal(byte)
                        if is_values_boundary(byte)
                            && looks_like_insert_prefix(&statement)
                            && ends_with_values_keyword(&statement) =>
                    {
                        if let Some(table_name) = parse_bulk_insert_header(&statement) {
                            bulk_header = Some((table_name, statement_line));
                            // Keep a compact, parseable INSERT in the bounded
                            // prelude so the enclosing procedure AST retains
                            // its static table relationship. The data rows
                            // are represented separately by the bulk summary.
                            let mut placeholder = statement.clone();
                            while placeholder
                                .last()
                                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(')
                            {
                                placeholder.pop();
                            }
                            placeholder.extend_from_slice(b" (NULL);");
                            append_prelude_chunk(
                                &mut prelude,
                                &mut prelude_line_map,
                                &placeholder,
                                statement_line,
                                line_count,
                            );
                            statement.clear();
                            statement_has_token = false;
                            scan_bulk_line(
                                &line_buffer[cursor..],
                                &mut bulk_state,
                                &mut bulk_depth,
                                &mut bulk_rows,
                                &mut bulk_ended,
                                &mut trailing_statement,
                                path,
                            )?;
                            break;
                        }
                    }
                    SqlLexEvent::Normal(b';') if delimiter != ";" => {
                        append_prelude_chunk(
                            &mut prelude,
                            &mut prelude_line_map,
                            &statement,
                            statement_line,
                            line_count,
                        );
                        statement.clear();
                        statement_has_token = false;
                    }
                    _ => {}
                }
                if statement.len() > MAX_SQL_STATEMENT_BYTES {
                    return Err(ParserError::UnsupportedFeature(
                        path.to_path_buf(),
                        format!("oversized SQL statement is not a recognized VALUES bulk INSERT (limit {MAX_SQL_STATEMENT_BYTES} bytes)"),
                    ));
                }
            }
        }

        if let Some((table_name, insert_line)) = bulk_header.take() {
            if !bulk_ended || bulk_depth != 0 || bulk_rows == 0 || trailing_statement {
                return Err(ParserError::SyntaxError(
                    path.to_path_buf(),
                    line_count,
                    1,
                    "incomplete or empty VALUES bulk INSERT".to_string(),
                ));
            }
            bulk_summaries.push((table_name, insert_line, bulk_rows));
        }
        if has_sql_tokens(&statement) || bulk_summaries.is_empty() {
            return Err(ParserError::UnsupportedFeature(
                path.to_path_buf(),
                "file exceeds the parser limit and has no complete recognized MySQL VALUES bulk INSERT".to_string(),
            ));
        };

        let prelude = String::from_utf8(prelude).map_err(|error| {
            ParserError::ParseError(path.to_path_buf(), format!("SQL is not UTF-8: {error}"))
        })?;
        let (prelude, key_directives, dynamic_statements) =
            prepare_large_prelude(&prelude, &prelude_line_map, path)?;
        // The caller selected streaming because the complete file exceeded
        // its normal cap. The prelude has its own tighter 1 MiB cap, so let
        // the AST parser accept that bounded chunk even under a smaller test
        // or deployment max_file_size setting.
        let prelude_parser =
            Self::with_config(self.config.clone().with_max_file_size(prelude.len().max(1)));
        let mut info = prelude_parser.parse(&prelude, path, graph)?;
        add_mysql_dynamic_statement_nodes(graph, info.file_id, path, dynamic_statements)?;
        let path_text = path.to_string_lossy().to_string();
        let streamed_procedures: Vec<_> = graph
            .nodes_by_path(&path_text)
            .into_iter()
            .filter_map(|id| {
                let node = graph.get_node(id).ok()?;
                (node.properties.get_string("path") == Some(path_text.as_str())
                    && node.properties.get_string("kind") == Some("stored_procedure"))
                .then_some(id)
            })
            .collect();
        for id in streamed_procedures {
            let previous = graph.get_node(id).ok().and_then(|node| node.properties.get_string("unsupported_constructs")).unwrap_or_default().to_string();
            let streaming = "large routine body streamed to bulk summaries; procedural statements may be omitted";
            let details = if previous.is_empty() { streaming.to_string() } else { format!("{previous}, {streaming}") };
            let properties = PropertyMap::new()
                .with("coverage", "partial")
                .with("unsupported_constructs", details.as_str());
            graph
                .update_node_properties(id, properties)
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }
        remap_graph_source_lines(graph, path, &prelude_line_map);
        let mut schema_changes: Vec<_> = graph.nodes_by_path(&path_text).into_iter().filter_map(|id| {
            let node = graph.get_node(id).ok()?;
            if node.properties.get_bool("sql_use") != Some(true) { return None; }
            let line = usize::try_from(node.properties.get_int("line_start")?).ok()?;
            let schema = node.properties.get_string("sql_schema").map(str::to_owned);
            Some((line, schema))
        }).collect();
        schema_changes.sort_by_key(|(line, _)| *line);
        // Keep local references within this file; cross-file links are scoped later.
        let mut table_ids: HashMap<String, Option<NodeId>> = HashMap::new();
        for (key, id) in graph.nodes_by_path(&path_text).into_iter().filter_map(|id| {
                let node = graph.get_node(id).ok()?;
                (node.properties.get_string("kind") == Some("table"))
                    .then(|| node.properties.get_string("name"))
                    .flatten()
                    .map(|name| (sql_relation_key(name, node.properties.get_string("sql_schema")), id))
            }) {
            table_ids.entry(key).and_modify(|entry| *entry = None).or_insert(Some(id));
        }
        for directive in key_directives {
            let directive_id = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(
                        path,
                        &format!("ALTER TABLE {} {} KEYS", directive.table, directive.action),
                        "mysql_key_directive",
                        directive.line,
                    )
                    .with("action", format!("{}_keys", directive.action)),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(
                    info.file_id,
                    directive_id,
                    EdgeType::Contains,
                    PropertyMap::new(),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;

            let schema = sql_schema_at_line(&schema_changes, directive.line);
            let normalized = sql_relation_key(&directive.table, schema);
            let target_id = match table_ids.get(&normalized).filter(|_| schema != Some("")).copied().flatten() {
                Some(id) => id,
                None => {
                    let id = graph
                        .add_node(
                            NodeType::Generic,
                            sql_relation_properties(
                                path,
                                &directive.table,
                                "table_reference",
                                directive.line,
                                schema,
                            ),
                        )
                        .map_err(|error| ParserError::GraphError(error.to_string()))?;
                    if schema != Some("") { table_ids.entry(normalized).or_insert(Some(id)); }
                    id
                }
            };
            graph
                .add_edge(
                    directive_id,
                    target_id,
                    EdgeType::References,
                    PropertyMap::new().with("relation", "sql_table"),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }
        for (table_name, insert_line, row_count) in bulk_summaries {
            let insert_id = graph
                .add_node(
                    NodeType::Generic,
                    sql_node_properties(
                        path,
                        &format!("INSERT INTO {table_name}"),
                        "bulk_insert",
                        insert_line,
                    )
                    .with("row_count", i64::try_from(row_count).unwrap_or(i64::MAX)),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
            graph
                .add_edge(
                    info.file_id,
                    insert_id,
                    EdgeType::Contains,
                    PropertyMap::new(),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;

            let schema = sql_schema_at_line(&schema_changes, insert_line);
            let normalized = sql_relation_key(&table_name, schema);
            let target_id = match table_ids.get(&normalized).filter(|_| schema != Some("")).copied().flatten() {
                Some(id) => id,
                None => {
                    let id = graph
                        .add_node(
                            NodeType::Generic,
                            sql_relation_properties(path, &table_name, "table_reference", insert_line, schema),
                        )
                        .map_err(|error| ParserError::GraphError(error.to_string()))?;
                    if schema != Some("") { table_ids.entry(normalized).or_insert(Some(id)); }
                    id
                }
            };
            graph
                .add_edge(
                    insert_id,
                    target_id,
                    EdgeType::References,
                    PropertyMap::new()
                        .with("relation", "sql_table")
                        .with("row_count", i64::try_from(row_count).unwrap_or(i64::MAX)),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }

        info.line_count = line_count;
        info.byte_count = byte_count;
        info.parse_time = started.elapsed();
        Ok(info)
    }

    fn record(&self, succeeded: bool, elapsed: std::time::Duration, entities: usize) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.files_attempted += 1;
            if succeeded {
                metrics.files_succeeded += 1;
                metrics.total_entities += entities;
            } else {
                metrics.files_failed += 1;
            }
            metrics.total_parse_time += elapsed;
        }
    }
}

fn append_prelude_chunk(
    prelude: &mut Vec<u8>,
    line_map: &mut Vec<usize>,
    statement: &[u8],
    token_line: usize,
    current_line: usize,
) {
    let source_start_line = first_sql_token_offset(statement)
        .map(|offset| {
            token_line.saturating_sub(
                statement[..offset]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
            )
        })
        .unwrap_or_else(|| {
            current_line.saturating_sub(statement.iter().filter(|byte| **byte == b'\n').count())
        });
    // Bulk bodies are absent from `prelude`; map its next compact line to
    // this source statement's original line before appending its own newlines.
    if let Some(current_source_line) = line_map.last_mut() {
        *current_source_line = source_start_line;
    }
    let mut source_line = source_start_line;
    for byte in statement {
        if *byte == b'\n' {
            source_line = source_line.saturating_add(1);
            line_map.push(source_line);
        }
    }
    prelude.extend_from_slice(statement);
}

fn first_sql_token_offset(statement: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    let mut state = SqlLexState::Normal;
    while cursor < statement.len() {
        let start = cursor;
        if let SqlLexEvent::Normal(byte) = next_lex_event(statement, &mut cursor, &mut state) {
            if !byte.is_ascii_whitespace() && byte != b';' {
                return Some(start);
            }
        }
    }
    None
}

fn remap_graph_source_lines(graph: &mut CodeGraph, path: &Path, line_map: &[usize]) {
    let path = path.to_string_lossy().to_string();
    let file_node_ids = graph.nodes_by_path(&path);
    let lines: Vec<_> = file_node_ids
        .into_iter()
        .filter_map(|id| {
            let node = graph.get_node(id).ok()?;
            (node.properties.get_string("path") == Some(path.as_str()))
                .then(|| node.properties.get_int("line_start"))
                .flatten()
                .and_then(|line| usize::try_from(line).ok())
                .and_then(|line| line_map.get(line.saturating_sub(1)).copied())
                .map(|line| (id, line))
        })
        .collect();
    for (id, line) in lines {
        let properties =
            PropertyMap::new().with("line_start", i64::try_from(line).unwrap_or(i64::MAX));
        let _ = graph.update_node_properties(id, properties);
    }
}

struct MysqlKeyDirective {
    table: String,
    action: &'static str,
    line: usize,
}

struct MysqlTableOption {
    table: String,
    option: String,
    value: String,
    line: usize,
    coverage: &'static str,
    unsupported_constructs: String,
}

// Preserve these MySQL forms as partial graph nodes; their effects are not applied.
fn strip_mysql_persist_and_check_alters(source: &str) -> (String, Vec<(String, usize)>, Vec<MysqlTableOption>) {
    static SETTING: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static CHECK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let setting = SETTING.get_or_init(|| regex::Regex::new(r"(?is)^SET\s+PERSIST\s+([A-Za-z_][A-Za-z0-9_$]*)\s*=\s*(?:[0-9]+|'(?:''|[^'])*')\s*;\s*$").unwrap());
    let check = CHECK.get_or_init(|| regex::Regex::new(r"(?is)^ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+DROP\s+CHECK\s+(`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s*,\s*ADD\s+CONSTRAINT\s+(`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s+CHECK\s*\([^;]+\)\s*;\s*$").unwrap());
    let mut output = String::with_capacity(source.len());
    let (mut settings, mut options) = (Vec::new(), Vec::new());
    let (mut start, mut cursor, mut line) = (0, 0, 1);
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let bytes = source.as_bytes();
        if bytes[cursor] >= 0x80 { cursor += utf8_char_width(bytes[cursor]); continue; }
        if matches!(next_lex_event(bytes, &mut cursor, &mut state), SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            let offset = first_sql_token_offset(statement.as_bytes()).unwrap_or(statement.len());
            let body = &statement[offset..];
            let source_line = line + statement[..offset].bytes().filter(|b| *b == b'\n').count();
            let recognized = if let Some(c) = setting.captures(body) {
                settings.push((c[1].to_string(), source_line)); true
            } else if let Some(c) = check.captures(body) {
                options.push(MysqlTableOption { table: c[1].replace(' ', ""), option: "check_constraint".to_string(), value: format!("drop {}; add {}", &c[2], &c[3]), line: source_line, coverage: "partial", unsupported_constructs: "check expression and schema effects are not modeled".to_string() }); true
            } else { false };
            if recognized {
                output.extend(statement.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
            } else { output.push_str(statement); }
            line += statement.bytes().filter(|b| *b == b'\n').count();
            start = cursor;
        }
    }
    output.push_str(&source[start..]);
    (output, settings, options)
}

/// Extract a specific MySQL ALTER TABLE envelope that combines DROP columns,
/// RENAME TO and a trailing table COMMENT. It is retained as partial metadata
/// because the graph does not apply or fully model those schema effects.
fn strip_mysql_drop_rename_comment_alters(source: &str) -> (String, Vec<MysqlTableOption>) {
    static ALTER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let alter = ALTER.get_or_init(|| {
        regex::Regex::new(r"(?ims)^[ \t]*ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+(?:DROP\s+(?:COLUMN\s+)?(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s*,\s*)+RENAME\s+TO\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s*,\s*COMMENT\s*=\s*'((?:''|[^'])*)'\s*;?")
            .expect("static MySQL drop/rename/comment ALTER regex")
    });
    let mut output = String::with_capacity(source.len());
    let mut options = Vec::new();
    let mut cursor = 0usize;
    for captures in alter.captures_iter(source) {
        let matched = captures.get(0).unwrap();
        output.push_str(&source[cursor..matched.start()]);
        let line = 1 + source[..matched.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        options.push(MysqlTableOption {
            table: captures[1].replace(' ', ""),
            option: "drop_rename_comment".to_string(),
            value: format!(
                "rename_to={}; comment={}",
                captures[2].replace(' ', ""),
                captures[3].replace("''", "'")
            ),
            line,
            coverage: "partial",
            unsupported_constructs: "DROP column, table rename, and table COMMENT effects are recorded as a partial migration; schema effects are not applied".to_string(),
        });
        output.extend(matched.as_str().chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        cursor = matched.end();
    }
    output.push_str(&source[cursor..]);
    (output, options)
}

/// Normalize only observed MySQL table-option forms that sqlparser rejects.
/// Preserve their table reference, source row and explicit partial coverage.
fn strip_mysql_engine_options(source: &str) -> (String, Vec<MysqlTableOption>) {
    static TABLE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static STANDALONE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TRAILING: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static LEGACY_COMPOUND: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static LEADING_CHARSET: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE_CHARSET: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static CONVERT_CHARSET: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static CHANGE_CHARSET: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let table_pattern = TABLE.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)")
            .expect("static MySQL table option table regex")
    });
    let standalone = STANDALONE.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+ENGINE\s*=\s*([A-Za-z_][A-Za-z0-9_$]*)\s*;?\s*$")
            .expect("static MySQL standalone engine regex")
    });
    let trailing = TRAILING.get_or_init(|| {
        regex::Regex::new(r"(?is),\s*ENGINE\s*=\s*([A-Za-z_][A-Za-z0-9_$]*)")
            .expect("static MySQL trailing engine regex")
    });
    let legacy_compound = LEGACY_COMPOUND.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+ENGINE\s*=?\s*([A-Za-z_][A-Za-z0-9_$]*)\s+ROW_FORMAT\s*=\s*([A-Za-z_][A-Za-z0-9_$]*),\s*CONVERT\s+TO\s+CHARSET\s+([A-Za-z_][A-Za-z0-9_$]*)\s+COLLATE\s+'([^']+)'\s*;?\s*$")
            .expect("static legacy MySQL table options regex")
    });
    let leading_charset = LEADING_CHARSET.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+(CHARSET\s*=\s*'([^']+)'\s*,)")
            .expect("static MySQL leading charset regex")
    });
    let simple_charset = SIMPLE_CHARSET.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+(CHARSET|COLLATE)\s*=\s*'([^']+)'\s*;?\s*$")
            .expect("static MySQL simple charset/collation regex")
    });
    let convert_charset = CONVERT_CHARSET.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+CONVERT\s+TO\s+CHARSET\s+([A-Za-z_][A-Za-z0-9_$]*)\s+COLLATE\s+'([^']+)'\s*;?\s*$")
            .expect("static MySQL convert charset regex")
    });
    let change_charset = CHANGE_CHARSET.get_or_init(|| {
        regex::Regex::new(r"(?is)(\bCHANGE\s+`state`\s+`state`\s+ENUM\([^;]*?\))\s+CHARSET\s+([A-Za-z_][A-Za-z0-9_$]*)\s+COLLATE\s+([A-Za-z_][A-Za-z0-9_$]*)")
            .expect("static MySQL CHANGE charset regex")
    });

    let mut output = String::with_capacity(source.len());
    let mut options = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    let mut statement_line = 1usize;
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let byte_start = cursor;
        let bytes = source.as_bytes();
        let event = if bytes[cursor] >= 0x80 {
            cursor += utf8_char_width(bytes[cursor]);
            SqlLexEvent::Ignored
        } else {
            next_lex_event(bytes, &mut cursor, &mut state)
        };
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            append_engine_processed_statement(
                &mut output,
                &mut options,
                statement,
                statement_line,
                table_pattern,
                standalone,
                trailing,
                legacy_compound,
                leading_charset,
                simple_charset,
                convert_charset,
                change_charset,
            );
            statement_line += statement.bytes().filter(|byte| *byte == b'\n').count();
            start = cursor;
        }
        debug_assert!(cursor > byte_start);
    }
    append_engine_processed_statement(
        &mut output,
        &mut options,
        &source[start..],
        statement_line,
        table_pattern,
        standalone,
        trailing,
        legacy_compound,
        leading_charset,
        simple_charset,
        convert_charset,
        change_charset,
    );
    (output, options)
}

/// MySQL accepts quoted identifiers as values for CREATE TABLE's ENGINE and
/// COLLATE options. sqlparser treats these as string literals, while MySQL
/// treats them as option names. Replace only the quote delimiters with spaces
/// for these two option values, keeping source byte offsets and line numbers.
fn normalize_quoted_create_table_options(source: &str) -> String {
    let mut bytes = source.as_bytes().to_vec();
    let mut cursor = 0usize;
    let mut statement_start = 0usize;
    let mut state = SqlLexState::Normal;
    while cursor < bytes.len() {
        let event = next_lex_event(&bytes, &mut cursor, &mut state);
        if matches!(event, SqlLexEvent::Terminator) {
            statement_start = cursor;
            continue;
        }
        if let SqlLexEvent::Normal(first) = event {
            if first.is_ascii_alphabetic() || first == b'_' {
                let word_start = cursor - 1;
                while cursor < bytes.len()
                    && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
                {
                    cursor += 1;
                }
                let word = &bytes[word_start..cursor];
                if !word.eq_ignore_ascii_case(b"ENGINE") && !word.eq_ignore_ascii_case(b"COLLATE") {
                    continue;
                }
                let prefix = String::from_utf8_lossy(&bytes[statement_start..word_start]);
                static CREATE_TABLE_PREFIX: std::sync::OnceLock<regex::Regex> =
                    std::sync::OnceLock::new();
                let is_create_table = CREATE_TABLE_PREFIX
                    .get_or_init(|| {
                        regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)CREATE\s+TABLE\b")
                            .expect("static CREATE TABLE prefix regex")
                    })
                    .is_match(&prefix);
                if !is_create_table {
                    continue;
                }
                let mut value_start = cursor;
                while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
                    value_start += 1;
                }
                if value_start < bytes.len() && bytes[value_start] == b'=' {
                    value_start += 1;
                    while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
                        value_start += 1;
                    }
                }
                if value_start >= bytes.len() || bytes[value_start] != b'\'' {
                    continue;
                }
                let mut value_end = value_start + 1;
                while value_end < bytes.len()
                    && (bytes[value_end].is_ascii_alphanumeric()
                        || bytes[value_end] == b'_'
                        || bytes[value_end] == b'$')
                {
                    value_end += 1;
                }
                if value_end > value_start + 1
                    && value_end < bytes.len()
                    && bytes[value_end] == b'\''
                {
                    bytes[value_start] = b' ';
                    bytes[value_end] = b' ';
                }
            }
        }
    }
    String::from_utf8(bytes).expect("SQL source was valid UTF-8")
}

fn append_engine_processed_statement(
    output: &mut String,
    options: &mut Vec<MysqlTableOption>,
    statement: &str,
    base_line: usize,
    table_pattern: &regex::Regex,
    standalone: &regex::Regex,
    trailing: &regex::Regex,
    legacy_compound: &regex::Regex,
    leading_charset: &regex::Regex,
    simple_charset: &regex::Regex,
    convert_charset: &regex::Regex,
    change_charset: &regex::Regex,
) {
    let Some(table_match) = table_pattern.captures(statement) else {
        output.push_str(statement);
        return;
    };
    let table = table_match[1].replace(' ', "");
    let statement_line = base_line
        + statement[..table_match.get(1).unwrap().start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
    static DROP_RENAME_COMMENT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if let Some(captures) = DROP_RENAME_COMMENT
        .get_or_init(|| {
            regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+(?:DROP\s+(?:COLUMN\s+)?(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s*,\s*)+RENAME\s+TO\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s*,\s*COMMENT\s*=\s*'((?:''|[^'])*)'\s*;?\s*$")
                .expect("static MySQL drop/rename/comment ALTER regex")
        })
        .captures(statement)
    {
        let target = captures[2].replace(' ', "");
        let comment = captures[3].replace("''", "'");
        options.push(MysqlTableOption {
            table,
            option: "drop_rename_comment".to_string(),
            value: format!("rename_to={target}; comment={comment}"),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs: "DROP column, table rename, and table COMMENT effects are recorded as a partial migration; schema effects are not applied".to_string(),
        });
        output.extend(statement.chars().map(|character| {
            if character == '\n' { '\n' } else { ' ' }
        }));
        return;
    }
    static EMPTY_ALTER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if EMPTY_ALTER
        .get_or_init(|| {
            regex::Regex::new(r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s*;?\s*$")
                .expect("static empty ALTER TABLE regex")
        })
        .is_match(statement)
    {
        options.push(MysqlTableOption {
            table,
            option: "malformed_empty_alter".to_string(),
            value: "ALTER TABLE has no operation".to_string(),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs: "historical statement is malformed: ALTER TABLE requires an operation; no schema change was applied".to_string(),
        });
        output.extend(statement.chars().map(|character| {
            if character == '\n' { '\n' } else { ' ' }
        }));
        return;
    }
    if let Some(captures) = legacy_compound.captures(statement) {
        options.push(MysqlTableOption {
            table,
            option: "engine_row_format_charset_conversion".to_string(),
            value: format!(
                "engine={}, row_format={}, charset={}, collation={}",
                &captures[2], &captures[3], &captures[4], &captures[5]
            ),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs: "storage engine, row format, and charset conversion semantics are recorded as options only".to_string(),
        });
        output.extend(statement.chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        return;
    }
    if let Some(captures) = standalone.captures(statement) {
        let engine = captures[2].to_string();
        options.push(MysqlTableOption {
            table,
            option: "engine".to_string(),
            value: engine,
            line: statement_line,
            coverage: "parsed",
            unsupported_constructs: String::new(),
        });
        output.extend(statement.chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        return;
    }
    if let Some(captures) = trailing.captures(statement) {
        let engine = captures[1].to_string();
        let range = captures.get(0).unwrap();
        let mut modified = statement.to_string();
        modified.replace_range(
            range.start()..range.end(),
            &statement[range.start()..range.end()]
                .chars()
                .map(|character| if character == '\n' { '\n' } else { ' ' })
                .collect::<String>(),
        );
        options.push(MysqlTableOption {
            table,
            option: "engine".to_string(),
            value: engine,
            line: statement_line,
            coverage: "parsed",
            unsupported_constructs: String::new(),
        });
        output.push_str(&modified);
        return;
    }
    if let Some(captures) = leading_charset.captures(statement) {
        options.push(MysqlTableOption {
            table,
            option: "charset_and_alter".to_string(),
            value: captures[3].to_string(),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs: "table charset and accompanying ALTER clauses are recorded as partial; column changes are not modeled".to_string(),
        });
        output.extend(statement.chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        return;
    }
    if let Some(captures) = simple_charset.captures(statement) {
        options.push(MysqlTableOption {
            table,
            option: captures[2].to_ascii_lowercase(),
            value: captures[3].to_string(),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs:
                "table character-set or collation semantics are recorded as an option only"
                    .to_string(),
        });
        output.extend(statement.chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        return;
    }
    if let Some(captures) = convert_charset.captures(statement) {
        options.push(MysqlTableOption {
            table,
            option: "convert_to_charset".to_string(),
            value: format!("charset={}, collation={}", &captures[2], &captures[3]),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs:
                "table charset conversion and collation semantics are recorded as options only"
                    .to_string(),
        });
        output.extend(statement.chars().map(
            |character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            },
        ));
        return;
    }
    if let Some(captures) = change_charset.captures(statement) {
        let start = captures.get(1).unwrap().end();
        let end = captures.get(3).unwrap().end();
        options.push(MysqlTableOption {
            table,
            option: "column_charset_collation".to_string(),
            value: format!("charset={}, collation={}", &captures[2], &captures[3]),
            line: statement_line,
            coverage: "partial",
            unsupported_constructs:
                "column character-set and collation semantics are recorded as options only"
                    .to_string(),
        });
        let mut modified = statement.to_string();
        modified.replace_range(
            start..end,
            &statement[start..end]
                .chars()
                .map(|character| if character == '\n' { '\n' } else { ' ' })
                .collect::<String>(),
        );
        output.push_str(&modified);
        return;
    }
    output.push_str(statement);
}

/// Retain a mysqldump database encryption option as a partial graph node.
fn strip_mysql_database_encryption(source: &str) -> (String, Vec<(String, String, String, usize)>) {
    static OPTION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let option = OPTION.get_or_init(|| regex::Regex::new(
        r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*(?:\*/|[^!].*?\*/))\s*)*CREATE\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+NOT\s+EXISTS\s+)?(`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*)\s*(?:/\*![0-9]{5,6}\s+DEFAULT\s+CHARACTER\s+SET\s+[A-Z0-9_]+(?:\s+COLLATE\s+[A-Z0-9_]+)?\s*\*/\s*)?(/\*!([0-9]{5,6})\s+DEFAULT\s+ENCRYPTION\s*=\s*'([YN])'\s*\*/)\s*;\s*$"
    ).expect("static MySQL database encryption option regex"));
    let mut output = String::with_capacity(source.len());
    let mut options = Vec::new();
    let (mut start, mut cursor, mut line) = (0, 0, 1);
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let event = next_lex_event(source.as_bytes(), &mut cursor, &mut state);
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            if let Some(c) = option.captures(statement) {
                let part = c.get(2).unwrap();
                options.push((
                    c[1].to_string(),
                    c[4].to_ascii_uppercase(),
                    c[3].to_string(),
                    line + statement[..part.start()]
                        .bytes()
                        .filter(|b| *b == b'\n')
                        .count(),
                ));
                output.push_str(&statement[..part.start()]);
                output.extend(
                    part.as_str()
                        .chars()
                        .map(|c| if c == '\n' { '\n' } else { ' ' }),
                );
                output.push_str(&statement[part.end()..]);
            } else {
                output.push_str(statement);
            }
            line += statement.bytes().filter(|b| *b == b'\n').count();
            start = cursor;
        }
    }
    output.push_str(&source[start..]);
    (output, options)
}

/// Keep trigger statements while marking supported local declarations as partial.
fn mysql_trigger_header() -> &'static regex::Regex {
    static HEADER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    HEADER.get_or_init(|| regex::Regex::new(
        r"(?is)^CREATE\s+TRIGGER\s+((?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*)(?:\s*\.\s*(?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*))?)\s+(?:BEFORE|AFTER)\s+(?:INSERT|UPDATE|DELETE)\s+ON\s+(?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*)(?:\s*\.\s*(?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*))?\s+FOR\s+EACH\s+ROW\s+BEGIN\b"
    ).expect("static MySQL trigger header regex"))
}

fn strip_mysql_trigger_declarations(source: &str) -> (String, Vec<String>) {
    static DECLARATION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let header = mysql_trigger_header();
    let declaration = DECLARATION.get_or_init(|| regex::Regex::new(
        r"(?is)^DECLARE\s+(?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*)\s+(?:INT|INTEGER)\s*;$"
    ).expect("static MySQL integer declaration regex"));
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut partial = Vec::new();
    let mut cursor = 0;
    let mut state = SqlLexState::Normal;
    while cursor < bytes.len() {
        if state == SqlLexState::Normal && (bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_') {
            let start = cursor;
            while cursor < bytes.len() && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_') { cursor += 1; }
            if !source[start..cursor].eq_ignore_ascii_case("CREATE") { continue; }
            let Some(captures) = header.captures(&source[start..]) else { continue; };
            let name = normalize_procedure_name(&captures[1]);
            let mut next = start + captures.get(0).unwrap().end();
            while let Some((word, word_end)) = next_keyword_after_comments(source, next) {
                if !word.eq_ignore_ascii_case("DECLARE") { break; }
                let declaration_start = word_end - word.len();
                let mut end = word_end;
                let mut declaration_state = SqlLexState::Normal;
                while end < bytes.len() {
                    if matches!(next_lex_event(bytes, &mut end, &mut declaration_state), SqlLexEvent::Terminator) { break; }
                }
                if !declaration.is_match(&source[declaration_start..end]) { break; }
                for byte in &mut output[declaration_start..end] { if *byte != b'\n' { *byte = b' '; } }
                if !partial.contains(&name) { partial.push(name.clone()); }
                next = end;
            }
            cursor = next;
        } else {
            next_lex_event(bytes, &mut cursor, &mut state);
        }
    }
    (String::from_utf8(output).expect("replaced ASCII bytes preserve UTF-8"), partial)
}

/// Keep static procedure queries while recording validated SIGNAL semantics as partial.
fn strip_mysql_procedure_signals(source: &str) -> (String, Vec<String>, Vec<String>, bool) {
    static SIGNAL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static PROCEDURE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let valid = SIGNAL.get_or_init(|| regex::Regex::new(
        r"(?is)^SIGNAL\s+SQLSTATE\s+(?:VALUE\s+)?'((?-u:[0-9A-Z]{5}))'(?:\s+SET\s+MESSAGE_TEXT\s*=\s*'(?:''|\\.|[^'\\])*')?\s*;$"
    ).expect("static MySQL SIGNAL regex"));
    let procedure_start = PROCEDURE.get_or_init(|| regex::Regex::new(r"(?is)^CREATE\s+(?:DEFINER\s*=\s*(?:CURRENT_USER(?:\(\))?|(?:'[^']*'|`[^`]*`|[A-Z0-9_$]+)\s*@\s*(?:'[^']*'|`[^`]*`|[A-Z0-9_$]+))\s+)?PROCEDURE\s+((?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*)(?:\s*\.\s*(?:`(?:``|[^`])+`|[A-Z_][A-Z0-9_$]*))?)\s*\(").expect("static MySQL procedure header regex"));
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut signal_procedures = Vec::new();
    let mut signal_triggers = Vec::new();
    let mut procedure_key_directive = false;
    let (mut cursor, mut depth) = (0, 0usize);
    let mut procedure: Option<String> = None;
    let mut is_trigger = false;
    let mut state = SqlLexState::Normal;
    while cursor < bytes.len() {
        if state == SqlLexState::Normal
            && (bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_')
        {
            let start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            let token = &source[start..cursor];
            if token.eq_ignore_ascii_case("CREATE") {
                if let Some(captures) = procedure_start.captures(&source[start..]) {
                    procedure = Some(normalize_procedure_name(&captures[1]));
                    is_trigger = false;
                    cursor = start + captures.get(0).unwrap().end();
                } else if let Some(captures) = mysql_trigger_header().captures(&source[start..]) {
                    procedure = Some(normalize_procedure_name(&captures[1]));
                    is_trigger = true;
                    depth = 1;
                    cursor = start + captures.get(0).unwrap().end();
                }
                continue;
            }
            if procedure.is_none() {
                continue;
            }
            if token.eq_ignore_ascii_case("BEGIN") || token.eq_ignore_ascii_case("CASE") {
                depth += 1;
            }
            let (end_suffix, suffix_end) = next_keyword_after_comments(source, cursor).unwrap_or(("", cursor));
            if token.eq_ignore_ascii_case("END") && depth > 0 && !["IF", "WHILE", "LOOP", "REPEAT"].iter().any(|suffix| end_suffix.eq_ignore_ascii_case(suffix)) {
                depth -= 1;
                if end_suffix.eq_ignore_ascii_case("CASE") {
                    cursor = suffix_end;
                }
                if depth == 0 {
                    procedure = None;
                }
            }
            if depth > 0 && token.eq_ignore_ascii_case("ALTER") {
                let mut end = cursor;
                let mut statement_state = SqlLexState::Normal;
                while end < bytes.len() {
                    if matches!(next_lex_event(bytes, &mut end, &mut statement_state), SqlLexEvent::Terminator) { break; }
                }
                procedure_key_directive |= parse_mysql_key_directive(&source[start..end], 1).is_some();
            }
            if depth > 0 && token.eq_ignore_ascii_case("SIGNAL") {
                let mut end = cursor;
                let mut signal_state = SqlLexState::Normal;
                while end < bytes.len() {
                    if matches!(
                        next_lex_event(bytes, &mut end, &mut signal_state),
                        SqlLexEvent::Terminator
                    ) {
                        break;
                    }
                }
                let statement = &source[start..end];
                if let Some(c) = valid.captures(statement) {
                    if !c[1].starts_with("00") {
                        let targets = if is_trigger { &mut signal_triggers } else { &mut signal_procedures };
                        targets.push(procedure.as_ref().unwrap().clone());
                        for byte in &mut output[start..end] {
                            if *byte != b'\n' {
                                *byte = b' ';
                            }
                        }
                        cursor = end;
                    }
                }
            }
        } else {
            next_lex_event(bytes, &mut cursor, &mut state);
        }
    }
    (
        String::from_utf8(output).expect("replaced ASCII bytes preserve UTF-8"),
        signal_procedures,
        signal_triggers,
        procedure_key_directive,
    )
}

fn next_keyword_after_comments(source: &str, mut cursor: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let mut state = SqlLexState::Normal;
    while cursor < bytes.len() {
        if state == SqlLexState::Normal && bytes[cursor].is_ascii_alphabetic() {
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_alphabetic() { cursor += 1; }
            return Some((&source[start..cursor], cursor));
        }
        match next_lex_event(bytes, &mut cursor, &mut state) {
            SqlLexEvent::Normal(byte) if !byte.is_ascii_whitespace() => return None,
            SqlLexEvent::Terminator => return None,
            _ if matches!(state, SqlLexState::SingleQuoted | SqlLexState::DoubleQuoted | SqlLexState::BacktickQuoted) => return None,
            _ => {}
        }
    }
    None
}

fn normalize_procedure_name(name: &str) -> String {
    let mut quoted = false;
    let mut normalized = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch == '`' { quoted = !quoted; }
        if quoted || !ch.is_whitespace() { normalized.push(ch); }
    }
    normalize_name(&normalized)
}


/// sqlparser's MySQL dialect does not currently accept the two mysqldump
/// load-control statements `ALTER TABLE t DISABLE KEYS` and `ENABLE KEYS`.
/// Accept only those exact forms, retain them as explicit source-located
/// directive nodes, and leave every other unparsed statement as an error.
fn prepare_large_prelude(
    prelude: &str,
    line_map: &[usize],
    path: &Path,
) -> ParserResult<(String, Vec<MysqlKeyDirective>, Vec<MysqlDynamicStatement>)> {
    let normalized = normalize_mysql_delimiters(prelude, path)?;
    let (normalized, mut dynamic_statements) = strip_mysql_dynamic_statements(&normalized);
    for statement in &mut dynamic_statements {
        statement.line = map_source_line(line_map, statement.line);
    }
    let prelude = normalized.as_str();
    let (preview, _) = strip_mysql_database_encryption(prelude);
    let (preview, _) = strip_mysql_trigger_declarations(&preview);
    let (preview, _, _, procedure_key_directive) = strip_mysql_procedure_signals(&preview);
    if procedure_key_directive {
        return Err(ParserError::UnsupportedFeature(path.to_path_buf(),
            "procedure-local ENABLE/DISABLE KEYS cannot yet retain its table relationship".to_string()));
    }
    if Parser::parse_sql(&MySqlDialect {}, &preview).is_ok() {
        return Ok((prelude.to_string(), Vec::new(), dynamic_statements));
    }

    // Validate the entire prelude after the same normalizations used by the
    // normal parser, but retain its original options for metadata extraction.
    let (without_keys, directives) = strip_mysql_key_directives(prelude, line_map);
    if !directives.is_empty() {
        let (preview, _) = strip_mysql_database_encryption(&without_keys);
        let (preview, _) = strip_mysql_trigger_declarations(&preview);
        let (preview, _, _, _) = strip_mysql_procedure_signals(&preview);
        let (preview, _) = strip_mysql_engine_options(&preview);
        if Parser::parse_sql(&MySqlDialect {}, &preview).is_ok() {
            return Ok((without_keys, directives, dynamic_statements));
        }
    }

    let routine_skeleton = strip_procedure_bodies(prelude);
    let (routine_skeleton, routine_key_directives) =
        strip_mysql_key_directives(&routine_skeleton, line_map);
    let (skeleton_without_engine, _) = strip_mysql_engine_options(&routine_skeleton);
    if routine_skeleton != prelude
        && Parser::parse_sql(&MySqlDialect {}, &skeleton_without_engine).is_ok()
    {
        return Ok((routine_skeleton, routine_key_directives, dynamic_statements));
    }

    let mut output = String::with_capacity(prelude.len());
    let mut directives = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;

    let mut statement_line = 1usize;
    let mut state = SqlLexState::Normal;
    while cursor < prelude.len() {
        let event = next_lex_event(prelude.as_bytes(), &mut cursor, &mut state);
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &prelude[start..cursor];
            if Parser::parse_sql(&MySqlDialect {}, statement).is_ok() {
                output.push_str(statement);
            } else if {
                let (without_engine, options) = strip_mysql_engine_options(statement);
                !options.is_empty() && Parser::parse_sql(&MySqlDialect {}, &without_engine).is_ok()
            } {
                // Keep source syntax intact here; the ordinary parser pass
                // emits source-located ENGINE option nodes.
                output.push_str(statement);
            } else if let Some(directive) =
                parse_mysql_key_directive(statement, map_source_line(line_map, statement_line))
            {
                directives.push(directive);
                // Preserve line positions for subsequent sqlparser diagnostics.
                output.extend(
                    statement
                        .chars()
                        .map(|character| if character == '\n' { '\n' } else { ' ' }),
                );
            } else {
                let message = Parser::parse_sql(&MySqlDialect {}, statement)
                    .expect_err("statement already failed")
                    .to_string();
                let (line, column) = error_location(&message);
                return Err(ParserError::SyntaxError(
                    path.to_path_buf(),
                    statement_line.saturating_add(line).saturating_sub(1),
                    column,
                    message,
                ));
            }
            statement_line += statement.bytes().filter(|byte| *byte == b'\n').count();
            start = cursor;
        }
    }
    let trailing = &prelude[start..];
    if has_sql_tokens(trailing.as_bytes()) {
        let (without_engine, engine_options) = strip_mysql_engine_options(trailing);
        if !engine_options.is_empty()
            && Parser::parse_sql(&MySqlDialect {}, &without_engine).is_ok()
        {
            output.push_str(trailing);
        } else if let Some(directive) =
            parse_mysql_key_directive(trailing, map_source_line(line_map, statement_line))
        {
            directives.push(directive);
            output.extend(
                trailing
                    .chars()
                    .map(|character| if character == '\n' { '\n' } else { ' ' }),
            );
        } else {
            let message = Parser::parse_sql(&MySqlDialect {}, trailing)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unterminated SQL statement".to_string());
            let (line, column) = error_location(&message);
            return Err(ParserError::SyntaxError(
                path.to_path_buf(),
                statement_line.saturating_add(line).saturating_sub(1),
                column,
                message,
            ));
        }
    } else {
        output.push_str(trailing);
    }
    Ok((output, directives, dynamic_statements))
}

fn strip_procedure_bodies(source: &str) -> String {
    let procedure =
        regex::Regex::new(r"(?is)(CREATE\s+PROCEDURE\b.*?\)\s+AS\s+BEGIN\b)(.*?)\bEND\s*;")
            .expect("static stored procedure envelope regex");
    procedure
        .replace_all(source, |captures: &regex::Captures<'_>| {
            let mut output = captures[1].to_string();
            output.extend(captures[2].chars().map(
                |character| {
                    if character == '\n' {
                        '\n'
                    } else {
                        ' '
                    }
                },
            ));
            output.push_str(" END;");
            output
        })
        .into_owned()
}

fn strip_mysql_key_directives(
    source: &str,
    line_map: &[usize],
) -> (String, Vec<MysqlKeyDirective>) {
    let mut output = String::with_capacity(source.len());
    let mut directives = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    let mut statement_line = 1usize;
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let bytes = source.as_bytes();
        let event = if bytes[cursor] >= 0x80 {
            cursor += utf8_char_width(bytes[cursor]);
            SqlLexEvent::Ignored
        } else {
            next_lex_event(bytes, &mut cursor, &mut state)
        };
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            if let Some(directive) =
                parse_mysql_key_directive(statement, map_source_line(line_map, statement_line))
            {
                directives.push(directive);
                output.extend(statement.chars().map(
                    |character| {
                        if character == '\n' {
                            '\n'
                        } else {
                            ' '
                        }
                    },
                ));
            } else {
                output.push_str(statement);
            }
            statement_line += statement.bytes().filter(|byte| *byte == b'\n').count();
            start = cursor;
        }
    }
    let trailing = &source[start..];
    if let Some(directive) =
        parse_mysql_key_directive(trailing, map_source_line(line_map, statement_line))
    {
        directives.push(directive);
        output.extend(
            trailing
                .chars()
                .map(|character| if character == '\n' { '\n' } else { ' ' }),
        );
    } else {
        output.push_str(trailing);
    }
    (output, directives)
}

struct MysqlDynamicStatement {
    kind: &'static str,
    line: usize,
}

struct MysqlMultiTableUpdate {
    line: usize,
    table_references: Vec<(String, usize)>,
}

/// Extract the narrow MySQL comma-join UPDATE form seen in migration files.
/// Assignment expressions and WHERE/JOIN semantics remain explicitly partial.
fn strip_mysql_multi_table_updates(source: &str) -> (String, Vec<MysqlMultiTableUpdate>) {
    static START: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TABLES: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TABLE_ALIAS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let start_regex = START.get_or_init(|| {
        regex::Regex::new(r"(?im)^[ \t]*UPDATE\b").expect("static MySQL UPDATE line-start regex")
    });
    let prefix = PREFIX.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*UPDATE\s+(.+?)\s+SET\b")
            .expect("static MySQL multi-table UPDATE prefix regex")
    });
    let tables = TABLES.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_$]*)?(?:\s*,\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_$]*)?)+)\s*$")
            .expect("static MySQL multi-table list regex")
    });
    let table_alias = TABLE_ALIAS.get_or_init(|| {
        regex::Regex::new(r"(?is)^\s*(`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_$]*)?\s*$")
            .expect("static MySQL table alias regex")
    });

    let mut updates = Vec::new();
    let mut replacement_ranges = Vec::new();
    let mut cursor = 0usize;
    let mut line_cursor = 0usize;
    let mut line_number = 1usize;
    let mut statement_has_code = false;
    let mut state = SqlLexState::Normal;
    let bytes = source.as_bytes();
    for candidate in start_regex.find_iter(source) {
        let candidate_start = candidate.start();
        if candidate_start < cursor {
            continue;
        }
        while cursor < candidate_start {
            if bytes[cursor] >= 0x80 {
                cursor += utf8_char_width(bytes[cursor]);
                statement_has_code = true;
                continue;
            }
            match next_lex_event(bytes, &mut cursor, &mut state) {
                SqlLexEvent::Terminator => statement_has_code = false,
                SqlLexEvent::Normal(byte) if !byte.is_ascii_whitespace() => {
                    statement_has_code = true;
                }
                _ => {}
            }
        }
        line_number += source[line_cursor..candidate_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        line_cursor = candidate_start;
        if state != SqlLexState::Normal || statement_has_code {
            continue;
        }

        let mut end_cursor = candidate_start;
        let mut end_state = SqlLexState::Normal;
        while end_cursor < source.len() {
            if bytes[end_cursor] >= 0x80 {
                end_cursor += utf8_char_width(bytes[end_cursor]);
                continue;
            }
            if matches!(
                next_lex_event(bytes, &mut end_cursor, &mut end_state),
                SqlLexEvent::Terminator
            ) {
                break;
            }
        }
        if end_cursor >= source.len() || end_state != SqlLexState::Normal {
            continue;
        }
        let statement = &source[candidate_start..end_cursor];
        let Some(captures) = prefix.captures(statement) else {
            continue;
        };
        let list = captures.get(1).unwrap();
        if !tables.is_match(list.as_str()) {
            continue;
        }
        let mut refs = Vec::new();
        let mut list_offset = 0usize;
        for segment in list.as_str().split(',') {
            if let Some(captures) = table_alias.captures(segment) {
                let identifier = captures.get(1).unwrap();
                let reference_line = line_number
                    + source[candidate_start
                        ..candidate_start + list.start() + list_offset + identifier.start()]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count();
                refs.push((identifier.as_str().to_string(), reference_line));
            }
            list_offset += segment.len() + 1;
        }
        if refs.len() < 2 {
            continue;
        }
        let update_line = line_number
            + source[candidate_start..candidate_start + captures.get(0).unwrap().start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
        updates.push(MysqlMultiTableUpdate {
            line: update_line,
            table_references: refs,
        });
        replacement_ranges.push(candidate_start..end_cursor);
        cursor = end_cursor;
        state = SqlLexState::Normal;
        statement_has_code = false;
        line_number += source[line_cursor..end_cursor]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        line_cursor = end_cursor;
    }

    let mut output = source.to_string();
    for range in replacement_ranges.into_iter().rev() {
        let replacement = source[range.clone()]
            .chars()
            .map(|character| if character == '\n' { '\n' } else { ' ' })
            .collect::<String>();
        output.replace_range(range, &replacement);
    }
    (output, updates)
}

fn add_mysql_multi_table_update_nodes(
    graph: &mut CodeGraph,
    file_id: NodeId,
    file_path: &Path,
    updates: Vec<MysqlMultiTableUpdate>,
    defined_nodes: &mut HashMap<String, Option<NodeId>>,
    schema_changes: &[(usize, Option<String>)],
) -> ParserResult<()> {
    for update in updates {
        let update_id = graph
            .add_node(
                NodeType::Generic,
                sql_node_properties(
                    file_path,
                    "UPDATE",
                    "mysql_multi_table_update",
                    update.line,
                )
                .with("coverage", "partial")
                .with(
                    "unsupported_constructs",
                    "multi-table UPDATE assignment, join, and filter semantics are not fully modeled",
                ),
            )
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
        graph
            .add_edge(file_id, update_id, EdgeType::Contains, PropertyMap::new())
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
        for (table, line) in update.table_references {
            let schema = sql_schema_at_line(schema_changes, line);
            let key = sql_relation_key(&table, schema);
            let table_id = if let Some(Some(id)) = defined_nodes.get(&key).filter(|_| schema != Some("")) {
                *id
            } else {
                let id = graph
                    .add_node(
                        NodeType::Generic,
                        sql_relation_properties(file_path, &table, "table_reference", line, schema),
                    )
                    .map_err(|error| ParserError::GraphError(error.to_string()))?;
                if schema != Some("") { defined_nodes.entry(key).or_insert(Some(id)); }
                id
            };
            graph
                .add_edge(
                    update_id,
                    table_id,
                    EdgeType::References,
                    PropertyMap::new().with("relation", "sql_table"),
                )
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }
    }
    Ok(())
}

struct MysqlStoredFunction {
    name: String,
    line: usize,
    table_references: Vec<(String, usize)>,
}

/// Extract the observed simple MySQL function envelope as a partial graph
/// entity. The function body remains explicitly partial; this only records
/// statically spelled INSERT/UPDATE/DELETE table targets.
fn strip_mysql_function_bodies(source: &str) -> (String, Vec<MysqlStoredFunction>) {
    static FUNCTION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TABLE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let function = FUNCTION.get_or_init(|| {
        regex::Regex::new(r"(?ims)^[ \t]*CREATE\s+FUNCTION\s+(`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s*\([^;]*?\)\s+RETURNS\s+[A-Za-z_][A-Za-z0-9_$]*(?:\s*\([^)]*\))?(?:\s+[A-Za-z_][A-Za-z0-9_$]*)*\s+(?:BEGIN\b(.*?)\bEND\s*;|RETURN\b(.*?);)")
            .expect("static MySQL stored function envelope regex")
    });
    let table = TABLE.get_or_init(|| {
        regex::Regex::new(r"(?is)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)")
            .expect("static MySQL stored function table-reference regex")
    });

    let mut output = String::with_capacity(source.len());
    let mut functions = Vec::new();
    let mut cursor = 0usize;
    let mut current_line = 1usize;
    for captures in function.captures_iter(source) {
        let matched = captures.get(0).unwrap();
        output.push_str(&source[cursor..matched.start()]);
        current_line += source[cursor..matched.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let body = captures.get(2).or_else(|| captures.get(3)).unwrap();
        let body_start_line = current_line
            + source[matched.start()..body.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
        let mut table_references = Vec::new();
        for reference in table.captures_iter(body.as_str()) {
            let name = reference[1].replace(' ', "");
            let name_offset = reference.get(1).unwrap().start();
            let line = body_start_line
                + body.as_str()[..name_offset]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count();
            table_references.push((name, line));
        }
        functions.push(MysqlStoredFunction {
            name: captures[1].to_string(),
            line: current_line,
            table_references,
        });
        output.extend(
            source[matched.start()..matched.end()]
                .chars()
                .map(|character| if character == '\n' { '\n' } else { ' ' }),
        );
        current_line += source[matched.start()..matched.end()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        cursor = matched.end();
    }
    output.push_str(&source[cursor..]);
    (output, functions)
}

fn add_mysql_dynamic_statement_nodes(
    graph: &mut CodeGraph,
    file_id: NodeId,
    file_path: &Path,
    statements: Vec<MysqlDynamicStatement>,
) -> ParserResult<()> {
    for statement in statements {
        let node_id = graph
            .add_node(
                NodeType::Generic,
                sql_node_properties(
                    file_path,
                    statement.kind,
                    "mysql_dynamic_sql",
                    statement.line,
                )
                .with("coverage", "partial")
                .with(
                    "unsupported_constructs",
                    "dynamic SQL is not statically resolved",
                ),
            )
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
        graph
            .add_edge(file_id, node_id, EdgeType::Contains, PropertyMap::new())
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
    }
    Ok(())
}

struct MysqlPrivilegeStatement {
    form: &'static str,
    action: &'static str,
    line: usize,
    account: Option<String>,
}

fn strip_mysql_privilege_statements(source: &str) -> (String, Vec<MysqlPrivilegeStatement>) {
    static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let prefix = PREFIX.get_or_init(|| {
        regex::Regex::new(
            r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)(?:(REVOKE\s+(GRANT\s+OPTION\s+ON\b|ALL\s+PRIVILEGES\s*,\s*GRANT\s+OPTION\s+FROM\b))|(DROP\s+USER\b)|(CREATE\s+USER\b))",
        )
        .expect("static MySQL privilege statement regex")
    });
    let mut output = String::with_capacity(source.len());
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    let mut statement_line = 1usize;
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let bytes = source.as_bytes();
        if bytes[cursor] >= 0x80 {
            cursor += utf8_char_width(bytes[cursor]);
            continue;
        }
        let event = next_lex_event(bytes, &mut cursor, &mut state);
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            if let Some(captures) = prefix.captures(statement) {
                let (form, action, keyword_start) = if let Some(create_user) = captures.get(4) {
                    ("CREATE USER", "CREATE_USER", create_user.start())
                } else if let Some(drop_user) = captures.get(3) {
                    ("DROP USER", "DROP_USER", drop_user.start())
                } else if captures[2]
                    .to_ascii_uppercase()
                    .starts_with("GRANT OPTION ON")
                {
                    (
                        "REVOKE GRANT OPTION",
                        "REVOKE",
                        captures.get(1).unwrap().start(),
                    )
                } else {
                    (
                        "REVOKE ALL PRIVILEGES, GRANT OPTION",
                        "REVOKE",
                        captures.get(1).unwrap().start(),
                    )
                };
                let account = if action == "CREATE_USER" || action == "DROP_USER" {
                    static ACCOUNT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
                    ACCOUNT
                        .get_or_init(|| {
                            regex::Regex::new(
                                r"(?is)\b(?:CREATE|DROP)\s+USER\s+(?:IF\s+EXISTS\s+)?'([^']+)'\s*@\s*'([^']+)'",
                            )
                            .expect("static MySQL account identity regex")
                        })
                        .captures(statement)
                        .map(|account| format!("{}@{}", &account[1], &account[2]))
                } else {
                    None
                };
                let complete_supported_create = if action == "CREATE_USER" {
                    static CREATE_USER_FORM: std::sync::OnceLock<regex::Regex> =
                        std::sync::OnceLock::new();
                    CREATE_USER_FORM
                        .get_or_init(|| {
                            regex::Regex::new(r"(?is)\bCREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?'[^']+'\s*@\s*'[^']+'\s+IDENTIFIED\s+BY\s+'(?:''|[^'])*'")
                                .expect("static supported CREATE USER regex")
                        })
                        .is_match(statement)
                } else {
                    true
                };
                let extract_statement = match action {
                    "CREATE_USER" => account.is_some() && complete_supported_create,
                    "DROP_USER" => account.is_some(),
                    _ => true,
                };
                if extract_statement {
                    statements.push(MysqlPrivilegeStatement {
                        form,
                        action,
                        line: statement_line
                            + statement[..keyword_start]
                                .bytes()
                                .filter(|byte| *byte == b'\n')
                                .count(),
                        account,
                    });
                    output.extend(statement.chars().map(|character| {
                        if character == '\n' {
                            '\n'
                        } else {
                            ' '
                        }
                    }));
                } else {
                    output.push_str(&redact_mysql_create_user_password(statement));
                }
            } else {
                output.push_str(statement);
            }
            statement_line += statement.bytes().filter(|byte| *byte == b'\n').count();
            start = cursor;
        }
    }
    output.push_str(&source[start..]);
    (output, statements)
}

/// Remove a CREATE USER password from an unsupported statement before it can
/// enter parser diagnostics. Preserve character positions and source lines.
fn redact_mysql_create_user_password(statement: &str) -> String {
    static PASSWORD: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PASSWORD
        .get_or_init(|| {
            regex::Regex::new(r"(?is)(\bIDENTIFIED\s+BY\s+)(?:'(?:''|[^'])*'|[^\s;,]+)")
                .expect("static MySQL password redaction regex")
        })
        .replace_all(statement, |captures: &regex::Captures<'_>| {
            let matched = captures.get(0).unwrap();
            let prefix = captures.get(1).unwrap();
            let secret = &matched.as_str()[prefix.end()..];
            let mut redacted = prefix.as_str().to_string();
            redacted.extend(secret.chars().map(
                |character| {
                    if character == '\n' {
                        '\n'
                    } else {
                        ' '
                    }
                },
            ));
            redacted
        })
        .into_owned()
}

fn add_mysql_privilege_statement_nodes(
    graph: &mut CodeGraph,
    file_id: NodeId,
    file_path: &Path,
    statements: Vec<MysqlPrivilegeStatement>,
) -> ParserResult<()> {
    for statement in statements {
        let unsupported = if statement.action == "DROP_USER" || statement.action == "CREATE_USER" {
            "MySQL user-account management syntax is not represented"
        } else {
            "MySQL grant-option privilege semantics are not represented"
        };
        let node_id = graph
            .add_node(
                NodeType::Generic,
                sql_node_properties(
                    file_path,
                    statement.form,
                    "mysql_privilege_statement",
                    statement.line,
                )
                .with("action", statement.action)
                .with("coverage", "partial")
                .with("unsupported_constructs", unsupported),
            )
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
        let mut properties = PropertyMap::new();
        if let Some(account) = statement.account {
            properties.insert("account".to_string(), PropertyValue::String(account));
        }
        if !properties.is_empty() {
            graph
                .update_node_properties(node_id, properties)
                .map_err(|error| ParserError::GraphError(error.to_string()))?;
        }
        graph
            .add_edge(file_id, node_id, EdgeType::Contains, PropertyMap::new())
            .map_err(|error| ParserError::GraphError(error.to_string()))?;
    }
    Ok(())
}

fn strip_mysql_dynamic_statements(source: &str) -> (String, Vec<MysqlDynamicStatement>) {
    static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let prefix = PREFIX.get_or_init(|| {
        regex::Regex::new(
            r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|/\*.*?\*/\s*)*)(PREPARE\b|EXECUTE\b|DEALLOCATE\s+PREPARE\b)",
        )
        .expect("static MySQL dynamic statement prefix regex")
    });
    let mut output = String::with_capacity(source.len());
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    let mut statement_line = 1usize;
    let mut state = SqlLexState::Normal;
    while cursor < source.len() {
        let bytes = source.as_bytes();
        if bytes[cursor] >= 0x80 {
            cursor += utf8_char_width(bytes[cursor]);
            continue;
        }
        let event = next_lex_event(bytes, &mut cursor, &mut state);
        if matches!(event, SqlLexEvent::Terminator) {
            let statement = &source[start..cursor];
            if let Some(captures) = prefix.captures(statement) {
                let token = captures[1].to_ascii_uppercase();
                let kind = if token.starts_with("DEALLOCATE") {
                    "dynamic_sql_deallocate"
                } else if token == "PREPARE" {
                    "dynamic_sql_prepare"
                } else {
                    "dynamic_sql_execute"
                };
                statements.push(MysqlDynamicStatement {
                    kind,
                    line: statement_line
                        + statement[..captures.get(1).unwrap().start()]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count(),
                });
                output.extend(statement.chars().map(
                    |character| {
                        if character == '\n' {
                            '\n'
                        } else {
                            ' '
                        }
                    },
                ));
            } else {
                output.push_str(statement);
            }
            statement_line += statement.bytes().filter(|byte| *byte == b'\n').count();
            start = cursor;
        }
    }
    output.push_str(&source[start..]);
    (output, statements)
}

/// Remove MySQL client `DELIMITER` commands and rewrite their terminators to
/// semicolons while preserving source line count. This lets sqlparser consume
/// each stored routine as one AST statement, including its nested body.
fn normalize_mysql_delimiters(source: &str, path: &Path) -> ParserResult<String> {
    let mut output = String::with_capacity(source.len());
    let mut delimiter = ";".to_string();
    let mut state = SqlLexState::Normal;
    for line in source.split_inclusive('\n') {
        if matches!(state, SqlLexState::Normal) {
            let trimmed = line.trim_start();
            if trimmed
                .get(..9)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("DELIMITER"))
            {
                let mut fields = trimmed.split_ascii_whitespace();
                let command = fields.next().unwrap_or_default();
                let value = fields.next();
                let trailing_comment = value
                    .and_then(|value| trimmed.find(value).map(|position| position + value.len()))
                    .map(|position| trimmed[position..].trim_start())
                    .unwrap_or_default();
                if !command.eq_ignore_ascii_case("DELIMITER")
                    || value.is_none()
                    || (!trailing_comment.is_empty()
                        && !trailing_comment.starts_with("--")
                        && !trailing_comment.starts_with('#')
                        && !(trailing_comment.starts_with("/*")
                            && trailing_comment.ends_with("*/")))
                {
                    return Err(ParserError::UnsupportedFeature(
                        path.to_path_buf(),
                        "malformed MySQL DELIMITER command".to_string(),
                    ));
                }
                delimiter = value.unwrap().to_string();
                if delimiter.len() > 16
                    || delimiter
                        .bytes()
                        .any(|byte| byte.is_ascii_whitespace() || byte == b'\'')
                {
                    return Err(ParserError::UnsupportedFeature(
                        path.to_path_buf(),
                        "unsupported MySQL DELIMITER token".to_string(),
                    ));
                }
                output.extend(line.chars().map(
                    |character| {
                        if character == '\n' {
                            '\n'
                        } else {
                            ' '
                        }
                    },
                ));
                continue;
            }
        }

        let bytes = line.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            if state == SqlLexState::SingleQuoted
                && bytes[cursor] == b'\\'
                && bytes.get(cursor + 1) == Some(&b'\'')
            {
                output.push_str("''");
                cursor += 2;
                continue;
            }
            if state == SqlLexState::SingleQuoted
                && bytes[cursor] == b'\\'
                && bytes.get(cursor + 1) == Some(&b'"')
            {
                output.push('"');
                cursor += 2;
                continue;
            }
            if matches!(state, SqlLexState::Normal)
                && delimiter != ";"
                && bytes[cursor..].starts_with(delimiter.as_bytes())
            {
                output.push(';');
                cursor += delimiter.len();
                continue;
            }
            if matches!(state, SqlLexState::Normal) && bytes[cursor..].starts_with(b":=") {
                output.push('=');
                cursor += 2;
                continue;
            }
            if bytes[cursor] >= 0x80 {
                let start = cursor;
                cursor += utf8_char_width(bytes[cursor]);
                output.push_str(&line[start..cursor]);
                continue;
            }
            let start = cursor;
            let _ = next_lex_event(bytes, &mut cursor, &mut state);
            output.push_str(&line[start..cursor]);
        }
    }

    // sqlparser models procedural bodies, but its dialect parser expects an
    // `AS` introducer that MySQL does not use. It also does not parse MySQL's
    // IF ... THEN wrapper or dynamic PREPARE statement. Keep executable static
    // statements in the AST, while the procedure node records these omitted
    // constructs as partial coverage.
    if output.to_ascii_uppercase().contains("CREATE PROCEDURE") {
        output = replace_matches_with_whitespace(r"(?is)\bIF\s+NOT\s+EXISTS\s*\(", &output);
        output = replace_matches_with_whitespace(r"(?is)\bIF\s+[^;]*?\bTHEN\b", &output);
        output = replace_matches_with_terminator(r"(?is)\)\s*THEN\b", &output);
        output = replace_matches_with_whitespace(
            r"(?is)\bEND\s+IF\s*;|\bDECLARE\b[^;]*;|\bLEAVE\s+[A-Za-z_][A-Za-z0-9_]*\s*;|(?im)^[ \t]*[A-Za-z_][A-Za-z0-9_]*\s*:",
            &output,
        );
    }
    let begin = regex::Regex::new(
        r"(?is)(\bCREATE\s+PROCEDURE\b[^;]*?\))\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*:\s*)?(BEGIN\b)",
    )
    .expect("static routine header regex");
    Ok(begin.replace_all(&output, "$1 AS $2").into_owned())
}

fn utf8_char_width(first: u8) -> usize {
    match first {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

fn replace_matches_with_whitespace(pattern: &str, source: &str) -> String {
    let regex = regex::Regex::new(pattern).expect("static SQL normalization regex");
    regex
        .replace_all(source, |captures: &regex::Captures<'_>| {
            captures[0]
                .chars()
                .map(|character| if character == '\n' { '\n' } else { ' ' })
                .collect::<String>()
        })
        .into_owned()
}

fn replace_matches_with_terminator(pattern: &str, source: &str) -> String {
    let regex = regex::Regex::new(pattern).expect("static SQL terminator regex");
    regex
        .replace_all(source, |captures: &regex::Captures<'_>| {
            let mut result = String::with_capacity(captures[0].len());
            result.push(';');
            result.extend(captures[0].chars().skip(1).map(|character| {
                if character == '\n' {
                    '\n'
                } else {
                    ' '
                }
            }));
            result
        })
        .into_owned()
}

fn delimiter_command(line: &[u8]) -> Option<Result<String, String>> {
    let text = std::str::from_utf8(line).ok()?;
    let trimmed = text.trim_start();
    let (command, rest) = trimmed.split_once(char::is_whitespace)?;
    if !command.eq_ignore_ascii_case("DELIMITER") {
        return None;
    }
    let mut fields = rest.split_ascii_whitespace();
    let Some(value) = fields.next() else {
        return Some(Err("malformed MySQL DELIMITER command".to_string()));
    };
    if fields.next().is_some() {
        return Some(Err("malformed MySQL DELIMITER command".to_string()));
    }
    if value.len() > 16 || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Some(Err("unsupported MySQL DELIMITER token".to_string()));
    }
    Some(Ok(value.to_string()))
}

fn map_source_line(line_map: &[usize], compact_line: usize) -> usize {
    line_map
        .get(compact_line.saturating_sub(1))
        .copied()
        .unwrap_or(compact_line)
}

fn parse_mysql_key_directive(statement: &str, line: usize) -> Option<MysqlKeyDirective> {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static ALTER_START: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?is)^\s*(?:(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|/\*[^!].*?\*/\s*)*)(?:/\*!\d*\s*)?ALTER\s+TABLE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*))?)\s+(DISABLE|ENABLE)\s+KEYS\s*(?:\*/)?\s*;?\s*$",
        )
        .expect("static MySQL key directive regex")
    });
    let captures = pattern.captures(statement)?;
    let table = captures.get(1)?.as_str().replace(' ', "");
    let matched = captures.get(0).unwrap();
    let alter_start = ALTER_START.get_or_init(|| {
        regex::Regex::new(r"(?i)ALTER\s+TABLE").expect("static ALTER TABLE line regex")
    });
    let alter_offset = alter_start
        .find(matched.as_str())
        .map(|found| matched.start() + found.start())
        .unwrap_or(matched.start());
    let line = line.saturating_add(
        statement[..alter_offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
    );
    let action = if captures.get(2)?.as_str().eq_ignore_ascii_case("DISABLE") {
        "DISABLE"
    } else {
        "ENABLE"
    };
    Some(MysqlKeyDirective {
        table,
        action,
        line,
    })
}

impl CodeParser for SqlParser {
    fn language(&self) -> &str {
        "sql"
    }

    fn file_extensions(&self) -> &[&str] {
        EXTENSIONS
    }

    fn parse_file(&self, path: &Path, graph: &mut CodeGraph) -> ParserResult<FileInfo> {
        let start = Instant::now();
        if !self.can_parse(path) {
            return Err(ParserError::ParseError(
                path.to_path_buf(),
                "Invalid file extension for SQL parser".to_string(),
            ));
        }
        let metadata = std::fs::metadata(path)
            .map_err(|error| ParserError::IoError(path.to_path_buf(), error))?;
        if metadata.len() > MAX_SQL_FILE_SIZE_BYTES {
            return Err(ParserError::FileTooLarge(
                path.to_path_buf(),
                usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            ));
        }
        let before = graph.node_count();
        let result = if metadata.len() > self.config.max_file_size as u64 {
            self.parse_large_bulk_file(path, graph)
        } else {
            let source = std::fs::read_to_string(path)
                .map_err(|error| ParserError::IoError(path.to_path_buf(), error))?;
            self.parse(&source, path, graph)
        };
        self.record(
            result.is_ok(),
            start.elapsed(),
            graph.node_count().saturating_sub(before),
        );
        result
    }

    fn parse_source(
        &self,
        source: &str,
        file_path: &Path,
        graph: &mut CodeGraph,
    ) -> ParserResult<FileInfo> {
        self.parse(source, file_path, graph)
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SqlLexState {
    Normal,
    SingleQuoted,
    DoubleQuoted,
    BacktickQuoted,
    LineComment,
    BlockComment,
}

#[derive(Clone, Copy)]
enum SqlLexEvent {
    Normal(u8),
    Terminator,
    Ignored,
}

fn is_values_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == b'('
}

fn has_sql_tokens(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    let mut state = SqlLexState::Normal;
    while cursor < bytes.len() {
        match next_lex_event(bytes, &mut cursor, &mut state) {
            SqlLexEvent::Normal(byte) if !byte.is_ascii_whitespace() && byte != b';' => {
                return true;
            }
            SqlLexEvent::Terminator | SqlLexEvent::Ignored | SqlLexEvent::Normal(_) => {}
        }
    }
    false
}

fn read_limited_sql_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut read = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(read);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > MAX_SQL_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SQL line exceeds bounded scanner buffer",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        read += take;
        if newline.is_some() {
            return Ok(read);
        }
    }
}

fn looks_like_insert_prefix(statement: &[u8]) -> bool {
    let prefix = statement
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take(8)
        .collect::<Vec<_>>();
    (prefix.len() >= 7
        && prefix[..6].eq_ignore_ascii_case(b"INSERT")
        && prefix[6].is_ascii_whitespace())
        || (prefix.len() >= 8
            && prefix[..7].eq_ignore_ascii_case(b"REPLACE")
            && prefix[7].is_ascii_whitespace())
}

fn ends_with_values_keyword(statement: &[u8]) -> bool {
    let end = statement
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace() && *byte != b'(')
        .map_or(0, |position| position + 1);
    let start = statement[..end]
        .iter()
        .rposition(|byte| byte.is_ascii_whitespace() || *byte == b'(')
        .map_or(0, |position| position + 1);
    statement[start..end].eq_ignore_ascii_case(b"VALUES")
}

fn parse_bulk_insert_header(statement: &[u8]) -> Option<String> {
    let prefix = String::from_utf8(statement.to_vec()).ok()?;
    let sql = format!("{prefix} (NULL);");
    let mut statements = Parser::parse_sql(&MySqlDialect {}, &sql).ok()?;
    if statements.len() != 1 {
        return None;
    }
    match statements.remove(0) {
        Statement::Insert(insert) => match insert.table {
            sqlparser::ast::TableObject::TableName(name) => Some(name.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn scan_bulk_line(
    bytes: &[u8],
    state: &mut SqlLexState,
    depth: &mut usize,
    rows: &mut u64,
    ended: &mut bool,
    trailing_statement: &mut bool,
    path: &Path,
) -> ParserResult<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        match next_lex_event(bytes, &mut cursor, state) {
            SqlLexEvent::Normal(byte) if *ended => {
                if !byte.is_ascii_whitespace() {
                    *trailing_statement = true;
                }
            }
            SqlLexEvent::Normal(b'(') => {
                if *depth == 0 {
                    *rows = rows.saturating_add(1);
                }
                *depth += 1;
            }
            SqlLexEvent::Normal(b')') => {
                if *depth == 0 {
                    return Err(ParserError::ParseError(
                        path.to_path_buf(),
                        "unexpected closing parenthesis in bulk INSERT".to_string(),
                    ));
                }
                *depth -= 1;
            }
            SqlLexEvent::Normal(_) | SqlLexEvent::Ignored => {}
            SqlLexEvent::Terminator => {
                if *depth != 0 {
                    return Err(ParserError::ParseError(
                        path.to_path_buf(),
                        "unbalanced row tuple in bulk INSERT".to_string(),
                    ));
                }
                *ended = true;
            }
        }
    }
    Ok(())
}

fn next_lex_event(bytes: &[u8], cursor: &mut usize, state: &mut SqlLexState) -> SqlLexEvent {
    let byte = bytes[*cursor];
    let next = bytes.get(*cursor + 1).copied();
    match *state {
        SqlLexState::Normal => {
            if byte == b'#'
                || (byte == b'-'
                    && next == Some(b'-')
                    && bytes
                        .get(*cursor + 2)
                        .is_some_and(|following| following.is_ascii_whitespace()))
            {
                *state = SqlLexState::LineComment;
                *cursor += if byte == b'#' { 1 } else { 2 };
                SqlLexEvent::Ignored
            } else if byte == b'/' && next == Some(b'*') {
                *state = SqlLexState::BlockComment;
                *cursor += 2;
                SqlLexEvent::Ignored
            } else if byte == b'\'' || byte == b'"' || byte == b'`' {
                *state = match byte {
                    b'\'' => SqlLexState::SingleQuoted,
                    b'"' => SqlLexState::DoubleQuoted,
                    _ => SqlLexState::BacktickQuoted,
                };
                *cursor += 1;
                SqlLexEvent::Ignored
            } else {
                *cursor += 1;
                if byte == b';' {
                    SqlLexEvent::Terminator
                } else {
                    SqlLexEvent::Normal(byte)
                }
            }
        }
        SqlLexState::LineComment => {
            *cursor += 1;
            if byte == b'\n' {
                *state = SqlLexState::Normal;
            }
            SqlLexEvent::Ignored
        }
        SqlLexState::BlockComment => {
            if byte == b'*' && next == Some(b'/') {
                *state = SqlLexState::Normal;
                *cursor += 2;
            } else {
                *cursor += 1;
            }
            SqlLexEvent::Ignored
        }
        SqlLexState::SingleQuoted | SqlLexState::DoubleQuoted | SqlLexState::BacktickQuoted => {
            let quote = match *state {
                SqlLexState::SingleQuoted => b'\'',
                SqlLexState::DoubleQuoted => b'"',
                SqlLexState::BacktickQuoted => b'`',
                _ => unreachable!(),
            };
            if byte == b'\\' && *state != SqlLexState::BacktickQuoted {
                *cursor += if next.is_some() { 2 } else { 1 };
            } else if byte == quote {
                if next == Some(quote) {
                    *cursor += 2;
                } else {
                    *cursor += 1;
                    *state = SqlLexState::Normal;
                }
            } else {
                *cursor += 1;
            }
            SqlLexEvent::Ignored
        }
    }
}

#[derive(Default)]
struct RelationCollector {
    relations: Vec<(String, usize)>,
}

impl Visitor for RelationCollector {
    type Break = std::convert::Infallible;

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        let span = relation.span();
        self.relations.push((
            relation.to_string(),
            usize::try_from(span.start.line).unwrap_or(0),
        ));
        ControlFlow::Continue(())
    }
}

fn definition(statement: &Statement) -> Option<(&'static str, String)> {
    match statement {
        Statement::CreateTable(table) => Some(("table", table.name.to_string())),
        Statement::CreateView(view) => Some(("view", view.name.to_string())),
        Statement::CreateIndex(index) => {
            index.name.as_ref().map(|name| ("index", name.to_string()))
        }
        Statement::CreateProcedure { name, .. } => Some(("stored_procedure", name.to_string())),
        Statement::CreateTrigger(trigger) => Some(("trigger", trigger.name.to_string())),
        _ => None,
    }
}

fn statement_kind(statement: &Statement) -> &'static str {
    match statement {
        Statement::CreateTable(_) => "create_table",
        Statement::CreateView(_) => "create_view",
        Statement::CreateIndex(_) => "create_index",
        Statement::CreateProcedure { .. } => "create_procedure",
        Statement::CreateTrigger(_) => "create_trigger",
        Statement::AlterTable { .. } => "alter_table",
        Statement::Insert(_) => "insert",
        Statement::Update { .. } => "update",
        Statement::Delete(_) => "delete",
        Statement::Query(_) => "query",
        _ => "statement",
    }
}

fn statement_line(statement: &Statement, source: &str) -> usize {
    let span_line = usize::try_from(statement.span().start.line).unwrap_or(0);
    if span_line > 0 {
        return span_line;
    }
    if let Statement::CreateProcedure { name, .. } = statement {
        if let Some(name_offset) = source.find(&name.to_string()) {
            let prefix = &source[..name_offset];
            if let Some(start) = prefix.to_ascii_lowercase().rfind("create procedure") {
                return source[..start]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1;
            }
        }
    }
    span_line
}

fn sql_node_properties(path: &Path, name: &str, kind: &str, line: usize) -> PropertyMap {
    PropertyMap::new()
        .with("name", name)
        .with("kind", kind)
        .with("language", "sql")
        .with("path", path.to_string_lossy().to_string())
        .with("line_start", i64::try_from(line).unwrap_or(0))
}

fn simple_sql_identifier(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('`');
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$'))
        .then(|| value.to_ascii_lowercase())
}

pub(crate) fn sql_relation_parts(name: &str, current: Option<&str>) -> Option<(Option<String>, String)> {
    let parts: Vec<_> = name.split('.').collect();
    match parts.as_slice() {
        [table] => Some((current.map(str::to_owned), simple_sql_identifier(table)?)),
        [schema, table] => Some((Some(simple_sql_identifier(schema)?), simple_sql_identifier(table)?)),
        _ => None,
    }
}

fn sql_relation_key(name: &str, current: Option<&str>) -> String {
    match sql_relation_parts(name, current) {
        Some((Some(schema), table)) if schema.is_empty() => format!("?\0{table}"),
        Some((schema, table)) => format!("{}\0{table}", schema.unwrap_or_default()),
        None => format!("!{}\0{}", current.unwrap_or_default(), name.to_ascii_lowercase()),
    }
}

fn sql_relation_properties(path: &Path, name: &str, kind: &str, line: usize, current: Option<&str>) -> PropertyMap {
    let properties = sql_node_properties(path, name, kind, line);
    match sql_relation_parts(name, current) {
        Some((Some(schema), _)) => properties.with("sql_schema", schema),
        _ => properties,
    }
}

fn sql_schema_at_line(changes: &[(usize, Option<String>)], line: usize) -> Option<&str> {
    if line == 0 { return (!changes.is_empty()).then_some(""); }
    let mut current = None;
    let mut i = 0;
    while i < changes.len() {
        let (change_line, schema) = &changes[i];
        if *change_line == 0 || *change_line == line { return Some(""); }
        if *change_line > line { break; }
        let mut next = i + 1;
        while next < changes.len() && changes[next].0 == *change_line { next += 1; }
        current = if next - i > 1 { Some("") } else { schema.as_deref() };
        i = next;
    }
    current
}

fn normalize_name(name: &str) -> String {
    name.trim_matches('`').to_ascii_lowercase()
}

fn error_location(message: &str) -> (usize, usize) {
    // sqlparser includes locations in parser errors as "at Line: N, Column: M".
    // Tokenizer failures can lack a span; preserve the message and use 1:1 then.
    let Some((line_part, column_part)) = message.split_once("at Line: ") else {
        return (1, 1);
    };
    let _ = line_part;
    let Some((line, column_part)) = column_part.split_once(", Column: ") else {
        return (1, 1);
    };
    let column = column_part
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    (line.parse().unwrap_or(1), column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph::{Direction, EdgeType};
    use std::io::Write as _;

    fn graph() -> CodeGraph {
        CodeGraph::in_memory().unwrap()
    }

    #[test]
    fn schema_switches_and_ambiguous_definitions_do_not_cross_link() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser.parse_source(
            "USE alpha;\nCREATE TABLE item (id INT);\nSELECT * FROM item;\nUSE beta;\nCREATE TABLE item (id INT);\nSELECT * FROM item;\nSELECT * FROM `alpha`.`item`;\nCREATE TABLE repeated (id INT);\nCREATE TABLE repeated (id INT);\nSELECT * FROM repeated;",
            Path::new("schema-switch.sql"), &mut graph,
        ).unwrap();
        let table = |name: &str, schema: &str| graph.iter_nodes().filter(|(_, n)|
            n.properties.get_string("kind") == Some("table") &&
            n.properties.get_string("name") == Some(name) &&
            n.properties.get_string("sql_schema") == Some(schema))
            .map(|(id, _)| id).collect::<Vec<_>>();
        let alpha = table("item", "alpha")[0];
        let beta = table("item", "beta")[0];
        let duplicate = table("repeated", "beta");
        assert_eq!(duplicate.len(), 2);
        let ref_nodes = graph.iter_nodes().filter(|(_, n)| n.properties.get_string("kind") == Some("table_reference") && n.properties.get_string("name") == Some("repeated")).map(|(id, _)| id).collect::<Vec<_>>();
        assert_eq!(ref_nodes.len(), 1);
        for d in duplicate { assert!(graph.get_edges_between(ref_nodes[0], d).unwrap().is_empty()); }
        let mut statement_targets = Vec::new();
        for (id, n) in graph.iter_nodes() {
            if n.properties.get_string("kind") != Some("statement") { continue; }
            let line = n.properties.get_int("line_start").unwrap_or(0);
            if (line == 3 || line == 6 || line == 7) && !graph.get_edges_between(id, alpha).unwrap().is_empty() { statement_targets.push((line, "alpha")); }
            if (line == 3 || line == 6 || line == 7) && !graph.get_edges_between(id, beta).unwrap().is_empty() { statement_targets.push((line, "beta")); }
        }
        statement_targets.sort();
        assert_eq!(statement_targets, vec![(3, "alpha"), (6, "beta"), (7, "alpha")]);
    }

    #[test]
    fn streamed_bulk_inserts_keep_their_use_schema() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(&mut file, b"USE alpha;\nCREATE TABLE item (id INT);\nINSERT INTO item VALUES (1),(2);\nUSE beta;\nCREATE TABLE item (id INT);\nINSERT INTO item VALUES (3),(4);\n").unwrap();
        parser.parse_file(file.path(), &mut graph).unwrap();
        let mut inserts = graph.iter_nodes().filter(|(_, n)| n.properties.get_string("kind") == Some("bulk_insert"))
            .map(|(id, n)| (n.properties.get_int("line_start").unwrap_or(0), id)).collect::<Vec<_>>();
        inserts.sort();
        assert_eq!(inserts.len(), 2);
        for ((_, insert), expected) in inserts.into_iter().zip(["alpha", "beta"]) {
            let targets = graph.get_neighbors_by_edge_type(insert, Direction::Outgoing, EdgeType::References).unwrap();
            assert_eq!(targets.len(), 1);
            assert_eq!(graph.get_node(targets[0]).unwrap().properties.get_string("sql_schema"), Some(expected));
        }
    }

    #[test]
    fn streamed_same_line_use_fails_closed() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(&mut file, b"CREATE TABLE item (id INT);\nUSE beta; INSERT INTO item VALUES (1),(2);\n").unwrap();
        parser.parse_file(file.path(), &mut graph).unwrap();
        let insert = graph.iter_nodes().find(|(_, n)| n.properties.get_string("kind") == Some("bulk_insert")).unwrap().0;
        let targets = graph.get_neighbors_by_edge_type(insert, Direction::Outgoing, EdgeType::References).unwrap();
        assert_eq!(targets.len(), 1);
        let target = graph.get_node(targets[0]).unwrap();
        assert_eq!(target.properties.get_string("kind"), Some("table_reference"));
        assert_eq!(target.properties.get_string("sql_schema"), Some(""));
    }

    #[test]
    fn unordered_same_line_schema_changes_remain_unknown_until_next_use() {
        let changes = vec![(2, Some("alpha".to_string())), (2, Some("beta".to_string())), (4, Some("gamma".to_string()))];
        assert_eq!(sql_schema_at_line(&changes, 3), Some(""));
        assert_eq!(sql_schema_at_line(&changes, 5), Some("gamma"));
    }

    #[test]
    fn unknown_use_contexts_never_share_local_definitions() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser.parse_source("USE `one.bad`;\nCREATE TABLE item (id INT);\nUSE `two.bad`;\nSELECT * FROM item;", Path::new("unknown.sql"), &mut graph).unwrap();
        let reference = graph.iter_nodes().find(|(_, n)| n.properties.get_string("kind") == Some("table_reference") && n.properties.get_string("name") == Some("item")).unwrap();
        assert_eq!(reference.1.properties.get_string("sql_schema"), Some(""));
    }

    #[test]
    fn mysql_key_directives_keep_schema_after_use_changes() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser.parse_source("USE alpha;\nCREATE TABLE item (id INT);\nALTER TABLE item DISABLE KEYS;\nUSE beta;\nCREATE TABLE item (id INT);\nALTER TABLE item DISABLE KEYS;", Path::new("keys.sql"), &mut graph).unwrap();
        let mut directives = graph.iter_nodes().filter(|(_, n)| n.properties.get_string("kind") == Some("mysql_key_directive"))
            .map(|(id, n)| (n.properties.get_int("line_start").unwrap_or(0), id)).collect::<Vec<_>>();
        directives.sort();
        assert_eq!(directives.len(), 2);
        for ((_, directive), expected) in directives.into_iter().zip(["alpha", "beta"]) {
            let targets = graph.get_neighbors_by_edge_type(directive, Direction::Outgoing, EdgeType::References).unwrap();
            assert_eq!(targets.len(), 1);
            assert_eq!(graph.get_node(targets[0]).unwrap().properties.get_string("sql_schema"), Some(expected));
        }
    }

    #[test]
    fn mysql_persist_and_check_changes_are_visible_as_partial() {
        let source = "-- settings\nSET PERSIST innodb_buffer_pool_size = 2147483648;\nALTER TABLE `population_director_owner_state`\n DROP CHECK `old`, ADD CONSTRAINT `new` CHECK (`current_epoch` BETWEEN 1 AND `highest_owner_level_seen`);";
        let mut graph = graph();
        SqlParser::with_config(ParserConfig::default()).parse_source(source, Path::new("migration.sql"), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, n)| n).collect();
        assert!(nodes.iter().any(|n| n.properties.get_string("kind") == Some("mysql_persistent_setting") && n.properties.get_string("coverage") == Some("partial") && n.properties.get_int("line_start") == Some(2)));
        assert!(nodes.iter().any(|n| n.properties.get_string("kind") == Some("mysql_table_option") && n.properties.get_string("option") == Some("check_constraint") && n.properties.get_string("coverage") == Some("partial")));
        assert!(nodes.iter().any(|n| n.properties.get_string("name") == Some("`population_director_owner_state`")));
        assert!(SqlParser::with_config(ParserConfig::default()).parse_source("SET PERSIST x = ;", Path::new("bad.sql"), &mut CodeGraph::in_memory().unwrap()).is_err());
    }

    #[test]
    fn parses_mysql_objects_and_source_located_relationships() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "CREATE TABLE `characters` (id INT PRIMARY KEY);\nCREATE VIEW `active_characters` AS SELECT id FROM `characters`;";
        parser
            .parse_source(source, Path::new("migration.sql"), &mut graph)
            .unwrap();

        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();
        let definitions: Vec<_> = nodes
            .iter()
            .filter(|node| {
                node.properties.get_string("kind") == Some("table")
                    || node.properties.get_string("kind") == Some("view")
            })
            .collect();
        assert_eq!(definitions.len(), 2);
        assert!(definitions.iter().any(|node| {
            node.properties.get_string("name") == Some("`characters`")
                && node.properties.get_int("line_start") == Some(1)
        }));
        assert!(definitions.iter().any(|node| {
            node.properties.get_string("name") == Some("`active_characters`")
                && node.properties.get_int("line_start") == Some(2)
        }));
        let view = definitions
            .iter()
            .find(|node| node.properties.get_string("kind") == Some("view"))
            .unwrap();
        let refs = graph
            .get_neighbors_by_edge_type(view.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert!(!refs.is_empty());
    }

    #[test]
    fn parses_delimited_mysql_procedure_body_and_table_relationship() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "-- routine migration\nDELIMITER $$\nCREATE PROCEDURE `refresh_x`()\nBEGIN\n  SELECT id FROM `x`;\nEND$$\nDELIMITER ;\n";
        let info = parser
            .parse_source(source, Path::new("routine.sql"), &mut graph)
            .unwrap();
        let procedure = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("stored_procedure"))
            .unwrap();
        assert_eq!(procedure.properties.get_string("name"), Some("`refresh_x`"));
        assert_eq!(procedure.properties.get_int("line_start"), Some(3));
        let references = graph
            .get_neighbors_by_edge_type(procedure.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert!(references.iter().any(|id| {
            graph
                .get_node(*id)
                .is_ok_and(|node| node.properties.get_string("name") == Some("`x`"))
        }));
        assert_eq!(info.line_count, 7);
    }

    #[test]
    fn records_mysql_function_and_static_table_reference_as_partial() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "-- helper\nDELIMITER $$\nCREATE FUNCTION AddObject(x double)\nRETURNS decimal\nDETERMINISTIC\nBEGIN\nINSERT INTO `gameobject` (`id`) VALUES (1);\nRETURN x;\nEND $$\nDELIMITER ;\nCREATE FUNCTION PackDate(x INT) RETURNS INT UNSIGNED DETERMINISTIC RETURN x;\n",
                Path::new("function.sql"),
                &mut graph,
            )
            .unwrap();
        let functions: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_stored_function"))
            .collect();
        assert_eq!(functions.len(), 2);
        let function = functions
            .iter()
            .find(|node| node.properties.get_string("name") == Some("AddObject"))
            .expect("partial stored function node");
        assert_eq!(function.properties.get_string("name"), Some("AddObject"));
        assert_eq!(function.properties.get_int("line_start"), Some(3));

        assert_eq!(function.properties.get_string("coverage"), Some("partial"));
        let table = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| {
                node.properties.get_string("kind") == Some("table_reference")
                    && node.properties.get_string("name") == Some("`gameobject`")
            })
            .expect("static function table reference");
        assert_eq!(table.properties.get_int("line_start"), Some(7));
    }

    #[test]
    fn parses_versioned_create_database_encryption_option() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "-- mysqldump header\n/**/\nCREATE DATABASE IF NOT EXISTS `demo` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;\nCREATE TABLE t (id INT);";
        parser
            .parse_source(source, Path::new("versioned.sql"), &mut graph)
            .unwrap();
        assert!(graph
            .iter_nodes()
            .any(
                |(_, node)| node.properties.get_string("kind") == Some("table")
                    && node.properties.get_string("name") == Some("t")
            ));
        assert!(graph
            .iter_nodes()
            .any(|(_, node)| node.properties.get_string("kind")
                == Some("mysql_database_encryption_option")
                && node.properties.get_string("coverage") == Some("partial")
                && node.properties.get_string("version_guard") == Some("80016")));
    }

    #[test]
    fn parses_valid_signal_and_preserves_procedure_references() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "DELIMITER //\nCREATE PROCEDURE p() BEGIN\n IF NOT EXISTS (SELECT 1 FROM t WHERE id = n) THEN\n SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic';\n END IF;\nEND//\nDELIMITER ;";
        parser
            .parse_source(source, Path::new("signal.sql"), &mut graph)
            .unwrap();
        let procedure = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("stored_procedure"))
            .unwrap();
        assert_eq!(procedure.properties.get_string("coverage"), Some("partial"));
        assert!(procedure
            .properties
            .get_string("unsupported_constructs")
            .unwrap_or_default()
            .contains("SIGNAL"));
        let refs = graph
            .get_neighbors_by_edge_type(procedure.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert!(refs.iter().any(|id| graph
            .get_node(*id)
            .is_ok_and(|node| node.properties.get_string("name") == Some("t"))));
    }

    #[test]
    fn rejects_malformed_signal_and_versioned_encryption() {
        let parser = SqlParser::with_config(ParserConfig::default());
        for source in ["DELIMITER //\nCREATE PROCEDURE p() BEGIN SIGNAL SQLSTATE '4' SET MESSAGE_TEXT = 'bad'; END//\nDELIMITER ;", "CREATE DATABASE d /*!80016 DEFAULT ENCRYPTION='maybe' */;"] {
            assert!(parser.parse_source(source, Path::new("bad.sql"), &mut graph()).is_err());
        }
    }

    #[test]
    fn signal_normalization_does_not_touch_literals_comments_or_other_procedures() {
        let source = "SELECT 'SIGNAL SQLSTATE ''45000'''; -- SIGNAL SQLSTATE '45000';\nCREATE PROCEDURE p() BEGIN SELECT 1; SIGNAL SQLSTATE '45000'; END; CREATE PROCEDURE q() BEGIN SELECT 1; END;";
        let (normalized, procedures, _, _) = strip_mysql_procedure_signals(source);
        assert!(normalized.starts_with("SELECT 'SIGNAL SQLSTATE ''45000'''; -- SIGNAL SQLSTATE '45000';"));
        assert_eq!(procedures, vec!["p"]);
        assert!(normalized.contains("CREATE PROCEDURE q() BEGIN SELECT 1; END;"));
        let outside = "SIGNAL SQLSTATE '45000';";
        assert_eq!(strip_mysql_procedure_signals(outside).0, outside);
        let loop_source = "CREATE PROCEDURE p() BEGIN WHILE x DO SELECT 1; END WHILE; SIGNAL SQLSTATE '45000'; END;";
        assert_eq!(strip_mysql_procedure_signals(loop_source).1, vec!["p"]);
        let case_source = "CREATE PROCEDURE p() BEGIN CASE x WHEN 1 THEN SELECT 1; END CASE; END; SIGNAL SQLSTATE '45000';";
        assert_eq!(strip_mysql_procedure_signals(case_source).0, case_source);
        let commented_case = "CREATE PROCEDURE p() BEGIN CASE x WHEN 1 THEN SELECT 1; END /* comment */ CASE; END; SIGNAL SQLSTATE '45000';";
        assert_eq!(strip_mysql_procedure_signals(commented_case).0, commented_case);
        let unicode_state = "CREATE PROCEDURE p() BEGIN SIGNAL SQLSTATE 'K5000'; END;";
        assert_eq!(strip_mysql_procedure_signals(unicode_state).0, unicode_state);
        assert_eq!(normalize_procedure_name("db . `p name`"), normalize_procedure_name("db.`p name`"));
    }

    #[test]
    fn same_line_qualified_procedures_keep_distinct_signal_coverage() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "DELIMITER //\nCREATE PROCEDURE `db` . `p`() BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'one; two'; END// CREATE PROCEDURE q() BEGIN SELECT 1; END//\nDELIMITER ;";
        parser.parse_source(source, Path::new("two.sql"), &mut graph).unwrap();
        let procedures: Vec<_> = graph.iter_nodes().map(|(_, node)| node).filter(|node| node.properties.get_string("kind") == Some("stored_procedure")).collect();
        assert_eq!(procedures.len(), 2);
        let marked = procedures.iter().filter(|node| node.properties.get_string("unsupported_constructs").unwrap_or_default().contains("SIGNAL")).count();
        assert_eq!(marked, 1);
        assert!(procedures.iter().any(|node| node.properties.get_string("name").unwrap_or_default().contains("`p`") && node.properties.get_string("coverage") == Some("partial")));
    }

    #[test]
    fn streamed_sql_keeps_signal_coverage_and_database_option() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(&mut file, b"CREATE DATABASE d /*!80016 DEFAULT ENCRYPTION='N' */;\nDELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1 FROM t; SIGNAL SQLSTATE '45000'; END//\nDELIMITER ;\nINSERT INTO t VALUES (1), (2);\n").unwrap();
        parser.parse_file(file.path(), &mut graph).unwrap();
        let procedure = graph.iter_nodes().map(|(_, node)| node).find(|node| node.properties.get_string("kind") == Some("stored_procedure")).unwrap();
        assert!(procedure.properties.get_string("unsupported_constructs").unwrap_or_default().contains("SIGNAL"));
        assert!(graph.iter_nodes().any(|(_, node)| node.properties.get_string("kind") == Some("mysql_database_encryption_option")));
    }

    #[test]
    fn streams_mixed_database_option_key_directive_and_routine() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(&mut file, b"CREATE DATABASE d /*!80016 DEFAULT ENCRYPTION='N' */;\nCREATE TABLE t (id INT);\nALTER TABLE t DISABLE KEYS;\nDELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1 FROM t; SIGNAL SQLSTATE '45000'; END//\nDELIMITER ;\nINSERT INTO t VALUES (1), (2);\n").unwrap();
        parser.parse_file(file.path(), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();
        assert!(nodes.iter().any(|node| node.properties.get_string("kind") == Some("mysql_database_encryption_option")));
        assert!(nodes.iter().any(|node| node.properties.get_string("kind") == Some("mysql_key_directive")));
        assert!(nodes.iter().any(|node| node.properties.get_string("kind") == Some("bulk_insert")));
        let procedure = nodes.iter().find(|node| node.properties.get_string("kind") == Some("stored_procedure")).unwrap();
        assert!(procedure.properties.get_string("unsupported_constructs").unwrap_or_default().contains("SIGNAL"));
        let refs = graph.get_neighbors_by_edge_type(procedure.id, Direction::Outgoing, EdgeType::References).unwrap();
        assert!(refs.iter().any(|id| graph.get_node(*id).is_ok_and(|node| node.properties.get_string("name") == Some("t"))));
    }

    #[test]
    fn rejects_procedure_local_key_directive_without_losing_reference() {
        let source = "DELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1; ALTER TABLE t DISABLE KEYS; SIGNAL SQLSTATE '45000'; END//\nDELIMITER ;\nINSERT INTO t VALUES (1), (2);\n";
        for streaming in [false, true] {
            let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(if streaming { 64 } else { 4096 }));
            let mut graph = graph();
            let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
            std::io::Write::write_all(&mut file, source.as_bytes()).unwrap();
            assert!(matches!(parser.parse_file(file.path(), &mut graph), Err(ParserError::UnsupportedFeature(_, _))));
            assert_eq!(graph.node_count(), 0);
        }
    }

    #[test]
    fn parses_trigger_declaration_and_preserves_static_references() {
        let source = "DELIMITER //\nCREATE TRIGGER tr BEFORE INSERT ON target FOR EACH ROW BEGIN\n DECLARE counter INT;\n SELECT COUNT(*) INTO counter FROM source WHERE id = NEW.id;\n IF counter > 0 THEN SET NEW.value = (SELECT value FROM source WHERE id = NEW.id); ELSE SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture'; END IF;\nEND//\nDELIMITER ;";
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser.parse_source(source, Path::new("trigger.sql"), &mut graph).unwrap();
        let trigger = graph.iter_nodes().map(|(_, node)| node).find(|node| node.properties.get_string("kind") == Some("trigger")).unwrap();
        assert_eq!(trigger.properties.get_string("coverage"), Some("partial"));
        assert!(trigger.properties.get_string("unsupported_constructs").unwrap_or_default().contains("SIGNAL"));
        let refs = graph.get_neighbors_by_edge_type(trigger.id, Direction::Outgoing, EdgeType::References).unwrap();
        for name in ["target", "source"] {
            assert!(refs.iter().any(|id| graph.get_node(*id).is_ok_and(|node| node.properties.get_string("name") == Some(name))), "missing trigger reference: {name}");
        }
    }

    #[test]
    fn rejects_malformed_trigger_declaration() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "DELIMITER //\nCREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN DECLARE counter INT garbage; SELECT 1; END//\nDELIMITER ;";
        assert!(parser.parse_source(source, Path::new("bad-trigger.sql"), &mut graph).is_err());
        assert_eq!(graph.node_count(), 0);
    }


    #[test]
    fn marks_mysql_routine_control_flow_and_dynamic_sql_as_partial() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source = "DELIMITER $$\nCREATE PROCEDURE p()\nBEGIN\n IF NOT EXISTS (\n  SELECT 1 FROM information_schema.columns WHERE table_name = 'x'\n ) THEN\n  SET @sql = CONCAT('ALTER TABLE ', 'x');\n  PREPARE q FROM @sql;\n  EXECUTE q;\n  DEALLOCATE PREPARE q;\n END IF;\nEND$$\nDELIMITER ;\n";
        parser
            .parse_source(source, Path::new("partial_routine.sql"), &mut graph)
            .unwrap();
        let procedure = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("stored_procedure"))
            .unwrap();
        assert_eq!(procedure.properties.get_string("coverage"), Some("partial"));
        assert_eq!(
            procedure.properties.get_string("unsupported_constructs"),
            Some("conditional control flow, dynamic SQL PREPARE")
        );
        let references = graph
            .get_neighbors_by_edge_type(procedure.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert!(references.iter().any(|id| {
            graph.get_node(*id).is_ok_and(|node| {
                node.properties.get_string("name") == Some("information_schema.columns")
            })
        }));
    }

    #[test]
    fn rejects_malformed_delimiter_directives() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let error = parser
            .parse_source("DELIMITER\nSELECT 1;", Path::new("bad.sql"), &mut graph)
            .unwrap_err();
        assert!(matches!(error, ParserError::UnsupportedFeature(_, _)));
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn accepts_inline_comment_after_delimiter_reset_but_rejects_extra_tokens() {
        let source = normalize_mysql_delimiters(
            "DELIMITER //\nSELECT 1//\nDELIMITER ; -- reset delimiter\nSELECT 2;\n",
            Path::new("delimiter_comment.sql"),
        )
        .unwrap();
        assert!(source.contains("SELECT 1;"));
        assert!(source.contains("SELECT 2;"));
        assert!(normalize_mysql_delimiters(
            "DELIMITER ; junk\nSELECT 1;\n",
            Path::new("bad_delimiter.sql"),
        )
        .is_err());
    }

    #[test]
    fn parses_mysql_variable_assignment_and_engine_table_options() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "SET @OGUID := 50675;\nALTER TABLE `auth_version` ADD COLUMN `sql_rev` VARCHAR(100) NOT NULL FIRST, ENGINE=INNODB;",
                Path::new("mysql_options.sql"),
                &mut graph,
            )
            .unwrap();
        let option = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("mysql_table_option"))
            .unwrap();
        assert_eq!(option.properties.get_string("value"), Some("INNODB"));
        assert_eq!(option.properties.get_int("line_start"), Some(2));
        let references = graph
            .get_neighbors_by_edge_type(option.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert!(references.iter().any(|id| {
            graph
                .get_node(*id)
                .is_ok_and(|node| node.properties.get_string("name") == Some("`auth_version`"))
        }));
    }

    #[test]
    fn records_legacy_mysql_engine_row_format_and_charset_options_partially() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "ALTER TABLE `account` ENGINE InnoDB ROW_FORMAT=DEFAULT, CONVERT TO CHARSET utf8mb4 COLLATE 'utf8mb4_unicode_ci';\nALTER TABLE `account_muted` CHARSET = 'utf8', MODIFY `mutedby` varchar(50) NOT NULL;\nALTER TABLE `updates` CHANGE `state` `state` ENUM('RELEASED','CUSTOM') CHARSET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT 'RELEASED' NOT NULL;\nALTER TABLE `item_dbc` COLLATE='utf8mb4_unicode_ci';\n",
                Path::new("legacy_options.sql"),
                &mut graph,
            )
            .unwrap();

        let mut options: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_table_option"))
            .collect();
        options.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(options.len(), 4);
        assert_eq!(options[0].properties.get_int("line_start"), Some(1));
        assert_eq!(options[1].properties.get_int("line_start"), Some(2));
        assert_eq!(options[2].properties.get_int("line_start"), Some(3));
        assert_eq!(options[3].properties.get_int("line_start"), Some(4));
        assert!(options
            .iter()
            .all(|node| node.properties.get_string("coverage") == Some("partial")));
        assert!(options.iter().all(|node| node
            .properties
            .get_string("unsupported_constructs")
            .is_some()));
        let table_refs = graph
            .iter_nodes()
            .filter(|(_, node)| node.properties.get_string("kind") == Some("table_reference"))
            .count();
        assert_eq!(table_refs, 4);
    }

    #[test]
    fn reports_mysql_syntax_errors_with_source_position() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let error = parser
            .parse_source("SELECT *\nFROM ;", Path::new("bad.sql"), &mut graph)
            .unwrap_err();
        assert!(
            matches!(error, ParserError::SyntaxError(path, line, _, _) if path == Path::new("bad.sql") && line >= 1)
        );
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn refuses_oversized_data_sql_without_partial_graph() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let error = parser
            .parse_source(
                "INSERT INTO names VALUES ('this is too large');",
                Path::new("data.sql"),
                &mut graph,
            )
            .unwrap_err();
        assert!(matches!(error, ParserError::FileTooLarge(_, _)));
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn streams_large_mysql_values_insert_as_bounded_row_summary() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CREATE TABLE `travel_nodes` (id INT);\nINSERT INTO `travel_nodes` (id) VALUES\n(1),\n(2),\n(3);\n",
        )
        .unwrap();

        let info = parser.parse_file(file.path(), &mut graph).unwrap();
        let bulk = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("bulk_insert"))
            .unwrap();
        assert_eq!(bulk.properties.get_int("row_count"), Some(3));
        assert_eq!(bulk.properties.get_int("line_start"), Some(2));
        assert_eq!(info.line_count, 5);
        let table = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("name") == Some("`travel_nodes`"))
            .unwrap();
        assert!(graph
            .get_neighbors_by_edge_type(bulk.id, Direction::Outgoing, EdgeType::References)
            .unwrap()
            .contains(&table.id));
    }

    #[test]
    fn rejects_unbalanced_large_insert_before_graph_mutation() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CREATE TABLE `travel_nodes` (id INT);\nINSERT INTO `travel_nodes` (id) VALUES\n(1,\n(2);\n",
        )
        .unwrap();

        assert!(parser.parse_file(file.path(), &mut graph).is_err());
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn streams_multiple_large_insert_batches() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CREATE TABLE `travel_nodes` (id INT);\nINSERT INTO `travel_nodes` (id) VALUES\n(1),(2);\nINSERT INTO `travel_nodes` (id) VALUES\n(3);\n",
        )
        .unwrap();

        parser.parse_file(file.path(), &mut graph).unwrap();
        let mut batches: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("bulk_insert"))
            .collect();
        batches.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].properties.get_int("row_count"), Some(2));
        assert_eq!(batches[1].properties.get_int("row_count"), Some(1));
        assert_eq!(batches[0].properties.get_int("line_start"), Some(2));
        assert_eq!(batches[1].properties.get_int("line_start"), Some(4));
    }

    #[test]
    fn resolves_many_bulk_inserts_through_one_cached_table_reference() {
        const INSERTS: usize = 4096;
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(&mut file, b"CREATE TABLE `many_rows` (id INT);\n").unwrap();
        for value in 0..INSERTS {
            writeln!(file, "INSERT INTO `many_rows` VALUES ({value});").unwrap();
        }

        parser.parse_file(file.path(), &mut graph).unwrap();
        let nodes: Vec<_> = graph.iter_nodes().map(|(_, node)| node).collect();
        let inserts: Vec<_> = nodes
            .iter()
            .filter(|node| node.properties.get_string("kind") == Some("bulk_insert"))
            .collect();
        assert_eq!(inserts.len(), INSERTS);
        let tables: Vec<_> = nodes
            .iter()
            .filter(|node| node.properties.get_string("kind") == Some("table"))
            .collect();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].properties.get_string("name"), Some("`many_rows`"));
        assert!(inserts.iter().all(|insert| graph
            .get_neighbors_by_edge_type(insert.id, Direction::Outgoing, EdgeType::References)
            .unwrap()
            .contains(&tables[0].id)));
    }

    #[test]
    fn streamed_insert_never_binds_to_another_files_table() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(64));
        let mut graph = graph();
        parser.parse("CREATE TABLE `same_name` (id INT);", Path::new("/other/schema.sql"), &mut graph).unwrap();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        for value in 0..20 { writeln!(file, "INSERT INTO `same_name` VALUES ({value});").unwrap(); }
        parser.parse_file(file.path(), &mut graph).unwrap();
        let table = graph.iter_nodes().map(|(_, n)| n).find(|n|
            n.properties.get_string("kind") == Some("table")).unwrap();
        let inserts: Vec<_> = graph.iter_nodes().map(|(_, n)| n).filter(|n|
            n.properties.get_string("kind") == Some("bulk_insert")).collect();
        assert_eq!(inserts.len(), 20);
        for n in &inserts {
            let targets = graph.get_neighbors_by_edge_type(n.id, Direction::Outgoing, EdgeType::References).unwrap();
            assert!(!targets.contains(&table.id) && targets.iter().any(|id| {
                let target = graph.get_node(*id).unwrap();
                target.properties.get_string("kind") == Some("table_reference")
                    && target.properties.get_string("path") == file.path().to_str()
            }), "targets={targets:?} unrelated={}", table.id);
        }
    }

    #[test]
    fn streams_mysql_dump_key_directives_with_table_references() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CREATE TABLE `broadcast_text_locale` (id INT);\n/*!40000 ALTER TABLE `broadcast_text_locale` DISABLE KEYS */;\nINSERT INTO `broadcast_text_locale` VALUES\n(1);\n/*!40000 ALTER TABLE `broadcast_text_locale` ENABLE KEYS */;\n",
        )
        .unwrap();

        parser.parse_file(file.path(), &mut graph).unwrap();
        let mut directives: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_key_directive"))
            .collect();
        assert_eq!(directives.len(), 2);
        directives.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(
            directives[0].properties.get_string("action"),
            Some("DISABLE_keys")
        );
        assert_eq!(directives[0].properties.get_int("line_start"), Some(2));
        assert_eq!(
            directives[1].properties.get_string("action"),
            Some("ENABLE_keys")
        );
        assert_eq!(directives[1].properties.get_int("line_start"), Some(5));
        let table = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| {
                node.properties.get_string("kind") == Some("table")
                    && node.properties.get_string("name") == Some("`broadcast_text_locale`")
            })
            .unwrap();
        for directive in directives {
            assert!(graph
                .get_neighbors_by_edge_type(directive.id, Direction::Outgoing, EdgeType::References)
                .unwrap()
                .contains(&table.id));
        }
    }

    #[test]
    fn parses_small_mysql_dump_key_directives_with_table_references() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "CREATE TABLE `items` (id INT);\n-- update key index\n/*!40000 ALTER TABLE `items` DISABLE KEYS */;\n/*!40000 ALTER TABLE `items` ENABLE KEYS */;\n",
                Path::new("small_dump.sql"),
                &mut graph,
            )
            .unwrap();
        let mut directives: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_key_directive"))
            .collect();
        assert_eq!(directives.len(), 2);
        directives.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(directives[0].properties.get_int("line_start"), Some(3));
        assert_eq!(directives[1].properties.get_int("line_start"), Some(4));
        let table = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("table"))
            .unwrap();
        for directive in directives {
            assert!(graph
                .get_neighbors_by_edge_type(directive.id, Direction::Outgoing, EdgeType::References)
                .unwrap()
                .contains(&table.id));
        }
    }

    #[test]
    fn reports_mysql_dynamic_sql_as_partial_without_inventing_references() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "SET @ddl := 'ALTER TABLE `items` ADD COLUMN c INT';\nPREPARE stmt FROM @ddl;\nEXECUTE stmt;\nDEALLOCATE PREPARE stmt;\n",
                Path::new("dynamic.sql"),
                &mut graph,
            )
            .unwrap();
        let mut dynamic: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_dynamic_sql"))
            .collect();
        dynamic.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(dynamic.len(), 3);
        assert_eq!(
            dynamic[0].properties.get_string("name"),
            Some("dynamic_sql_prepare")
        );
        assert_eq!(
            dynamic[0].properties.get_string("coverage"),
            Some("partial")
        );
        assert_eq!(dynamic[0].properties.get_int("line_start"), Some(2));
        assert_eq!(dynamic[1].properties.get_int("line_start"), Some(3));
        assert_eq!(dynamic[2].properties.get_int("line_start"), Some(4));
        assert!(graph
            .get_neighbors_by_edge_type(dynamic[0].id, Direction::Outgoing, EdgeType::References)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn preserves_explicit_partial_nodes_for_mysql_grant_option_revokes() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "REVOKE GRANT OPTION ON `acore_playerbots` . * FROM 'acore'@'localhost';\nREVOKE ALL PRIVILEGES, GRANT OPTION FROM 'acore'@'localhost';\n",
                Path::new("drop_mysql.sql"),
                &mut graph,
            )
            .unwrap();
        let mut revokes: Vec<_> = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .filter(|node| node.properties.get_string("kind") == Some("mysql_privilege_statement"))
            .collect();
        revokes.sort_by_key(|node| node.properties.get_int("line_start"));
        assert_eq!(revokes.len(), 2);
        assert_eq!(revokes[0].properties.get_int("line_start"), Some(1));
        assert_eq!(revokes[1].properties.get_int("line_start"), Some(2));
        assert!(revokes
            .iter()
            .all(|node| node.properties.get_string("coverage") == Some("partial")));
    }

    #[test]
    fn records_create_user_account_without_retaining_credentials() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let source =
            "-- account setup\nCREATE USER 'acore'@'localhost' IDENTIFIED BY 'secret-sentinel';\n";
        parser
            .parse_source(source, Path::new("create_mysql.sql"), &mut graph)
            .unwrap();
        let account = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("mysql_privilege_statement"))
            .unwrap();
        assert_eq!(account.properties.get_string("action"), Some("CREATE_USER"));
        assert_eq!(
            account.properties.get_string("account"),
            Some("acore@localhost")
        );
        assert_eq!(account.properties.get_int("line_start"), Some(2));
        assert_eq!(account.properties.get_string("coverage"), Some("partial"));
        assert!(graph.iter_nodes().all(|(_, node)| node
            .properties
            .iter()
            .all(|(_, value)| !matches!(value, PropertyValue::String(text) if text.contains("secret-sentinel")))));
    }

    #[test]
    fn malformed_create_user_redacts_password_before_error_reporting() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        let result = parser.parse_source(
            "CREATE USER IDENTIFIED BY 'diagnostic-secret-sentinel';\n",
            Path::new("malformed_user.sql"),
            &mut graph,
        );
        let error = result.unwrap_err().to_string();
        assert!(!error.contains("diagnostic-secret-sentinel"));
        assert_eq!(graph.node_count(), 0);
    }

    #[test]
    fn parses_quoted_mysql_create_table_engine_and_collation_options() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "CREATE TABLE `requirements` (id INT, comment varchar(255) COLLATE 'utf8mb4_general_ci') COMMENT='keep quoted text' ENGINE='MyISAM' COLLATE 'utf8mb4_general_ci';\n",
                Path::new("quoted_options.sql"),
                &mut graph,
            )
            .unwrap();
        let table = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("table"))
            .unwrap();
        assert_eq!(table.properties.get_string("name"), Some("`requirements`"));
        assert_eq!(table.properties.get_int("line_start"), Some(1));
    }

    #[test]
    fn records_mysql_drop_rename_comment_alter_as_partial() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "ALTER TABLE `access_requirement`\nDROP `item`,\nDROP `item2`,\nRENAME TO `dungeon_access_template`,\nCOMMENT='Dungeon/raid access template and single requirements';\n",
                Path::new("rename_comment.sql"),
                &mut graph,
            )
            .unwrap();
        let alter = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("mysql_table_option"))
            .unwrap();
        assert_eq!(alter.properties.get_int("line_start"), Some(1));
        assert_eq!(alter.properties.get_string("coverage"), Some("partial"));
        assert!(alter
            .properties
            .get_string("value")
            .unwrap()
            .contains("rename_to=`dungeon_access_template`"));
    }

    #[test]
    fn marks_historical_empty_alter_as_malformed_partial_coverage() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "ALTER TABLE `dungeon_access_requirements`;\n",
                Path::new("empty_alter.sql"),
                &mut graph,
            )
            .unwrap();
        let malformed = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("mysql_table_option"))
            .unwrap();
        assert_eq!(
            malformed.properties.get_string("option"),
            Some("malformed_empty_alter")
        );
        assert_eq!(malformed.properties.get_int("line_start"), Some(1));
        assert_eq!(malformed.properties.get_string("coverage"), Some("partial"));
        assert!(malformed
            .properties
            .get_string("unsupported_constructs")
            .unwrap()
            .contains("malformed"));
    }

    #[test]
    fn records_comma_join_mysql_multi_table_update_with_table_relationships() {
        let parser = SqlParser::with_config(ParserConfig::default());
        let mut graph = graph();
        parser
            .parse_source(
                "-- normalize herb nodes\nUPDATE `gameobject` g,\n       `herb_varieties` hv\nSET g.id = hv.normal\nWHERE g.id = hv.special;\n",
                Path::new("multi_update.sql"),
                &mut graph,
            )
            .unwrap();
        let update = graph
            .iter_nodes()
            .map(|(_, node)| node)
            .find(|node| node.properties.get_string("kind") == Some("mysql_multi_table_update"))
            .unwrap();
        assert_eq!(update.properties.get_int("line_start"), Some(2));
        assert_eq!(update.properties.get_string("coverage"), Some("partial"));
        assert!(update
            .properties
            .get_string("unsupported_constructs")
            .unwrap()
            .contains("assignment"));
        let refs = graph
            .get_neighbors_by_edge_type(update.id, Direction::Outgoing, EdgeType::References)
            .unwrap();
        assert_eq!(refs.len(), 2);
        let referenced_names: Vec<_> = refs
            .iter()
            .map(|id| {
                graph
                    .get_node(*id)
                    .unwrap()
                    .properties
                    .get_string("name")
                    .unwrap()
            })
            .collect();
        assert!(referenced_names.contains(&"`gameobject`"));
        assert!(referenced_names.contains(&"`herb_varieties`"));
        let herb = refs
            .iter()
            .map(|id| graph.get_node(*id).unwrap())
            .find(|node| node.properties.get_string("name") == Some("`herb_varieties`"))
            .unwrap();
        assert_eq!(herb.properties.get_int("line_start"), Some(3));
    }

    #[test]
    fn unknown_large_mysql_alter_syntax_is_refused_without_partial_graph() {
        let parser = SqlParser::with_config(ParserConfig::default().with_max_file_size(32));
        let mut graph = graph();
        let mut file = tempfile::NamedTempFile::with_suffix(".sql").unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CREATE TABLE `t` (id INT);\nALTER TABLE `t` DISABLE MAGIC;\nINSERT INTO `t` VALUES\n(1);\n",
        )
        .unwrap();

        assert!(matches!(
            parser.parse_file(file.path(), &mut graph),
            Err(ParserError::SyntaxError(_, _, _, _))
        ));
        assert_eq!(graph.node_count(), 0);
    }
}
