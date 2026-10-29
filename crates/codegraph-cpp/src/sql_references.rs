// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Extract table names from literal database calls without storing SQL text.

use codegraph::{CodeGraph, GraphError, PropertyMap};
use codegraph_parser_api::FileInfo;
use sqlparser::ast::{ObjectName, Statement, Visit, Visitor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use tree_sitter::Node;

#[derive(Default)]
struct Relations(Vec<String>);

impl Visitor for Relations {
    type Break = std::convert::Infallible;
    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        self.0.push(relation.to_string());
        ControlFlow::Continue(())
    }
}

fn query_tables(sql: &str) -> Vec<String> {
    let normalized = sql.replace("{}", "?");
    let Ok(statements) = Parser::parse_sql(&MySqlDialect {}, &normalized) else {
        return Vec::new();
    };
    if statements.len() != 1
        || !matches!(
            statements[0],
            Statement::Query(_)
                | Statement::Insert(_)
                | Statement::Update { .. }
                | Statement::Delete(_)
        )
    {
        return Vec::new();
    }
    // shortcut: CTE aliases can look like tables; resolve them when CTE scope is modeled.
    if sql
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| word.eq_ignore_ascii_case("with"))
    {
        return Vec::new();
    }
    let mut relations = Relations::default();
    let _ = statements[0].visit(&mut relations);
    relations
        .0
        .into_iter()
        .filter_map(|name| {
            let name = name.trim_matches('`').to_ascii_lowercase();
            (!name.is_empty() && !name.contains('.') && !name.contains('`')).then_some(name)
        })
        .collect()
}

fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "concatenated_string" {
        let mut cursor = node.walk();
        let mut output = String::new();
        for child in node.named_children(&mut cursor) {
            output.push_str(&literal(child, source)?);
        }
        return Some(output);
    }
    if node.kind() != "string_literal" {
        return None;
    }
    let text = node.utf8_text(source.as_bytes()).ok()?;
    let text = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut output = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        output.push(match chars.next()? {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return None,
        });
    }
    Some(output)
}

fn collect_calls(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        if current.kind() == "call_expression" {
            if let (Some(function), Some(arguments)) = (
                current.child_by_field_name("function"),
                current.child_by_field_name("arguments"),
            ) {
                let name = function
                    .child_by_field_name("field")
                    .unwrap_or(function)
                    .utf8_text(source.as_bytes())
                    .unwrap_or("");
                let arg_index = match name.to_ascii_lowercase().as_str() {
                    "query" | "execute" | "exec" | "prepare" => Some(0),
                    "preparestatement" => Some(1),
                    _ => None,
                };
                if let Some(sql) = arg_index
                    .and_then(|i| arguments.named_child(i))
                    .and_then(|arg| literal(arg, source))
                {
                    result.extend(query_tables(&sql));
                }
            }
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    result
}

pub(crate) fn record(
    source: &str,
    file: &FileInfo,
    graph: &mut CodeGraph,
) -> Result<(), GraphError> {
    let lower = source.to_ascii_lowercase();
    if !["query", "execute", "exec", "prepare"]
        .iter()
        .any(|name| lower.contains(name))
    {
        return Ok(());
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return Ok(());
    }
    let Some(tree) = parser.parse(source, None) else {
        return Ok(());
    };
    let mut functions = HashMap::new();
    for id in &file.functions {
        let node = graph.get_node(*id)?;
        if let (Some(start), Some(end)) = (
            node.properties.get_int("line_start"),
            node.properties.get_int("line_end"),
        ) {
            functions
                .entry((start as usize, end as usize))
                .or_insert_with(Vec::new)
                .push(*id);
        }
    }
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "function_definition" {
            let key = (node.start_position().row + 1, node.end_position().row + 1);
            if let (Some([id]), Some(body)) = (
                functions.get(&key).map(Vec::as_slice),
                node.child_by_field_name("body"),
            ) {
                let mut tables: Vec<_> = collect_calls(body, source).into_iter().collect();
                tables.sort();
                if !tables.is_empty() {
                    graph.update_node_properties(
                        *id,
                        PropertyMap::new().with("sql_literal_tables", tables),
                    )?;
                }
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph_parser_api::CodeParser;
    use std::path::Path;

    #[test]
    fn extracts_formatted_and_adjacent_literals_and_prepared_statements() {
        let source = r#"
            void load() {
                db.Query("SELECT * FROM mail WHERE receiver = {}", receiver);
                PrepareStatement(MAIL_SEL, "SELECT id, " "receiver FROM mail_items WHERE id = ?", flags);
                db.Execute("UPDATE guild SET note = \"hello\" WHERE id = {}", id);
            }
        "#;
        let mut graph = CodeGraph::in_memory().unwrap();
        let info = crate::CppParser::new()
            .parse_source(source, Path::new("/repo/src/f.cpp"), &mut graph)
            .unwrap();
        let node = graph.get_node(info.functions[0]).unwrap();
        assert_eq!(
            node.properties
                .get_string_list("sql_literal_tables")
                .unwrap(),
            &[
                "guild".to_string(),
                "mail".to_string(),
                "mail_items".to_string()
            ]
        );
    }

    #[test]
    fn rejects_dynamic_and_unsafe_literal_forms() {
        let source = r#"void load() { db.Query(make_sql()); db.Query("SELECT * FROM \\x6dail"); }"#;
        let mut graph = CodeGraph::in_memory().unwrap();
        let info = crate::CppParser::new()
            .parse_source(source, Path::new("/repo/src/f.cpp"), &mut graph)
            .unwrap();
        assert!(graph
            .get_node(info.functions[0])
            .unwrap()
            .properties
            .get_string_list("sql_literal_tables")
            .is_none());
    }
}
