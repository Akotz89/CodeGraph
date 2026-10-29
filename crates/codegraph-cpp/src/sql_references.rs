// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Extract table names from literal database calls without storing SQL text.

use codegraph::{CodeGraph, GraphError, PropertyMap};
use codegraph_parser_api::FileInfo;
use sqlparser::ast::{ObjectName, Query, Statement, Visit, Visitor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use tree_sitter::Node;

#[derive(Default)]
struct Relations {
    tables: Vec<String>,
    scopes: Vec<QueryScope>,
}

struct QueryScope {
    aliases: Vec<String>,
    bodies: Vec<*const Query>,
    visible: usize,
    parent_visible: Option<usize>,
    recursive: bool,
}

impl Visitor for Relations {
    type Break = std::convert::Infallible;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let mut parent_visible = None;
        if let Some(parent) = self.scopes.last_mut() {
            if let Some(index) = parent
                .bodies
                .iter()
                .position(|body| *body == query as *const Query)
            {
                parent_visible = Some(parent.visible);
                parent.visible = index + usize::from(parent.recursive);
            }
        }
        let with = query.with.as_ref();
        let aliases: Vec<String> = with
            .into_iter()
            .flat_map(|with| &with.cte_tables)
            .map(|cte| cte.alias.name.value.to_ascii_lowercase())
            .collect();
        let bodies = with
            .into_iter()
            .flat_map(|with| &with.cte_tables)
            .map(|cte| cte.query.as_ref() as *const Query)
            .collect();
        let recursive = with.is_some_and(|with| with.recursive);
        let visible = aliases.len();
        self.scopes.push(QueryScope {
            aliases,
            bodies,
            visible,
            parent_visible,
            recursive,
        });
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        if let Some(scope) = self.scopes.pop() {
            if let (Some(previous), Some(parent)) = (scope.parent_visible, self.scopes.last_mut()) {
                parent.visible = previous;
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        let name = relation.to_string();
        let simple = name.trim_matches('`').to_ascii_lowercase();
        let is_alias = !simple.contains('.')
            && self.scopes.iter().rev().any(|scope| {
                scope.aliases[..scope.visible]
                    .iter()
                    .any(|alias| alias == &simple)
            });
        if !is_alias {
            self.tables.push(name);
        }
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
    let mut relations = Relations::default();
    let _ = statements[0].visit(&mut relations);
    relations
        .tables
        .into_iter()
        .filter_map(|name| {
            let name = name.trim_matches('`').to_ascii_lowercase();
            (!name.is_empty() && !name.contains('.') && !name.contains('`')).then_some(name)
        })
        .collect()
}

fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "raw_string_literal" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "raw_string_content")
            .and_then(|content| content.utf8_text(source.as_bytes()).ok())
            .map(str::to_owned);
    }
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

#[derive(Default)]
struct Calls {
    tables: HashSet<String>,
    definitions: Vec<String>,
    uses: HashSet<String>,
}

fn collect_calls(root: Node<'_>, source: &str) -> Calls {
    let mut result = Calls::default();
    let mut occurrences: HashMap<String, usize> = HashMap::new();
    let mut declarations: HashMap<String, (usize, String)> = HashMap::new();
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        if current.kind() == "identifier" {
            if let Ok(name) = current.utf8_text(source.as_bytes()) {
                *occurrences.entry(name.to_owned()).or_default() += 1;
            }
        }
        if current.kind() == "init_declarator"
            && current.parent().and_then(|parent| parent.parent()) == Some(root)
        {
            if let (Some(name), Some(value)) = (
                current.child_by_field_name("declarator"),
                current.child_by_field_name("value"),
            ) {
                if name.kind() == "identifier" {
                    if let (Ok(name), Some(value)) =
                        (name.utf8_text(source.as_bytes()), literal(value, source))
                    {
                        declarations.insert(name.to_owned(), (current.end_byte(), value));
                    }
                }
            }
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
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
                let method = name.to_ascii_lowercase();
                let identifier = arguments
                    .named_child(0)
                    .filter(|node| node.kind() == "identifier")
                    .and_then(|node| node.utf8_text(source.as_bytes()).ok());
                if method == "getpreparedstatement" {
                    if let Some(identifier) = identifier {
                        result.uses.insert(identifier.to_owned());
                    }
                }
                let arg_index = match method.as_str() {
                    "query" | "execute" | "exec" | "prepare" => Some(0),
                    "preparestatement" => Some(1),
                    _ => None,
                };
                let tables = arg_index
                    .and_then(|i| arguments.named_child(i))
                    .and_then(|arg| {
                        literal(arg, source).or_else(|| {
                            if arg.kind() != "identifier" {
                                return None;
                            }
                            let name = arg.utf8_text(source.as_bytes()).ok()?;
                            let (decl_end, value) = declarations.get(name)?;
                            let mut ancestor = current;
                            while ancestor.parent().is_some_and(|parent| parent != root) {
                                ancestor = ancestor.parent()?;
                            }
                            (ancestor.parent() == Some(root)
                                && *decl_end < current.start_byte()
                                && occurrences.get(name) == Some(&2))
                            .then(|| value.clone())
                        })
                    })
                    .map(|sql| query_tables(&sql))
                    .unwrap_or_default();
                if method == "preparestatement" {
                    if let Some(identifier) = identifier {
                        result
                            .definitions
                            .push(format!("{}\t{}", identifier, tables.join("\t")));
                    }
                }
                result.tables.extend(tables);
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
                let calls = collect_calls(body, source);
                let mut tables: Vec<_> = calls.tables.into_iter().collect();
                tables.sort();
                let mut uses: Vec<_> = calls.uses.into_iter().collect();
                uses.sort();
                if !tables.is_empty() || !uses.is_empty() || !calls.definitions.is_empty() {
                    graph.update_node_properties(
                        *id,
                        PropertyMap::new()
                            .with("sql_literal_tables", tables)
                            .with("sql_prepared_definitions", calls.definitions)
                            .with("sql_prepared_uses", uses),
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
    fn resolves_cte_sources_without_aliases_or_scope_leaks() {
        assert_eq!(query_tables("WITH chances AS (SELECT * FROM creature_loot_template JOIN item_template ON 1=1) SELECT * FROM chances"), vec!["creature_loot_template", "item_template"]);
        assert_eq!(
            query_tables("WITH x AS (SELECT * FROM x) SELECT * FROM x"),
            vec!["x"]
        );
        assert_eq!(query_tables("WITH RECURSIVE x AS (SELECT * FROM base UNION ALL SELECT * FROM x) SELECT * FROM x"), vec!["base"]);
        assert_eq!(query_tables("WITH x AS (SELECT * FROM base) SELECT * FROM x WHERE EXISTS (WITH y AS (SELECT * FROM x JOIN inner_table ON 1=1) SELECT * FROM y)"), vec!["base", "inner_table"]);
        assert_eq!(query_tables("WITH a AS (SELECT * FROM b), b AS (SELECT * FROM source_table) SELECT * FROM a JOIN b ON 1=1"), vec!["b", "source_table"]);
        assert_eq!(query_tables("WITH x AS (SELECT * FROM outer_table) SELECT * FROM x WHERE EXISTS (WITH x AS (SELECT * FROM x) SELECT * FROM x)"), vec!["outer_table"]);
        assert_eq!(
            query_tables("SELECT * FROM mail WHERE subject = 'with friends'"),
            vec!["mail"]
        );
    }

    #[test]
    fn extracts_raw_local_query_and_rejects_mutation_or_shadowing() {
        let source = r####"
            void safe() {
                std::string q = R"SQL(WITH chances AS (SELECT * FROM creature_loot_template JOIN item_template ON 1=1) SELECT * FROM chances)SQL";
                db.Query(q);
            }
            void modified() {
                std::string q = R"SQL(SELECT * FROM mail)SQL";
                q = make_sql();
                db.Query(q);
            }
            void escaped() {
                std::string q = R"SQL(SELECT * FROM item_template)SQL";
                modify(q);
                db.Query(q);
            }
            void ambiguous() {
                std::string q = R"SQL(SELECT * FROM guild)SQL";
                if (condition) { std::string q = other(); db.Query(q); }
            }
        "####;
        let mut graph = CodeGraph::in_memory().unwrap();
        let info = crate::CppParser::new()
            .parse_source(source, Path::new("/repo/src/f.cpp"), &mut graph)
            .unwrap();
        let mut found = HashMap::new();
        for id in info.functions {
            let node = graph.get_node(id).unwrap();
            found.insert(
                node.properties.get_string("name").unwrap().to_owned(),
                node.properties
                    .get_string_list("sql_literal_tables")
                    .map(|values| values.to_vec()),
            );
        }
        assert_eq!(
            found["safe"],
            Some(vec![
                "creature_loot_template".to_string(),
                "item_template".to_string()
            ])
        );
        assert_eq!(found["modified"], None);
        assert_eq!(found["escaped"], None);
        assert_eq!(found["ambiguous"], None);
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
