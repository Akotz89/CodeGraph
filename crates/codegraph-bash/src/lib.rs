// Copyright 2024-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Bash/Shell parser for CodeGraph

mod extractor;
mod mapper;
mod parser_impl;
mod visitor;

pub use parser_impl::BashParser;

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph::CodeGraph;
    use codegraph_parser_api::CodeParser;
    use std::path::Path;

    #[test]
    fn test_parser_creation() {
        let parser = BashParser::new();
        assert_eq!(parser.language(), "bash");
    }

    #[test]
    fn assignment_names_are_indexed_without_values_or_function_locals() {
        let parser = BashParser::new();
        let mut graph = CodeGraph::in_memory().unwrap();
        let source = r#"export GDB_ENABLED="fake-secret-value-123"
DB_AUTH_CUSTOM_PATHS+=("/fake/path")
ordinary="another-fake-secret"
function f() { local LOCAL_VALUE="private"; }
"#;
        parser.parse_source(source, Path::new("conf.sh.dist"), &mut graph).unwrap();
        let variables: Vec<_> = graph.iter_nodes().filter_map(|(_, node)|
            (node.node_type == codegraph::NodeType::Variable).then_some(node)).collect();
        let names: Vec<_> = variables.iter().filter_map(|node| node.properties.get_string("name")).collect();
        assert!(names.contains(&"GDB_ENABLED"));
        assert!(names.contains(&"DB_AUTH_CUSTOM_PATHS"));
        assert!(names.contains(&"ordinary"));
        assert!(!names.contains(&"LOCAL_VALUE"));
        for node in variables {
            let props = format!("{:?}", node.properties);
            assert!(!props.contains("fake-secret-value-123"));
            assert!(!props.contains("another-fake-secret"));
            assert!(!props.contains("/fake/path"));
        }
    }

    #[test]
    fn test_parse_simple_source() {
        let parser = BashParser::new();
        let mut graph = CodeGraph::in_memory().unwrap();

        let source = r#"#!/bin/bash
greet() {
    echo "Hello, world!"
}
"#;

        let result = parser.parse_source(source, Path::new("hello.sh"), &mut graph);
        assert!(result.is_ok());

        let file_info = result.unwrap();
        assert_eq!(file_info.functions.len(), 1);
    }
}
