// Copyright 2024-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! C++ parser for CodeGraph
//!
//! This crate provides a C++ language parser that extracts code entities
//! (classes, structs, functions, namespaces) and their relationships from C++ source files.
//!
//! # Example
//!
//! ```rust
//! use codegraph::CodeGraph;
//! use codegraph_cpp::CppParser;
//! use codegraph_parser_api::CodeParser;
//! use std::path::Path;
//!
//! let parser = CppParser::new();
//! let mut graph = CodeGraph::in_memory().unwrap();
//!
//! let source = r#"
//!     class MyClass {
//!     public:
//!         void myMethod() {}
//!     };
//! "#;
//!
//! let file_info = parser.parse_source(source, Path::new("example.cpp"), &mut graph).unwrap();
//! println!("Found {} classes", file_info.classes.len());
//! ```
//!
//! **Author:** Andrey Vasilevsky \<anvanster@gmail.com\>
//! **License:** Apache-2.0
//! **Repository:** <https://github.com/anvanster/codegraph>

mod extractor;
mod mapper;
mod parser_impl;
mod sql_references;
mod visitor;

pub use parser_impl::CppParser;

/// Recognize constructs that require the C++ grammar in an ambiguous header.
/// Headers without such syntax remain ambiguous and should retain their default language.
pub fn has_cpp_header_syntax(source: &str) -> bool {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_cpp::LANGUAGE.into()).is_err() {
        return false;
    }
    let Some(tree) = parser.parse(source, None) else { return false };
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "class_specifier" | "template_declaration" | "namespace_definition"
            | "namespace_alias_definition" | "using_declaration" | "alias_declaration"
            | "concept_definition" | "qualified_identifier") {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

#[cfg(test)]
mod header_syntax_tests {
    use super::has_cpp_header_syntax;

    #[test]
    fn identifies_cpp_syntax_without_matching_c_comments_or_linkage() {
        assert!(has_cpp_header_syntax("template <typename T> class Cache {};"));
        assert!(has_cpp_header_syntax("namespace n { using Value = int; }"));
        assert!(has_cpp_header_syntax("std::string name;"));
        assert!(!has_cpp_header_syntax("/* class Cache {}; namespace n {} */\nstruct CRecord { int value; };"));
        assert!(!has_cpp_header_syntax("#ifdef __cplusplus\nextern \"C\" {\n#endif\nint f(void);\n#ifdef __cplusplus\n}\n#endif"));
    }
}
