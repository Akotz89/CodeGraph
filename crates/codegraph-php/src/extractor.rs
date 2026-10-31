// Copyright 2024-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! AST extraction for PHP source code

use codegraph_parser_api::{CodeIR, ModuleEntity, ParserConfig, ParserError};
use std::path::Path;
use tree_sitter::Parser;

use crate::visitor::PhpVisitor;

fn followed_by_named_argument_colon(mut tail: &[u8]) -> bool {
    loop {
        tail = tail.trim_ascii_start();
        if tail.starts_with(b"/*") {
            let Some(end) = tail.windows(2).position(|part| part == b"*/") else {
                return false;
            };
            tail = &tail[end + 2..];
        } else if tail.starts_with(b"//") || (tail.starts_with(b"#") && !tail.starts_with(b"#[")) {
            let Some(end) = tail.iter().position(|b| *b == b'\n' || *b == b'\r') else {
                return false;
            };
            tail = &tail[end..];
        } else {
            return tail.starts_with(b":") && !tail.starts_with(b"::");
        }
    }
}

// Tree-sitter rejects reserved words as PHP named-argument labels.
fn keyword_argument_errors(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    spans: &mut Vec<std::ops::Range<usize>>,
) {
    // In nested expressions the grammar can misread `new:` as object creation.
    if node.kind() == "object_creation_expression" && node.has_error() {
        let start = node.start_byte();
        let tail = &source[start..node.end_byte()];
        let in_arguments = std::iter::successors(node.parent(), |parent| parent.parent())
            .any(|parent| parent.kind() == "arguments");
        if in_arguments && tail.len() >= 4 && tail[..3].eq_ignore_ascii_case(b"new") {
            if followed_by_named_argument_colon(&tail[3..]) {
                spans.push(start..start + 3);
            }
        }
    }
    if node.is_error()
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "arguments")
    {
        let mut cursor = node.walk();
        let parts: Vec<_> = node
            .children(&mut cursor)
            .filter(|part| part.kind() != "comment")
            .collect();
        if let [label, colon] = parts.as_slice() {
            let name = &source[label.byte_range()];
            if !name.is_empty()
                && &source[colon.byte_range()] == b":"
                && (name[0].is_ascii_alphabetic() || name[0] == b'_')
                && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                spans.push(label.byte_range());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.has_error() {
            keyword_argument_errors(child, source, spans);
        }
    }
}

fn invalid_repaired_argument_order(
    node: tree_sitter::Node<'_>,
    spans: &[std::ops::Range<usize>],
) -> bool {
    if node.kind() == "arguments" {
        let mut cursor = node.walk();
        let arguments: Vec<_> = node
            .children(&mut cursor)
            .filter(|child| child.kind() == "argument")
            .collect();
        let repaired = arguments.iter().any(|argument| {
            argument
                .child_by_field_name("name")
                .is_some_and(|name| spans.contains(&name.byte_range()))
        });
        if repaired {
            let mut named = false;
            for argument in arguments {
                if argument.child_by_field_name("name").is_some() {
                    named = true;
                } else if named {
                    return true;
                }
            }
        }
    }
    let mut cursor = node.walk();
    let invalid = node
        .children(&mut cursor)
        .any(|child| invalid_repaired_argument_order(child, spans));
    invalid
}

/// Extract code entities and relationships from PHP source code
pub fn extract(
    source: &str,
    file_path: &Path,
    _config: &ParserConfig,
) -> Result<CodeIR, ParserError> {
    let mut parser = Parser::new();
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    parser
        .set_language(&language)
        .map_err(|e| ParserError::ParseError(file_path.to_path_buf(), e.to_string()))?;

    let mut tree = parser.parse(source, None).ok_or_else(|| {
        ParserError::ParseError(file_path.to_path_buf(), "Failed to parse".to_string())
    })?;

    if tree.root_node().has_error() {
        let mut spans = Vec::new();
        keyword_argument_errors(tree.root_node(), source.as_bytes(), &mut spans);
        if !spans.is_empty() {
            let mut normalized = source.as_bytes().to_vec();
            for span in &spans {
                normalized[span.clone()].fill(b'x');
            }
            tree = parser.parse(&normalized, None).ok_or_else(|| {
                ParserError::ParseError(file_path.to_path_buf(), "Failed to parse".to_string())
            })?;
            if !tree.root_node().has_error()
                && invalid_repaired_argument_order(tree.root_node(), &spans)
            {
                return Err(ParserError::SyntaxError(
                    file_path.to_path_buf(),
                    0,
                    0,
                    "Positional or unpacked argument after named argument".to_string(),
                ));
            }
        }
    }

    let root_node = tree.root_node();

    if root_node.has_error() {
        return Err(ParserError::SyntaxError(
            file_path.to_path_buf(),
            0,
            0,
            "Syntax error".to_string(),
        ));
    }

    let mut ir = CodeIR::new(file_path.to_path_buf());

    let module_name = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    ir.module = Some(ModuleEntity {
        name: module_name,
        path: file_path.display().to_string(),
        language: "php".to_string(),
        line_count: source.lines().count(),
        doc_comment: None,
        attributes: Vec::new(),
    });

    let mut visitor = PhpVisitor::new(source.as_bytes());
    visitor.visit_node(root_node);
    // shortcut: file-scope import aliases need name resolution before calls can be linked safely.
    if visitor.has_namespace_import {
        visitor.calls.retain(|call| call.caller != crate::FILE_SCOPE_CALLER);
    }

    ir.functions = visitor.functions;
    ir.classes = visitor.classes;
    ir.traits = visitor.traits;
    ir.imports = visitor.imports;
    ir.calls = visitor.calls;
    ir.inheritance = visitor.inheritance;
    ir.implementations = visitor.implementations;

    Ok(ir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_scope_calls_with_imports_are_not_guessed() {
        let source = "<?php\nuse function Other\\target as target;\ntarget();\n";
        let ir = extract(source, Path::new("caller.php"), &ParserConfig::default()).unwrap();
        assert!(ir.calls.iter().all(|call| call.caller != crate::FILE_SCOPE_CALLER));
    }

    #[test]
    fn parses_keyword_named_argument_but_rejects_bad_syntax() {
        let config = ParserConfig::default();
        let valid = "<?php\nfunction f($new) {}\nfunction caller() { f(new: 1); }";
        let ir = extract(valid, Path::new("valid.php"), &config).unwrap();
        assert!(ir.functions.iter().any(|f| f.name == "caller"));
        assert!(ir
            .calls
            .iter()
            .any(|c| c.caller == "caller" && c.callee == "f" && c.call_site_line == 3));
        let nested = "<?php function caller($v) { check(!f($v, new: 'x') && !$v->flag, 'ok'); }";
        let nested_ir = extract(nested, Path::new("nested.php"), &config).unwrap();
        assert!(nested_ir.calls.iter().any(|c| c.callee == "f"));
        let adjacent = "<?php $x = new Probe(); check(!f($x, new: 'x') && !$x->flag, 'ok');";
        assert!(extract(adjacent, Path::new("adjacent.php"), &config).is_ok());
        let commented = "<?php f(new /* note */ : 1);";
        assert!(extract(commented, Path::new("commented.php"), &config).is_ok());
        let nested_comment =
            "<?php $x = new Probe(); check(!f($x, new /* note */ : 'x') && !$x->flag, 'ok');";
        assert!(extract(nested_comment, Path::new("nested-comment.php"), &config).is_ok());
        let literals = "<?php function caller() { f('new:'); /* new: */ f(new: 1); }";
        assert!(extract(literals, Path::new("literals.php"), &config).is_ok());
        let duplicate = "<?php f(new: 1, new: 2);";
        assert!(extract(duplicate, Path::new("duplicate.php"), &config).is_ok());
        for invalid in ["<?php f(new: 1, 2);", "<?php f(new: 1, ...[2]);"] {
            assert!(matches!(
                extract(invalid, Path::new("bad-order.php"), &config),
                Err(ParserError::SyntaxError(..))
            ));
        }
        let invalid = "<?php function f($new) {} f(new: );";
        assert!(matches!(
            extract(invalid, Path::new("bad.php"), &config),
            Err(ParserError::SyntaxError(..))
        ));
        let unrelated_error = "<?php function f($new) {} f(new: 1); function broken( {";
        assert!(matches!(
            extract(unrelated_error, Path::new("bad.php"), &config),
            Err(ParserError::SyntaxError(..))
        ));
    }

    #[test]
    fn test_extract_simple_function() {
        let source = r#"<?php
function hello() {
    echo "Hello, world!";
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.functions.len(), 1);
        assert_eq!(ir.functions[0].name, "hello");
    }

    #[test]
    fn test_extract_class() {
        let source = r#"<?php
class Person {
    public string $name;
    private int $age;
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.classes.len(), 1);
        assert_eq!(ir.classes[0].name, "Person");
    }

    #[test]
    fn test_extract_interface() {
        let source = r#"<?php
interface Readable {
    public function read(): string;
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.traits.len(), 1);
        assert_eq!(ir.traits[0].name, "Readable");
    }

    #[test]
    fn test_extract_trait() {
        let source = r#"<?php
trait Loggable {
    public function log(string $message): void {
        echo $message;
    }
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.traits.len(), 1);
        assert_eq!(ir.traits[0].name, "Loggable");
    }

    #[test]
    fn test_extract_method() {
        let source = r#"<?php
class Calculator {
    public function add(int $a, int $b): int {
        return $a + $b;
    }
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.classes.len(), 1);
        // Methods are tracked within the class
    }

    #[test]
    fn test_extract_namespace_and_use() {
        let source = r#"<?php
namespace App\Controllers;

use App\Models\User;
use App\Services\AuthService;
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.imports.len(), 2);
    }

    #[test]
    fn test_extract_multiple_entities() {
        let source = r#"<?php
namespace App;

use Exception;

interface Shape {
    public function area(): float;
}

class Circle implements Shape {
    private float $radius;

    public function __construct(float $radius) {
        $this->radius = $radius;
    }

    public function area(): float {
        return 3.14 * $this->radius * $this->radius;
    }
}

function main(): void {
    echo "Hello";
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.traits.len(), 1);
        // Namespaced: App\Shape
        assert_eq!(ir.traits[0].name, "App\\Shape");
        assert_eq!(ir.classes.len(), 1);
        // Namespaced: App\Circle
        assert_eq!(ir.classes[0].name, "App\\Circle");
        assert!(!ir.functions.is_empty()); // main function
        assert_eq!(ir.imports.len(), 1);
    }

    #[test]
    fn test_extract_module_info() {
        let source = r#"<?php
function test(): void {
    echo "test";
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("module.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert!(ir.module.is_some());
        let module = ir.module.unwrap();
        assert_eq!(module.name, "module");
        assert_eq!(module.language, "php");
        assert!(module.line_count > 0);
    }

    #[test]
    fn test_extract_function_with_return_type() {
        let source = r#"<?php
function add(int $a, int $b): int {
    return $a + $b;
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.functions.len(), 1);
        assert_eq!(ir.functions[0].name, "add");
    }

    #[test]
    fn test_extract_enum() {
        let source = r#"<?php
enum Status: string {
    case Pending = 'pending';
    case Active = 'active';
    case Completed = 'completed';
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        // Enums are mapped to classes
        assert_eq!(ir.classes.len(), 1);
        assert_eq!(ir.classes[0].name, "Status");
    }

    #[test]
    fn test_extract_inheritance() {
        let source = r#"<?php
class Animal {
    protected string $name;
}

class Dog extends Animal {
    public function bark(): void {
        echo "Woof!";
    }
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);

        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.classes.len(), 2);
        assert!(!ir.inheritance.is_empty());
    }

    #[test]
    fn test_extract_calls() {
        let source = r#"<?php
function helper() {
    return 42;
}

function caller() {
    helper();
    strlen("hello");
}

class MyClass {
    public function process() {
        $this->validate();
        helper();
    }

    private function validate() {
        return true;
    }
}
"#;
        let config = ParserConfig::default();
        let result = extract(source, Path::new("test.php"), &config);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert!(!ir.calls.is_empty(), "Expected calls to be extracted");

        // caller -> helper
        assert!(
            ir.calls
                .iter()
                .any(|c| c.caller == "caller" && c.callee == "helper"),
            "Expected caller -> helper call, got: {:?}",
            ir.calls
                .iter()
                .map(|c| format!("{}->{}", c.caller, c.callee))
                .collect::<Vec<_>>()
        );
        // caller -> strlen
        assert!(
            ir.calls
                .iter()
                .any(|c| c.caller == "caller" && c.callee == "strlen"),
            "Expected caller -> strlen call"
        );
        // process -> validate (method call via $this->)
        assert!(
            ir.calls
                .iter()
                .any(|c| c.caller == "process" && c.callee == "validate"),
            "Expected process -> validate call"
        );
        // process -> helper
        assert!(
            ir.calls
                .iter()
                .any(|c| c.caller == "process" && c.callee == "helper"),
            "Expected process -> helper call"
        );
    }
}
