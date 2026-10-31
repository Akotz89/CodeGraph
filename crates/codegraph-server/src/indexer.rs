// Copyright 2025-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared indexer — used by both MCP and LSP backends.
//!
//! Provides hash-based incremental indexing, configurable directory exclusions,
//! and cross-file import resolution. Persists file hashes via [`IndexState`] so
//! unchanged files are skipped across server restarts.

use crate::index_state::IndexState;
use crate::parser_registry::ParserRegistry;
use crate::sql_parser::{is_sql_path, MAX_SQL_FILE_SIZE_BYTES};
use crate::watcher::GraphUpdater;
use codegraph::CodeGraph;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Resolve an existing path to its canonical identity, or retain missing
/// descendants beneath the nearest canonical existing ancestor. The latter
/// keeps exact include identity stable while one or more parent directories
/// are temporarily deleted.
pub(crate) fn canonical_candidate(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.exists() {
        missing.push(ancestor.file_name()?.to_os_string());
        ancestor = ancestor.parent()?;
    }
    let mut resolved = ancestor.canonicalize().ok()?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Some(resolved)
}

/// Read a file for indexing while keeping the SQL parser's larger-file policy
/// bounded at the indexer's earlier content-hash read as well.
fn read_index_content(path: &Path) -> Result<Vec<u8>, String> {
    if !is_sql_path(path) {
        return std::fs::read(path).map_err(|e| format!("Read error: {e}"));
    }

    let metadata = std::fs::metadata(path).map_err(|e| format!("Read error: {e}"))?;
    if metadata.len() > MAX_SQL_FILE_SIZE_BYTES {
        return Err(format!(
            "SQL file exceeds {} byte limit ({} bytes): {}",
            MAX_SQL_FILE_SIZE_BYTES,
            metadata.len(),
            path.display()
        ));
    }

    // Metadata can go stale if a file grows between stat and read. Read at
    // most one byte beyond the cap so the race cannot turn into an unbounded
    // allocation before the parser gets a chance to reject it.
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("Read error: {e}"))?;
    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SQL_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("Read error: {e}"))?;
    if content.len() as u64 > MAX_SQL_FILE_SIZE_BYTES {
        return Err(format!(
            "SQL file exceeds {} byte limit: {}",
            MAX_SQL_FILE_SIZE_BYTES,
            path.display()
        ));
    }
    Ok(content)
}

/// Whether one directory entry is excluded from the graph.
///
/// This is the single statement of the rule. The indexer applies it to every
/// entry as it walks, and [`WorkspaceFilter`] applies it to every component of
/// a path the file watcher reports. The watcher used to carry its own shorter
/// list instead, so `--exclude`, `.codegraphignore` and most of the default
/// exclusions kept generated files out of the initial index and then let every
/// later write to them straight back in (issue #23).
pub(crate) fn is_excluded_entry(
    config: &IndexConfig,
    exclude_set: &globset::GlobSet,
    path: &Path,
    is_dir: bool,
) -> bool {
    let Some(name) = path.file_name() else {
        return true;
    };
    let name = name.to_string_lossy();
    if name.starts_with('.') {
        return true;
    }
    if exclude_set.is_match(path) {
        return true;
    }
    is_dir
        && (config.exclude_dirs.iter().any(|d| d == name.as_ref())
            || exclude_set.is_match(name.as_ref()))
}

/// External directories are retained only when explicitly added and still allowed.
pub(crate) fn external_root_allowed(root: &Path, config: &IndexConfig) -> bool {
    let Ok(canonical) = root.canonicalize() else { return false; };
    if !root.is_absolute() || canonical != root || !canonical.is_dir() { return false; }
    let mut scoped = config.clone();
    scoped.extend_from_codegraphignore(root);
    let exclude_set = scoped.build_exclude_set();
    let temp = std::env::temp_dir();
    let resolved_temp = temp.canonicalize().unwrap_or_else(|_| temp.clone());
    !root.ancestors().chain(canonical.ancestors()).any(|ancestor| {
        exclude_set.is_match(ancestor) || ancestor.file_name().is_some_and(|name| {
            exclude_set.is_match(name)
                || (ancestor != temp && ancestor != resolved_temp
                    && scoped.exclude_dirs.iter().any(|excluded| name == std::ffi::OsStr::new(excluded)))
        })
    })
}

pub(crate) fn authorized_external_roots(graph: &CodeGraph, config: &IndexConfig) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    for (_, node) in graph.iter_nodes() {
        if let Some(root) = node.properties.get_string("codegraph_external_root") {
            let root = PathBuf::from(root);
            if !external_root_allowed(&root, config) || std::fs::read_dir(&root).is_err() {
                return Err("Cannot verify authorized external directory".into());
            }
            if !roots.contains(&root) { roots.push(root); }
        }
    }
    Ok(roots)
}

pub(crate) fn external_filter(roots: &[PathBuf], config: &IndexConfig) -> WorkspaceFilter {
    let mut config = config.clone();
    config.explicit_source_files.clear();
    config.filename_exception_files.clear();
    config.exact_cpp_files.clear();
    WorkspaceFilter::new(roots, &config)
}

/// Decides whether the file watcher may admit a path, by the same rule the
/// indexer used to build the graph.
///
/// The indexer only reaches a file after every directory above it has passed,
/// because it recurses. A watcher event arrives as one bare path with no such
/// history, so the rule is applied to each ancestor in turn - otherwise a file
/// under an excluded directory would be judged only by its own name.
///
/// Built per workspace root because `.codegraphignore` is read per root, as
/// the indexer does. It is read once, when the watcher starts: editing
/// `.codegraphignore` takes effect on the next start, like `--exclude`.
#[derive(Clone)]
pub(crate) struct WorkspaceFilter {
    /// `(root as given, root canonicalised, config, exclude globs)`.
    roots: Vec<(PathBuf, PathBuf, IndexConfig, globset::GlobSet)>,
    /// Canonical caller-selected source files. These are exact-file
    /// exceptions to example/build directory pruning, never directory roots.
    explicit_files: std::collections::HashSet<PathBuf>,
    exact_cpp_files: std::collections::HashSet<PathBuf>,
}

impl WorkspaceFilter {
    pub(crate) fn new(roots: &[PathBuf], base: &IndexConfig) -> Self {
        let roots = roots
            .iter()
            .map(|root| {
                let mut config = base.clone();
                config.extend_from_codegraphignore(root);
                let exclude_set = config.build_exclude_set();
                let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
                (root.clone(), canonical, config, exclude_set)
            })
            .collect();
        let explicit_files = base
            .explicit_source_files
            .iter()
            .filter_map(|path| canonical_candidate(path))
            .collect();
        Self {
            roots,
            explicit_files,
            exact_cpp_files: base.exact_cpp_files.iter().cloned().collect(),
        }
    }

    pub(crate) fn covers(&self, path: &Path) -> bool {
        self.locate(path).is_some()
    }

    pub(crate) fn explicit_source_files(&self) -> Vec<PathBuf> {
        self.explicit_files.iter().cloned().collect()
    }

    pub(crate) fn is_explicit_file(&self, path: &Path) -> bool {
        canonical_candidate(path).is_some_and(|candidate| self.explicit_files.contains(&candidate))
    }

    pub(crate) fn is_exact_cpp_file(&self, path: &Path) -> bool {
        self.exact_cpp_files.contains(path) && self.admits(path)
    }

    pub(crate) fn admits_explicit_parent(&self, path: &Path) -> bool {
        let Some(candidate) = canonical_candidate(path) else {
            return false;
        };
        self.explicit_files
            .iter()
            .any(|file| file.parent() == Some(candidate.as_path()))
    }

    /// Whether `path` is a workspace-contained directory on the chain to an
    /// exact included file. This permits a nonrecursive watch to notice when
    /// an excluded immediate parent is removed and recreated.
    pub(crate) fn admits_explicit_ancestor(&self, path: &Path) -> bool {
        let Some((root, relative, _, _)) = self.locate(path) else {
            return false;
        };
        let candidate = canonical_candidate(path).unwrap_or_else(|| root.join(relative));
        let canonical_root = root.canonicalize().unwrap_or(root);
        candidate.starts_with(&canonical_root)
            && self
                .explicit_files
                .iter()
                .any(|file| file.starts_with(&candidate) && file != &candidate)
    }

    /// Existing directories on the path from the workspace root to this
    /// exact file's parent. Watching this chain nonrecursively lets the
    /// watcher recover if an excluded parent is removed and recreated, while
    /// never traversing sibling directories.
    pub(crate) fn explicit_watch_chain(&self, path: &Path) -> Vec<PathBuf> {
        let Some(file) = canonical_candidate(path) else {
            return Vec::new();
        };
        if !self.explicit_files.contains(&file) || !self.admits(&file) {
            return Vec::new();
        }
        let Some((root, _, _, _)) = self.locate(&file) else {
            return Vec::new();
        };
        let canonical_root = root.canonicalize().unwrap_or(root);
        let Some(mut directory) = file.parent().map(Path::to_path_buf) else {
            return Vec::new();
        };
        if !directory.starts_with(&canonical_root) {
            return Vec::new();
        }
        let mut chain = Vec::new();
        loop {
            if directory.is_dir() {
                if let Ok(canonical) = directory.canonicalize() {
                    if canonical.starts_with(&canonical_root) {
                        chain.push(canonical);
                    }
                }
            }
            if directory == canonical_root {
                break;
            }
            let Some(parent) = directory.parent() else {
                return Vec::new();
            };
            if !parent.starts_with(&canonical_root) {
                return Vec::new();
            }
            directory = parent.to_path_buf();
        }
        chain.reverse();
        chain.dedup();
        chain
    }

    /// Whether `path`, a file, belongs in the graph.
    ///
    /// Deleted files cannot be stat'd, so the size limit is only applied to a
    /// file that still exists; every other check depends on the path alone.
    /// That keeps a delete for a file the index never held from being admitted
    /// on a technicality, and a delete for one it did hold from being refused.
    pub(crate) fn admits(&self, path: &Path) -> bool {
        let Some((root, relative, config, exclude_set)) = self.locate(path) else {
            return false;
        };
        // A lexical in-root path can traverse a symlink outside the workspace.
        // Apply the same canonical containment rule to watcher and direct-file
        // admission, including deleted paths resolved via their nearest parent.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        if !canonical_candidate(path).is_some_and(|resolved| resolved.starts_with(&canonical_root)) {
            return false;
        }
        let mut component_path = root.clone();
        for component in relative.components() {
            component_path.push(component);
            if std::fs::symlink_metadata(&component_path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return false;
            }
        }

        let candidate = root.join(&relative);
        let is_explicit = self.explicit_files.contains(&candidate)
            || canonical_candidate(&candidate)
                .is_some_and(|canonical| self.explicit_files.contains(&canonical));
        if is_explicit {
            return self.admits_explicit_file(path, &root, &relative, config, exclude_set);
        }

        let components: Vec<_> = relative.components().collect();
        // Directories above the file, matching the walk's depth accounting.
        if components.len().saturating_sub(1) > config.max_depth as usize {
            return false;
        }

        let mut current = root;
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let is_dir = index + 1 < components.len();
            if is_excluded_entry(config, exclude_set, &current, is_dir) {
                return false;
            }
        }

        match std::fs::metadata(path) {
            Ok(metadata) => is_sql_path(path) || metadata.len() <= config.max_file_size_bytes,
            Err(_) => true,
        }
    }

    fn admits_explicit_file(
        &self,
        path: &Path,
        root: &Path,
        relative: &Path,
        config: &IndexConfig,
        exclude_set: &globset::GlobSet,
    ) -> bool {
        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        // Exact includes still have to be source files. The server's parser
        // registry is the authoritative extension list; the shared filter
        // keeps this list to text source formats supported by it.
        let exact_cpp = config.exact_cpp_files.iter().any(|selected| selected == path);
        let cmake_lists = path.file_name().is_some_and(|name| name == "CMakeLists.txt");
        if !ext.is_empty() && !exact_cpp && !cmake_lists && crate::parser_registry::source_template_kind(path).is_none() && !config
            .explicit_source_extensions
            .iter()
            .any(|known| known == ext)
        {
            return false;
        }
        let mut bypasses_pruned_directory = false;
        let components: Vec<_> = relative.components().collect();
        if components.len().saturating_sub(1) > config.max_depth as usize {
            return false;
        }
        let filename_exception = canonical_candidate(path).is_some_and(|candidate| {
            config.filename_exception_files.iter().any(|selected| canonical_candidate(selected).as_ref() == Some(&candidate))
        });
        let mut current = root.to_path_buf();
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let name = component.as_os_str().to_string_lossy();
            let is_dir = index + 1 < components.len();
            let leaf_exception = !is_dir && filename_exception;
            let excluded = if leaf_exception {
                let mut strict = config.clone();
                strict.exclude_patterns.retain(|pattern| pattern != "**/*secret*" && pattern != "**/*credential*");
                strict.build_exclude_set().is_match(&current)
            } else {
                exclude_set.is_match(&current)
            };
            if name.starts_with('.') || excluded {
                return false;
            }
            if is_dir
                && config
                    .exclude_dirs
                    .iter()
                    .any(|excluded| excluded == name.as_ref())
            {
                if filename_exception {
                    return false;
                }
                if (name == "fixtures" && ext == "json") || (name == "logs" && ext == "php") {
                    // Only the exact source file is admitted; siblings stay pruned.
                    continue;
                } else if name == "examples" || name == "dist" || (name == "bin" && ext.is_empty()) {
                    bypasses_pruned_directory = true;
                } else {
                    return false;
                }
            }
        }
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return false;
        }
        if ext.is_empty() && path.exists() && crate::parser_registry::extensionless_source_kind(path).is_none() {
            return false;
        }
        // The caller-owned exception covers hand-maintained shell launch
        // scripts and CMake source/configuration under default-pruned example
        // and dist trees. Compiled web assets and other generated outputs stay
        // out even when a caller accidentally lists them.
        if bypasses_pruned_directory && !cmake_lists && !matches!(ext, "sh" | "cmake" | "") {
            return false;
        }
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let Some(canonical_file) = canonical_candidate(path) else {
            // For a watched deletion, the file itself is gone; resolving its
            // existing parent still proves the exact in-root path identity.
            let Some(canonical_missing_file) = canonical_candidate(path) else {
                return false;
            };
            if !canonical_missing_file.starts_with(&canonical_root) {
                return false;
            }
            return true;
        };
        if !canonical_file.starts_with(&canonical_root) {
            return false;
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return false,
            _ => {}
        }
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file() && (metadata.len() <= config.max_file_size_bytes
                || (ext == "json" && metadata.len() <= 4 * 1024 * 1024)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }

    /// Whether a directory is part of the walk for one of the configured
    /// workspace roots. The root itself is admitted just as
    /// `index_workspace()` admits its root before `index_directory()` checks
    /// descendants; every child component uses the exact shared exclusion
    /// predicate and depth accounting used by that walk.
    pub(crate) fn admits_directory(&self, path: &Path) -> bool {
        let Some((root, relative, config, exclude_set)) = self.locate(path) else {
            return false;
        };
        let components: Vec<_> = relative.components().collect();
        if components.len() > config.max_depth as usize {
            return false;
        }

        let mut current = root;
        for component in components {
            current.push(component);
            if std::fs::symlink_metadata(&current)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
                || is_excluded_entry(config, exclude_set, &current, true)
            {
                return false;
            }
        }
        true
    }

    /// `path` spelled the way the indexer stored it.
    ///
    /// The indexer records each file under the workspace root as it was given,
    /// while FSEvents reports the resolved location. On a workspace reached
    /// through a symlink the two never match, so every lookup by event path
    /// missed: an edit re-parsed the file without removing its old symbols, a
    /// delete removed nothing, and the graph only ever grew. Translating at
    /// intake gives every later step one spelling.
    pub(crate) fn indexed_form(&self, path: &Path) -> PathBuf {
        match self.locate(path) {
            Some((root, relative, _, _)) => root.join(relative),
            None => path.to_path_buf(),
        }
    }

    /// The workspace root `path` falls under, in the form it was given, and
    /// `path` relative to it.
    ///
    /// Roots and event paths do not reliably share a spelling. A workspace
    /// opened as `/var/folders/...` or through any symlinked directory is
    /// reported by FSEvents at its resolved location, `/private/var/folders/...`,
    /// so a plain prefix test rejected every event and the watcher admitted
    /// nothing at all. The event path is compared, as reported, against both
    /// spellings of the root; that needs no filesystem access, so it still
    /// works when the file's directory was deleted along with it.
    ///
    /// A path reported in unresolved form is additionally resolved through its
    /// parent directory. The most specific root wins when workspace folders
    /// nest.
    fn locate(&self, path: &Path) -> Option<(PathBuf, PathBuf, &IndexConfig, &globset::GlobSet)> {
        let resolved = path
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .zip(path.file_name())
            .map(|(parent, name)| parent.join(name));

        let mut best: Option<(usize, PathBuf, PathBuf, &IndexConfig, &globset::GlobSet)> = None;
        for (given, canonical, config, exclude_set) in &self.roots {
            for (candidate, root) in [
                (Some(path), given),
                (Some(path), canonical),
                (resolved.as_deref(), canonical),
            ] {
                let Some(candidate) = candidate else { continue };
                let Ok(relative) = candidate.strip_prefix(root) else {
                    continue;
                };
                let depth = root.components().count();
                if best.as_ref().is_none_or(|(d, ..)| depth > *d) {
                    best = Some((
                        depth,
                        given.clone(),
                        relative.to_path_buf(),
                        config,
                        exclude_set,
                    ));
                }
            }
        }
        best.map(|(_, root, relative, config, exclude_set)| (root, relative, config, exclude_set))
    }
}

/// Configuration for a single indexing run.
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Directory names to always skip (e.g. `node_modules`, `target`).
    pub exclude_dirs: Vec<String>,
    /// Glob patterns for additional exclusions (user-configured).
    pub exclude_patterns: Vec<String>,
    /// Maximum file size in bytes. Files larger than this are skipped.
    pub max_file_size_bytes: u64,
    /// Maximum recursion depth for directory traversal.
    pub max_depth: u32,
    /// Maximum number of files to index in a single run.
    pub max_files: usize,
    /// Exact source paths supplied by the workspace owner. These paths may
    /// bypass only `examples`/`dist` directory pruning; file-pattern,
    /// credential, root-containment and symlink checks still apply.
    pub explicit_source_files: Vec<PathBuf>,
    /// Exact paths explicitly declared to be C++ despite an ambiguous suffix.
    pub exact_cpp_files: Vec<PathBuf>,
    /// Exact source paths allowed to bypass only the two filename globs.
    pub filename_exception_files: Vec<PathBuf>,
    /// Extensions supported by the caller's parser registry, without dots.
    pub explicit_source_extensions: Vec<String>,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            exclude_dirs: Self::default_exclude_dirs(),
            exclude_patterns: Self::default_exclude_patterns(),
            max_file_size_bytes: 1024 * 1024, // 1 MiB
            max_depth: 20,
            max_files: 5_000,
            explicit_source_files: Vec::new(),
            exact_cpp_files: Vec::new(),
            filename_exception_files: Vec::new(),
            explicit_source_extensions: Vec::new(),
        }
    }
}

impl IndexConfig {
    /// The hardcoded list of directories that are always excluded.
    ///
    /// Three categories:
    /// 1. **Build / dependency / cache dirs** — never source code, dragging them
    ///    through tree-sitter wastes cycles. Indexer-runaway protection
    ///    (see workspace_indexer_embedding_runaway memory note: codegraph-pro
    ///    MCP startup spinning fastembed/ONNX for 30+ min on large workspaces).
    /// 2. **IDE / tooling state** — ephemeral, churns frequently, no semantic
    ///    value for code intelligence.
    /// 3. **Sensitive credential dirs** — `~/.aws`, `~/.ssh` etc. A user who
    ///    accidentally indexes their home dir (or a project rooted inside it)
    ///    should not have those embedded into graph.db. Defense in depth on
    ///    top of the per-extension secret skip in `default_exclude_patterns`.
    pub fn default_exclude_dirs() -> Vec<String> {
        [
            // Generic build / artifact dirs
            "node_modules",
            "target",
            "dist",
            "build",
            "out",
            "coverage",
            "htmlcov",
            "results",
            "logs",
            "tmp",
            // VCS / SCM metadata
            ".git",
            // Python tooling
            "__pycache__",
            "vendor",
            ".venv",
            "venv",
            ".tox",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".eggs",
            // Node / JS tooling
            ".next",
            ".nuxt",
            ".svelte-kit",
            ".parcel-cache",
            ".npm",
            ".yarn",
            ".pnpm-store",
            ".cache",
            // Rust / Ruby / Java / Gradle
            ".cargo",
            ".bundle",
            ".gradle",
            ".kotlin",
            // Apple / iOS
            "DerivedData",
            "Pods",
            "xcuserdata",
            // CMake out-of-source build dirs
            "cmake-build-debug",
            "cmake-build-release",
            // Test / benchmark / example / binary-output dirs
            "benches",
            "examples",
            "fixtures",
            "cases",
            "bin",
            // IDE state
            ".idea",
            ".vscode-test",
            ".fleet",
            // Infrastructure-as-code state
            ".terraform",
            ".terragrunt-cache",
            ".serverless",
            // Sensitive credential / config dirs — never code, often secret
            ".aws",
            ".ssh",
            ".gnupg",
            ".kube",
            ".docker",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// Built-in glob patterns for files we should never index — binary
    /// archives, prebuilt artifacts, OS metadata. These shapes are
    /// near-universally non-source and dragging them through tree-sitter
    /// + embedding wastes cycles. Bounty 2026-05-03: a `bounty/` workspace
    /// containing thousands of `.tar.gz` / `.deb` proof bundles caused a
    /// 4.3 GB / 644% CPU runaway during initial embedding because the
    /// indexer didn't filter binary file extensions.
    pub fn default_exclude_patterns() -> Vec<String> {
        [
            // Archives / packaged artifacts
            "**/*.tar.gz",
            "**/*.tar.bz2",
            "**/*.tar.xz",
            "**/*.tgz",
            "**/*.tbz2",
            "**/*.zip",
            "**/*.7z",
            "**/*.rar",
            "**/*.deb",
            "**/*.rpm",
            "**/*.pkg",
            "**/*.dmg",
            "**/*.iso",
            "**/*.img",
            // Compiled / native binaries
            "**/*.exe",
            "**/*.dll",
            "**/*.so",
            "**/*.dylib",
            "**/*.bin",
            "**/*.o",
            "**/*.a",
            "**/*.lib",
            "**/*.obj",
            "**/*.pdb",
            // Compiled bytecode (already in __pycache__/ etc. but glob covers stragglers)
            "**/*.pyc",
            "**/*.pyo",
            "**/*.class",
            "**/*.jar",
            "**/*.war",
            // Disk images / proof bundles
            "**/*.qcow2",
            "**/*.vmdk",
            "**/*.vdi",
            "**/*.vhd",
            // Office / PDF / media (not code)
            "**/*.pdf",
            "**/*.docx",
            "**/*.xlsx",
            "**/*.pptx",
            "**/*.png",
            "**/*.jpg",
            "**/*.jpeg",
            "**/*.gif",
            "**/*.bmp",
            "**/*.svg",
            "**/*.mp3",
            "**/*.mp4",
            "**/*.mov",
            "**/*.avi",
            "**/*.webm",
            // OS metadata
            "**/.DS_Store",
            "**/Thumbs.db",
            // Misc bulky non-source
            "**/*.sqlite",
            "**/*.db",
            "**/*.lock",
            // Package artifacts
            "**/*.vsix",
            "**/*.tgz",
            "**/*.whl",
            "**/*.gem",
            "**/*.nupkg",
            // Vendored tree-sitter parser sources (generated C, not user code).
            // Two globs needed: one matches the dir itself so it's skipped
            // during directory walk, the other matches files inside it.
            "**/tree-sitter-*-src",
            "**/tree-sitter-*-src/**",
            // Cryptographic material — never code; never want this content
            // either parsed OR embedded into graph.db. Coverage:
            //   - Private keys: PEM / DER / PKCS#12 / PKCS#8 / OpenSSH
            //   - Certificates: PEM / DER / certificate bundles
            //   - PGP / GPG keyrings + ASCII-armored signatures
            //   - Password databases (KeePass)
            //   - Web-auth artifacts (htpasswd, netrc)
            //   - SSH key filenames per OpenSSH convention
            //   - Terraform state (contains secrets after apply)
            "**/*.pem",
            "**/*.key",
            "**/*.priv",
            "**/*.privkey",
            "**/*.p12",
            "**/*.pfx",
            "**/*.crt",
            "**/*.cer",
            "**/*.der",
            "**/*.gpg",
            "**/*.asc",
            "**/*.kdb",
            "**/*.kdbx",
            "**/.htpasswd",
            "**/.netrc",
            "**/id_rsa",
            "**/id_rsa.pub",
            "**/id_ed25519",
            "**/id_ed25519.pub",
            "**/id_dsa",
            "**/id_ecdsa",
            "**/known_hosts",
            "**/authorized_keys",
            "**/*.tfstate",
            "**/*.tfstate.backup",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// Bounty 2026-05-03 — extend the exclude_patterns from a workspace's
    /// `.codegraphignore` file if present. Format is simple gitignore-like:
    /// one pattern per line, `#` for comments, blank lines ignored. Not a
    /// full gitignore parser (no `!` negation, no path-anchored `/`-prefix
    /// semantics) — keeps complexity bounded while solving the bounty
    /// workspace runaway.
    ///
    /// If `.codegraphignore` doesn't exist, this is a no-op (returns
    /// without modifying `self`). Errors reading the file are logged
    /// and ignored.
    pub fn extend_from_codegraphignore(&mut self, workspace_root: &Path) {
        let path = workspace_root.join(".codegraphignore");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to read {}: {}", path.display(), e);
                }
                return;
            }
        };
        let mut added = 0usize;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.exclude_patterns.push(trimmed.to_string());
            added += 1;
        }
        if added > 0 {
            tracing::info!("Loaded {} patterns from {}", added, path.display());
        }
    }

    /// Build a `GlobSet` from `exclude_patterns`.
    pub(crate) fn build_exclude_set(&self) -> globset::GlobSet {
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in &self.exclude_patterns {
            match globset::Glob::new(pattern) {
                Ok(g) => {
                    builder.add(g);
                }
                Err(e) => {
                    tracing::warn!("Invalid exclude pattern '{}': {}", pattern, e);
                }
            }
        }
        builder.build().unwrap_or_else(|e| {
            tracing::warn!("Failed to build exclude GlobSet: {}", e);
            globset::GlobSet::empty()
        })
    }


}

/// Result of an indexing run.
#[derive(Debug, Clone, Default)]
pub struct IndexResult {
    /// Cross-file resolution failure; callers must not report or persist success.
    pub resolution_error: Option<String>,
    /// Total files encountered (parsed + skipped).
    pub total_files: usize,
    /// Files that were actually parsed (new or changed).
    pub files_parsed: usize,
    /// Previously indexed files removed from the graph.
    pub files_removed: usize,
    /// Existing files received new volume metadata that must be persisted.
    pub volume_metadata_changed: bool,
    /// Files skipped because their content hash was unchanged.
    pub files_skipped: usize,
    /// Per-language file counts (key: parser's `language()` string).
    /// Used for `index.languageBreakdown` telemetry so we know which
    /// parsers are actually exercised on real workspaces. Counts include
    /// both parsed and hash-skipped files (all files the parser claimed).
    pub by_language: std::collections::HashMap<String, usize>,
    /// Per-language parser error counts. A parser error here means the
    /// tree-sitter parse step itself failed — distinct from "no files
    /// of this language found." Drives parser-quality prioritization.
    pub parser_errors_by_language: std::collections::HashMap<String, usize>,
}

impl IndexResult {
    /// Human-readable reason an indexing run cannot be committed as complete.
    pub fn failure(&self) -> Option<String> {
        let failed: usize = self.parser_errors_by_language.values().sum();
        match (&self.resolution_error, failed) {
            (Some(error), 0) => Some(format!("Cross-file resolution failed: {error}")),
            (Some(error), n) => Some(format!("Cross-file resolution failed: {error}; failed to parse {n} file(s)")),
            (None, 0) => None,
            (None, n) => Some(format!("Failed to parse {n} file(s)")),
        }
    }
}

/// Shared indexer for walking directories, hashing files, and parsing them
/// into a [`CodeGraph`].
pub struct Indexer {
    /// Serializes MCP watcher and explicit indexing batches with forced rebuilds.
    pub(crate) mcp_operation_lock: Mutex<()>,
    pub(crate) mcp_reindex_incomplete: Arc<std::sync::atomic::AtomicBool>,
    parsers: Arc<ParserRegistry>,
    index_state: Arc<Mutex<IndexState>>,
    mount_table: std::sync::RwLock<Option<Vec<(PathBuf, String, PathBuf)>>>,
    uuid_cache: std::sync::Mutex<std::collections::HashMap<String, Option<String>>>,
}

// Check every existing ancestor, not just metadata on the workspace root.
// An unreadable directory can still report `is_dir() == true`.
#[cfg(test)]
fn readable_ancestors(path: &Path, root: &Path) -> bool {
    readable_ancestors_cached(path, root, &mut std::collections::HashMap::new())
}

fn readable_ancestors_cached(path: &Path, root: &Path, cache: &mut std::collections::HashMap<PathBuf, bool>) -> bool {
    let mut current = path.parent();
    while let Some(dir) = current {
        if !dir.starts_with(root) {
            return false;
        }
        let readable = *cache.entry(dir.to_path_buf()).or_insert_with(|| match std::fs::read_dir(dir) {
            Ok(entries) => entries.into_iter().all(|entry| entry.is_ok()),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound && dir != root,
        });
        if !readable { return false; }
        if dir == root {
            return true;
        }
        current = dir.parent();
    }
    false
}

// Identity lookup can take long enough for the file to be recreated. Check on
// both sides of that lookup and reject a changed or unavailable identity.
fn confirm_missing_with_identity(path: &Path, expected: &str, identity: impl FnOnce() -> Option<String>) -> bool {
    matches!(path.try_exists(), Ok(false))
        && identity().as_deref() == Some(expected)
        && matches!(path.try_exists(), Ok(false))
}

// A mount point can remain as an empty directory when its volume disappears.
// Linux mountinfo provides both a device and a filesystem-relative root;
// the latter also distinguishes bind mounts on the same device.
#[cfg(target_os = "linux")]
fn parse_mount_table(table: &str) -> Option<Vec<(PathBuf, String, PathBuf)>> {
    fn unescape(value: &str) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStringExt;
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                if i + 3 >= bytes.len() || !bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
                    return None;
                }
                let value = (bytes[i + 1] - b'0') as u16 * 64
                    + (bytes[i + 2] - b'0') as u16 * 8 + (bytes[i + 3] - b'0') as u16;
                if value > 255 { return None; }
                decoded.push(value as u8);
                i += 4;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        Some(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
    }
    table.lines().map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 7 || !fields.contains(&"-") { return None; }
        Some((unescape(fields[4])?, fields[2].to_string(), unescape(fields[3])?))
    }).collect()
}

fn mount_identity_from_entries(entries: &[(PathBuf, String, PathBuf)], path: &Path) -> Option<(PathBuf, String, PathBuf)> {
    entries.iter().filter(|(mount, _, _)| path.starts_with(mount))
        .max_by_key(|(mount, _, _)| mount.components().count()).cloned()
}

#[cfg(all(test, target_os = "linux"))]
fn mount_identity_from_table(table: &str, path: &Path) -> Option<(PathBuf, String, PathBuf)> {
    mount_identity_from_entries(&parse_mount_table(table)?, path)
}

fn current_mount_table() -> Option<Vec<(PathBuf, String, PathBuf)>> {
    #[cfg(target_os = "linux")]
    { parse_mount_table(&std::fs::read_to_string("/proc/self/mountinfo").ok()?) }
    #[cfg(not(target_os = "linux"))]
    { None }
}

#[derive(Default)]
struct LiveMountTable {
    raw: Option<String>,
    parsed: Option<Vec<(PathBuf, String, PathBuf)>>,
    #[cfg(target_os = "linux")]
    uuid_stamp: Option<(u64, u64, i64, i64, i64, i64)>,
    #[cfg(target_os = "linux")]
    uuid_checked: Option<std::time::Instant>,
    #[cfg(target_os = "linux")]
    uuids: std::collections::HashMap<String, Option<String>>,
}

impl LiveMountTable {
    #[cfg(target_os = "linux")]
    fn update(&mut self, raw: String) -> Option<&[(PathBuf, String, PathBuf)]> {
        if self.raw.as_ref() != Some(&raw) {
            self.parsed = parse_mount_table(&raw);
            self.raw = Some(raw);
            self.uuids.clear();
            self.uuid_checked = None;
        }
        self.parsed.as_deref()
    }

    fn refresh(&mut self) -> Option<&[(PathBuf, String, PathBuf)]> {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/self/mountinfo") {
                Ok(raw) => self.update(raw),
                Err(_) => { self.raw = None; self.parsed = None; None }
            }
        }
        #[cfg(not(target_os = "linux"))]
        { None }
    }

    fn identity(&mut self, path: &Path) -> Option<String> {
        self.identity_with_uuid_directory(path, Path::new("/dev/disk/by-uuid"))
    }

    fn identity_with_uuid_directory(&mut self, path: &Path, uuid_dir: &Path) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let canonical = canonical_candidate(path)?;
            let mount = mount_identity_from_entries(self.refresh()?, &canonical)?;
            let meta = std::fs::metadata(uuid_dir).ok()?;
            let stamp = (meta.dev(), meta.ino(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec());
            if self.uuid_stamp != Some(stamp) || self.uuid_checked.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(1)) {
                self.uuids.clear();
                self.uuid_stamp = Some(stamp);
                self.uuid_checked = Some(std::time::Instant::now());
            }
            let uuid = self.uuids.entry(mount.1.clone())
                .or_insert_with(|| filesystem_uuid_in(&mount.1, uuid_dir)).clone()?;
            // Device-mapper topology can change without a mount-table change.
            let device_id = filesystem_device_id(&mount.1)?;
            let volume = serde_json::to_string(&(uuid, device_id)).ok()?;
            serde_json::to_string(&(mount, volume)).ok()
        }
        #[cfg(not(target_os = "linux"))]
        { let _ = (path, uuid_dir); None }
    }
}

// Device numbers can be reassigned after unplugging a volume. A filesystem
// UUID makes a match meaningful across remounts; if no UUID is available,
// retain missing paths rather than guessing.
// UUIDs may be cloned. Require a hardware or virtual-disk identifier as well,
// and keep stale entries when the platform cannot provide one.
#[cfg(target_os = "linux")]
fn filesystem_device_id(device: &str) -> Option<String> {
    filesystem_device_id_in(device, Path::new("/sys/dev/block"))
}

#[cfg(target_os = "linux")]
fn filesystem_device_id_in(device: &str, sys_root: &Path) -> Option<String> {
    if !device.split(':').all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
        || device.matches(':').count() != 1 { return None; }
    let sys = sys_root.join(device);
    // Device-mapper UUIDs can be cloned with their on-disk metadata, so bind
    // the mapping to every underlying device's identity as well.
    let is_dm = sys.join("dm").try_exists().ok()?;
    if is_dm {
        let dm_uuid = std::fs::read_to_string(sys.join("dm/uuid")).ok()?;
        let dm_uuid = dm_uuid.trim();
        if dm_uuid.is_empty() || dm_uuid.len() > 256 { return None; }
        let mut children = Vec::new();
        for entry in std::fs::read_dir(sys.join("slaves")).ok()? {
            let entry = entry.ok()?;
            let child = std::fs::read_to_string(entry.path().join("dev")).ok()?;
            let child = child.trim();
            if child == device { return None; }
            // Do not recurse through nested mappings: without cycle detection
            // their identity cannot be established safely here.
            if sys_root.join(child).join("dm").try_exists().ok()? { return None; }
            // The same disk WWID can back multiple partitions; retain the
            // child's device number as well so they do not collapse together.
            children.push((child.to_owned(), filesystem_device_id_in(child, sys_root)?));
        }
        if children.is_empty() { return None; }
        children.sort();
        // Refuse a mixed observation if the mapping changed while the backing
        // identities were being read.
        let mut after = Vec::new();
        for entry in std::fs::read_dir(sys.join("slaves")).ok()? {
            let entry = entry.ok()?;
            let child = std::fs::read_to_string(entry.path().join("dev")).ok()?;
            let child = child.trim();
            if child == device || sys_root.join(child).join("dm").try_exists().ok()? { return None; }
            after.push((child.to_owned(), filesystem_device_id_in(child, sys_root)?));
        }
        after.sort();
        if children != after || std::fs::read_to_string(sys.join("dm/uuid")).ok()?.trim() != dm_uuid {
            return None;
        }
        return serde_json::to_string(&("device-mapper", dm_uuid, children)).ok();
    }
    for candidate in [sys.join("device/wwid"), sys.join("wwid"), sys.join("../device/wwid"), sys.join("../wwid")] {
        if let Ok(value) = std::fs::read_to_string(candidate) {
            let value = value.trim();
            if !value.is_empty() && value.len() <= 256 { return Some(value.to_owned()); }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn filesystem_uuid_in(device: &str, uuid_dir: &Path) -> Option<String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut parts = device.split(':');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() { return None; }
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(uuid_dir).ok()? {
        // An unreadable entry prevents proving uniqueness; fail closed.
        let entry = entry.ok()?;
        let meta = std::fs::metadata(entry.path()).ok()?;
        if !meta.file_type().is_block_device() { return None; }
        let dev = meta.rdev();
        let entry_major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
        let entry_minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
        if entry_major == major && entry_minor == minor {
            if let Some(uuid) = entry.file_name().to_str() { matches.push(uuid.to_owned()); }
        }
    }
    matches.sort();
    matches.dedup();
    (matches.len() == 1).then(|| matches.remove(0))
}

// During one workspace walk the captured mount table is shared. Resolve each
// backing device's UUID once instead of scanning /dev for every source file.
fn cached_volume_identity(table: Option<&[(PathBuf, String, PathBuf)]>, path: &Path, cache: &std::sync::Mutex<std::collections::HashMap<String, Option<String>>>) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let mount = mount_identity_from_entries(table?, &canonical_candidate(path)?)?;
        let mut cache = cache.lock().ok()?;
        let uuid = cache.entry(mount.1.clone())
            .or_insert_with(|| filesystem_uuid_in(&mount.1, Path::new("/dev/disk/by-uuid"))).clone()?;
        drop(cache);
        let device_id = filesystem_device_id(&mount.1)?;
        let volume = serde_json::to_string(&(uuid, device_id)).ok()?;
        serde_json::to_string(&(mount, volume)).ok()
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = (table, path, cache); None }
}

impl Indexer {
    /// Create a new indexer backed by the given parser registry and index state.
    pub fn new(parsers: Arc<ParserRegistry>, index_state: Arc<Mutex<IndexState>>) -> Self {
        Self {
            mcp_operation_lock: Mutex::new(()),
            mcp_reindex_incomplete: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            parsers,
            index_state,
            mount_table: std::sync::RwLock::new(current_mount_table()),
            uuid_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Refresh mount data and its dependent UUID cache as one generation.
    pub(crate) fn refresh_mount_snapshot(&self) {
        if let Ok(mut table) = self.mount_table.write() {
            // Keep the write lock while clearing: readers take table before cache.
            match self.uuid_cache.lock() {
                Ok(mut cache) => { cache.clear(); *table = current_mount_table(); }
                Err(_) => *table = None,
            }
        }
    }

    /// Compute a fast content hash (FNV-1a 64-bit).
    pub fn hash_content(content: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &byte in content {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Index all workspace folders, resolve cross-file imports, and persist
    /// index state.
    ///
    /// This is the main entry-point for full (re-)indexing.
    pub async fn index_workspace(
        &self,
        graph: &Arc<RwLock<CodeGraph>>,
        folders: &[PathBuf],
        config: &IndexConfig,
    ) -> IndexResult {
        // Crash-phase breadcrumb: parsing runs native tree-sitter grammars over
        // arbitrary source — the leading suspect for the remaining win32
        // 0xC0000005 startup crashes. Shared by the MCP and LSP backends, so
        // this one guard tags every parse pass. Resets to `serving` on return.
        let _phase = crate::crash_phase::enter("index_parse");
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut result = IndexResult::default();
        if let Err(error) = crate::watcher::validate_call_scope_configuration() {
            result.resolution_error = Some(error.to_string());
            return result;
        }
        self.refresh_mount_snapshot();

        for folder in folders {
            // Bounty 2026-05-03 — extend exclude_patterns from this
            // folder's `.codegraphignore` if present. Per-folder so each
            // workspace can have its own rules; doesn't pollute other
            // folders' configs.
            let mut folder_config = config.clone();
            // Reserve capacity for the owner's exact inclusions so a large
            // ordinary walk cannot consume the entire limit before they are
            // reached. The total still stays within `max_files`.
            folder_config.max_files = config
                .max_files
                .saturating_sub(config.explicit_source_files.len().min(config.max_files));
            folder_config.extend_from_codegraphignore(folder);
            let (total, parsed, skipped, by_lang, parser_errors) = self
                .index_directory(graph, folder, &folder_config, 0, counter.clone())
                .await;
            result.total_files += total;
            result.files_parsed += parsed;
            result.files_skipped += skipped;
            for (lang, count) in by_lang {
                *result.by_language.entry(lang).or_insert(0) += count;
            }
            for (lang, count) in parser_errors {
                *result.parser_errors_by_language.entry(lang).or_insert(0) += count;
            }
        }

        // The owner may name exact source files under normally-pruned example
        // or distribution directories. Index only those paths, after applying
        // the same root, secret-pattern, size and symlink checks used by the
        // watcher. No excluded directory is traversed.
        if !config.explicit_source_files.is_empty() {
            let filter = WorkspaceFilter::new(folders, config);
            for source in &config.explicit_source_files {
                if !filter.admits(source) {
                    tracing::warn!("Ignoring explicit source path that failed workspace filters");
                    continue;
                }
                let Some(source) = canonical_candidate(source) else {
                    tracing::warn!("Ignoring explicit source path with unresolved parent");
                    continue;
                };
                if !filter.admits(&source) {
                    tracing::warn!("Ignoring explicit source path that failed workspace filters");
                    continue;
                }
                if counter.load(std::sync::atomic::Ordering::Relaxed) >= config.max_files {
                    tracing::warn!("Reached max indexed file limit of {}", config.max_files);
                    break;
                }
                match self.index_file(graph, &source).await {
                    Ok(parsed) => {
                        result.total_files += 1;
                        if parsed {
                            result.files_parsed += 1;
                        } else {
                            result.files_skipped += 1;
                        }
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!("Failed to index explicit source file: {error}");
                        *result.parser_errors_by_language.entry("explicit-source".to_string()).or_default() += 1;
                    },
                }
            }
        }

        // Revoke previously indexed paths when current workspace exclusions change.
        let filter = WorkspaceFilter::new(folders, config);
        let external_roots = match authorized_external_roots(&*graph.read().await, config) {
            Ok(roots) => roots,
            Err(error) => { result.resolution_error = Some(error); Vec::new() }
        };
        let external = external_filter(&external_roots, config);
        let graph_paths: std::collections::HashSet<PathBuf> = {
            let graph = graph.read().await;
            graph.iter_nodes().filter_map(|(_, node)| node.properties.get_string("path").map(PathBuf::from)).collect()
        };
        let mut indexed_paths = graph_paths.clone();
        {
            let state = self.index_state.lock().await;
            indexed_paths.extend(state.all_hashes().keys().cloned());
        }
        let mut excluded = Vec::new();
        for path in indexed_paths {
            if let Some((root, _, _, _)) = filter.locate(&path) {
                if std::fs::read_dir(root).is_err() {
                    if graph_paths.contains(&path) { result.resolution_error = Some("Cannot verify indexed paths in an inaccessible workspace".into()); }
                } else if !filter.admits(&path) {
                    excluded.push(path);
                }
            } else if let Some((root, _, _, _)) = external.locate(&path) {
                if std::fs::read_dir(root).is_err() {
                    if graph_paths.contains(&path) { result.resolution_error = Some("Cannot verify indexed paths in an inaccessible external directory".into()); }
                } else if !external.admits(&path) {
                    excluded.push(path);
                }
            } else if graph_paths.contains(&path) {
                result.resolution_error = Some("Indexed graph contains a path outside the configured workspaces".into());
            }
        }
        {
            let mut g = graph.write().await;
            let mut state = self.index_state.lock().await;
            for path in excluded {
                if filter.admits(&path) || (!filter.covers(&path) && external.admits(&path)) { continue; }
                let mut deleted = true;
                for id in g.nodes_by_path(&path.to_string_lossy()) {
                    if let Err(error) = g.delete_node(id) {
                        tracing::warn!("Failed to remove excluded path from graph: {}", error);
                        deleted = false;
                    }
                }
                if deleted {
                    state.remove(&path);
                    result.files_removed += 1;
                } else {
                    result.resolution_error = Some("Failed to remove excluded path from graph".into());
                }
            }
        }

        // A watcher cannot observe deletes made while the server was stopped.
        // Only prune missing paths under currently accessible workspace roots.
        let roots: Vec<(PathBuf, bool)> = folders.iter().filter_map(|root| {
            canonical_candidate(root).map(|path| (path, std::fs::read_dir(root).is_ok()))
        }).collect();
        let missing: Vec<PathBuf> = {
            let state = self.index_state.lock().await;
            let mut accessible = std::collections::HashMap::new();
            state.all_hashes().keys().filter(|path| {
                matches!(path.try_exists(), Ok(false)) && canonical_candidate(path).is_some_and(|p| {
                    roots.iter().filter(|(root, _)| p.starts_with(root))
                        .max_by_key(|(root, _)| root.components().count())
                        .is_some_and(|(root, available)| *available && readable_ancestors_cached(&p, root, &mut accessible))
                })
            }).cloned().collect()
        };
        let mut reappeared = Vec::new();
        {
            let mut g = graph.write().await;
            let mut state = self.index_state.lock().await;
            let mut accessible = std::collections::HashMap::new();
            let mut mounts = LiveMountTable::default();
            for path in missing {
                if !matches!(path.try_exists(), Ok(false)) { continue; }
                let Some(canonical) = canonical_candidate(&path) else { continue; };
                let Some(root) = roots.iter().filter(|(root, _)| canonical.starts_with(root))
                    .max_by_key(|(root, _)| root.components().count()) else { continue; };
                if !readable_ancestors_cached(&canonical, &root.0, &mut accessible) { continue; }
                let current = mounts.identity(&canonical);
                if current.as_deref().is_none() || state.volume(&path) != current.as_deref() { continue; }
                if !confirm_missing_with_identity(&path, current.as_deref().unwrap(), || mounts.identity(&canonical)) { continue; }
                let mut deleted = true;
                for id in g.nodes_by_path(&path.to_string_lossy()) {
                    if let Err(error) = g.delete_node(id) {
                        tracing::warn!("Failed to remove deleted {:?} from graph: {}", path, error);
                        deleted = false;
                    }
                }
                if deleted {
                    state.remove(&path);
                    result.files_removed += 1;
                    if matches!(path.try_exists(), Ok(true)) {
                        reappeared.push(path);
                    }
                }
            }
        }

        // If a file reappeared after the last check, rebuild it after releasing
        // the locks; the hash was removed so indexing cannot skip it as unchanged.
        result.files_parsed += self.reindex_reappeared(graph, folders, config, reappeared).await;

        // Resolve even after parse failures so the in-memory graph does not
        // retain relationships to removed nodes.
        // Resolve cross-file imports
        {
            let mut g = graph.write().await;
            if let Err(error) = GraphUpdater::resolve_cross_file_imports(&mut g) {
                result.resolution_error = Some(error.to_string());
            }
        }
        if result.failure().is_some() {
            self.invalidate_index_state().await;
            return result;
        }

        // Detect runtime dependencies
        {
            let mut g = graph.write().await;
            let routes = crate::runtime_deps::detect_route_handlers(&mut g);
            let clients = crate::runtime_deps::detect_http_client_calls(&mut g);
            if routes > 0 || clients > 0 {
                let edges = crate::runtime_deps::create_runtime_call_edges(&mut g);
                tracing::info!(
                    "Runtime deps: {} routes, {} clients, {} edges",
                    routes,
                    clients,
                    edges
                );
            }
        }

        result.volume_metadata_changed = self.index_state.lock().await.volumes_dirty();
        result
    }

    async fn reindex_reappeared(&self, graph: &Arc<RwLock<CodeGraph>>, folders: &[PathBuf], config: &IndexConfig, paths: Vec<PathBuf>) -> usize {
        if paths.is_empty() { return 0; }
        self.refresh_mount_snapshot();
        let filter = WorkspaceFilter::new(folders, config);
        let mut parsed = 0;
        for path in paths {
            if !filter.admits(&path) {
                tracing::warn!("Skipping recreated path that no longer passes workspace filters");
                continue;
            }
            match self.index_file(graph, &path).await {
                Ok(true) => parsed += 1,
                Ok(false) => {},
                Err(error) => tracing::warn!("Failed to reindex recreated {:?}: {}", path, error),
            }
        }
        parsed
    }

    /// Persist file hashes only after the caller has successfully persisted
    /// the graph they describe.
    pub async fn save_index_state(&self) -> bool {
        let mut state = self.index_state.lock().await;
        if state.save() {
            state.acknowledge_volumes_saved();
            true
        } else {
            state.invalidate_saved_state();
            false
        }
    }

    /// Invalidate hashes after graph persistence fails. A future run must
    /// rebuild rather than skip files based on state that may no longer match
    /// the persisted graph.
    pub async fn invalidate_index_state(&self) -> bool {
        self.index_state.lock().await.invalidate_saved_state()
    }

    /// Commit or invalidate file hashes according to the graph persistence
    /// result. This is the single gate for callers that finish a workspace
    /// parse: durable hashes are written only after the graph write succeeds.
    pub async fn finalize_graph_persist(&self, graph_persisted: bool) -> bool {
        if graph_persisted {
            self.save_index_state().await
        } else {
            self.invalidate_index_state().await;
            false
        }
    }

    /// Persist a stable graph snapshot before committing the hashes that
    /// describe it. Every incremental writer (MCP tools and filesystem
    /// watcher included) must pass through this gate so a failed graph write
    /// invalidates the checkpoint instead of acknowledging mismatched state.
    pub async fn persist_graph_snapshot<F>(
        &self,
        graph: &Arc<RwLock<CodeGraph>>,
        persist: F,
    ) -> Result<(), String>
    where
        F: FnOnce(&CodeGraph) -> Result<(), String>,
    {
        let persist_result = {
            let graph = graph.read().await;
            persist(&graph)
        };
        let graph_persisted = persist_result.is_ok();
        let state_saved = self.finalize_graph_persist(graph_persisted).await;
        match persist_result {
            Err(error) => Err(error),
            Ok(()) if !state_saved => {
                Err("graph persisted, but index state could not be committed".to_string())
            }
            Ok(()) => Ok(()),
        }
    }

    /// Remove a deleted path from the in-memory index checkpoint. The next
    /// successful graph snapshot commits this change with the graph itself.
    pub async fn remove_file_hash(&self, path: &Path) -> bool {
        let mut state = self.index_state.lock().await;
        let existed = state.get_hash(path).is_some();
        state.remove(path);
        existed
    }

    /// Recursively walk a directory and index supported files.
    ///
    /// Returns `(total_encountered, files_parsed, files_skipped)`.
    pub fn index_directory<'a>(
        &'a self,
        graph: &'a Arc<RwLock<CodeGraph>>,
        dir: &'a Path,
        config: &'a IndexConfig,
        depth: u32,
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = (
                        usize,
                        usize,
                        usize,
                        std::collections::HashMap<String, usize>,
                        std::collections::HashMap<String, usize>,
                    ),
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use std::sync::atomic::Ordering;

            if depth == 0 { self.refresh_mount_snapshot(); }

            let empty_by_lang: std::collections::HashMap<String, usize> = Default::default();
            let empty_errors: std::collections::HashMap<String, usize> = Default::default();

            if depth > config.max_depth {
                tracing::warn!(
                    "Skipping {:?}: exceeded max indexing depth of {}",
                    dir,
                    config.max_depth
                );
                return (0, 0, 0, empty_by_lang, empty_errors);
            }

            if counter.load(Ordering::Relaxed) >= config.max_files {
                return (0, 0, 0, empty_by_lang, empty_errors);
            }

            let exclude_set = config.build_exclude_set();
            let supported_extensions = self.parsers.supported_extensions();

            tracing::debug!("Scanning directory: {:?}", dir);

            let mut total = 0usize;
            let mut parsed = 0usize;
            let mut skipped = 0usize;
            let mut by_language: std::collections::HashMap<String, usize> = Default::default();
            let mut parser_errors: std::collections::HashMap<String, usize> = Default::default();

            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Cannot read directory {:?}: {}", dir, e);
                    return (0, 0, 0, empty_by_lang, empty_errors);
                }
            };

            for entry in entries.flatten() {
                if counter.load(Ordering::Relaxed) >= config.max_files {
                    tracing::warn!(
                        "Reached max indexed file limit of {}; stopping",
                        config.max_files
                    );
                    break;
                }

                let path = entry.path();
                let Ok(file_type) = entry.file_type() else { continue };
                if file_type.is_symlink() {
                    continue;
                }
                let is_dir = file_type.is_dir();
                if is_excluded_entry(config, &exclude_set, &path, is_dir) {
                    continue;
                }

                if is_dir {
                    let (t, p, s, child_by_lang, child_errors) = self
                        .index_directory(graph, &path, config, depth + 1, counter.clone())
                        .await;
                    total += t;
                    parsed += p;
                    skipped += s;
                    for (lang, count) in child_by_lang {
                        *by_language.entry(lang).or_insert(0) += count;
                    }
                    for (lang, count) in child_errors {
                        *parser_errors.entry(lang).or_insert(0) += count;
                    }
                } else if path.is_file() {
                    // Skip files that exceed the configurable size limit
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() > config.max_file_size_bytes && !is_sql_path(&path) {
                            tracing::info!(
                                "Skipping {:?}: file size {} exceeds limit of {}",
                                path,
                                metadata.len(),
                                config.max_file_size_bytes
                            );
                            continue;
                        }
                    }

                    // Check if file has a supported extension
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy();
                        let ext_with_dot = format!(".{}", ext_str);
                        let is_supported = supported_extensions
                            .iter()
                            .any(|e| *e == ext_str.as_ref() || *e == ext_with_dot)
                            || path
                                .file_name()
                                .is_some_and(|name| name == "CMakeLists.txt");

                        let config_is_explicit = !matches!(ext_str.as_ref(), "conf" | "dist")
                            || config.explicit_source_files.iter().any(|p| canonical_candidate(p) == canonical_candidate(&path));
                        if is_supported && config_is_explicit && self.parsers.can_parse(&path) {
                            // Resolve the parser before parsing so we can
                            // attribute the file (and any error) to a
                            // specific language for telemetry.
                            let language = if path.extension().is_some_and(|ext| ext == "h")
                                && !config.exact_cpp_files.contains(&path) {
                                "c-or-cpp".to_string()
                            } else {
                                self.parsers.parser_for_path(&path)
                                    .map(|p| p.language().to_string())
                                    .unwrap_or_else(|| "unknown".to_string())
                            };
                            match self.index_file(graph, &path).await {
                                Ok(was_parsed) => {
                                    total += 1;
                                    counter.fetch_add(1, Ordering::Relaxed);
                                    *by_language.entry(language).or_insert(0) += 1;
                                    if was_parsed {
                                        parsed += 1;
                                    } else {
                                        skipped += 1;
                                        tracing::trace!("Skipped unchanged: {:?}", path);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to index {:?}: {}", path, e);
                                    *parser_errors.entry(language).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }

            (total, parsed, skipped, by_language, parser_errors)
        })
    }

    /// Index a single file. Returns `Ok(true)` if the file was parsed,
    /// `Ok(false)` if it was skipped because the content hash is unchanged.
    pub async fn index_file(
        &self,
        graph: &Arc<RwLock<CodeGraph>>,
        path: &Path,
    ) -> Result<bool, String> {
        crate::watcher::validate_call_scope_configuration().map_err(|error| error.to_string())?;
        // Read content and compute hash. SQL has a parser-specific larger
        // bound, enforced before allocating the full contents.
        let content = read_index_content(path)?;
        let hash = Self::hash_content(&content);

        // Check if file content has changed since last index
        {
            let mut state = self.index_state.lock().await;
            if let Some(cached_hash) = state.get_hash(path) {
                if cached_hash == hash {
                    let identity = self.mount_table.read().ok().and_then(|table| cached_volume_identity(table.as_deref(), path, &self.uuid_cache));
                    if let Some(identity) = identity { state.set_volume(path, identity); }
                    return Ok(false); // Unchanged
                }
            }
        }

        // The old graph nodes are about to be removed. If parsing fails,
        // a later return to the previous bytes must not skip reconstruction.
        self.remove_file_hash(path).await;
        {
            let mut g = graph.write().await;
            let path_str = path.to_string_lossy().to_string();
            for old_id in g.nodes_by_path(&path_str) {
                g.delete_node(old_id).map_err(|error| format!("Failed to remove old file nodes: {error}"))?;
            }

            match self.parsers.parse_file(path, &mut g) {
                Ok(_file_info) => {
                    drop(g);
                    // Update hash in index state
                    let mut state = self.index_state.lock().await;
                    state.set_hash(path.to_path_buf(), hash);
                    let identity = self.mount_table.read().ok().and_then(|table| cached_volume_identity(table.as_deref(), path, &self.uuid_cache));
                    if let Some(identity) = identity { state.set_volume(path, identity); }
                    Ok(true)
                }
                Err(e) => Err(format!("{:?}", e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegraph::{NamespacedBackend, NodeType, PropertyMap, RocksDBBackend};

    #[tokio::test]
    async fn header_parser_upgrade_needs_fresh_index_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let file = root.join("cache.h");
        let source = b"template <typename T> class Cache {};\n";
        std::fs::write(&file, source).unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("header-upgrade-test", &root)));
        state.lock().await.set_hash(file.clone(), Indexer::hash_content(source));
        let indexer = Indexer::new(parsers, state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        // A pre-upgrade hash alone cannot identify the old parser version.
        assert!(!indexer.index_file(&graph, &file).await.unwrap());
        state.lock().await.clear();
        assert!(indexer.index_file(&graph, &file).await.unwrap());
        assert!(graph.read().await.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("Cache")));
    }

    #[tokio::test]
    async fn failed_parse_cannot_leave_an_old_hash_that_skips_restoration() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let file = root.join("example.py");
        let original = b"def restored_function():\n    return 1\n";
        std::fs::write(&file, original).unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("parse-failure-test", &root)));
        let indexer = Indexer::new(parsers, state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        assert!(indexer.index_file(&graph, &file).await.unwrap());
        std::fs::write(&file, [0xff]).unwrap();
        assert!(indexer.index_file(&graph, &file).await.is_err());
        assert!(state.lock().await.get_hash(&file).is_none());
        std::fs::write(&file, original).unwrap();
        assert!(indexer.index_file(&graph, &file).await.unwrap());
        assert!(graph.read().await.iter_nodes().any(|(_, node)|
            node.properties.get_string("name") == Some("restored_function")));
    }

    #[test]
    fn missing_file_recreated_during_identity_check_is_not_pruned() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source.rs");
        assert!(confirm_missing_with_identity(&path, "same", || Some("same".into())));
        assert!(!confirm_missing_with_identity(&path, "same", || Some("changed".into())));
        assert!(!confirm_missing_with_identity(&path, "same", || {
            std::fs::write(&path, "fn recreated() {}\n").unwrap();
            Some("same".into())
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reappeared_paths_are_reindexed_only_when_still_in_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let allowed = root.join("allowed.rs");
        let outside = temp.path().join("outside.rs");
        let redirected = root.join("redirected.rs");
        std::fs::write(&allowed, "fn returned_symbol() {}\n").unwrap();
        std::fs::write(&outside, "fn outside_symbol() {}\n").unwrap();
        std::os::unix::fs::symlink(&outside, &redirected).unwrap();
        let state = Arc::new(Mutex::new(IndexState::for_workspace("reappeared-filter", &root)));
        let indexer = Indexer::new(Arc::new(ParserRegistry::new()), state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let parsed = indexer.reindex_reappeared(&graph, &[root], &IndexConfig::default(), vec![allowed.clone(), redirected.clone()]).await;
        assert_eq!(parsed, 1);
        assert!(state.lock().await.get_hash(&allowed).is_some());
        assert!(state.lock().await.get_hash(&redirected).is_none());
        let graph = graph.read().await;
        assert!(graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("returned_symbol")));
        assert!(!graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("outside_symbol")));
    }

    #[test]
    fn refresh_waits_for_readers_before_clearing_volume_cache() {
        let root = tempfile::tempdir().unwrap();
        let indexer = Arc::new(Indexer::new(
            Arc::new(ParserRegistry::new()),
            Arc::new(Mutex::new(IndexState::for_workspace("refresh-lock", root.path()))),
        ));
        indexer.uuid_cache.lock().unwrap().insert("old-device".into(), Some("old-uuid".into()));
        let read_guard = indexer.mount_table.read().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let other = indexer.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            other.refresh_mount_snapshot();
            done_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(std::time::Duration::from_millis(50)).is_err());
        assert!(indexer.uuid_cache.lock().unwrap().contains_key("old-device"));
        drop(read_guard);
        done_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert!(indexer.uuid_cache.lock().unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_identity_distinguishes_missing_and_bind_mounted_volumes() {
        let root = "1 0 8:1 / / rw - ext4 /dev/root rw\n";
        let mounted = format!("{root}2 1 8:1 /actual /mnt/source\\040disk rw - ext4 /dev/root rw\n");
        let file = Path::new("/mnt/source disk/module/file.cpp");
        let original = mount_identity_from_table(&mounted, file).unwrap();
        assert_eq!(original.0, PathBuf::from("/mnt/source disk"));
        assert_eq!(original.2, PathBuf::from("/actual"));
        let disconnected = mount_identity_from_table(root, file).unwrap();
        assert_ne!(original, disconnected);
        assert!(mount_identity_from_table("malformed", file).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_mount_table_reparses_changes_and_rejects_invalid_data() {
        let mut live = LiveMountTable::default();
        let root = "1 0 8:1 / / rw - ext4 /dev/root rw\n";
        let file = Path::new("/mnt/target/file.rs");
        assert_eq!(mount_identity_from_entries(live.update(root.into()).unwrap(), file).unwrap().0, PathBuf::from("/"));
        live.uuids.insert("8:1".into(), Some("old".into()));
        assert!(live.update(root.into()).is_some());
        assert!(live.uuids.contains_key("8:1"));
        let changed = format!("{root}2 1 8:2 / /mnt/target rw - ext4 /dev/other rw\n");
        assert_eq!(mount_identity_from_entries(live.update(changed).unwrap(), file).unwrap().0, PathBuf::from("/mnt/target"));
        assert!(live.uuids.is_empty());
        assert!(live.update("invalid".into()).is_none());
        assert!(live.update(root.into()).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_or_broken_uuid_directory_never_authorizes_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let uuid_dir = temp.path().join("uuid");
        assert!(filesystem_uuid_in("0:0", &uuid_dir).is_none());
        std::fs::create_dir(&uuid_dir).unwrap();
        std::os::unix::fs::symlink(temp.path().join("missing-device"), uuid_dir.join("broken")).unwrap();
        assert!(filesystem_uuid_in("0:0", &uuid_dir).is_none());
        let mut live = LiveMountTable::default();
        assert!(live.identity_with_uuid_directory(temp.path(), &uuid_dir).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_identity_handles_missing_partition_and_cloned_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let devices = temp.path().join("devices");
        let block = temp.path().join("block");
        std::fs::create_dir_all(&block).unwrap();
        for (name, wwid) in [("disk-a", "device-a"), ("disk-b", "device-b")] {
            let disk = devices.join(name);
            std::fs::create_dir_all(disk.join("device")).unwrap();
            std::fs::create_dir_all(disk.join("part")).unwrap();
            std::fs::write(disk.join("device/wwid"), wwid).unwrap();
        }
        std::os::unix::fs::symlink(devices.join("disk-a/part"), block.join("8:1")).unwrap();
        std::os::unix::fs::symlink(devices.join("disk-b/part"), block.join("8:2")).unwrap();
        std::fs::create_dir_all(devices.join("disk-a/part2")).unwrap();
        std::os::unix::fs::symlink(devices.join("disk-a/part2"), block.join("8:3")).unwrap();
        assert!(filesystem_device_id_in("8:9", &block).is_none());
        assert!(filesystem_device_id_in("../../bad", &block).is_none());
        let first = filesystem_device_id_in("8:1", &block).unwrap();
        let second = filesystem_device_id_in("8:2", &block).unwrap();
        assert_eq!(first, "device-a");
        assert_eq!(second, "device-b");
        assert_ne!(("same-filesystem-uuid", first), ("same-filesystem-uuid", second));
        let mapped = block.join("253:0");
        std::fs::create_dir_all(mapped.join("dm")).unwrap();
        std::fs::create_dir_all(mapped.join("slaves/disk")).unwrap();
        std::fs::write(mapped.join("dm/uuid"), "same-mapping-uuid").unwrap();
        std::fs::write(mapped.join("slaves/disk/dev"), "8:1").unwrap();
        let mapped_a = filesystem_device_id_in("253:0", &block).unwrap();
        std::fs::write(mapped.join("slaves/disk/dev"), "8:3").unwrap();
        let mapped_other_partition = filesystem_device_id_in("253:0", &block).unwrap();
        assert_ne!(mapped_a, mapped_other_partition);
        std::fs::write(mapped.join("slaves/disk/dev"), "8:2").unwrap();
        let mapped_b = filesystem_device_id_in("253:0", &block).unwrap();
        assert_ne!(mapped_a, mapped_b);
        std::fs::write(mapped.join("slaves/disk/dev"), "8:9").unwrap();
        assert!(filesystem_device_id_in("253:0", &block).is_none());
        // A present DM directory with an unreadable UUID must not fall back
        // to a WWID and be treated as an ordinary disk.
        std::fs::remove_file(mapped.join("dm/uuid")).unwrap();
        std::fs::create_dir(mapped.join("dm/uuid")).unwrap();
        std::fs::write(mapped.join("wwid"), "unsafe-fallback").unwrap();
        assert!(filesystem_device_id_in("253:0", &block).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uuid_cache_expires_and_directory_change_invalidates_it() {
        let temp = tempfile::tempdir().unwrap();
        let uuid_dir = temp.path().join("uuid");
        std::fs::create_dir(&uuid_dir).unwrap();
        let mut live = LiveMountTable::default();
        assert!(live.identity_with_uuid_directory(temp.path(), &uuid_dir).is_none());
        live.uuids.insert("sentinel".into(), Some("stale".into()));
        live.uuid_checked = Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
        assert!(live.identity_with_uuid_directory(temp.path(), &uuid_dir).is_none());
        assert!(!live.uuids.contains_key("sentinel"));
        live.uuids.insert("sentinel".into(), Some("stale".into()));
        std::fs::write(uuid_dir.join("new-entry"), "x").unwrap();
        assert!(live.identity_with_uuid_directory(temp.path(), &uuid_dir).is_none());
        assert!(!live.uuids.contains_key("sentinel"));
    }

    #[test]
    fn missing_path_ancestors_must_be_enumerable() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let deleted = nested.join("deleted.rs");
        assert!(readable_ancestors(&deleted, root.path()));
        std::fs::remove_dir(&nested).unwrap();
        assert!(readable_ancestors(&deleted, root.path()));
        std::fs::write(&nested, "not a directory").unwrap();
        assert!(!readable_ancestors(&deleted, root.path()));
        assert!(!readable_ancestors(&deleted, &root.path().join("other")));
    }

    #[tokio::test]
    async fn incremental_reindex_prunes_deleted_paths_only_in_available_roots() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        let unavailable = root.join("unavailable");
        std::fs::create_dir_all(&root).unwrap();
        let deleted = root.join("removed.rs");
        let kept = root.join("kept.rs");
        let elsewhere = temp.path().join("outside.rs");
        let offline = unavailable.join("offline.rs");
        std::fs::write(&deleted, "fn deleted_example() {}\n").unwrap();
        std::fs::write(&kept, "fn kept_example() {}\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("deleted-path-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let mut config = IndexConfig::default();
        config.explicit_source_extensions = parsers.supported_extensions().iter()
            .map(|s| s.trim_start_matches('.').to_string()).collect();
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        assert!(!graph.write().await.nodes_by_path(&deleted.to_string_lossy()).is_empty());
        assert!(state.lock().await.get_hash(&deleted).is_some());
        let identifiable = state.lock().await.volume(&deleted).is_some();
        state.lock().await.set_hash(elsewhere.clone(), 1);
        state.lock().await.set_hash(offline.clone(), 2);
        std::fs::remove_file(&deleted).unwrap();
        let result = indexer.index_workspace(&graph, &[root.clone(), unavailable], &config).await;
        assert_eq!(result.files_parsed, 0);
        assert_eq!(result.files_removed, usize::from(identifiable));
        let mut g = graph.write().await;
        assert_eq!(g.nodes_by_path(&deleted.to_string_lossy()).is_empty(), identifiable);
        assert!(!g.nodes_by_path(&kept.to_string_lossy()).is_empty());
        drop(g);
        let hashes = state.lock().await;
        assert_eq!(hashes.get_hash(&deleted).is_none(), identifiable);
        assert!(hashes.get_hash(&kept).is_some());
        assert_eq!(hashes.get_hash(&elsewhere), Some(1));
        assert_eq!(hashes.get_hash(&offline), Some(2));
        drop(hashes);
        let db = temp.path().join("graph.db");
        indexer.persist_graph_snapshot(&graph, |graph| {
            let backend = RocksDBBackend::open(&db).map_err(|error| error.to_string())?;
            graph.persist_to(Box::new(NamespacedBackend::new(Box::new(backend), "deleted-path-test")))
                .map_err(|error| error.to_string())
        }).await.unwrap();
        let backend = RocksDBBackend::open(&db).unwrap();
        let mut restored = CodeGraph::with_backend(Box::new(NamespacedBackend::new(
            Box::new(backend), "deleted-path-test"))).unwrap();
        assert_eq!(restored.nodes_by_path(&deleted.to_string_lossy()).is_empty(), identifiable);
        assert!(!restored.nodes_by_path(&kept.to_string_lossy()).is_empty());
        restored.detach_storage().unwrap();
        let mut restored_state = IndexState::for_workspace("deleted-path-test", &root);
        restored_state.load();
        assert_eq!(restored_state.get_hash(&deleted).is_none(), identifiable);
        assert!(restored_state.get_hash(&kept).is_some());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn incremental_pruning_accepts_symlinked_workspace_root() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let deleted = alias.join("deleted.rs");
        std::fs::write(&deleted, "fn symlinked_file() {}\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("symlink-prune", &real)));
        let indexer = Indexer::new(parsers, state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        let config = IndexConfig::default();
        indexer.index_workspace(&graph, std::slice::from_ref(&alias), &config).await;
        assert!(state.lock().await.get_hash(&deleted).is_some());
        let identifiable = state.lock().await.volume(&deleted).is_some();
        std::fs::remove_file(&deleted).unwrap();
        let result = indexer.index_workspace(&graph, std::slice::from_ref(&alias), &config).await;
        assert_eq!(result.files_removed, usize::from(identifiable));
        assert_eq!(state.lock().await.get_hash(&deleted).is_none(), identifiable);
        assert_eq!(graph.write().await.nodes_by_path(&deleted.to_string_lossy()).is_empty(), identifiable);
    }

    #[tokio::test]
    async fn missing_legacy_volume_identity_preserves_graph_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let source = root.join("legacy.rs");
        std::fs::write(&source, "fn legacy_source() {}\n").unwrap();
        let state = Arc::new(Mutex::new(IndexState::for_workspace("legacy-volume", root)));
        let indexer = Indexer::new(Arc::new(ParserRegistry::new()), state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, &[root.to_path_buf()], &IndexConfig::default()).await;
        {
            let mut state = state.lock().await;
            let hash = state.get_hash(&source).unwrap();
            // Model a legacy checkpoint that has a hash but no volume sidecar.
            state.set_hash(source.clone(), hash.wrapping_add(1));
            state.set_hash(source.clone(), hash);
            assert!(state.volume(&source).is_none());
        }
        std::fs::remove_file(&source).unwrap();
        let result = indexer.index_workspace(&graph, &[root.to_path_buf()], &IndexConfig::default()).await;
        assert_eq!(result.files_removed, 0);
        assert!(state.lock().await.get_hash(&source).is_some());
        assert!(!graph.write().await.nodes_by_path(&source.to_string_lossy()).is_empty());
    }

    #[tokio::test]
    async fn hashes_commit_after_graph_success_and_stale_state_is_invalidated_on_failure() {
        let workspace = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(IndexState::for_workspace(
            "indexer-state-test",
            workspace.path(),
        )));
        let indexer = Indexer::new(Arc::new(ParserRegistry::new()), Arc::clone(&state));
        let source = workspace.path().join("source.rs");

        {
            let mut hashes = state.lock().await;
            hashes.set_hash(source.clone(), 11);
            assert!(hashes.save());
            hashes.set_hash(source.clone(), 22);
        }
        assert!(!indexer.finalize_graph_persist(false).await);
        {
            let mut loaded = IndexState::for_workspace("indexer-state-test", workspace.path());
            assert_eq!(loaded.load(), 0);
            assert!(loaded.get_hash(&source).is_none());
        }

        state.lock().await.set_hash(source.clone(), 33);
        assert!(indexer.finalize_graph_persist(true).await);
        let mut loaded = IndexState::for_workspace("indexer-state-test", workspace.path());
        assert_eq!(loaded.load(), 1);
        assert_eq!(loaded.get_hash(&source), Some(33));
    }

    #[tokio::test]
    async fn shared_persistence_gate_commits_graph_and_hashes_for_restart() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("codegraph-harness-gate-restart");
        std::fs::create_dir_all(&workspace).unwrap();
        let db = workspace.join("graph.db");
        let state = Arc::new(Mutex::new(IndexState::for_workspace(
            "gate-restart-test",
            &workspace,
        )));
        let indexer = Indexer::new(Arc::new(ParserRegistry::new()), Arc::clone(&state));
        let source = workspace.join("source.rs");
        state.lock().await.set_hash(source.clone(), 1234);
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        graph
            .write()
            .await
            .add_node(NodeType::Function, PropertyMap::new())
            .unwrap();

        indexer
            .persist_graph_snapshot(&graph, |graph| {
                let backend = RocksDBBackend::open(&db).map_err(|error| error.to_string())?;
                graph
                    .persist_to(Box::new(NamespacedBackend::new(
                        Box::new(backend),
                        "gate-restart-test",
                    )))
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        // Simulate process restart: both the graph namespace and its matching
        // file hashes must be independently reloadable after the gate returns.
        let backend = RocksDBBackend::open(&db).unwrap();
        let mut restored = CodeGraph::with_backend(Box::new(NamespacedBackend::new(
            Box::new(backend),
            "gate-restart-test",
        )))
        .unwrap();
        assert_eq!(restored.node_count(), 1);
        restored.detach_storage().unwrap();
        let mut restored_state = IndexState::for_workspace("gate-restart-test", &workspace);
        assert_eq!(restored_state.load(), 1);
        assert_eq!(restored_state.get_hash(&source), Some(1234));
    }

    #[tokio::test]
    async fn failed_shared_persistence_gate_invalidates_hash_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("codegraph-harness-gate-failure");
        std::fs::create_dir_all(&workspace).unwrap();
        let source = workspace.join("source.rs");
        let state = Arc::new(Mutex::new(IndexState::for_workspace(
            "gate-failure-test",
            &workspace,
        )));
        {
            let mut state = state.lock().await;
            state.set_hash(source.clone(), 5678);
            assert!(state.save());
        }
        let indexer = Indexer::new(Arc::new(ParserRegistry::new()), Arc::clone(&state));
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));

        let result = indexer
            .persist_graph_snapshot(&graph, |_| Err("simulated database lock".to_string()))
            .await;
        assert_eq!(result.unwrap_err(), "simulated database lock");

        let mut restored_state = IndexState::for_workspace("gate-failure-test", &workspace);
        assert_eq!(restored_state.load(), 0);
        assert!(workspace
            .join(".codegraph-state/index_state.invalid")
            .exists());
    }

    #[test]
    fn default_exclude_patterns_includes_binary_archives() {
        let patterns = IndexConfig::default_exclude_patterns();
        // Bounty 2026-05-03 specifically called out these archive shapes.
        assert!(patterns.iter().any(|p| p.contains("tar.gz")));
        assert!(patterns.iter().any(|p| p.contains("zip")));
        assert!(patterns.iter().any(|p| p.contains("deb")));
        assert!(patterns.iter().any(|p| p.contains("DS_Store")));
    }

    #[test]
    fn default_config_has_default_exclude_patterns() {
        let config = IndexConfig::default();
        assert!(
            !config.exclude_patterns.is_empty(),
            "default IndexConfig must populate exclude_patterns"
        );
    }

    fn filter_config(exclude_dirs: &[&str], max_depth: u32) -> IndexConfig {
        IndexConfig {
            exclude_dirs: exclude_dirs.iter().map(|d| d.to_string()).collect(),
            exclude_patterns: vec![],
            max_file_size_bytes: 1024 * 1024,
            max_depth,
            max_files: 1000,
            explicit_source_files: vec![],
            exact_cpp_files: vec![],
            filename_exception_files: vec![],
            explicit_source_extensions: vec![],
        }
    }

    #[cfg(unix)]
    #[test]
    fn workspace_filter_rejects_traversal_and_symlinks_outside_root() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("workspace");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(outside.join("source.rs"), "fn outside() {}").unwrap();
        std::fs::write(root.join("private/source.rs"), "fn excluded() {}").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(root.join("private"), root.join("alias")).unwrap();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &filter_config(&["private"], 20));
        assert!(!filter.admits(&root.join("../outside/source.rs")));
        assert!(!filter.admits(&root.join("escape/source.rs")));
        assert!(!filter.admits(&root.join("alias/source.rs")));
    }

    #[test]
    fn workspace_filter_excludes_what_the_indexer_excludes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join("src/cache")).unwrap();
        let filter =
            WorkspaceFilter::new(std::slice::from_ref(&root), &filter_config(&["cache"], 20));

        assert!(filter.admits(&root.join("src/lib.rs")));
        // An excluded directory excludes everything beneath it, however deep -
        // a watcher event names only the file, so every ancestor is checked.
        assert!(!filter.admits(&root.join("src/cache/gen.rs")));
        assert!(!filter.admits(&root.join("cache/deep/er/gen.rs")));
        // Hidden entries, at any level, as the indexer's walk skips them.
        assert!(!filter.admits(&root.join(".hidden.rs")));
        assert!(!filter.admits(&root.join("src/.git/x.rs")));
        // Outside every workspace root.
        assert!(!filter.admits(Path::new("/somewhere/else/lib.rs")));
    }

    #[test]
    fn exact_source_includes_bypass_only_example_dist_and_never_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let examples = root.join("apps/examples");
        let dist = root.join("conf/dist");
        let dist_cmake = root.join("conf/dist/config.cmake");
        let generated = root.join("module/dist/assets");
        let private = root.join("private");
        std::fs::create_dir_all(&examples).unwrap();
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::create_dir_all(&generated).unwrap();
        std::fs::create_dir_all(&private).unwrap();
        let example_shell = examples.join("restarter.sh");
        let dist_shell = dist.join("config.sh");
        let sibling = examples.join("unlisted.sh");
        let generated_js = generated.join("bundle.js");
        let private_shell = private.join("credentials.sh");
        let secret_file = root.join(".env");
        for path in [
            &example_shell,
            &dist_shell,
            &sibling,
            &generated_js,
            &private_shell,
            &secret_file,
        ] {
            std::fs::write(path, "#!/bin/sh\n").unwrap();
        }
        std::fs::write(&dist_cmake, "include(sample)\n").unwrap();
        let outside = tmp.path().join("outside.sh");
        std::fs::write(&outside, "#!/bin/sh\n").unwrap();
        let symlink = examples.join("outside.sh");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &symlink).unwrap();

        let mut config = IndexConfig::default();
        config.exclude_dirs.push("private".into());
        config.explicit_source_files = vec![
            example_shell.clone(),
            dist_shell.clone(),
            dist_cmake.clone(),
            generated_js.clone(),
            private_shell.clone(),
            secret_file.clone(),
        ];
        #[cfg(unix)]
        config.explicit_source_files.push(symlink.clone());
        config.explicit_source_extensions =
            vec!["sh".into(), "cmake".into(), "js".into(), "env".into()];
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);

        assert!(filter.admits(&example_shell));
        assert!(filter.admits(&dist_shell));
        assert!(filter.admits(&dist_cmake));
        assert!(!filter.admits(&sibling));
        assert!(!filter.admits(&generated_js));
        assert!(!filter.admits(&private_shell));
        assert!(!filter.admits(&secret_file));
        #[cfg(unix)]
        assert!(!filter.admits(&symlink));
    }

    #[test]
    fn exact_extensionless_sources_allow_scripts_but_not_binaries_or_private_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        let script = root.join("bin/acore");
        let binary = root.join("bin/program");
        let sibling = root.join("bin/unlisted");
        let private = root.join("private/tool");
        let docker = root.join("Dockerfile");
        for p in [&script, &sibling, &private] { std::fs::write(p, "#!/usr/bin/env bash\necho ok\n").unwrap(); }
        std::fs::write(&binary, b"\x7fELFbinary").unwrap();
        std::fs::write(&docker, "FROM example\n").unwrap();
        let mut config = IndexConfig::default();
        config.exclude_dirs.push("private".into());
        config.explicit_source_files = vec![script.clone(), binary.clone(), private.clone(), docker.clone()];
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&script)); assert!(filter.admits(&docker));
        assert!(!filter.admits(&binary)); assert!(!filter.admits(&private)); assert!(!filter.admits(&sibling));
        assert_eq!(crate::parser_registry::extensionless_source_kind(&script), Some("bash"));
        std::fs::remove_file(&script).unwrap();
        assert!(filter.admits(&script));
        assert!(filter.is_explicit_file(&script));
    }

    #[test]
    fn exact_json_fixture_does_not_open_the_fixture_directory() {
        let tmp = tempfile::tempdir().unwrap(); let root = tmp.path().join("project");
        let dir = root.join("t/fixtures/nav"); std::fs::create_dir_all(&dir).unwrap();
        let selected = dir.join("selected.json"); let sibling = dir.join("sibling.json");
        std::fs::write(&selected, "{\"name\":\"selected\"}").unwrap(); std::fs::write(&sibling, "{\"name\":\"sibling\"}").unwrap();
        let mut config = IndexConfig::default(); config.explicit_source_files = vec![selected.clone()]; config.explicit_source_extensions = vec!["json".into()];
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&selected)); assert!(!filter.admits(&sibling));
    }

    #[test]
    fn exact_php_source_does_not_open_the_logs_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let selected = logs.join("index.php");
        let sibling = logs.join("other.php");
        let log = logs.join("runtime.log");
        let private = root.join("private/logs/index.php");
        std::fs::create_dir_all(private.parent().unwrap()).unwrap();
        for path in [&selected, &sibling, &log, &private] {
            std::fs::write(path, "<?php http_response_code(403);").unwrap();
        }
        let mut config = IndexConfig::default();
        config.exclude_dirs.push("private".into());
        config.explicit_source_files = vec![selected.clone(), log.clone(), private.clone()];
        config.explicit_source_extensions = vec!["php".into(), "log".into()];
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&selected));
        assert!(!filter.admits(&sibling));
        assert!(!filter.admits(&log));
        assert!(!filter.admits(&private));
        let mut excluded = config.clone();
        excluded.exclude_patterns.push("**/index.php".into());
        assert!(!WorkspaceFilter::new(&[root], &excluded).admits(&selected));
    }

    #[test]
    fn filename_exceptions_never_bypass_excluded_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (dir, name) in [("logs", "credential.php"), ("fixtures", "credential.json"),
            ("examples", "credential.sh"), ("dist", "credential.sh"), ("bin", "credential")] {
            let path = root.join(dir).join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "#!/bin/sh\necho test\n").unwrap();
            let mut config = IndexConfig::default();
            if !config.exclude_dirs.iter().any(|entry| entry == dir) { config.exclude_dirs.push(dir.into()); }
            config.explicit_source_extensions = vec!["php".into(), "json".into(), "sh".into()];
            config.explicit_source_files = vec![path.clone()];
            assert!(WorkspaceFilter::new(&[root.to_path_buf()], &config).admits(&path), "legacy include {dir}");
            config.exclude_patterns.push("**/*credential*".into());
            config.filename_exception_files.push(path.clone());
            assert!(!WorkspaceFilter::new(&[root.to_path_buf()], &config).admits(&path), "exception {dir}");
        }
    }

    #[tokio::test]
    async fn filename_exceptions_are_exact_and_keep_other_protections() {
        let tmp = tempfile::Builder::new().prefix("codegraph-harness-").tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let selected = root.join("source_secret.rs");
        let sibling = root.join("other_secret.rs");
        let mixed = root.join("blocked_credential.rs");
        let hidden = root.join(".private/hidden_secret.rs");
        let private = root.join("private/private_secret.rs");
        let unsupported = root.join("source_secret.pem");
        let oversized = root.join("oversized_secret.rs");
        for path in [&selected, &sibling, &mixed, &hidden, &private, &unsupported, &oversized] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "pub fn selected_marker() {}\n").unwrap();
        }
        let mut config = IndexConfig::default();
        config.explicit_source_extensions = vec!["rs".into()];
        config.exclude_dirs.push("private".into());
        config.exclude_patterns.extend(["**/*secret*".into(), "**/*credential*".into(), "**/blocked_*".into()]);
        std::fs::OpenOptions::new().write(true).open(&oversized).unwrap().set_len(config.max_file_size_bytes + 1).unwrap();
        config.explicit_source_files = vec![selected.clone(), mixed.clone(), hidden.clone(), private.clone(), unsupported.clone(), oversized.clone()];
        let baseline = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(!baseline.admits(&selected));
        config.filename_exception_files = config.explicit_source_files.clone();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&selected));
        for path in [&sibling, &mixed, &hidden, &private, &unsupported, &oversized] { assert!(!filter.admits(path)); }
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("outside_secret.rs");
        std::fs::write(&outside_file, "pub fn outside() {}\n").unwrap();
        config.explicit_source_files.push(outside_file.clone());
        config.filename_exception_files.push(outside_file.clone());
        assert!(!WorkspaceFilter::new(std::slice::from_ref(&root), &config).admits(&outside_file));
        #[cfg(unix)] {
            let link = root.join("linked_secret.rs");
            std::os::unix::fs::symlink(&selected, &link).unwrap();
            config.explicit_source_files.push(link.clone());
            config.filename_exception_files.push(link.clone());
            assert!(!WorkspaceFilter::new(std::slice::from_ref(&root), &config).admits(&link));
        }
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("filename-exception-test", &root)));
        let indexer = Indexer::new(parsers, state.clone());
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let checkpoint = state.lock().await;
        assert!(checkpoint.get_hash(&selected).is_some());
        assert!(checkpoint.get_hash(&sibling).is_none());
        assert!(checkpoint.get_hash(&mixed).is_none());
        assert!(checkpoint.save());
        drop(checkpoint);
        let mut restored = IndexState::for_workspace("filename-exception-test", &root);
        assert!(restored.load() > 0);
        assert!(restored.get_hash(&selected).is_some());
        assert!(restored.get_hash(&sibling).is_none());
        state.lock().await.remove(&selected);
        assert!(graph.read().await.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("selected_marker")));
        let foreign_id = graph.write().await.add_node(codegraph::NodeType::Function,
            codegraph::PropertyMap::new().with("path", outside_file.to_string_lossy().to_string())).unwrap();
        let narrowed = indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        assert!(narrowed.failure().is_some());
        graph.write().await.delete_node(foreign_id).unwrap();
        config.filename_exception_files.clear();
        let moved = root.with_extension("offline");
        std::fs::rename(&root, &moved).unwrap();
        let unavailable = indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        assert!(unavailable.failure().is_some());
        if root.exists() { std::fs::remove_dir_all(&root).unwrap(); }
        std::fs::rename(&moved, &root).unwrap();
        std::fs::remove_file(&selected).unwrap();
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        assert!(state.lock().await.get_hash(&selected).is_none());
        assert!(!graph.read().await.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("selected_marker")));
    }

    #[test]
    fn larger_json_requires_exact_inclusion_and_remains_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let selected = root.join("selected.json");
        let sibling = root.join("sibling.json");
        for path in [&selected, &sibling] {
            std::fs::File::create(path).unwrap().set_len(2 * 1024 * 1024).unwrap();
        }
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![selected.clone()];
        config.explicit_source_extensions = vec!["json".into()];
        let filter = WorkspaceFilter::new(&[root.to_path_buf()], &config);
        assert!(filter.admits(&selected));
        assert!(!filter.admits(&sibling));
        std::fs::OpenOptions::new().write(true).open(&selected).unwrap().set_len(4 * 1024 * 1024 + 1).unwrap();
        assert!(!filter.admits(&selected));
    }

    #[tokio::test]
    async fn exact_cmake_lists_are_indexed_without_admitting_other_text() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let examples = root.join("examples");
        std::fs::create_dir_all(&examples).unwrap();
        let selected = examples.join("CMakeLists.txt");
        let unrelated = examples.join("notes.txt");
        let sibling = root.join("dist/CMakeLists.txt");
        std::fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        std::fs::write(&selected, "project(selected_project)\n").unwrap();
        std::fs::write(&unrelated, "private notes\n").unwrap();
        std::fs::write(&sibling, "project(unselected_project)\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("exact-cmake-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![selected.clone(), unrelated.clone()];
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&selected));
        assert!(!filter.admits(&unrelated));
        assert!(!filter.admits(&sibling));
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let hashes = state.lock().await;
        assert!(hashes.get_hash(&selected).is_some());
        assert!(hashes.get_hash(&unrelated).is_none());
        assert!(hashes.get_hash(&sibling).is_none());
    }

    #[tokio::test]
    async fn config_templates_are_not_walked_without_exact_inclusion() {
        let tmp = tempfile::tempdir().unwrap(); let root = tmp.path().to_path_buf();
        let allowed = root.join("selected.conf.dist"); let other = root.join("other.conf");
        std::fs::write(&allowed, "Selected.Option = fake-value\n").unwrap();
        std::fs::write(&other, "Unlisted.Option = fake-value\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("config-scope-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state);
        let mut config = IndexConfig::default(); config.explicit_source_files = vec![allowed];
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let g = graph.read().await;
        assert!(g.iter_nodes().any(|(_, n)| n.properties.get_string("name") == Some("Selected.Option")));
        assert!(!g.iter_nodes().any(|(_, n)| n.properties.get_string("name") == Some("Unlisted.Option")));
    }

    #[tokio::test]
    async fn exact_source_templates_are_indexed_without_opening_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let shell = root.join("selected.sh.dist");
        let header = root.join("selected.h.in");
        let other_shell = root.join("other.sh.dist");
        let other_header = root.join("other.h.in");
        for p in [&shell, &other_shell] { std::fs::write(p, "function template_shell() { echo ok; }\n").unwrap(); }
        for p in [&header, &other_header] { std::fs::write(p, "int template_header(void);\n").unwrap(); }
        let parsers = Arc::new(ParserRegistry::new());
        assert_eq!(parsers.language_for_path(&shell), Some("bash"));
        assert_eq!(parsers.language_for_path(&header), Some("c"));
        let state = Arc::new(Mutex::new(IndexState::for_workspace("template-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![shell.clone(), header.clone()];
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let hashes = state.lock().await;
        assert!(hashes.get_hash(&shell).is_some());
        assert!(hashes.get_hash(&header).is_some());
        assert!(hashes.get_hash(&other_shell).is_none());
        assert!(hashes.get_hash(&other_header).is_none());
    }

    #[tokio::test]
    async fn indexes_python_stubs_and_commonjs_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let stub = root.join("api.pyi");
        let commonjs = root.join("app.cjs");
        std::fs::write(&stub, "def fetch_player() -> int: ...\n").unwrap();
        std::fs::write(&commonjs, "function fetchPlayer() { return 1; }\nmodule.exports = fetchPlayer;\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("extra-source-formats-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let mut config = IndexConfig::default();
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let hashes = state.lock().await;
        assert!(hashes.get_hash(&stub).is_some());
        assert!(hashes.get_hash(&commonjs).is_some());
        drop(hashes);
        let g = graph.read().await;
        assert!(g.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("fetch_player")));
        assert!(g.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("fetchPlayer")));
    }

    #[tokio::test]
    async fn explicitly_selected_cpp_fragment_is_indexed_without_generic_inc() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let fragment = root.join("selected.cpp.inc");
        let sibling = root.join("unselected.cpp.inc");
        let ambiguous = root.join("ambiguous.inc");
        std::fs::write(&fragment, "int selected_fragment() { return 1; }\n").unwrap();
        std::fs::write(&sibling, "int unselected_fragment() { return 2; }\n").unwrap();
        std::fs::write(&ambiguous, "int ambiguous_fragment() { return 3; }\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        assert_eq!(parsers.language_for_path(&fragment), Some("cpp"));
        assert_eq!(parsers.language_for_path(&ambiguous), None);
        let state = Arc::new(Mutex::new(IndexState::for_workspace("cpp-fragment-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let mut config = IndexConfig::default();
        config.explicit_source_files = vec![fragment.clone()];
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let hashes = state.lock().await;
        assert!(hashes.get_hash(&fragment).is_some());
        assert!(hashes.get_hash(&sibling).is_none());
        assert!(hashes.get_hash(&ambiguous).is_none());
        drop(hashes);
        let g = graph.read().await;
        assert!(g.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("selected_fragment")));
    }

    #[tokio::test]
    async fn exact_cpp_mapping_indexes_only_the_named_ambiguous_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let selected = root.join("selected.inc");
        let sibling = root.join("sibling.inc");
        std::fs::write(&selected, "int exact_selected() { return 1; }").unwrap();
        std::fs::write(&sibling, "int exact_sibling() { return 1; }").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        parsers.set_exact_cpp_files(std::slice::from_ref(&selected)).unwrap();
        let state = Arc::new(Mutex::new(IndexState::for_workspace("exact-cpp-mapping", &root)));
        let indexer = Indexer::new(parsers, state.clone());
        let config = IndexConfig {
            explicit_source_files: vec![selected.clone()],
            exact_cpp_files: vec![selected.clone()],
            ..IndexConfig::default()
        };
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &config);
        assert!(filter.admits(&selected));
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let hashes = state.lock().await;
        assert!(hashes.get_hash(&selected).is_some());
        assert!(hashes.get_hash(&sibling).is_none());
        drop(hashes);
        let graph = graph.read().await;
        assert!(graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("exact_selected")));
        assert!(!graph.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("exact_sibling")));
    }

    #[tokio::test]
    async fn explicitly_selected_unit_and_ahk_templates_are_indexed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let unit = root.join("realm.service.in");
        let script = root.join("smoke.ahk.in");
        let sibling = root.join("unlisted.service");
        std::fs::write(&unit, "[Service]\nExecStart=/bin/example\n").unwrap();
        std::fs::write(&script, "Smoke() {\n value := 1\n}\n").unwrap();
        std::fs::write(&sibling, "[Service]\nExecStart=/bin/unlisted\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("unit-ahk-templates", &root)));
        let indexer = Indexer::new(parsers, state.clone());
        let config = IndexConfig { explicit_source_files: vec![unit.clone(), script.clone()], ..IndexConfig::default() };
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        let state = state.lock().await;
        assert!(state.get_hash(&unit).is_some());
        assert!(state.get_hash(&script).is_some());
        assert!(state.get_hash(&sibling).is_none());
    }

    #[tokio::test]
    async fn indexes_autohotkey_without_source_values() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let script = root.join("sample.ahk");
        std::fs::write(&script, "Login() {\n password := \"SYNTHETIC_AHK_SECRET_7921\"\n}\n").unwrap();
        let parsers = Arc::new(ParserRegistry::new());
        assert_eq!(parsers.language_for_path(&script), Some("autohotkey"));
        assert!(parsers.get_parser("ahk").is_some());
        let state = Arc::new(Mutex::new(IndexState::for_workspace("autohotkey-index-test", &root)));
        let indexer = Indexer::new(parsers.clone(), state.clone());
        let mut config = IndexConfig::default();
        config.explicit_source_extensions = parsers.supported_extensions().iter().map(|s| s.trim_start_matches('.').to_string()).collect();
        let graph = Arc::new(RwLock::new(CodeGraph::in_memory().unwrap()));
        indexer.index_workspace(&graph, std::slice::from_ref(&root), &config).await;
        assert!(state.lock().await.get_hash(&script).is_some());
        let g = graph.read().await;
        assert!(g.iter_nodes().any(|(_, node)| node.properties.get_string("name") == Some("Login")));
        assert!(g.iter_nodes().all(|(_, node)| !format!("{:?}", node.properties).contains("SYNTHETIC_AHK_SECRET_7921")));
    }

    #[test]
    fn workspace_filter_reads_codegraphignore_per_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::write(root.join(".codegraphignore"), "**/generated/**\n").unwrap();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &filter_config(&[], 20));

        assert!(!filter.admits(&root.join("src/generated/out.rs")));
        assert!(filter.admits(&root.join("src/handwritten.rs")));
    }

    #[test]
    fn workspace_filter_enforces_max_depth() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &filter_config(&[], 1));

        assert!(filter.admits(&root.join("a/file.rs")));
        assert!(!filter.admits(&root.join("a/b/file.rs")));
    }

    #[test]
    fn workspace_filter_keeps_sql_for_its_bounded_parser_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let sql = root.join("large.sql");
        let source = root.join("large.rs");
        std::fs::File::create(&sql)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        std::fs::File::create(&source)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        let filter = WorkspaceFilter::new(std::slice::from_ref(&root), &filter_config(&[], 20));

        assert!(filter.admits(&sql));
        assert!(!filter.admits(&source));
    }

    #[test]
    fn index_content_rejects_oversized_sql_before_reading_it() {
        let tmp = tempfile::tempdir().unwrap();
        let sql = tmp.path().join("oversized.sql");
        std::fs::File::create(&sql)
            .unwrap()
            .set_len(MAX_SQL_FILE_SIZE_BYTES + 1)
            .unwrap();

        let error = read_index_content(&sql).unwrap_err();
        assert!(error.contains("SQL file exceeds"), "{error}");
        assert!(error.contains(&MAX_SQL_FILE_SIZE_BYTES.to_string()));
    }

    /// A workspace reached through a symlink is reported by the OS at its
    /// resolved location. An explicit symlink is used rather than relying on
    /// macOS's `/var` -> `/private/var`, which Linux CI would not exercise.
    #[cfg(unix)]
    #[test]
    fn workspace_filter_matches_events_at_the_resolved_path() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(real.join("src/cache")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let filter =
            WorkspaceFilter::new(std::slice::from_ref(&link), &filter_config(&["cache"], 20));
        let resolved = real.canonicalize().unwrap();

        // Admitted and excluded by the same rule whichever spelling arrives.
        assert!(filter.admits(&resolved.join("src/lib.rs")));
        assert!(!filter.admits(&resolved.join("src/cache/gen.rs")));

        // Translated back to the spelling the indexer stored, so lookups by
        // path find the file's existing nodes instead of duplicating them.
        assert_eq!(
            filter.indexed_form(&resolved.join("src/lib.rs")),
            link.join("src/lib.rs")
        );
        assert_eq!(
            filter.indexed_form(&link.join("src/lib.rs")),
            link.join("src/lib.rs")
        );
    }

    /// Deleting a directory removes the parent an event path would be resolved
    /// through, so a resolved-form path must be located without touching disk.
    #[cfg(unix)]
    #[test]
    fn workspace_filter_locates_files_in_a_deleted_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(real.join("src/old")).unwrap();
        std::fs::write(real.join("src/old/a.rs"), "fn a() {}\n").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let filter = WorkspaceFilter::new(std::slice::from_ref(&link), &filter_config(&[], 20));
        let deleted = real.canonicalize().unwrap().join("src/old/a.rs");
        std::fs::remove_dir_all(real.join("src/old")).unwrap();

        assert!(filter.admits(&deleted));
        assert_eq!(filter.indexed_form(&deleted), link.join("src/old/a.rs"));
    }

    #[test]
    fn workspace_filter_prefers_the_most_specific_root() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().to_path_buf();
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        // Only the inner root excludes `vendor`.
        std::fs::write(inner.join(".codegraphignore"), "**/vendor/**\n").unwrap();
        let filter = WorkspaceFilter::new(&[outer.clone(), inner.clone()], &filter_config(&[], 20));

        assert!(!filter.admits(&inner.join("vendor/x.rs")));
    }

    #[test]
    fn extend_from_codegraphignore_appends_patterns() {
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::write(
            tmp.path().join(".codegraphignore"),
            "# comment line\n\nproof-*-*/\n*.poc.cpp\n  spaced-pattern.zip  \n",
        )
        .unwrap();
        let mut config = IndexConfig {
            exclude_dirs: vec![],
            exclude_patterns: vec!["already-here".to_string()],
            max_file_size_bytes: 1024,
            max_depth: 5,
            max_files: 100,
            explicit_source_files: vec![],
            exact_cpp_files: vec![],
            filename_exception_files: vec![],
            explicit_source_extensions: vec![],
        };
        config.extend_from_codegraphignore(tmp.path());
        // Pre-existing patterns are kept.
        assert!(config.exclude_patterns.iter().any(|p| p == "already-here"));
        // New patterns appended (3 valid lines, comment + blank skipped).
        assert!(config.exclude_patterns.iter().any(|p| p == "proof-*-*/"));
        assert!(config.exclude_patterns.iter().any(|p| p == "*.poc.cpp"));
        // Whitespace trimmed.
        assert!(config
            .exclude_patterns
            .iter()
            .any(|p| p == "spaced-pattern.zip"));
    }

    #[test]
    fn extend_from_codegraphignore_no_op_when_file_missing() {
        let tmp = tempfile::tempdir().expect("tmp");
        let mut config = IndexConfig::default();
        let before_len = config.exclude_patterns.len();
        config.extend_from_codegraphignore(tmp.path());
        assert_eq!(
            config.exclude_patterns.len(),
            before_len,
            "missing .codegraphignore must not change exclude_patterns"
        );
    }

    #[test]
    fn build_exclude_set_matches_default_archive_patterns() {
        let config = IndexConfig::default();
        let set = config.build_exclude_set();
        // Files matching defaults should be filtered.
        assert!(set.is_match("/repo/proof-bundle.tar.gz"));
        assert!(set.is_match("/repo/MSRC-VULN-12345.zip"));
        assert!(set.is_match("/path/to/.DS_Store"));
        assert!(set.is_match("/path/to/binary.so"));
        // Source files should NOT be filtered.
        assert!(!set.is_match("/repo/src/main.rs"));
        assert!(!set.is_match("/repo/src/handler.go"));
        assert!(!set.is_match("/repo/lib/foo.cpp"));
    }

    #[test]
    fn default_exclude_dirs_includes_python_node_and_credential_dirs() {
        let dirs = IndexConfig::default_exclude_dirs();
        // Python tooling caches
        assert!(dirs.iter().any(|d| d == ".venv"));
        assert!(dirs.iter().any(|d| d == ".pytest_cache"));
        assert!(dirs.iter().any(|d| d == ".mypy_cache"));
        // Node tooling
        assert!(dirs.iter().any(|d| d == ".next"));
        assert!(dirs.iter().any(|d| d == ".yarn"));
        // iOS / Apple
        assert!(dirs.iter().any(|d| d == "Pods"));
        // IaC
        assert!(dirs.iter().any(|d| d == ".terraform"));
        // Sensitive credential dirs
        assert!(dirs.iter().any(|d| d == ".aws"));
        assert!(dirs.iter().any(|d| d == ".ssh"));
        assert!(dirs.iter().any(|d| d == ".gnupg"));
        assert!(dirs.iter().any(|d| d == ".kube"));
    }

    #[test]
    fn build_exclude_set_filters_secret_file_extensions() {
        let config = IndexConfig::default();
        let set = config.build_exclude_set();
        // Private keys + cert bundles — must never be indexed or embedded.
        assert!(set.is_match("/repo/keys/server.pem"));
        assert!(set.is_match("/repo/secret.key"));
        assert!(set.is_match("/repo/identity.p12"));
        assert!(set.is_match("/repo/codesign.pfx"));
        // Certificates
        assert!(set.is_match("/repo/cert.crt"));
        assert!(set.is_match("/repo/cert.cer"));
        assert!(set.is_match("/repo/cert.der"));
        // PGP / GPG
        assert!(set.is_match("/repo/release.gpg"));
        assert!(set.is_match("/repo/release.asc"));
        // Password DBs
        assert!(set.is_match("/repo/passwords.kdbx"));
        // SSH conventional filenames (no extension)
        assert!(set.is_match("/home/user/.ssh/id_rsa"));
        assert!(set.is_match("/home/user/.ssh/id_ed25519"));
        assert!(set.is_match("/home/user/.ssh/authorized_keys"));
        assert!(set.is_match("/home/user/.ssh/known_hosts"));
        // Web auth
        assert!(set.is_match("/repo/.htpasswd"));
        assert!(set.is_match("/repo/.netrc"));
        // Terraform state (secrets after apply)
        assert!(set.is_match("/repo/terraform.tfstate"));
        assert!(set.is_match("/repo/terraform.tfstate.backup"));
        // Source files MUST still pass — bg: a file called `crypto.rs`
        // looks key-adjacent but is normal source.
        assert!(!set.is_match("/repo/src/crypto.rs"));
        assert!(!set.is_match("/repo/src/keys.go"));
        assert!(!set.is_match("/repo/src/auth.py"));
    }
}
