//! Review generator: orchestrates policy generation on the before/after versions
//! of changed files, computes the permission delta, and formats Markdown review
//! comments.
//!
//! ## How it works
//!
//! The caller supplies:
//! - The full file content at the base (before) and head (after) commits via
//!   [`ReviewInput::base_files`] and [`ReviewInput::head_files`].
//! - A unified diff string via [`ReviewInput::diff`] that identifies which lines
//!   were added in the PR.
//!
//! For each file that appears in either map the generator:
//!
//! 1. Runs policy generation with `individual_policies = true` on the base
//!    version and on the head version concurrently.  Individual policies give
//!    one [`PolicyWithMetadata`] per SDK call, which lets us attribute each
//!    IAM action to the exact call expression that requires it.
//! 2. Runs `extract_sdk_calls` on the head version to obtain the source-code
//!    line number for each SDK call.  Because `generate_policies` with
//!    `individual_policies = true` preserves the extraction order, the i-th
//!    policy corresponds to the i-th extracted SDK call.
//! 3. For each SDK call whose `start_line()` falls within the added lines from
//!    the diff, emits a separate [`ReviewComment`] anchored to that line and
//!    containing only the IAM actions required by that specific call.
//! 4. Computes the overall permission delta (base vs. head) and, when there are
//!    permissions that are no longer required, emits one additional comment
//!    anchored to the first added line (or line 1).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
#[cfg(test)]
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use futures::future::join_all;
use iam_policy_autopilot_policy_generation::api::extract_sdk_calls;
use iam_policy_autopilot_policy_generation::api::model::{
    AwsContext, ExtractSdkCallsConfig, GeneratePoliciesResult, GeneratePolicyConfig, ServiceHints,
};
use iam_policy_autopilot_policy_generation::api::generate_policies;
use iam_policy_autopilot_policy_generation::{Explanations, OperationSource};
use log::warn;

// ── Public input/output types ─────────────────────────────────────────────────

/// Input to the review generator.
#[derive(Debug, Clone)]
pub struct ReviewInput {
    /// AWS region for ARN generation (use `"*"` for region-agnostic output).
    pub region: String,
    /// AWS account ID for ARN generation (use `"*"` for account-agnostic output).
    pub account: String,
    /// Optionally restrict analysis to specific AWS services.
    pub service_hints: Option<Vec<String>>,
    /// When `true`, include explain output in the comment body.
    pub explain: bool,
    /// Full source-file content at the **base** (before) commit.
    ///
    /// Keys are file paths relative to the repository root.  Files present
    /// here are analysed for the "before" permission set.  Files absent here
    /// but present in `head_files` are treated as newly added (empty base).
    pub base_files: HashMap<String, String>,
    /// Full source-file content at the **head** (after) commit.
    ///
    /// Keys are file paths relative to the repository root.  Files present
    /// here are analysed for the "after" permission set.  Files absent here
    /// but present in `base_files` are treated as deleted (empty head).
    pub head_files: HashMap<String, String>,
    /// Unified diff string (e.g. from `git diff`) used to determine which lines
    /// were added in the PR.  Used to anchor review comments to the correct line.
    ///
    /// When empty, comments are anchored to line 1.
    pub diff: String,
}

/// Which side of the diff the comment is anchored to.
///
/// - `Right` (default): the comment is on an **added** line in the head version.
/// - `Left`: the comment is on a **removed** line in the base version.
///
/// Maps directly to the GitHub Pull Request review comment API `side` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CommentSide {
    Left,
    Right,
}

/// A single inline review comment ready to be posted to the GitHub API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReviewComment {
    /// File path relative to the repository root.
    pub path: String,
    /// Line number to anchor the comment on (1-based).
    pub line: u32,
    /// Which side of the diff the comment is anchored to.
    ///
    /// `Right` for comments on added lines; `Left` for comments on removed lines.
    pub side: CommentSide,
    /// Markdown-formatted comment body.
    pub body: String,
}

// ── Language detection ────────────────────────────────────────────────────────

/// Supported source languages, detected from file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Python,
    JavaScript,
    TypeScript,
    Go,
}

impl Language {
    fn from_path(path: &str) -> Option<Self> {
        let ext = std::path::Path::new(path).extension()?.to_str()?;
        match ext {
            "py" => Some(Self::Python),
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" | "tsx" => Some(Self::TypeScript),
            "go" => Some(Self::Go),
            _ => None,
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::JavaScript => "js",
            Self::TypeScript => "ts",
            Self::Go => "go",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
        }
    }
}

// ── Diff parsing ──────────────────────────────────────────────────────────────

/// Parse a unified diff and return a map from file path → set of added line
/// numbers (1-based) in the **head** (after) version of each file.
///
/// Only lines that start with `+` (but not `+++`) are counted as added.
/// The hunk header `@@ -a,b +c,d @@` tells us the starting line in the head
/// file; we track the current head line number as we walk through the hunk.
fn parse_added_lines(diff: &str) -> HashMap<String, HashSet<u32>> {
    let mut result: HashMap<String, HashSet<u32>> = HashMap::new();
    let mut current_file: Option<String> = None;
    let mut head_line: u32 = 0;

    for line in diff.lines() {
        if let Some(stripped) = line.strip_prefix("+++ ") {
            // `+++ b/src/handler.py` → strip the `b/` prefix if present
            let path = stripped.trim();
            let path = path.strip_prefix("b/").unwrap_or(path);
            current_file = Some(path.to_string());
            continue;
        }

        if line.starts_with("--- ") {
            // base file marker – skip
            continue;
        }

        if line.starts_with("diff ") || line.starts_with("index ") || line.starts_with("new file")
            || line.starts_with("deleted file") || line.starts_with("old mode")
            || line.starts_with("new mode")
        {
            continue;
        }

        if line.starts_with("@@ ") {
            // Parse `@@ -a,b +c,d @@` to get the starting head line `c`.
            // Format: `@@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@`
            if let Some(new_start) = parse_hunk_new_start(line) {
                head_line = new_start;
            }
            continue;
        }

        let Some(ref file) = current_file else {
            continue;
        };

        if line.starts_with('+') {
            // Added line – record the current head line number
            result.entry(file.clone()).or_default().insert(head_line);
            head_line += 1;
        } else if line.starts_with('-') {
            // Removed line – does not advance head line counter
        } else {
            // Context line – advances head line counter
            head_line += 1;
        }
    }

    result
}

/// Parse a unified diff and return a map from file path → set of removed line
/// numbers (1-based) in the **base** (before) version of each file.
///
/// Only lines that start with `-` (but not `---`) are counted as removed.
/// The hunk header `@@ -a,b +c,d @@` tells us the starting line in the base
/// file; we track the current base line number as we walk through the hunk.
fn parse_removed_lines(diff: &str) -> HashMap<String, HashSet<u32>> {
    let mut result: HashMap<String, HashSet<u32>> = HashMap::new();
    // Track the base-file path from the `--- a/…` header line.
    let mut current_file: Option<String> = None;
    let mut base_line: u32 = 0;

    for line in diff.lines() {
        if let Some(stripped) = line.strip_prefix("--- ") {
            // `--- a/src/handler.py` → strip the `a/` prefix if present.
            // For deleted files the head side is `/dev/null`; we use the base path.
            let path = stripped.trim();
            let path = path.strip_prefix("a/").unwrap_or(path);
            // Skip `/dev/null` (new files have no base)
            if path != "/dev/null" {
                current_file = Some(path.to_string());
            }
            continue;
        }

        if line.starts_with("+++ ") {
            // head file marker – skip (we already captured the base path above)
            continue;
        }

        if line.starts_with("diff ") || line.starts_with("index ") || line.starts_with("new file")
            || line.starts_with("deleted file") || line.starts_with("old mode")
            || line.starts_with("new mode")
        {
            continue;
        }

        if line.starts_with("@@ ") {
            if let Some(old_start) = parse_hunk_old_start(line) {
                base_line = old_start;
            }
            continue;
        }

        let Some(ref file) = current_file else {
            continue;
        };

        if line.starts_with('-') {
            // Removed line – record the current base line number
            result.entry(file.clone()).or_default().insert(base_line);
            base_line += 1;
        } else if line.starts_with('+') {
            // Added line – does not advance base line counter
        } else {
            // Context line – advances base line counter
            base_line += 1;
        }
    }

    result
}

/// Extract the new-file starting line number from a unified diff hunk header.
///
/// Hunk header format: `@@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@`
fn parse_hunk_new_start(hunk_header: &str) -> Option<u32> {
    // Find the `+` part after `@@`
    let after_at = hunk_header.strip_prefix("@@ ")?;
    // Skip the `-old` part and find `+new`
    let plus_pos = after_at.find(" +")?;
    let new_part = &after_at[plus_pos + 2..];
    // Take up to the next space or comma
    let end = new_part
        .find([',', ' '])
        .unwrap_or(new_part.len());
    new_part[..end].parse().ok()
}

/// Extract the old-file starting line number from a unified diff hunk header.
///
/// Hunk header format: `@@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@`
fn parse_hunk_old_start(hunk_header: &str) -> Option<u32> {
    // Find the `-` part after `@@ `
    let after_at = hunk_header.strip_prefix("@@ ")?;
    // The old part starts with `-`
    let minus_part = after_at.strip_prefix('-')?;
    // Take up to the next space or comma
    let end = minus_part
        .find([',', ' '])
        .unwrap_or(minus_part.len());
    minus_part[..end].parse().ok()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract all IAM action strings from a `GeneratePoliciesResult`.
///
/// Because `IamPolicy` and `Statement` fields are `pub(crate)` in the
/// policy-generation crate, we round-trip through JSON to read them.
fn extract_actions(result: &GeneratePoliciesResult) -> BTreeSet<String> {
    let mut actions = BTreeSet::new();

    let Ok(json) = serde_json::to_value(result) else {
        return actions;
    };

    // Shape: { "Policies": [ { "Policy": { "Statement": [ { "Action": [...] } ] } } ] }
    if let Some(policies) = json.get("Policies").and_then(|v| v.as_array()) {
        for policy_entry in policies {
            if let Some(statements) = policy_entry
                .get("Policy")
                .and_then(|p| p.get("Statement"))
                .and_then(|s| s.as_array())
            {
                for stmt in statements {
                    if let Some(action_val) = stmt.get("Action") {
                        match action_val {
                            serde_json::Value::String(s) => {
                                actions.insert(s.clone());
                            }
                            serde_json::Value::Array(arr) => {
                                for a in arr {
                                    if let Some(s) = a.as_str() {
                                        actions.insert(s.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    actions
}

/// Extract the IAM actions for a single policy entry (by index) from a
/// `GeneratePoliciesResult`.
///
/// Returns the set of action strings from the i-th policy in the result.
/// Used to attribute permissions to a specific SDK call when
/// `individual_policies = true`.
fn extract_actions_for_policy(result: &GeneratePoliciesResult, index: usize) -> BTreeSet<String> {
    let mut actions = BTreeSet::new();

    let Ok(json) = serde_json::to_value(result) else {
        return actions;
    };

    let Some(policies) = json.get("Policies").and_then(|v| v.as_array()) else {
        return actions;
    };

    let Some(policy_entry) = policies.get(index) else {
        return actions;
    };

    let Some(statements) = policy_entry
        .get("Policy")
        .and_then(|p| p.get("Statement"))
        .and_then(|s| s.as_array())
    else {
        return actions;
    };

    for stmt in statements {
        if let Some(action_val) = stmt.get("Action") {
            match action_val {
                serde_json::Value::String(s) => {
                    actions.insert(s.clone());
                }
                serde_json::Value::Array(arr) => {
                    for a in arr {
                        if let Some(s) = a.as_str() {
                            actions.insert(s.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    actions
}

/// Returns `true` if any operation in the explanation reasons was added via
/// Forward Access Sessions (FAS) expansion.
fn explanation_has_fas(explanation: &iam_policy_autopilot_policy_generation::Explanation) -> bool {
    explanation.reasons.iter().any(|r| {
        r.operations
            .iter()
            .any(|op| matches!(op.source, OperationSource::Fas(_)))
    })
}

/// Extract explain text for a set of actions from a [`GeneratePoliciesResult`].
///
/// Returns a map from action name → human-readable explanation string.
///
/// Only actions that have a "surprising" reason are included:
/// - **Forward Access Sessions (FAS)**: the action was not called directly in
///   code but is required because AWS services call other services on your
///   behalf.
fn extract_explanations(result: &GeneratePoliciesResult) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let Some(explanations) = &result.explanations else {
        return map;
    };

    for (action, explanation) in &explanations.explanation_for_action {
        if explanation_has_fas(explanation) {
            map.insert(
                action.clone(),
                format!(
                    "needed for [Forward Access Session]({}) permissions",
                    Explanations::FAS_DOCS_URL
                ),
            );
        }
    }

    map
}

/// Write `content` to a named temporary file with the given extension and run
/// policy generation on it with `individual_policies = true`.
async fn analyse_source(
    content: &str,
    language: Language,
    aws_context: AwsContext,
    service_hints: Option<ServiceHints>,
    explain: bool,
) -> Result<GeneratePoliciesResult> {
    let suffix = format!(".{}", language.extension());
    let mut tmp = tempfile::Builder::new()
        .suffix(&suffix)
        .tempfile()
        .context("Failed to create temporary source file")?;
    tmp.write_all(content.as_bytes())
        .context("Failed to write source to temporary file")?;
    tmp.flush().context("Failed to flush temporary source file")?;

    let source_files = vec![PathBuf::from(tmp.path())];

    let explain_filters = if explain {
        Some(vec!["*".to_string()])
    } else {
        None
    };

    let result = generate_policies(&GeneratePolicyConfig {
        extract_sdk_calls_config: ExtractSdkCallsConfig {
            source_files,
            language: Some(language.as_str().to_string()),
            service_hints,
        },
        aws_context,
        individual_policies: true,
        minimize_policy_size: false,
        disable_file_system_cache: false,
        explain_filters,
    })
    .await
    .context("Policy generation failed")?;

    Ok(result)
}

/// Extract SDK call line numbers from the head file content.
///
/// Returns a sorted list of 1-based line numbers where SDK calls start,
/// in the same order as the calls were extracted (which matches the order
/// of policies produced by `generate_policies` with `individual_policies = true`).
async fn extract_sdk_call_lines(
    content: &str,
    language: Language,
    service_hints: Option<ServiceHints>,
) -> Vec<u32> {
    let suffix = format!(".{}", language.extension());
    let mut tmp = match tempfile::Builder::new().suffix(&suffix).tempfile() {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    if tmp.write_all(content.as_bytes()).is_err() {
        return vec![];
    }
    if tmp.flush().is_err() {
        return vec![];
    }

    let config = ExtractSdkCallsConfig {
        source_files: vec![PathBuf::from(tmp.path())],
        language: Some(language.as_str().to_string()),
        service_hints,
    };

    let extracted = match extract_sdk_calls(&config).await {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    extracted
        .methods
        .iter()
        .filter_map(|call| {
            call.metadata
                .as_ref()
                .and_then(|m| u32::try_from(m.location.start_line()).ok())
        })
        .collect()
}

/// Format a flat list of actions as Markdown bullet points, annotating FAS actions.
fn format_action_list(
    actions: &BTreeSet<String>,
    explanations: &HashMap<String, String>,
) -> String {
    let mut out = String::new();
    for action in actions {
        if let Some(reason) = explanations.get(action) {
            write!(out, "\n- `{action}` — {reason}").expect("writing to a String is infallible");
        } else {
            write!(out, "\n- `{action}`").expect("writing to a String is infallible");
        }
    }
    out
}

/// Format a Markdown review comment body for a set of added actions only.
///
/// Used when generating per-SDK-call comments (no "removed" section, since
/// removed permissions are reported in a separate file-level comment).
fn format_added_comment_body(
    added: &BTreeSet<String>,
    explanations: &HashMap<String, String>,
) -> String {
    if added.is_empty() {
        return String::new();
    }

    let mut section = "⚠️ **New IAM permissions required by this change:**\n".to_string();
    section.push_str(&format_action_list(added, explanations));
    section.push_str(
        "\n\n> These permissions were detected via static analysis of the added code.\n\
         > Review carefully before granting.",
    );
    section
}

/// Format a Markdown review comment body for a set of removed actions only.
fn format_removed_comment_body(removed: &BTreeSet<String>) -> String {
    if removed.is_empty() {
        return String::new();
    }

    let mut section =
        "✅ **IAM permissions no longer required after this change:**\n".to_string();
    for action in removed {
        write!(section, "\n- `{action}`").expect("writing to a String is infallible");
    }
    section
}

/// Format a Markdown review comment body for a set of added/removed actions.
///
/// When `added_groups` is `Some`, the added actions are rendered grouped by the
/// SDK call expression that requires them.  When it is `None`, a single flat
/// list is rendered.
///
/// This function is retained for use in unit tests that verify the combined
/// added+removed comment format.
#[cfg(test)]
fn format_comment_body(
    added: &BTreeSet<String>,
    removed: &BTreeSet<String>,
    explanations: &HashMap<String, String>,
    added_groups: Option<&BTreeMap<String, BTreeSet<String>>>,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !added.is_empty() {
        let mut section =
            "⚠️ **New IAM permissions required by this change:**\n".to_string();

        match added_groups {
            Some(groups) => {
                let mut group_parts: Vec<String> = Vec::new();
                for (op_key, actions) in groups {
                    if op_key.is_empty() {
                        group_parts.push(format_action_list(actions, explanations));
                    } else {
                        let mut part = format!("`{op_key}`");
                        part.push_str(&format_action_list(actions, explanations));
                        group_parts.push(part);
                    }
                }
                section.push('\n');
                section.push_str(&group_parts.join("\n\n"));
            }
            None => {
                section.push_str(&format_action_list(added, explanations));
            }
        }

        section.push_str(
            "\n\n> These permissions were detected via static analysis of the added code.\n\
             > Review carefully before granting.",
        );
        parts.push(section);
    }

    if !removed.is_empty() {
        let mut section =
            "✅ **IAM permissions no longer required after this change:**\n".to_string();
        for action in removed {
            section.push_str(&format!("\n- `{action}`"));
        }
        parts.push(section);
    }

    parts.join("\n\n---\n\n")
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate inline review comments by comparing the before and after versions
/// of changed source files.
///
/// # Process
/// 1. Collect the set of changed files from the union of `base_files` and
///    `head_files` keys, skipping files whose extension is not recognised.
/// 2. Parse the diff to determine which lines were added and which were removed
///    per file.
/// 3. For each changed file, run policy generation concurrently on the base
///    version and the head version using `individual_policies = true`.
/// 4. Also run `extract_sdk_calls` on the head version to get the source-code
///    line number for each SDK call (in extraction order, matching policy order).
/// 5. For each SDK call in the head file whose line is in the added lines set,
///    emit a separate `ReviewComment` (side = `Right`) anchored to that line
///    and containing only the IAM actions required by that specific call.
/// 6. Run `extract_sdk_calls` on the base version to attribute removed
///    permissions to the specific removed lines where they originated.  Emit
///    one `ReviewComment` (side = `Left`) per removed SDK call line.  Any
///    removed permissions that cannot be attributed to a specific removed line
///    fall back to a single `Right`-side comment anchored to the first added
///    line (or line 1).
///
/// Files whose extension is not recognised are silently skipped.
/// Files where policy generation fails are skipped with a warning.
pub async fn generate_review(input: ReviewInput) -> Result<Vec<ReviewComment>> {
    use std::collections::BTreeSet as BSet;

    // Collect all file paths that appear in either map.
    let all_files: BSet<String> = input
        .base_files
        .keys()
        .chain(input.head_files.keys())
        .cloned()
        .collect();

    // Filter to supported languages only.
    let supported_files: Vec<(String, Language)> = all_files
        .into_iter()
        .filter_map(|f| Language::from_path(&f).map(|lang| (f, lang)))
        .collect();

    if supported_files.is_empty() {
        return Ok(vec![]);
    }

    // ── Parse diff to get added and removed lines per file ────────────────────
    let added_lines_by_file: HashMap<String, HashSet<u32>> = parse_added_lines(&input.diff);
    let removed_lines_by_file: HashMap<String, HashSet<u32>> = parse_removed_lines(&input.diff);

    // ── Build AWS context once ────────────────────────────────────────────────
    let aws_context = AwsContext::new(input.region.clone(), input.account.clone())
        .context("Failed to build AWS context")?;

    let service_hints = input.service_hints.as_ref().map(|names| ServiceHints {
        service_names: names.clone(),
    });

    // ── Analyse each (file, direction) pair concurrently ─────────────────────
    // We spawn one future per (file, is_head) combination.
    let futures: Vec<_> = supported_files
        .iter()
        .flat_map(|(file, language)| {
            let base_content = input.base_files.get(file).cloned();
            let head_content = input.head_files.get(file).cloned();

            let mut pairs: Vec<(String, bool, String, Language)> = Vec::new();
            if let Some(content) = base_content {
                pairs.push((file.clone(), false, content, *language));
            }
            if let Some(content) = head_content {
                pairs.push((file.clone(), true, content, *language));
            }
            pairs
        })
        .map(|(file, is_head, content, language)| {
            let aws_ctx = aws_context.clone();
            let hints = service_hints.clone();
            let explain = input.explain;
            async move {
                let result = analyse_source(&content, language, aws_ctx, hints, explain).await;
                ((file, is_head), result)
            }
        })
        .collect();

    let results: Vec<_> = join_all(futures).await;

    // ── Map results back to (file, is_head) → GeneratePoliciesResult ─────────
    let mut result_map: HashMap<(String, bool), GeneratePoliciesResult> = HashMap::new();
    for ((file, is_head), result) in results {
        match result {
            Ok(r) => {
                result_map.insert((file, is_head), r);
            }
            Err(e) => {
                warn!(
                    "Policy generation failed for {}/{}: {e}",
                    file,
                    if is_head { "head" } else { "base" }
                );
            }
        }
    }

    // ── Compute per-file delta and build comments ─────────────────────────────
    let files: BSet<String> = result_map.keys().map(|(f, _)| f.clone()).collect();

    // Accumulate new-permission actions keyed by (file, line) so that multiple
    // SDK calls at the same source location are merged into a single comment.
    let mut added_by_location: std::collections::BTreeMap<(String, u32), BTreeSet<String>> =
        std::collections::BTreeMap::new();
    // Removed-permission actions keyed by (file, base-line) for LEFT-side comments.
    let mut removed_by_location: std::collections::BTreeMap<(String, u32), BTreeSet<String>> =
        std::collections::BTreeMap::new();
    // Fallback: removed permissions that could not be attributed to a specific
    // removed line are collected here and emitted as a single RIGHT-side comment
    // anchored to the first added line (or line 1).
    let mut removed_fallback: std::collections::BTreeMap<String, (u32, BTreeSet<String>)> =
        std::collections::BTreeMap::new();
    // Explanations per file (from head result).
    let mut explanations_by_file: HashMap<String, HashMap<String, String>> = HashMap::new();

    for file in &files {
        let head_result = result_map.get(&(file.clone(), true));
        let base_result = result_map.get(&(file.clone(), false));

        let head_actions = head_result.map(extract_actions).unwrap_or_default();
        let base_actions = base_result.map(extract_actions).unwrap_or_default();

        // Delta: permissions that are new (not present in base set)
        let new_permissions: BTreeSet<String> = head_actions
            .difference(&base_actions)
            .cloned()
            .collect();
        // Delta: permissions that are gone (not present in head set)
        let gone_permissions: BTreeSet<String> = base_actions
            .difference(&head_actions)
            .cloned()
            .collect();

        if new_permissions.is_empty() && gone_permissions.is_empty() {
            continue;
        }

        // Collect explanations from the head result (most relevant for new perms).
        let explanations = head_result.map(extract_explanations).unwrap_or_default();
        explanations_by_file.insert(file.clone(), explanations);

        let empty_set = HashSet::new();
        let added_lines = added_lines_by_file.get(file.as_str()).unwrap_or(&empty_set);
        let removed_lines = removed_lines_by_file.get(file.as_str()).unwrap_or(&empty_set);

        // Find the language for this file
        let language = Language::from_path(file);

        // ── Per-SDK-call accumulation for new permissions ─────────────────────
        // For each SDK call on an added line that introduces new permissions,
        // merge its actions into the per-location accumulator so that multiple
        // calls at the same source location produce a single merged comment.
        if let (Some(lang), Some(head_content), Some(head_res)) =
            (language, input.head_files.get(file), head_result)
        {
            if !added_lines.is_empty() && !new_permissions.is_empty() {
                // Get the ordered list of SDK call line numbers from the head file.
                // This list is in the same order as the policies in head_res.
                let sdk_call_lines =
                    extract_sdk_call_lines(head_content, lang, service_hints.clone()).await;

                for (idx, &sdk_line) in sdk_call_lines.iter().enumerate() {
                    if !added_lines.contains(&sdk_line) {
                        continue;
                    }

                    // Extract the actions for this specific policy (by index).
                    let call_actions = extract_actions_for_policy(head_res, idx);

                    // Only the actions that are genuinely new (not in base).
                    let call_new_actions: BTreeSet<String> = call_actions
                        .intersection(&new_permissions)
                        .cloned()
                        .collect();

                    if call_new_actions.is_empty() {
                        continue;
                    }

                    // Merge into the per-location accumulator.
                    added_by_location
                        .entry((file.clone(), sdk_line))
                        .or_default()
                        .extend(call_new_actions);
                }
            }
        }

        // ── Per-SDK-call accumulation for removed permissions ─────────────────
        // Try to attribute each gone permission to the specific base-file line
        // where the SDK call that required it was removed.  Any permissions that
        // cannot be attributed fall back to a single RIGHT-side comment.
        if !gone_permissions.is_empty() {
            let mut attributed: BTreeSet<String> = BTreeSet::new();

            if let (Some(lang), Some(base_content), Some(base_res)) =
                (language, input.base_files.get(file), base_result)
            {
                if !removed_lines.is_empty() {
                    // Get the ordered list of SDK call line numbers from the base file.
                    let base_sdk_lines =
                        extract_sdk_call_lines(base_content, lang, service_hints.clone()).await;

                    for (idx, &sdk_line) in base_sdk_lines.iter().enumerate() {
                        if !removed_lines.contains(&sdk_line) {
                            continue;
                        }

                        // Extract the actions for this specific base policy (by index).
                        let call_actions = extract_actions_for_policy(base_res, idx);

                        // Only the actions that are genuinely gone (not in head).
                        let call_gone_actions: BTreeSet<String> = call_actions
                            .intersection(&gone_permissions)
                            .cloned()
                            .collect();

                        if call_gone_actions.is_empty() {
                            continue;
                        }

                        attributed.extend(call_gone_actions.iter().cloned());

                        // Merge into the per-location accumulator (LEFT side).
                        removed_by_location
                            .entry((file.clone(), sdk_line))
                            .or_default()
                            .extend(call_gone_actions);
                    }
                }
            }

            // Any gone permissions not attributed to a specific removed line go
            // into the fallback RIGHT-side comment.
            let unattributed: BTreeSet<String> = gone_permissions
                .difference(&attributed)
                .cloned()
                .collect();

            if !unattributed.is_empty() {
                let anchor_line = {
                    let mut sorted: Vec<u32> = added_lines.iter().copied().collect();
                    sorted.sort_unstable();
                    sorted.into_iter().next().unwrap_or(1)
                };
                removed_fallback
                    .entry(file.clone())
                    .or_insert((anchor_line, BTreeSet::new()))
                    .1
                    .extend(unattributed);
            }
        }
    }

    // ── Emit comments in (file, line) order ──────────────────────────────────
    let mut comments: Vec<ReviewComment> = Vec::new();

    // RIGHT-side comments for new permissions on added lines.
    for ((file, line), actions) in &added_by_location {
        let explanations = explanations_by_file
            .get(file)
            .cloned()
            .unwrap_or_default();
        let body = format_added_comment_body(actions, &explanations);
        if !body.is_empty() {
            comments.push(ReviewComment {
                path: file.clone(),
                line: *line,
                side: CommentSide::Right,
                body,
            });
        }
    }

    // LEFT-side comments for removed permissions on removed lines.
    for ((file, line), actions) in &removed_by_location {
        let body = format_removed_comment_body(actions);
        if !body.is_empty() {
            comments.push(ReviewComment {
                path: file.clone(),
                line: *line,
                side: CommentSide::Left,
                body,
            });
        }
    }

    // RIGHT-side fallback comments for unattributed removed permissions.
    for (file, (anchor_line, actions)) in &removed_fallback {
        let body = format_removed_comment_body(actions);
        if !body.is_empty() {
            comments.push(ReviewComment {
                path: file.clone(),
                line: *anchor_line,
                side: CommentSide::Right,
                body,
            });
        }
    }

    Ok(comments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_comment_body_added_only() {
        let added: BTreeSet<String> = ["s3:PutObject", "s3:PutObjectAcl"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let removed = BTreeSet::new();
        let explanations = HashMap::new();
        let body = format_comment_body(&added, &removed, &explanations, None);
        let expected = "\
⚠️ **New IAM permissions required by this change:**\n\
\n\
- `s3:PutObject`\n\
- `s3:PutObjectAcl`\n\
\n\
> These permissions were detected via static analysis of the added code.\n\
> Review carefully before granting.";
        assert_eq!(body, expected);
    }

    #[test]
    fn test_format_comment_body_removed_only() {
        let added = BTreeSet::new();
        let removed: BTreeSet<String> = ["s3:GetObject"].iter().map(|s| s.to_string()).collect();
        let explanations = HashMap::new();
        let body = format_comment_body(&added, &removed, &explanations, None);
        let expected = "\
✅ **IAM permissions no longer required after this change:**\n\
\n\
- `s3:GetObject`";
        assert_eq!(body, expected);
    }

    #[test]
    fn test_format_comment_body_with_explanation() {
        let added: BTreeSet<String> = ["kms:GenerateDataKey"].iter().map(|s| s.to_string()).collect();
        let removed = BTreeSet::new();
        let mut explanations = HashMap::new();
        explanations.insert(
            "kms:GenerateDataKey".to_string(),
            format!(
                "needed for [Forward Access Session]({}) permissions",
                Explanations::FAS_DOCS_URL
            ),
        );
        let body = format_comment_body(&added, &removed, &explanations, None);
        let expected = format!(
            "⚠️ **New IAM permissions required by this change:**\n\n\
- `kms:GenerateDataKey` — needed for [Forward Access Session]({}) permissions\n\n\
> These permissions were detected via static analysis of the added code.\n\
> Review carefully before granting.",
            Explanations::FAS_DOCS_URL
        );
        assert_eq!(body, expected);
    }

    #[test]
    fn test_format_comment_body_both() {
        let added: BTreeSet<String> = ["s3:PutObject"].iter().map(|s| s.to_string()).collect();
        let removed: BTreeSet<String> = ["s3:GetObject"].iter().map(|s| s.to_string()).collect();
        let explanations = HashMap::new();
        let body = format_comment_body(&added, &removed, &explanations, None);
        let expected = "\
⚠️ **New IAM permissions required by this change:**\n\
\n\
- `s3:PutObject`\n\
\n\
> These permissions were detected via static analysis of the added code.\n\
> Review carefully before granting.\n\
\n\
---\n\
\n\
✅ **IAM permissions no longer required after this change:**\n\
\n\
- `s3:GetObject`";
        assert_eq!(body, expected);
    }

    #[test]
    fn test_format_comment_body_grouped_by_operation() {
        let added: BTreeSet<String> = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:PutObjectAcl",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let removed = BTreeSet::new();
        let explanations = HashMap::new();

        let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        groups.insert(
            "s3.get_object(Bucket='b', Key='k')".to_string(),
            ["s3:GetObject"].iter().map(|s| s.to_string()).collect(),
        );
        groups.insert(
            "s3.put_object(Bucket='b', Key='k', Body=b'')".to_string(),
            ["s3:PutObject", "s3:PutObjectAcl"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        let body = format_comment_body(&added, &removed, &explanations, Some(&groups));
        let expected = "\
⚠️ **New IAM permissions required by this change:**\n\
\n\
`s3.get_object(Bucket='b', Key='k')`\n\
- `s3:GetObject`\n\
\n\
`s3.put_object(Bucket='b', Key='k', Body=b'')`\n\
- `s3:PutObject`\n\
- `s3:PutObjectAcl`\n\
\n\
> These permissions were detected via static analysis of the added code.\n\
> Review carefully before granting.";
        assert_eq!(body, expected);
    }

    #[test]
    fn test_extract_actions_empty() {
        let result = GeneratePoliciesResult {
            policies: vec![],
            explanations: None,
        };
        assert!(extract_actions(&result).is_empty());
    }

    #[test]
    fn test_parse_added_lines_new_file() {
        let diff = "\
diff --git a/src/handler.py b/src/handler.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/src/handler.py
@@ -0,0 +1,3 @@
+import boto3
+s3 = boto3.client('s3')
+s3.put_object(Bucket='my-bucket', Key='my-key', Body=b'data')
";
        let result = parse_added_lines(diff);
        let lines = result.get("src/handler.py").expect("file not found");
        assert!(lines.contains(&1), "line 1 should be added");
        assert!(lines.contains(&2), "line 2 should be added");
        assert!(lines.contains(&3), "line 3 should be added");
    }

    #[test]
    fn test_parse_added_lines_modification() {
        let diff = "\
diff --git a/src/handler.py b/src/handler.py
index abc1234..def5678 100644
--- a/src/handler.py
+++ b/src/handler.py
@@ -1,3 +1,3 @@
 import boto3
 s3 = boto3.client('s3')
-s3.get_object(Bucket='my-bucket', Key='my-key')
+s3.put_object(Bucket='my-bucket', Key='my-key', Body=b'data')
";
        let result = parse_added_lines(diff);
        let lines = result.get("src/handler.py").expect("file not found");
        // Only line 3 is added (the put_object line)
        assert!(!lines.contains(&1), "line 1 is context, not added");
        assert!(!lines.contains(&2), "line 2 is context, not added");
        assert!(lines.contains(&3), "line 3 should be added");
    }

    #[test]
    fn test_parse_hunk_new_start() {
        assert_eq!(parse_hunk_new_start("@@ -0,0 +1,3 @@"), Some(1));
        assert_eq!(parse_hunk_new_start("@@ -1,3 +1,3 @@"), Some(1));
        assert_eq!(parse_hunk_new_start("@@ -10,5 +12,7 @@"), Some(12));
        assert_eq!(parse_hunk_new_start("@@ -1 +1 @@"), Some(1));
    }

    #[test]
    fn test_format_added_comment_body_empty() {
        let added = BTreeSet::new();
        let explanations = HashMap::new();
        let body = format_added_comment_body(&added, &explanations);
        assert!(body.is_empty());
    }

    #[test]
    fn test_format_added_comment_body_with_actions() {
        let added: BTreeSet<String> = ["s3:PutObject", "s3:PutObjectAcl"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let explanations = HashMap::new();
        let body = format_added_comment_body(&added, &explanations);
        let expected = "\
⚠️ **New IAM permissions required by this change:**\n\
\n\
- `s3:PutObject`\n\
- `s3:PutObjectAcl`\n\
\n\
> These permissions were detected via static analysis of the added code.\n\
> Review carefully before granting.";
        assert_eq!(body, expected);
    }

    #[test]
    fn test_format_removed_comment_body_empty() {
        let removed = BTreeSet::new();
        let body = format_removed_comment_body(&removed);
        assert!(body.is_empty());
    }

    #[test]
    fn test_format_removed_comment_body_with_actions() {
        let removed: BTreeSet<String> = ["s3:GetObject", "s3:GetObjectVersion"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let body = format_removed_comment_body(&removed);
        let expected = "\
✅ **IAM permissions no longer required after this change:**\n\
\n\
- `s3:GetObject`\n\
- `s3:GetObjectVersion`";
        assert_eq!(body, expected);
    }

}

