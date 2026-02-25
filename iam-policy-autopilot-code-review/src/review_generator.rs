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
//! 2. Computes the permission delta: actions present in the head but not the
//!    base are *new*; actions present in the base but not the head are *removed*.
//! 3. Determines the comment anchor line by:
//!    a. Parsing the diff to find which lines were added in the head file.
//!    b. Running `extract_sdk_calls` on the head file to get SDK call locations.
//!    c. Finding the first SDK call whose `start_line()` falls within the added
//!       lines, and using that line number as the anchor.
//!    d. Falling back to line 1 if no SDK call is on an added line.
//! 4. Formats the delta as a Markdown [`ReviewComment`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

/// A single inline review comment ready to be posted to the GitHub API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReviewComment {
    /// File path relative to the repository root.
    pub path: String,
    /// Line number to anchor the comment on (1-based).
    pub line: u32,
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
        if line.starts_with("+++ ") {
            // `+++ b/src/handler.py` → strip the `b/` prefix if present
            let path = line[4..].trim();
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
        .find(|c: char| c == ',' || c == ' ')
        .unwrap_or(new_part.len());
    new_part[..end].parse().ok()
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

/// Extract a mapping from SDK call expression → set of IAM actions required
/// by that call, using the individual policies from a `GeneratePoliciesResult`.
///
/// With `individual_policies = true` each policy in the result corresponds to
/// one SDK call.  The policy `Id` field holds the source call expression (e.g.
/// `"s3.put_object(Bucket='b', Key='k', Body=b'')"`) so we use it as the
/// group key.
///
/// Returns `None` when there is only one policy (grouping adds no value) or
/// when the result contains no policies.
fn extract_individual_action_groups(
    result: &GeneratePoliciesResult,
    all_actions: &BTreeSet<String>,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    if result.policies.len() <= 1 {
        return None;
    }

    let Ok(json) = serde_json::to_value(result) else {
        return None;
    };

    let policies = json.get("Policies")?.as_array()?;

    let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for policy_entry in policies {
        let policy = policy_entry.get("Policy")?;
        let id = policy.get("Id")?.as_str().unwrap_or("").to_string();
        let statements = policy.get("Statement")?.as_array()?;

        let mut call_actions = BTreeSet::new();
        for stmt in statements {
            if let Some(action_val) = stmt.get("Action") {
                match action_val {
                    serde_json::Value::String(s) => {
                        if all_actions.contains(s) {
                            call_actions.insert(s.clone());
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for a in arr {
                            if let Some(s) = a.as_str() {
                                if all_actions.contains(s) {
                                    call_actions.insert(s.to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if !call_actions.is_empty() {
            groups.entry(id).or_default().extend(call_actions);
        }
    }

    if groups.len() <= 1 {
        return None;
    }

    Some(groups)
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
/// Returns a sorted list of 1-based line numbers where SDK calls start.
/// Uses `extract_sdk_calls` to get `SdkMethodCallMetadata.location.start_line()`.
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

    let mut lines: Vec<u32> = extracted
        .methods
        .iter()
        .filter_map(|call| {
            call.metadata
                .as_ref()
                .map(|m| m.location.start_line() as u32)
        })
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// Determine the best comment anchor line for a file.
///
/// Algorithm:
/// 1. Find all SDK call line numbers in the head file.
/// 2. Find the first SDK call line that appears in the set of added lines from
///    the diff.
/// 3. Fall back to the first added line in the file if no SDK call is on an
///    added line.
/// 4. Fall back to line 1 if the diff has no added lines for this file.
async fn compute_anchor_line(
    _file: &str,
    head_content: &str,
    language: Language,
    added_lines: &HashSet<u32>,
    service_hints: Option<ServiceHints>,
) -> u32 {
    if added_lines.is_empty() {
        return 1;
    }

    let sdk_lines = extract_sdk_call_lines(head_content, language, service_hints).await;

    // Find the first SDK call line that is in the added lines set.
    for sdk_line in &sdk_lines {
        if added_lines.contains(sdk_line) {
            return *sdk_line;
        }
    }

    // Fall back: first added line in the file.
    let mut sorted: Vec<u32> = added_lines.iter().copied().collect();
    sorted.sort_unstable();
    sorted.into_iter().next().unwrap_or(1)
}

/// Format a flat list of actions as Markdown bullet points, annotating FAS actions.
fn format_action_list(
    actions: &BTreeSet<String>,
    explanations: &HashMap<String, String>,
) -> String {
    let mut out = String::new();
    for action in actions {
        if let Some(reason) = explanations.get(action) {
            out.push_str(&format!("\n- `{action}` — {reason}"));
        } else {
            out.push_str(&format!("\n- `{action}`"));
        }
    }
    out
}

/// Format a Markdown review comment body for a set of added/removed actions.
///
/// When `added_groups` is `Some`, the added actions are rendered grouped by the
/// SDK call expression that requires them.  When it is `None`, a single flat
/// list is rendered.
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
/// 2. Parse the diff to determine which lines were added per file.
/// 3. For each changed file, run policy generation concurrently on the base
///    version and the head version using `individual_policies = true`.
/// 4. Compute the permission delta per file.
/// 5. Determine the comment anchor line using SDK call locations from the diff.
/// 6. Format and return `ReviewComment` objects.
///
/// Files whose extension is not recognised are silently skipped.
/// Files where policy generation fails are skipped with a warning.
pub async fn generate_review(input: ReviewInput) -> Result<Vec<ReviewComment>> {
    // Collect all file paths that appear in either map.
    let all_files: BTreeSet<String> = input
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

    // ── Parse diff to get added lines per file ────────────────────────────────
    let added_lines_by_file: HashMap<String, HashSet<u32>> = parse_added_lines(&input.diff);

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
    let files: BTreeSet<String> = result_map.keys().map(|(f, _)| f.clone()).collect();

    let mut comments: Vec<ReviewComment> = Vec::new();

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

        // Use individual policies from the head result to group new permissions
        // by the SDK call expression that requires them.
        let added_groups = head_result
            .and_then(|r| extract_individual_action_groups(r, &new_permissions));

        let body = format_comment_body(
            &new_permissions,
            &gone_permissions,
            &explanations,
            added_groups.as_ref(),
        );

        // Determine the comment anchor line from the diff.
        let empty_set = HashSet::new();
        let added_lines = added_lines_by_file.get(file.as_str()).unwrap_or(&empty_set);

        // Find the language for this file (we know it's supported since it's in result_map)
        let language = Language::from_path(file);

        let line = if let (Some(lang), Some(head_content)) =
            (language, input.head_files.get(file))
        {
            compute_anchor_line(
                file,
                head_content,
                lang,
                added_lines,
                service_hints.clone(),
            )
            .await
        } else {
            // Deleted file or unsupported language – use first added line or 1
            let mut sorted: Vec<u32> = added_lines.iter().copied().collect();
            sorted.sort_unstable();
            sorted.into_iter().next().unwrap_or(1)
        };

        comments.push(ReviewComment {
            path: file.clone(),
            line,
            body,
        });
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
}
