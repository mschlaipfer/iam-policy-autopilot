//! Integration tests for [`iam_policy_autopilot_code_review::generate_review`].
//!
//! Every TOML file under `tests/fixtures/review_generator/` is exercised by the
//! single parametrised test [`test_review_generator_fixture`].  New fixture files
//! are picked up automatically via the rstest `#[files(...)]` glob — no code
//! change is needed when adding a new fixture.
//!
//! ## Fixture schema
//!
//! ```toml
//! description = "…"
//! region = "us-east-1"
//! account = "123456789012"
//! service_hints = ["s3"]   # omit for no hints
//! explain = false
//!
//! # Full file content at base/head commits.
//! # Keys are file paths relative to the repository root.
//! [base_files]
//! "src/handler.py" = """
//! <full source at base commit>
//! """
//!
//! [head_files]
//! "src/handler.py" = """
//! <full source at head commit>
//! """
//!
//! # Unified diff string used to determine which lines were added.
//! # When absent, comments are anchored to line 1.
//! diff = """
//! diff --git a/src/handler.py b/src/handler.py
//! ...
//! """
//!
//! [[expected_comments]]
//! path = "…"
//! line = N
//! body = """
//! <exact Markdown body>
//! """
//! ```

use iam_policy_autopilot_code_review::{generate_review, ReviewInput};
use rstest::rstest;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

// ── Fixture schema ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ReviewFixture {
    description: String,
    region: String,
    account: String,
    service_hints: Option<Vec<String>>,
    explain: bool,
    /// Full file content at the base (before) commit, keyed by file path.
    #[serde(default)]
    base_files: HashMap<String, String>,
    /// Full file content at the head (after) commit, keyed by file path.
    #[serde(default)]
    head_files: HashMap<String, String>,
    /// Unified diff string used to determine which lines were added.
    /// When absent, comments are anchored to line 1.
    #[serde(default)]
    diff: String,
    #[serde(default)]
    expected_comments: Vec<ExpectedComment>,
}

#[derive(Debug, Deserialize)]
struct ExpectedComment {
    path: String,
    line: u32,
    /// `"RIGHT"` (default) for comments on added lines; `"LEFT"` for removed lines.
    #[serde(default = "default_side")]
    side: String,
    body: String,
}

fn default_side() -> String {
    "RIGHT".to_string()
}

// ── Single parametrised test – auto-discovers every *.toml fixture ────────────

#[rstest]
#[tokio::test]
async fn test_review_generator_fixture(
    #[files("tests/fixtures/review_generator/*.toml")] path: PathBuf,
) {
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {path:?}: {e}"));
    let fixture: ReviewFixture = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("cannot parse fixture {path:?}: {e}"));

    // Strip leading newlines from file content values so authors can write
    // `"src/handler.py" = """\n<content>` naturally.
    let base_files: HashMap<String, String> = fixture
        .base_files
        .into_iter()
        .map(|(k, v)| (k, v.trim_start_matches('\n').to_owned()))
        .collect();
    let head_files: HashMap<String, String> = fixture
        .head_files
        .into_iter()
        .map(|(k, v)| (k, v.trim_start_matches('\n').to_owned()))
        .collect();

    let input = ReviewInput {
        region: fixture.region,
        account: fixture.account,
        service_hints: fixture.service_hints,
        explain: fixture.explain,
        base_files,
        head_files,
        diff: fixture.diff,
    };

    let comments = generate_review(input)
        .await
        .unwrap_or_else(|e| panic!("[{}] generate_review failed: {e}", fixture.description));

    assert_eq!(
        comments.len(),
        fixture.expected_comments.len(),
        "[{}] wrong number of review comments: got {}, expected {}",
        fixture.description,
        comments.len(),
        fixture.expected_comments.len(),
    );

    for (i, expected) in fixture.expected_comments.iter().enumerate() {
        let actual = &comments[i];
        assert_eq!(
            actual.path, expected.path,
            "[{}] comment[{i}] path: got {:?}, expected {:?}",
            fixture.description, actual.path, expected.path,
        );
        assert_eq!(
            actual.line, expected.line,
            "[{}] comment[{i}] line: got {}, expected {}",
            fixture.description, actual.line, expected.line,
        );
        let actual_side = format!("{:?}", actual.side).to_uppercase();
        assert_eq!(
            actual_side, expected.side,
            "[{}] comment[{i}] side: got {:?}, expected {:?}",
            fixture.description, actual_side, expected.side,
        );
        // TOML multiline strings include a leading newline; strip it.
        let expected_body = expected.body.trim_start_matches('\n');
        assert_eq!(
            actual.body, expected_body,
            "[{}] comment[{i}] body mismatch.\nGot:\n{}\n\nExpected:\n{}",
            fixture.description, actual.body, expected_body,
        );
    }
}
