//! IAM Policy Autopilot Code Review
//!
//! This crate provides functionality for generating IAM policy review comments
//! by comparing the before and after versions of source files.  It is used by
//! the `generate-review` CLI subcommand.
//!
//! # Overview
//!
//! Given the full file content at the base (before) and head (after) commits,
//! this crate:
//!
//! 1. **Analyses** each changed file using IAM Policy Autopilot, running the
//!    extractor on the complete file content at each commit.
//! 2. **Computes** the permission delta (new permissions, removed permissions)
//!    using `individual_policies` to attribute each permission to the exact
//!    SDK call that requires it.
//! 3. **Formats** the delta as Markdown inline review comments
//!    ([`review_generator::ReviewComment`]).
//!
//! # Quick start
//!
//! ```no_run
//! use iam_policy_autopilot_code_review::{generate_review, ReviewInput};
//! use std::collections::HashMap;
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let mut base_files = HashMap::new();
//! base_files.insert("src/handler.py".to_string(), "import boto3\ns3 = boto3.client('s3')\ns3.get_object(Bucket='b', Key='k')\n".to_string());
//!
//! let mut head_files = HashMap::new();
//! head_files.insert("src/handler.py".to_string(), "import boto3\ns3 = boto3.client('s3')\ns3.put_object(Bucket='b', Key='k', Body=b'')\n".to_string());
//!
//! let comments = generate_review(ReviewInput {
//!     region: "*".to_string(),
//!     account: "*".to_string(),
//!     service_hints: None,
//!     explain: true,
//!     base_files,
//!     head_files,
//!     line_hints: HashMap::new(),
//! }).await?;
//!
//! let json = serde_json::to_string_pretty(&comments)?;
//! println!("{json}");
//! # Ok(())
//! # }
//! ```

pub mod review_generator;

// Re-export the most commonly used public items at the crate root.
pub use review_generator::{generate_review, ReviewComment, ReviewInput};
