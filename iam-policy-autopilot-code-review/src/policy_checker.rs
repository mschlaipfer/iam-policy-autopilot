//! Reference policy checker: classifies required actions against an existing
//! IAM policy document.

use iam_policy_autopilot_policy_generation::api::action_matches_pattern;
use serde::Deserialize;

/// Classification of a required action against a reference policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionStatus {
    pub denied: bool,
    pub allowed: bool,
    /// Human-readable condition strings from matching Allow statements.
    pub conditions: Vec<String>,
    /// Resource ARNs from matching Allow statements that are not `"*"`.
    pub restricted_resources: Vec<String>,
}

impl ActionStatus {
    /// Returns `true` when the action is unconditionally allowed with broad resources.
    #[must_use]
    pub fn is_fully_allowed(&self) -> bool {
        self.allowed && self.conditions.is_empty() && self.restricted_resources.is_empty()
    }

    /// Returns `true` when the action is not covered by any Allow or Deny statement.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        !self.allowed && !self.denied
    }
}

/// A parsed reference IAM policy document ready for action lookups.
#[derive(Debug)]
pub struct PolicyChecker {
    statements: Vec<ParsedStatement>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyDocument {
    statement: StatementOrVec,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StatementOrVec {
    Single(Box<RawStatement>),
    Multiple(Vec<RawStatement>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatement {
    effect: String,
    #[serde(default)]
    action: StringOrVec,
    #[serde(default)]
    resource: StringOrVec,
    #[serde(default)]
    condition: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(untagged)]
enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
    #[default]
    Empty,
}

impl StringOrVec {
    fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(v) => v.clone(),
            Self::Empty => vec![],
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedStatement {
    effect: Effect,
    actions: Vec<String>,
    resources: Vec<String>,
    conditions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Allow,
    Deny,
}

impl PolicyChecker {
    /// Parse a JSON IAM policy document into a checker.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let doc: PolicyDocument =
            serde_json::from_str(json).map_err(|e| format!("invalid policy JSON: {e}"))?;

        let raw_statements = match doc.statement {
            StatementOrVec::Single(s) => vec![*s],
            StatementOrVec::Multiple(v) => v,
        };

        let statements = raw_statements
            .into_iter()
            .filter_map(|raw| {
                let effect = match raw.effect.as_str() {
                    "Allow" => Effect::Allow,
                    "Deny" => Effect::Deny,
                    _ => return None,
                };
                let conditions = raw
                    .condition
                    .as_ref()
                    .map(format_conditions)
                    .unwrap_or_default();
                Some(ParsedStatement {
                    effect,
                    actions: raw.action.to_vec(),
                    resources: raw.resource.to_vec(),
                    conditions,
                })
            })
            .collect();

        Ok(Self { statements })
    }

    /// Classify an action against this reference policy.
    #[must_use]
    pub fn check_action(&self, action: &str) -> ActionStatus {
        let mut status = ActionStatus {
            denied: false,
            allowed: false,
            conditions: Vec::new(),
            restricted_resources: Vec::new(),
        };

        // Deny statements take precedence.
        for stmt in &self.statements {
            if stmt.effect == Effect::Deny && stmt.matches_action(action) {
                status.denied = true;
            }
        }

        // Allow statements.
        for stmt in &self.statements {
            if stmt.effect == Effect::Allow && stmt.matches_action(action) {
                status.allowed = true;
                status.conditions.extend(stmt.conditions.iter().cloned());
                let restricted: Vec<String> = stmt
                    .resources
                    .iter()
                    .filter(|r| *r != "*")
                    .cloned()
                    .collect();
                if !restricted.is_empty() && !stmt.resources.iter().any(|r| r == "*") {
                    status.restricted_resources.extend(restricted);
                }
            }
        }

        status.conditions.sort();
        status.conditions.dedup();
        status.restricted_resources.sort();
        status.restricted_resources.dedup();

        status
    }
}

impl ParsedStatement {
    fn matches_action(&self, action: &str) -> bool {
        self.actions
            .iter()
            .any(|pattern| action_matches_pattern(action, pattern))
    }
}

/// Format a Condition JSON value into human-readable strings.
///
/// IAM conditions look like:
/// ```json
/// { "StringEquals": { "kms:ViaService": "s3.us-east-1.amazonaws.com" } }
/// ```
/// We render each key-value pair as: `Operator: key = value`
fn format_conditions(condition: &serde_json::Value) -> Vec<String> {
    let Some(obj) = condition.as_object() else {
        return vec![];
    };

    let mut results = Vec::new();
    for (operator, keys) in obj {
        let Some(keys_obj) = keys.as_object() else {
            continue;
        };
        for (key, values) in keys_obj {
            let vals = match values {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => continue,
            };
            results.push(format!("`{key} = {vals}` ({operator})"));
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> &'static str {
        r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                },
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": "s3.us-east-1.amazonaws.com"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": "dynamodb:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }"#
    }

    #[test]
    fn test_unconditionally_allowed() {
        let checker = PolicyChecker::from_json(sample_policy()).unwrap();
        let status = checker.check_action("dynamodb:PutItem");
        assert!(status.is_fully_allowed());
    }

    #[test]
    fn test_missing_action() {
        let checker = PolicyChecker::from_json(sample_policy()).unwrap();
        let status = checker.check_action("sqs:SendMessage");
        assert!(status.is_missing());
    }

    #[test]
    fn test_denied_action() {
        let checker = PolicyChecker::from_json(sample_policy()).unwrap();
        let status = checker.check_action("s3:DeleteObject");
        assert!(status.denied);
    }

    #[test]
    fn test_conditional_action() {
        let checker = PolicyChecker::from_json(sample_policy()).unwrap();
        let status = checker.check_action("kms:Decrypt");
        assert!(status.allowed);
        assert!(!status.conditions.is_empty());
        assert!(status.conditions[0].contains("kms:ViaService"));
    }

    #[test]
    fn test_resource_restricted() {
        let checker = PolicyChecker::from_json(sample_policy()).unwrap();
        let status = checker.check_action("s3:GetObject");
        assert!(status.allowed);
        assert!(!status.restricted_resources.is_empty());
        assert!(status.restricted_resources[0].contains("my-bucket"));
    }

    #[test]
    fn test_both_conditional_and_restricted() {
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::prod-bucket/*",
                "Condition": { "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" } }
            }]
        }"#;
        let checker = PolicyChecker::from_json(policy).unwrap();
        let status = checker.check_action("s3:PutObject");
        assert!(status.allowed);
        assert!(!status.conditions.is_empty());
        assert!(!status.restricted_resources.is_empty());
    }
}
