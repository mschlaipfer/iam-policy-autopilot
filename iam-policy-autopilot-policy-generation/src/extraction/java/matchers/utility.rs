//! [`match_utilities`] — maps [`Call`]s to [`SdkMethodCall`]s via
//! the `java-sdk-v2-utilities.json` model and `utility_imports`-based filtering.
//!
//! Matches a call against the utility model using:
//! 1. `call.receiver` → resolved to a class name via `utility_imports` from the same file
//! 2. `call.method` → `MethodName` lookup within the matched service entries
//!
//! Only utility imports from the same source file as the call are considered.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::extraction::framework::UtilitiesModel;
use crate::extraction::java::types::{ExtractionResult, UtilityImport};
use crate::extraction::{SdkMethodCall, SdkMethodCallMetadata, ServiceModelIndex};

// ================================================================================================
// match_utilities
// ================================================================================================

/// Match utility calls from an [`ExtractionResult`] using the
/// `java-sdk-v2-utilities.json` model.
///
/// For each [`Call`] in `result.calls`, checks whether the receiver's class
/// (resolved via `utility_imports` **from the same source file**) matches a
/// `receiver_class` in the model, and whether the method name matches a `MethodName`.
/// If both match, emits one [`SdkMethodCall`] **per operation** listed in the feature,
/// using the operation's `Name` (PascalCase API operation name) and `Service`.
pub(crate) fn match_utilities(
    result: &ExtractionResult,
    model: &UtilitiesModel,
    _service_index: &ServiceModelIndex,
    utility_imports_by_file: &HashMap<PathBuf, Vec<&UtilityImport>>,
) -> Vec<SdkMethodCall> {
    let mut output = Vec::new();

    for call in &result.calls {
        let Some(receiver) = &call.receiver else {
            continue;
        };

        // Resolve receiver variable → class name via utility_imports from the same file only.
        let file_utility_imports: &[&UtilityImport] = utility_imports_by_file
            .get(&call.location.file_path)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        // Direct match: receiver variable name equals class name (rare but valid)
        let matched_class: Option<&str> = file_utility_imports
            .iter()
            .find(|ui| receiver == &ui.class_name)
            .map(|ui| ui.class_name.as_str());

        // For each service in the model, look for a feature whose receiver_class matches
        // either the matched_class or any utility import class in the same file, and whose
        // method_name matches the call method.
        for (_service_name, methods) in &model.services {
            for (method_name, utility_method) in methods {
                // Check method name matches
                if method_name != &call.method {
                    continue;
                }

                // Check receiver class matches using the receiver_class field stored in
                // the UtilityMethod (populated during normalisation from the Java JSON).
                let receiver_matches = match &utility_method.receiver_class {
                    Some(expected_class) => {
                        // Check if the expected receiver class is imported in this file
                        let class_imported = file_utility_imports
                            .iter()
                            .any(|ui| &ui.class_name == expected_class);

                        // Match if:
                        // - direct class name match (receiver var name == class name), OR
                        // - the expected class is imported in the same file
                        matched_class == Some(expected_class.as_str()) || class_imported
                    }
                    // No receiver class constraint — match on method name alone.
                    // This is the case for languages that don't use class-based dispatch.
                    None => !file_utility_imports.is_empty(),
                };

                if !receiver_matches {
                    continue;
                }

                // Emit one SdkMethodCall per operation in the utility method.
                for op in &utility_method.operations {
                    let metadata =
                        SdkMethodCallMetadata::new(call.expr.clone(), call.location.clone())
                            .with_parameters(call.parameters.clone())
                            .with_receiver(receiver.clone());

                    output.push(SdkMethodCall {
                        name: op.name.clone(),
                        possible_services: vec![op.service.clone()],
                        metadata: Some(metadata),
                    });
                }
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use crate::java_matcher_test;

    java_matcher_test!("tests/java/matchers/utility/*.json", test_utility_matching);
}
