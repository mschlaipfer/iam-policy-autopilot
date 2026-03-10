//! Lint to detect `impl LanguageExtractor` blocks that override the provided `extract` method.

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::{ImplItemKind, Item, ItemKind, TraitRef};
use rustc_lint::{LateContext, LateLintPass, LintPass, LintStore};
use rustc_session::{declare_lint, Session};

declare_lint! {
    /// ### What it does
    /// Detects `impl LanguageExtractor` blocks that override the provided `extract` method.
    ///
    /// ### Why is this bad?
    /// `LanguageExtractor::extract` has a provided default implementation that drives the
    /// full parallel extraction pipeline using `LanguageExtractorSet`. Overriding it
    /// bypasses the single-pass AST scan and the discriminator-uniqueness guarantee.
    ///
    /// ### What to do instead
    /// Implement `extractor_set()` to return the `LanguageExtractorSet` for your language.
    /// The framework's provided `extract()` will call it automatically and handle the parallel
    /// extraction pipeline.
    ///
    /// ### Example
    /// ```rust
    /// // Bad: overrides the provided extract() method
    /// impl LanguageExtractor for MyLanguageExtractor {
    ///     fn extract(&self, source_files: &[SourceFile]) -> Vec<SdkMethodCall> {
    ///         // custom implementation
    ///     }
    /// }
    ///
    /// // Good: implement extractor_set() instead
    /// impl LanguageExtractor for MyLanguageExtractor {
    ///     fn extractor_set(&self) -> LanguageExtractorSet<MyLanguage, MyExtractionResult> {
    ///         LanguageExtractorSet::new(vec![...]).expect("unique discriminators")
    ///     }
    /// }
    /// ```
    pub NO_EXTRACT_OVERRIDE,
    Warn,
    "overriding the provided `extract` method in a `LanguageExtractor` impl"
}

pub struct NoExtractOverride;

impl LintPass for NoExtractOverride {
    fn name(&self) -> &'static str {
        "NoExtractOverride"
    }

    fn get_lints(&self) -> Vec<&'static rustc_lint::Lint> {
        vec![&NO_EXTRACT_OVERRIDE]
    }
}

impl<'tcx> LateLintPass<'tcx> for NoExtractOverride {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        // Match `impl <Trait> for <Type>` blocks
        let ItemKind::Impl(impl_block) = &item.kind else {
            return;
        };
        let Some(trait_ref) = &impl_block.of_trait else {
            return;
        };

        // Check if the trait being implemented is `LanguageExtractor`
        if !is_language_extractor_trait(trait_ref) {
            return;
        }

        // Check each impl item for a method named `extract`
        for impl_item_ref in impl_block.items {
            let impl_item = cx.tcx.hir().impl_item(impl_item_ref.id);
            if let ImplItemKind::Fn(..) = &impl_item.kind {
                if impl_item.ident.name.as_str() == "extract" {
                    span_lint_and_help(
                        cx,
                        NO_EXTRACT_OVERRIDE,
                        impl_item.span,
                        "overriding the provided `extract` method in a `LanguageExtractor` impl",
                        None,
                        "implement `extractor_set()` instead; the framework's provided \
                         `extract()` will call it automatically and handle the parallel \
                         extraction pipeline",
                    );
                }
            }
        }
    }
}

fn is_language_extractor_trait(trait_ref: &TraitRef<'_>) -> bool {
    // Resolve the trait path and check the final segment name
    trait_ref
        .path
        .segments
        .last()
        .map(|seg| seg.ident.name.as_str() == "LanguageExtractor")
        .unwrap_or(false)
}

pub fn register_lints(_sess: &Session, lint_store: &mut LintStore) {
    lint_store.register_lints(&[&NO_EXTRACT_OVERRIDE]);
    lint_store.register_late_pass(|_| Box::new(NoExtractOverride));
}
