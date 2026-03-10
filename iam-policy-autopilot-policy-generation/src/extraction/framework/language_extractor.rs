//! [`LanguageExtractor`] trait — the top-level contract for two-phase SDK call extraction.

use ast_grep_language::LanguageExt;
use async_trait::async_trait;

use crate::errors::Result;
use crate::extraction::{SdkMethodCall, ServiceModelIndex, SourceFile};

use super::extractor_set::{IrExtend, LanguageExtractorSet};
use super::utilities_model::UtilitiesModel;

/// Trait for language-specific two-phase SDK call extraction pipelines.
///
/// # Two-phase contract
///
/// ```text
/// Vec<SourceFile>
///      |
///      v  extract()   [provided default — do not override]
/// Self::ExtractionResult          <- language-specific IR, private to the module
///      |
///      v  match_calls()
/// Vec<SdkMethodCall>              <- shared output type
/// ```
///
/// # What to implement
///
/// Implementors provide three methods:
/// - [`extractor_set()`] — returns the [`LanguageExtractorSet`] for this language.
/// - [`utilities_model()`] — returns the language's utility model (or `None`).
/// - [`match_calls()`] — converts the IR into `Vec<SdkMethodCall>`.
///
/// The [`extract()`] method has a provided default implementation that drives the full
/// parallel extraction pipeline using the [`LanguageExtractorSet`] returned by
/// [`extractor_set()`]. **Do not override [`extract()`].**  Overriding it bypasses the
/// single-pass AST scan and the discriminator-uniqueness guarantee enforced by
/// [`LanguageExtractorSet`]. The `no_extract_override` Dylint lint enforces this.
///
/// # Extractor struct design
///
/// The implementing struct should be **stateless** — it should not store a
/// [`ServiceModelIndex`], [`UtilitiesModel`], or any other runtime data as a field.
/// Both are passed explicitly to [`match_calls()`]. Storing them as fields would allow
/// them to be used inside [`extract()`], which is contrary to the two-phase design
/// (extraction is pure AST work; matching is where the service index and utility
/// model are consulted).
///
/// [`extractor_set()`]: LanguageExtractor::extractor_set
/// [`utilities_model()`]: LanguageExtractor::utilities_model
/// [`match_calls()`]: LanguageExtractor::match_calls
/// [`extract()`]: LanguageExtractor::extract
#[async_trait]
pub(crate) trait LanguageExtractor: Send + Sync {
    /// The ast-grep language type for this extractor (e.g. `ast_grep_language::Java`).
    /// Must implement `Copy` (all ast-grep language types are unit structs) and
    /// `Deserialize` (implemented via `impl_alias!` in `ast-grep-language`).
    type Language: LanguageExt + Copy + Send + Sync + 'static + for<'de> serde::Deserialize<'de>;

    /// The language-specific intermediate representation produced by [`extract`] and
    /// consumed by [`match_calls`]. Must be `Send` (moved across threads in `spawn_blocking`)
    /// and `Default` (used as the initial accumulator in the merge step).
    ///
    /// This type is an implementation detail of the language module and must never be
    /// exposed outside it (`pub(crate)` at most).
    ///
    /// [`extract`]: LanguageExtractor::extract
    /// [`match_calls`]: LanguageExtractor::match_calls
    type ExtractionResult: Send + Default + IrExtend + 'static;

    /// Return the set of single-pattern AST extractors for this language.
    ///
    /// The framework calls this once per [`extract()`] invocation and uses the returned
    /// set to drive the parallel extraction phase. The set enforces discriminator label
    /// uniqueness at construction; use `.expect()` here since a duplicate label is a
    /// programming error:
    ///
    /// ```rust,ignore
    /// fn extractor_set(&self) -> LanguageExtractorSet<Java, MyIR> {
    ///     LanguageExtractorSet::new(vec![
    ///         Box::new(MyImportExtractor),
    ///         Box::new(MyCallExtractor),
    ///     ])
    ///     .expect("extractor labels must be unique")
    /// }
    /// ```
    ///
    /// [`extract()`]: LanguageExtractor::extract
    fn extractor_set(&self) -> LanguageExtractorSet<Self::Language, Self::ExtractionResult>;

    /// Return the utilities model for this language's SDK.
    ///
    /// The utilities model maps high-level SDK methods (e.g. `uploadFile`,
    /// `upload_file`) to the underlying API operations they require. It is passed to
    /// [`match_calls`] by the engine.
    ///
    /// Implementations should return a reference to a process-wide `LazyLock` static
    /// so the embedded JSON is parsed only once regardless of how many files are
    /// processed:
    ///
    /// ```rust,ignore
    /// static MY_UTILITIES_MODEL: LazyLock<UtilitiesModel> = LazyLock::new(|| {
    ///     // load and normalise from embedded JSON
    /// });
    ///
    /// fn utilities_model(&self) -> Option<&'static UtilitiesModel> {
    ///     Some(&MY_UTILITIES_MODEL)
    /// }
    /// ```
    ///
    /// Return `None` if the language's SDK has no utility methods (uncommon).
    ///
    /// [`match_calls`]: LanguageExtractor::match_calls
    fn utilities_model(&self) -> Option<&'static UtilitiesModel>;

    /// Phase 2 — convert the intermediate representation into validated SDK method calls.
    ///
    /// Consults `service_index` to validate and resolve direct SDK calls, and
    /// `utilities_model` to expand high-level utility calls into their underlying
    /// operations. Both are passed here (not stored on the struct) to keep the
    /// extraction phase independent of the service model and utility data.
    fn match_calls(
        &self,
        ir: &Self::ExtractionResult,
        service_index: &ServiceModelIndex,
        utilities_model: Option<&UtilitiesModel>,
    ) -> Vec<SdkMethodCall>;

    // ── Provided method ───────────────────────────────────────────────────────
    //
    // DO NOT OVERRIDE THIS METHOD.
    //
    // The default implementation drives the full parallel extraction pipeline using
    // the LanguageExtractorSet returned by `extractor_set()`. Overriding it bypasses
    // the single-pass AST scan and the discriminator-uniqueness guarantee.
    //
    // The `no_extract_override` Dylint lint (in `iam-policy-autopilot-lints`) will
    // emit a compile-time warning if this method is overridden in an `impl LanguageExtractor`.

    /// Phase 1 — parallel AST extraction.
    ///
    /// Fans out across `source_files` using `spawn_blocking` (CPU-bound tree-sitter work),
    /// merges per-file results via `IR::extend_from`, and returns the combined IR.
    async fn extract(&self, source_files: Vec<SourceFile>) -> Result<Self::ExtractionResult> {
        self.extractor_set().extract_from_files(source_files).await
    }
}
