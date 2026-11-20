//! Cross-file native C# type lookup for one project scan.

use std::borrow::Cow;
use std::sync::Arc;

use hoonarqube_core::{Language, is_razor_path, language_for_path};
use hoonarqube_csharp::ProjectTypeIndex;

use super::{
    AnalyzedSource, AnalyzerOptionsBundle, CollectedProjectInputs, ProjectInput, ProjectSourceRead,
    read_project_source,
};

pub(super) fn with_csharp_project_index(
    options: &AnalyzerOptionsBundle,
    collected: &CollectedProjectInputs,
) -> AnalyzerOptionsBundle {
    let mut options = options.clone();
    let inputs = collected.pending.iter().filter(|input| {
        language_for_path(&input.path) == Some(Language::CSharp) && !is_razor_path(&input.path)
    });
    // Single-file scans use the analyzer's existing local lookup.
    if inputs.clone().nth(1).is_none() {
        return options;
    }
    let sources = inputs.filter_map(|input| {
        index_source(input, &collected.source_inventory)
            .map(|source| (input.path.as_path(), source))
    });
    let mut readable = 0;
    let index = ProjectTypeIndex::from_sources(sources.inspect(|_| readable += 1));
    if readable >= 2 {
        options.csharp.project_type_index = Some(Arc::new(index));
    }
    options
}

fn index_source<'a>(input: &ProjectInput, retained: &'a [AnalyzedSource]) -> Option<Cow<'a, str>> {
    if let Some(index) = input.source_index {
        return retained
            .get(index)
            .map(|source| Cow::Borrowed(source.source.as_str()));
    }
    match read_project_source(&input.path, input.classification) {
        ProjectSourceRead::Source(source) => Some(Cow::Owned(source)),
        ProjectSourceRead::Oversize(_) | ProjectSourceRead::Failure(_) => None,
    }
}
