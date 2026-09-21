use crate::engine::file_context::{AnyImport, FileContext};
use crate::engine::scope::{Binding, BindingKind, SymbolTable};
use crate::support::{issue_at, keyword_value};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashMap;

// SonarPython RandomSeedCheck, Community 26.8.0.126808, sonarpy.jar SHA-256
// 126234f10b1507e63055a028f8762fa80beaf078bbe07cbe4571a62cdecef952.
// This is scientific-computing reproducibility, not the S2245 security hotspot.
pub(crate) fn check_unseeded_randomness(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = SeedFacts::new(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(path) = facts.path(&call.func, 0) else {
            continue;
        };
        let message = if let Some(keyword) = numpy_seed_keyword(&path) {
            let argument = call
                .arguments
                .args
                .first()
                .or_else(|| keyword_value(&call.arguments, keyword));
            facts
                .absent_or_none(argument)
                .then_some("Provide a seed for this random generator.")
        } else {
            sklearn_seed_policy(&path).and_then(|policy| {
                (facts.absent_or_none(keyword_value(&call.arguments, "random_state"))
                    && policy.requires_seed(call, &facts))
                .then_some("Provide a seed for the random_state parameter.")
            })
        };
        if let Some(message) = message {
            issues.push(issue_at(
                "python:S6709",
                message,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn numpy_seed_keyword(path: &str) -> Option<&'static str> {
    match path {
        "numpy.random.SeedSequence" => Some("entropy"),
        "numpy.seed"
        | "numpy.random.seed"
        | "numpy.random.default_rng"
        | "numpy.random.PCG64"
        | "numpy.random.PCG64DXSM"
        | "numpy.random.MT19937"
        | "numpy.random.SFC64"
        | "numpy.random.Philox" => Some("seed"),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum SeedPolicy {
    Always,
    Probability,
    Solver,
    Selection,
}

impl SeedPolicy {
    fn requires_seed(self, call: &ExprCall, facts: &SeedFacts<'_>) -> bool {
        match self {
            Self::Always => true,
            Self::Probability => keyword_value(&call.arguments, "probability").is_some_and(
                |value| !matches!(value, Expr::BooleanLiteral(literal) if !literal.value),
            ),
            Self::Solver => facts
                .keyword_string(call, "solver")
                .is_some_and(|value| value == "sag" || value == "saga"),
            Self::Selection => facts
                .keyword_string(call, "selection")
                .is_some_and(|value| value == "random"),
        }
    }
}

// Resolve through the existing lexical symbol table, not a file-wide map of
// spellings. Parameters, comprehensions, local definitions and reassignments
// must not inherit an unrelated NumPy/sklearn import's identity.
struct SeedFacts<'a> {
    symbols: &'a SymbolTable,
    loads: HashMap<TextRange, usize>,
    imports: HashMap<TextRange, String>,
    values: HashMap<TextRange, &'a Expr>,
    has_wildcard_import: bool,
}

impl<'a> SeedFacts<'a> {
    fn new(file_ctx: &'a FileContext<'a>) -> Self {
        let symbols = file_ctx.symbol_table();
        let loads = symbols
            .resolved_loads
            .iter()
            .enumerate()
            .map(|(index, load)| (load.range, index))
            .collect();
        let mut facts = Self {
            symbols,
            loads,
            imports: HashMap::new(),
            values: HashMap::new(),
            has_wildcard_import: false,
        };
        for import in &file_ctx.imports {
            facts.record_import(import);
        }
        for stmt in file_ctx.stmts.iter().copied() {
            facts.record_value(stmt);
        }
        facts
    }

    fn record_import(&mut self, import: &AnyImport<'_>) {
        match import {
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    let path = if alias.asname.is_some() {
                        alias.name.as_str()
                    } else {
                        alias.name.as_str().split('.').next().unwrap_or("")
                    };
                    self.imports.insert(alias.range(), path.to_owned());
                }
            }
            AnyImport::From(import) => {
                self.has_wildcard_import |=
                    import.names.iter().any(|alias| alias.name.as_str() == "*");
                if import.level != 0 {
                    return;
                }
                if let Some(module) = &import.module {
                    for alias in &import.names {
                        self.imports
                            .insert(alias.range(), format!("{}.{}", module, alias.name));
                    }
                }
            }
        }
    }

    fn record_value(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    if matches!(target, Expr::Name(_)) {
                        self.values.insert(target.range(), &assign.value);
                    }
                }
            }
            Stmt::AnnAssign(assign) => {
                if let Some(value) = &assign.value {
                    self.values.insert(assign.target.range(), value);
                }
            }
            _ => {}
        }
    }

    fn bindings(&self, expr: &Expr) -> Option<&[Binding]> {
        let load = &self.symbols.resolved_loads[*self.loads.get(&expr.range())?];
        let scope = load.target?;
        let bindings = self.symbols.scopes[scope].bindings.get(&load.name)?;
        // The shared table redirects global/nonlocal loads but retains remote
        // stores in their lexical scope. Do not mistake those stores for an
        // immutable import or seed value.
        if self.symbols.scopes.iter().any(|other| {
            (other.declares_global(&load.name) || other.declares_nonlocal(&load.name))
                && other.bindings.contains_key(&load.name)
        }) {
            return None;
        }
        if bindings
            .iter()
            .any(|binding| binding.range.end() > expr.range().start())
        {
            return None;
        }
        Some(bindings)
    }

    fn path(&self, expr: &Expr, depth: usize) -> Option<String> {
        if depth >= 32 || self.has_wildcard_import {
            return None;
        }
        match expr {
            Expr::Attribute(attribute) => {
                let mut path = self.path(&attribute.value, depth + 1)?;
                path.push('.');
                path.push_str(attribute.attr.as_str());
                Some(path)
            }
            Expr::Name(_) => {
                let [binding] = self.bindings(expr)? else {
                    return None;
                };
                match binding.kind {
                    BindingKind::Import => self.imports.get(&binding.range).cloned(),
                    BindingKind::Assignment => {
                        self.path(self.values.get(&binding.range)?, depth + 1)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn absent_or_none(&self, value: Option<&Expr>) -> bool {
        let Some(value) = value else {
            return true;
        };
        if matches!(value, Expr::NoneLiteral(_)) {
            return true;
        }
        matches!(value, Expr::Name(_))
            && self.bindings(value).is_some_and(|bindings| {
                !bindings.is_empty()
                    && bindings.iter().all(|binding| {
                        self.values
                            .get(&binding.range)
                            .is_some_and(|value| matches!(value, Expr::NoneLiteral(_)))
                    })
            })
    }

    fn keyword_string(&self, call: &ExprCall, keyword: &str) -> Option<String> {
        let mut value = keyword_value(&call.arguments, keyword)?;
        if matches!(value, Expr::Name(_)) {
            let [binding] = self.bindings(value)? else {
                return None;
            };
            value = self.values.get(&binding.range)?;
        }
        let Expr::StringLiteral(literal) = value else {
            return None;
        };
        Some(literal.value.to_str().to_owned())
    }
}

// Exact import paths with a random_state parameter, extracted from the
// pinned analyzer's third_party_protobuf_microsoft/sklearn*.protobuf files.
// Includes re-exports; never infer a signature from sklearn.* or a basename.

const SKLEARN_ALWAYS_SEEDED: &[&str] = &[
    "sklearn.calibration.LinearSVC",
    "sklearn.cluster.AffinityPropagation",
    "sklearn.cluster.BisectingKMeans",
    "sklearn.cluster.KMeans",
    "sklearn.cluster.MiniBatchKMeans",
    "sklearn.cluster.SpectralBiclustering",
    "sklearn.cluster.SpectralClustering",
    "sklearn.cluster.SpectralCoclustering",
    "sklearn.cluster._affinity_propagation.AffinityPropagation",
    "sklearn.cluster._affinity_propagation.affinity_propagation",
    "sklearn.cluster._bicluster.BaseSpectral",
    "sklearn.cluster._bicluster.KMeans",
    "sklearn.cluster._bicluster.MiniBatchKMeans",
    "sklearn.cluster._bicluster.SpectralBiclustering",
    "sklearn.cluster._bicluster.SpectralCoclustering",
    "sklearn.cluster._bicluster.randomized_svd",
    "sklearn.cluster._bisect_k_means.BisectingKMeans",
    "sklearn.cluster._kmeans.KMeans",
    "sklearn.cluster._kmeans.MiniBatchKMeans",
    "sklearn.cluster._kmeans._BaseKMeans",
    "sklearn.cluster._kmeans.k_means",
    "sklearn.cluster._kmeans.kmeans_plusplus",
    "sklearn.cluster._mean_shift.estimate_bandwidth",
    "sklearn.cluster._spectral.SpectralClustering",
    "sklearn.cluster._spectral.discretize",
    "sklearn.cluster._spectral.k_means",
    "sklearn.cluster._spectral.spectral_clustering",
    "sklearn.cluster._spectral.spectral_embedding",
    "sklearn.cluster.affinity_propagation",
    "sklearn.cluster.estimate_bandwidth",
    "sklearn.cluster.k_means",
    "sklearn.cluster.kmeans_plusplus",
    "sklearn.cluster.spectral_clustering",
    "sklearn.conftest.fetch_20newsgroups",
    "sklearn.conftest.fetch_covtype",
    "sklearn.conftest.fetch_kddcup99",
    "sklearn.conftest.fetch_olivetti_faces",
    "sklearn.conftest.fetch_rcv1",
    "sklearn.covariance.EllipticEnvelope",
    "sklearn.covariance.MinCovDet",
    "sklearn.covariance._elliptic_envelope.EllipticEnvelope",
    "sklearn.covariance._robust_covariance.MinCovDet",
    "sklearn.covariance._robust_covariance.c_step",
    "sklearn.covariance._robust_covariance.fast_mcd",
    "sklearn.covariance._robust_covariance.select_candidates",
    "sklearn.covariance.fast_mcd",
    "sklearn.datasets._base.load_files",
    "sklearn.datasets._covtype.fetch_covtype",
    "sklearn.datasets._kddcup99.fetch_kddcup99",
    "sklearn.datasets._kddcup99.shuffle_method",
    "sklearn.datasets._olivetti_faces.fetch_olivetti_faces",
    "sklearn.datasets._rcv1.fetch_rcv1",
    "sklearn.datasets._rcv1.shuffle_",
    "sklearn.datasets._samples_generator.make_biclusters",
    "sklearn.datasets._samples_generator.make_blobs",
    "sklearn.datasets._samples_generator.make_checkerboard",
    "sklearn.datasets._samples_generator.make_circles",
    "sklearn.datasets._samples_generator.make_classification",
    "sklearn.datasets._samples_generator.make_friedman1",
    "sklearn.datasets._samples_generator.make_friedman2",
    "sklearn.datasets._samples_generator.make_friedman3",
    "sklearn.datasets._samples_generator.make_gaussian_quantiles",
    "sklearn.datasets._samples_generator.make_hastie_10_2",
    "sklearn.datasets._samples_generator.make_low_rank_matrix",
    "sklearn.datasets._samples_generator.make_moons",
    "sklearn.datasets._samples_generator.make_multilabel_classification",
    "sklearn.datasets._samples_generator.make_regression",
    "sklearn.datasets._samples_generator.make_s_curve",
    "sklearn.datasets._samples_generator.make_sparse_coded_signal",
    "sklearn.datasets._samples_generator.make_sparse_spd_matrix",
    "sklearn.datasets._samples_generator.make_sparse_uncorrelated",
    "sklearn.datasets._samples_generator.make_spd_matrix",
    "sklearn.datasets._samples_generator.make_swiss_roll",
    "sklearn.datasets._samples_generator.sample_without_replacement",
    "sklearn.datasets._samples_generator.util_shuffle",
    "sklearn.datasets._twenty_newsgroups.fetch_20newsgroups",
    "sklearn.datasets._twenty_newsgroups.load_files",
    "sklearn.datasets.fetch_20newsgroups",
    "sklearn.datasets.fetch_covtype",
    "sklearn.datasets.fetch_kddcup99",
    "sklearn.datasets.fetch_olivetti_faces",
    "sklearn.datasets.fetch_rcv1",
    "sklearn.datasets.load_files",
    "sklearn.datasets.make_biclusters",
    "sklearn.datasets.make_blobs",
    "sklearn.datasets.make_checkerboard",
    "sklearn.datasets.make_circles",
    "sklearn.datasets.make_classification",
    "sklearn.datasets.make_friedman1",
    "sklearn.datasets.make_friedman2",
    "sklearn.datasets.make_friedman3",
    "sklearn.datasets.make_gaussian_quantiles",
    "sklearn.datasets.make_hastie_10_2",
    "sklearn.datasets.make_low_rank_matrix",
    "sklearn.datasets.make_moons",
    "sklearn.datasets.make_multilabel_classification",
    "sklearn.datasets.make_regression",
    "sklearn.datasets.make_s_curve",
    "sklearn.datasets.make_sparse_coded_signal",
    "sklearn.datasets.make_sparse_spd_matrix",
    "sklearn.datasets.make_sparse_uncorrelated",
    "sklearn.datasets.make_spd_matrix",
    "sklearn.datasets.make_swiss_roll",
    "sklearn.decomposition.DictionaryLearning",
    "sklearn.decomposition.FactorAnalysis",
    "sklearn.decomposition.FastICA",
    "sklearn.decomposition.KernelPCA",
    "sklearn.decomposition.LatentDirichletAllocation",
    "sklearn.decomposition.MiniBatchDictionaryLearning",
    "sklearn.decomposition.MiniBatchNMF",
    "sklearn.decomposition.MiniBatchSparsePCA",
    "sklearn.decomposition.NMF",
    "sklearn.decomposition.PCA",
    "sklearn.decomposition.SparsePCA",
    "sklearn.decomposition.TruncatedSVD",
    "sklearn.decomposition._dict_learning.DictionaryLearning",
    "sklearn.decomposition._dict_learning.Lars",
    "sklearn.decomposition._dict_learning.LassoLars",
    "sklearn.decomposition._dict_learning.MiniBatchDictionaryLearning",
    "sklearn.decomposition._dict_learning.dict_learning",
    "sklearn.decomposition._dict_learning.dict_learning_online",
    "sklearn.decomposition._dict_learning.randomized_svd",
    "sklearn.decomposition._factor_analysis.FactorAnalysis",
    "sklearn.decomposition._factor_analysis.randomized_svd",
    "sklearn.decomposition._fastica.FastICA",
    "sklearn.decomposition._fastica.fastica",
    "sklearn.decomposition._kernel_pca.KernelPCA",
    "sklearn.decomposition._lda.LatentDirichletAllocation",
    "sklearn.decomposition._nmf.MiniBatchNMF",
    "sklearn.decomposition._nmf.NMF",
    "sklearn.decomposition._nmf._BaseNMF",
    "sklearn.decomposition._nmf.non_negative_factorization",
    "sklearn.decomposition._nmf.randomized_svd",
    "sklearn.decomposition._pca.PCA",
    "sklearn.decomposition._pca.randomized_svd",
    "sklearn.decomposition._sparse_pca.MiniBatchDictionaryLearning",
    "sklearn.decomposition._sparse_pca.MiniBatchSparsePCA",
    "sklearn.decomposition._sparse_pca.SparsePCA",
    "sklearn.decomposition._sparse_pca._BaseSparsePCA",
    "sklearn.decomposition._sparse_pca.dict_learning",
    "sklearn.decomposition._sparse_pca.ridge_regression",
    "sklearn.decomposition._truncated_svd.TruncatedSVD",
    "sklearn.decomposition._truncated_svd.randomized_svd",
    "sklearn.decomposition.dict_learning",
    "sklearn.decomposition.dict_learning_online",
    "sklearn.decomposition.fastica",
    "sklearn.decomposition.non_negative_factorization",
    "sklearn.decomposition.randomized_svd",
    "sklearn.dummy.DummyClassifier",
    "sklearn.ensemble.AdaBoostClassifier",
    "sklearn.ensemble.AdaBoostRegressor",
    "sklearn.ensemble.BaggingClassifier",
    "sklearn.ensemble.BaggingRegressor",
    "sklearn.ensemble.ExtraTreesClassifier",
    "sklearn.ensemble.ExtraTreesRegressor",
    "sklearn.ensemble.GradientBoostingClassifier",
    "sklearn.ensemble.GradientBoostingRegressor",
    "sklearn.ensemble.HistGradientBoostingClassifier",
    "sklearn.ensemble.HistGradientBoostingRegressor",
    "sklearn.ensemble.IsolationForest",
    "sklearn.ensemble.RandomForestClassifier",
    "sklearn.ensemble.RandomForestRegressor",
    "sklearn.ensemble.RandomTreesEmbedding",
    "sklearn.ensemble._bagging.BaggingClassifier",
    "sklearn.ensemble._bagging.BaggingRegressor",
    "sklearn.ensemble._bagging.BaseBagging",
    "sklearn.ensemble._bagging.DecisionTreeClassifier",
    "sklearn.ensemble._bagging.DecisionTreeRegressor",
    "sklearn.ensemble._bagging.sample_without_replacement",
    "sklearn.ensemble._base.BaseDecisionTree",
    "sklearn.ensemble._base.DecisionTreeClassifier",
    "sklearn.ensemble._base.DecisionTreeRegressor",
    "sklearn.ensemble._forest.BaseDecisionTree",
    "sklearn.ensemble._forest.BaseForest",
    "sklearn.ensemble._forest.ExtraTreeClassifier",
    "sklearn.ensemble._forest.ExtraTreesClassifier",
    "sklearn.ensemble._forest.ExtraTreesRegressor",
    "sklearn.ensemble._forest.ForestClassifier",
    "sklearn.ensemble._forest.ForestRegressor",
    "sklearn.ensemble._forest.RandomForestClassifier",
    "sklearn.ensemble._forest.RandomForestRegressor",
    "sklearn.ensemble._forest.RandomTreesEmbedding",
    "sklearn.ensemble._gb.BaseGradientBoosting",
    "sklearn.ensemble._gb.DecisionTreeRegressor",
    "sklearn.ensemble._gb.GradientBoostingClassifier",
    "sklearn.ensemble._gb.GradientBoostingRegressor",
    "sklearn.ensemble._gb.train_test_split",
    "sklearn.ensemble._hist_gradient_boosting.binning._BinMapper",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.BaseHistGradientBoosting",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingClassifier",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingRegressor",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.resample",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.train_test_split",
    "sklearn.ensemble._iforest.IsolationForest",
    "sklearn.ensemble._weight_boosting.AdaBoostClassifier",
    "sklearn.ensemble._weight_boosting.AdaBoostRegressor",
    "sklearn.ensemble._weight_boosting.BaseWeightBoosting",
    "sklearn.ensemble._weight_boosting.DecisionTreeClassifier",
    "sklearn.ensemble._weight_boosting.DecisionTreeRegressor",
    "sklearn.experimental.enable_halving_search_cv.HalvingGridSearchCV",
    "sklearn.experimental.enable_halving_search_cv.HalvingRandomSearchCV",
    "sklearn.experimental.enable_iterative_imputer.IterativeImputer",
    "sklearn.feature_extraction.image.PatchExtractor",
    "sklearn.feature_extraction.image.extract_patches_2d",
    "sklearn.feature_selection._mutual_info.mutual_info_classif",
    "sklearn.feature_selection._mutual_info.mutual_info_regression",
    "sklearn.feature_selection.mutual_info_classif",
    "sklearn.feature_selection.mutual_info_regression",
    "sklearn.gaussian_process.GaussianProcessClassifier",
    "sklearn.gaussian_process.GaussianProcessRegressor",
    "sklearn.gaussian_process._gpc.GaussianProcessClassifier",
    "sklearn.gaussian_process._gpc._BinaryGaussianProcessClassifierLaplace",
    "sklearn.gaussian_process._gpr.GaussianProcessRegressor",
    "sklearn.impute.IterativeImputer",
    "sklearn.impute._iterative.IterativeImputer",
    "sklearn.inspection.PartialDependenceDisplay",
    "sklearn.inspection._partial_dependence.BaseGradientBoosting",
    "sklearn.inspection._partial_dependence.BaseHistGradientBoosting",
    "sklearn.inspection._partial_dependence.DecisionTreeRegressor",
    "sklearn.inspection._partial_dependence.RandomForestRegressor",
    "sklearn.inspection._permutation_importance.permutation_importance",
    "sklearn.inspection._plot.partial_dependence.PartialDependenceDisplay",
    "sklearn.inspection.permutation_importance",
    "sklearn.kernel_approximation.Nystroem",
    "sklearn.kernel_approximation.PolynomialCountSketch",
    "sklearn.kernel_approximation.RBFSampler",
    "sklearn.kernel_approximation.SkewedChi2Sampler",
    "sklearn.linear_model.ElasticNetCV",
    "sklearn.linear_model.Lars",
    "sklearn.linear_model.LassoCV",
    "sklearn.linear_model.LassoLars",
    "sklearn.linear_model.LogisticRegressionCV",
    "sklearn.linear_model.MultiTaskElasticNet",
    "sklearn.linear_model.MultiTaskElasticNetCV",
    "sklearn.linear_model.MultiTaskLasso",
    "sklearn.linear_model.MultiTaskLassoCV",
    "sklearn.linear_model.PassiveAggressiveClassifier",
    "sklearn.linear_model.PassiveAggressiveRegressor",
    "sklearn.linear_model.Perceptron",
    "sklearn.linear_model.RANSACRegressor",
    "sklearn.linear_model.RidgeClassifier",
    "sklearn.linear_model.SGDClassifier",
    "sklearn.linear_model.SGDOneClassSVM",
    "sklearn.linear_model.SGDRegressor",
    "sklearn.linear_model.TheilSenRegressor",
    "sklearn.linear_model._base.make_dataset",
    "sklearn.linear_model._coordinate_descent.ElasticNetCV",
    "sklearn.linear_model._coordinate_descent.LassoCV",
    "sklearn.linear_model._coordinate_descent.LinearModelCV",
    "sklearn.linear_model._coordinate_descent.MultiTaskElasticNet",
    "sklearn.linear_model._coordinate_descent.MultiTaskElasticNetCV",
    "sklearn.linear_model._coordinate_descent.MultiTaskLasso",
    "sklearn.linear_model._coordinate_descent.MultiTaskLassoCV",
    "sklearn.linear_model._least_angle.Lars",
    "sklearn.linear_model._least_angle.LassoLars",
    "sklearn.linear_model._logistic.LogisticRegressionCV",
    "sklearn.linear_model._logistic.sag_solver",
    "sklearn.linear_model._passive_aggressive.PassiveAggressiveClassifier",
    "sklearn.linear_model._passive_aggressive.PassiveAggressiveRegressor",
    "sklearn.linear_model._perceptron.Perceptron",
    "sklearn.linear_model._ransac.RANSACRegressor",
    "sklearn.linear_model._ransac.sample_without_replacement",
    "sklearn.linear_model._ridge.RidgeClassifier",
    "sklearn.linear_model._ridge._BaseRidge",
    "sklearn.linear_model._ridge.ridge_regression",
    "sklearn.linear_model._ridge.sag_solver",
    "sklearn.linear_model._sag.make_dataset",
    "sklearn.linear_model._sag.sag_solver",
    "sklearn.linear_model._stochastic_gradient.BaseSGD",
    "sklearn.linear_model._stochastic_gradient.BaseSGDClassifier",
    "sklearn.linear_model._stochastic_gradient.BaseSGDRegressor",
    "sklearn.linear_model._stochastic_gradient.SGDClassifier",
    "sklearn.linear_model._stochastic_gradient.SGDOneClassSVM",
    "sklearn.linear_model._stochastic_gradient.SGDRegressor",
    "sklearn.linear_model._stochastic_gradient.ShuffleSplit",
    "sklearn.linear_model._stochastic_gradient.StratifiedShuffleSplit",
    "sklearn.linear_model._stochastic_gradient.fit_binary",
    "sklearn.linear_model._stochastic_gradient.make_dataset",
    "sklearn.linear_model._theil_sen.TheilSenRegressor",
    "sklearn.linear_model.ridge_regression",
    "sklearn.manifold.LocallyLinearEmbedding",
    "sklearn.manifold.MDS",
    "sklearn.manifold.SpectralEmbedding",
    "sklearn.manifold.TSNE",
    "sklearn.manifold._isomap.KernelPCA",
    "sklearn.manifold._locally_linear.LocallyLinearEmbedding",
    "sklearn.manifold._locally_linear.locally_linear_embedding",
    "sklearn.manifold._locally_linear.null_space",
    "sklearn.manifold._mds.MDS",
    "sklearn.manifold._mds.smacof",
    "sklearn.manifold._spectral_embedding.SpectralEmbedding",
    "sklearn.manifold._spectral_embedding.spectral_embedding",
    "sklearn.manifold._t_sne.PCA",
    "sklearn.manifold._t_sne.TSNE",
    "sklearn.manifold.locally_linear_embedding",
    "sklearn.manifold.smacof",
    "sklearn.manifold.spectral_embedding",
    "sklearn.metrics.cluster._unsupervised.silhouette_score",
    "sklearn.metrics.cluster.silhouette_score",
    "sklearn.metrics.silhouette_score",
    "sklearn.mixture.BayesianGaussianMixture",
    "sklearn.mixture.GaussianMixture",
    "sklearn.mixture._base.BaseMixture",
    "sklearn.mixture._base.kmeans_plusplus",
    "sklearn.mixture._bayesian_mixture.BayesianGaussianMixture",
    "sklearn.mixture._gaussian_mixture.GaussianMixture",
    "sklearn.model_selection.BaseShuffleSplit",
    "sklearn.model_selection.GroupShuffleSplit",
    "sklearn.model_selection.HalvingGridSearchCV",
    "sklearn.model_selection.HalvingRandomSearchCV",
    "sklearn.model_selection.KFold",
    "sklearn.model_selection.ParameterSampler",
    "sklearn.model_selection.RandomizedSearchCV",
    "sklearn.model_selection.RepeatedKFold",
    "sklearn.model_selection.RepeatedStratifiedKFold",
    "sklearn.model_selection.ShuffleSplit",
    "sklearn.model_selection.StratifiedGroupKFold",
    "sklearn.model_selection.StratifiedKFold",
    "sklearn.model_selection.StratifiedShuffleSplit",
    "sklearn.model_selection._plot.learning_curve",
    "sklearn.model_selection._search.ParameterSampler",
    "sklearn.model_selection._search.RandomizedSearchCV",
    "sklearn.model_selection._search.sample_without_replacement",
    "sklearn.model_selection._search_successive_halving.BaseSuccessiveHalving",
    "sklearn.model_selection._search_successive_halving.HalvingGridSearchCV",
    "sklearn.model_selection._search_successive_halving.HalvingRandomSearchCV",
    "sklearn.model_selection._search_successive_halving.ParameterSampler",
    "sklearn.model_selection._search_successive_halving._SubsampleMetaSplitter",
    "sklearn.model_selection._search_successive_halving.resample",
    "sklearn.model_selection._split.BaseShuffleSplit",
    "sklearn.model_selection._split.GroupShuffleSplit",
    "sklearn.model_selection._split.KFold",
    "sklearn.model_selection._split.RepeatedKFold",
    "sklearn.model_selection._split.RepeatedStratifiedKFold",
    "sklearn.model_selection._split.ShuffleSplit",
    "sklearn.model_selection._split.StratifiedGroupKFold",
    "sklearn.model_selection._split.StratifiedKFold",
    "sklearn.model_selection._split.StratifiedShuffleSplit",
    "sklearn.model_selection._split._BaseKFold",
    "sklearn.model_selection._split._RepeatedSplits",
    "sklearn.model_selection._split.train_test_split",
    "sklearn.model_selection._validation.learning_curve",
    "sklearn.model_selection._validation.permutation_test_score",
    "sklearn.model_selection.learning_curve",
    "sklearn.model_selection.permutation_test_score",
    "sklearn.model_selection.train_test_split",
    "sklearn.multiclass.OutputCodeClassifier",
    "sklearn.multioutput._BaseChain",
    "sklearn.neighbors.NeighborhoodComponentsAnalysis",
    "sklearn.neighbors._nca.NeighborhoodComponentsAnalysis",
    "sklearn.neighbors._nca.PCA",
    "sklearn.neural_network.BernoulliRBM",
    "sklearn.neural_network.MLPClassifier",
    "sklearn.neural_network.MLPRegressor",
    "sklearn.neural_network._multilayer_perceptron.BaseMultilayerPerceptron",
    "sklearn.neural_network._multilayer_perceptron.MLPClassifier",
    "sklearn.neural_network._multilayer_perceptron.MLPRegressor",
    "sklearn.neural_network._multilayer_perceptron.train_test_split",
    "sklearn.neural_network._rbm.BernoulliRBM",
    "sklearn.preprocessing.KBinsDiscretizer",
    "sklearn.preprocessing.QuantileTransformer",
    "sklearn.preprocessing._data.QuantileTransformer",
    "sklearn.preprocessing._discretization.KBinsDiscretizer",
    "sklearn.preprocessing._discretization.KMeans",
    "sklearn.random_projection.BaseRandomProjection",
    "sklearn.random_projection.GaussianRandomProjection",
    "sklearn.random_projection.SparseRandomProjection",
    "sklearn.random_projection.sample_without_replacement",
    "sklearn.svm.LinearSVC",
    "sklearn.svm.LinearSVR",
    "sklearn.svm.NuSVC",
    "sklearn.svm._base.BaseLibSVM",
    "sklearn.svm._base.BaseSVC",
    "sklearn.svm._classes.LinearSVC",
    "sklearn.svm._classes.LinearSVR",
    "sklearn.svm._classes.NuSVC",
    "sklearn.tree.BaseDecisionTree",
    "sklearn.tree.DecisionTreeClassifier",
    "sklearn.tree.DecisionTreeRegressor",
    "sklearn.tree.ExtraTreeClassifier",
    "sklearn.tree.ExtraTreeRegressor",
    "sklearn.tree._classes.BaseDecisionTree",
    "sklearn.tree._classes.DecisionTreeClassifier",
    "sklearn.tree._classes.DecisionTreeRegressor",
    "sklearn.tree._classes.ExtraTreeClassifier",
    "sklearn.tree._classes.ExtraTreeRegressor",
    "sklearn.utils._random.sample_without_replacement",
    "sklearn.utils._testing.set_random_state",
    "sklearn.utils.estimator_checks.BaseRandomProjection",
    "sklearn.utils.estimator_checks.RANSACRegressor",
    "sklearn.utils.estimator_checks.SGDRegressor",
    "sklearn.utils.estimator_checks.ShuffleSplit",
    "sklearn.utils.estimator_checks.make_blobs",
    "sklearn.utils.estimator_checks.make_multilabel_classification",
    "sklearn.utils.estimator_checks.make_regression",
    "sklearn.utils.estimator_checks.set_random_state",
    "sklearn.utils.estimator_checks.shuffle",
    "sklearn.utils.estimator_checks.train_test_split",
    "sklearn.utils.extmath.randomized_range_finder",
    "sklearn.utils.extmath.randomized_svd",
    "sklearn.utils.resample",
    "sklearn.utils.shuffle",
];

fn sklearn_seed_policy(path: &str) -> Option<SeedPolicy> {
    match path {
        "sklearn.decomposition._dict_learning.Lasso"
        | "sklearn.linear_model.ElasticNet"
        | "sklearn.linear_model.Lasso"
        | "sklearn.linear_model._coordinate_descent.ElasticNet"
        | "sklearn.linear_model._coordinate_descent.Lasso" => Some(SeedPolicy::Selection),
        "sklearn.linear_model.LogisticRegression"
        | "sklearn.linear_model.Ridge"
        | "sklearn.linear_model._logistic.LogisticRegression"
        | "sklearn.linear_model._ridge.Ridge"
        | "sklearn.utils.estimator_checks.LogisticRegression"
        | "sklearn.utils.estimator_checks.Ridge" => Some(SeedPolicy::Solver),
        "sklearn.svm.SVC" | "sklearn.svm._classes.SVC" => Some(SeedPolicy::Probability),
        _ if SKLEARN_ALWAYS_SEEDED.binary_search(&path).is_ok() => Some(SeedPolicy::Always),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn numpy_generators_need_their_own_seed_not_a_file_seed() {
        let report = scan(concat!(
            "import numpy as np\n",
            "np.random.seed(42)\n",
            "np.random.default_rng()\n",
            "np.random.SeedSequence(entropy=None)\n",
            "np.random.PCG64(seed=0)\n",
            "np.random.default_rng(42)\n",
            "np.random.random()\n",
            "import random\n",
            "random.random()\n",
        ));
        let issues = findings(&report, "python:S6709");
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start, pos(3, 0));
        assert_eq!(issues[0].range.end, pos(3, 21));
        assert_eq!(issues[1].range.start, pos(4, 0));
    }

    #[test]
    fn seed_resolution_respects_aliases_parameters_and_rebinding() {
        let report = scan(concat!(
            "from numpy.random import default_rng as generator\n",
            "alias = generator\n",
            "seed = None\n",
            "alias(seed)\n",
            "def local(generator):\n",
            "    generator()\n",
            "def imported():\n",
            "    generator()\n",
            "def replaced():\n",
            "    from numpy.random import default_rng as rng\n",
            "    rng = factory\n",
            "    rng()\n",
            "def unknown_seed(seed):\n",
            "    generator(seed)\n",
            "[generator() for generator in factories]\n",
        ));
        let issues = findings(&report, "python:S6709");
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start, pos(4, 0));
        assert_eq!(issues[1].range.start, pos(8, 4));
    }

    #[test]
    fn sklearn_requires_a_known_signature_and_applies_solver_exceptions() {
        let report = scan(concat!(
            "from sklearn.model_selection import train_test_split as split\n",
            "from sklearn.linear_model import LogisticRegression, Lasso, Ridge\n",
            "from sklearn.svm import SVC\n",
            "from sklearn.preprocessing import StandardScaler\n",
            "split([1, 2, 3])\n",
            "split([1, 2, 3], random_state=42)\n",
            "LogisticRegression()\n",
            "solver = 'saga'\n",
            "LogisticRegression(solver=solver)\n",
            "Ridge(solver='sag', random_state=None)\n",
            "Lasso(selection='random')\n",
            "Lasso()\n",
            "SVC()\n",
            "SVC(probability=False)\n",
            "SVC(probability=True)\n",
            "StandardScaler()\n",
        ));
        let issues = findings(&report, "python:S6709");
        let lines: Vec<_> = issues.iter().map(|issue| issue.range.start.line).collect();
        assert_eq!(lines, vec![5, 9, 10, 11, 15]);
    }

    #[test]
    fn mixed_none_assignments_and_unknown_calls_are_not_seed_violations() {
        let report = scan(concat!(
            "import numpy as np\n",
            "seed = None\n",
            "if condition:\n",
            "    seed = 42\n",
            "np.random.default_rng(seed)\n",
            "def user(default_rng):\n",
            "    default_rng()\n",
            "def relative():\n",
            "    from .numpy.random import default_rng\n",
            "    default_rng()\n",
        ));
        assert!(findings(&report, "python:S6709").is_empty());
    }

    #[test]
    fn seed_resolution_follows_loads_into_nested_scopes() {
        // A call inside a nested function resolves through the enclosing
        // scope's assignment binding to the NumPy generator path.
        let report = scan(concat!(
            "import numpy as np\n",
            "def outer():\n",
            "    rng = np.random.default_rng\n",
            "    def inner():\n",
            "        rng()\n",
            "    return inner\n",
        ));
        let issues = findings(&report, "python:S6709");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start, pos(5, 8));
        // A sibling scope's same-named binding must not leak into `outer`.
        let sibling = scan(concat!(
            "import numpy as np\n",
            "def outer():\n",
            "    rng = np.random.default_rng\n",
            "    return rng\n",
            "def other():\n",
            "    rng = lambda: None\n",
            "    rng()\n",
        ));
        assert!(findings(&sibling, "python:S6709").is_empty());
    }

    #[test]
    fn stdlib_random_calls_are_not_seed_violations() {
        // Issue #620: Sonar's RandomSeedCheck only inspects NumPy generator
        // construction and sklearn random_state parameters. Stdlib `random`
        // calls are never S6709 findings (S2245 covers PRNG sensitivity), so
        // the file-level "no seed() call" heuristic must not return.
        let report = scan(concat!(
            "import random\n",
            "import random as rnd\n",
            "from random import randint\n",
            "x = random.random()\n",
            "y = rnd.randint(1, 10)\n",
            "z = randint(1, 10)\n",
            "random.choice([1, 2, 3])\n",
            "random.shuffle([1, 2, 3])\n",
        ));
        assert!(findings(&report, "python:S6709").is_empty());
        let seeded = scan("import random\nrandom.seed(7)\nx = random.random()\n");
        assert!(findings(&seeded, "python:S6709").is_empty());
    }
}
