// --- effect: effect / retention tracking.

pub(crate) const SIDE_EFFECT_TAILS: [&str; 10] = [
    "print", "input", "open", "system", "popen", "getcwd", "remove", "rename", "mkdir", "sleep",
];

pub(crate) const LOAD_MODEL_TAILS: [&str; 5] = [
    "load",
    "load_model",
    "load_state_dict",
    "from_pretrained",
    "load_weights",
];

pub(crate) const CANCELLATION_SCOPE_TAILS: [&str; 6] = [
    "move_on_after",
    "fail_after",
    "move_on_if",
    "CancelScope",
    "fail_at",
    "move_on_at",
];

pub(crate) const KNOWN_STEP_HINTS: [&str; 18] = [
    "pipeline",
    "model",
    "clf",
    "reg",
    "scaler",
    "preprocessor",
    "vectorizer",
    "encoder",
    "imputer",
    "transformer",
    "selector",
    "reducer",
    "classifier",
    "regressor",
    "steps",
    "features",
    "numeric",
    "categorical",
];
