//! `java:S1854` — unused assignments should be removed (dead stores).
//!
//! Contract pinned against the live SonarQube 26.8 Community reference
//! (rule show: scope ALL, MAJOR CODE_SMELL, no parameters; oracle: the
//! pinned `gson` scan with 85 findings, plus dedicated probe projects
//! scanned against the same reference). A store to a local variable is
//! reported when the stored value is dead at the store — the variable is
//! not read on any control path before it is overwritten. The analysis is
//! a backward liveness fixpoint over a per-method statement graph that
//! models branches, every loop form, `switch` fallthrough, labeled jumps,
//! and `try`/`catch`/`finally` with the reference's exception model:
//!
//! - Exception edges from a potentially throwing call reach only *runtime
//!   catches* (`catch (Exception …)`, `RuntimeException` subtypes, and
//!   types not provably `Exception` subtypes — unknown types included)
//!   plus checked catches that bidirectionally match a declared `throws`
//!   type of a same-file callee. Unresolvable callees therefore reach
//!   runtime catches only, which is why the pinned `Streams.parse` oracle
//!   flags `isEmpty = false` (its `catch (EOFException)` is unreachable
//!   from the unresolved `ADAPTER.read` call) while a `RuntimeException`
//!   catch keeps the same store live.
//! - A `throw` jumps directly to the last catch whose type is a supertype
//!   of the thrown expression's type; a `return`/`break`/`continue` jumps
//!   to the method exit — or to the post-`finally` continuation when the
//!   innermost enclosing `try` has a `finally` clause.
//! - The `try` statement element itself marks every local assigned inside
//!   the try body and read inside any catch as used at the try entry,
//!   which keeps pre-try stores live even when the reading catch is
//!   unreachable (probe-verified).
//! - Methods containing a `try`/`finally` whose finally reads a local, or
//!   any `try`-with-resources, are skipped entirely (reference bail-out).
//!
//! Reported stores: plain `=` assignments anywhere, statement-level
//! compound assignments and prefix `++`/`--`, postfix `++`/`--` anywhere,
//! and variable declarators whose initializer is not a usual default
//! (`0`, `1`, `true`, `false`, `""`, `null`, unary `-`/`+` of those).
//! Update expressions never kill the variable. Any unresolved identifier
//! name in the method exempts same-named locals. Findings span from the
//! `=` operator through the end of the stored value, mirroring the
//! reference text ranges.

use std::collections::{BTreeMap, BTreeSet};

use crate::context::{ByteReference, SemanticIndex, SymbolId, SymbolKind};
use crate::support::{LineIndex, node_text, walk_all};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

const MAX_DEPTH: usize = 128;

pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    lines: &LineIndex,
    semantics: &SemanticIndex,
) -> Vec<Issue> {
    let table = RefTable::build(semantics);
    let facts = FileFacts::build(root, source);
    let mut issues = Vec::new();
    for body in flow_roots(root) {
        if skips_analysis(body) {
            continue;
        }
        let unresolved = unresolved_names(body, source, &table);
        let mut flow = Flow::new(source, lines, semantics, &table, &facts);
        flow.alloc_exit();
        let frontier = flow.sequence(body, Vec::new(), 0);
        flow.connect(&frontier, flow.exit);
        flow.resolve_exceptions();
        let live_out = flow.solve();
        for (id, node) in flow.nodes.iter().enumerate() {
            for store in &node.stores {
                if !store.flaggable
                    || live_out[id].contains(&store.symbol)
                    || store.later_reads.contains(&store.symbol)
                    || unresolved.contains(store.name.as_str())
                {
                    continue;
                }
                issues.push(Issue::new(
                    "java:S1854",
                    format!(
                        "Remove this useless assignment to local variable \"{}\".",
                        store.name
                    ),
                    store.range.clone(),
                ));
            }
        }
    }
    issues
}

/// Bodies analyzed as independent flow graphs: method, constructor, and
/// compact-constructor bodies — the reference visits method trees only.
fn flow_roots(root: Node<'_>) -> Vec<Node<'_>> {
    let mut roots = Vec::new();
    walk_all(root, &mut |node: Node<'_>| {
        if matches!(
            node.kind(),
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        ) && let Some(body) = node.child_by_field_name("body")
        {
            roots.push(body);
        }
    });
    roots
}

/// Reference bail-out: a body is skipped when it contains a `try`/`finally`
/// whose finally subtree reads any local or parameter, or a
/// `try`-with-resources with at least one resource.
fn skips_analysis(body: Node<'_>) -> bool {
    let mut skip = false;
    walk_all(body, &mut |node: Node<'_>| {
        if skip {
            return;
        }
        match node.kind() {
            "try_with_resources_statement" => {
                if node
                    .child_by_field_name("resources")
                    .is_some_and(|spec| spec.named_child_count() > 0)
                {
                    skip = true;
                }
            }
            "try_statement" => {
                let mut cursor = node.walk();
                let has_finally_reads = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "finally_clause")
                    .any(|clause| count_local_reads(clause) > 0);
                if has_finally_reads {
                    skip = true;
                }
            }
            _ => {}
        }
    });
    skip
}

/// Counts reads of locals/parameters anywhere in a subtree (including
/// nested classes and lambdas, matching the reference extractor).
fn count_local_reads(root: Node<'_>) -> usize {
    let mut count = 0;
    walk_all(root, &mut |node: Node<'_>| {
        if node.kind() == "identifier" && !is_member_position(node) && is_plain_read(node) {
            count += 1;
        }
    });
    count
}

/// Whether an identifier is a plain read: never the exact left side of an
/// assignment (the reference marks the whole LHS tree, so even compound
/// left identifiers are not reads; sub-identifiers of `a.b`/`a[i]` left
/// sides are reads through normal recursion).
fn is_plain_read(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return true;
    };
    !(parent.kind() == "assignment_expression"
        && parent.child_by_field_name("left").is_some_and(|left| {
            left.start_byte() == identifier.start_byte() && left.end_byte() == identifier.end_byte()
        }))
}

/// Identifiers in member position (`a.b`, `foo()` name) are not reads and
/// are not collected as unresolved names, mirroring the reference visitor.
fn is_member_position(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    match parent.kind() {
        "field_access" => parent.child_by_field_name("field").is_some_and(|field| {
            field.start_byte() == identifier.start_byte() && field.end_byte() == identifier.end_byte()
        }),
        "method_invocation" => parent.child_by_field_name("name").is_some_and(|name| {
            name.start_byte() == identifier.start_byte() && name.end_byte() == identifier.end_byte()
        }),
        _ => false,
    }
}

/// Names of unresolved identifier references inside one body. Any local
/// sharing such a name is exempt from reporting (reference behavior).
fn unresolved_names(
    body: Node<'_>,
    source: &str,
    table: &RefTable,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    walk_all(body, &mut |node: Node<'_>| {
        if !matches!(node.kind(), "identifier" | "type_identifier") || is_member_position(node) {
            return;
        }
        if let Some(reference) = table.at(node.start_byte(), node.end_byte())
            && reference.symbol.is_none()
        {
            names.insert(node_text(node, source).to_owned());
        }
    });
    names
}

/// A flaggable store to a local variable.
struct Store {
    symbol: SymbolId,
    name: String,
    range: Range,
    flaggable: bool,
    /// Reads emitted after this store inside the same flow node; they
    /// consume the stored value before the node boundary.
    later_reads: BTreeSet<SymbolId>,
}

/// Ordered read/store events inside one flow node.
enum ScanEvent {
    Read(SymbolId),
    Store(usize),
}

/// Mutable output of a subtree scan.
#[derive(Default)]
struct ScanOut {
    reads: BTreeSet<SymbolId>,
    writes: BTreeSet<SymbolId>,
    events: Vec<ScanEvent>,
    stores: Vec<Store>,
    has_throw_call: bool,
    throws_declared: Vec<DeclaredThrow>,
    has_cast: bool,
}

impl ScanOut {
    fn read(&mut self, symbol: SymbolId) {
        self.reads.insert(symbol);
        self.events.push(ScanEvent::Read(symbol));
    }

    fn store(&mut self, store: Store) {
        self.writes.insert(store.symbol);
        self.events.push(ScanEvent::Store(self.stores.len()));
        self.stores.push(store);
    }

    /// Records a flaggable store that does not kill the variable
    /// (update expressions).
    fn non_killing_store(&mut self, store: Store) {
        self.events.push(ScanEvent::Store(self.stores.len()));
        self.stores.push(store);
    }

    /// Computes `later_reads` for every recorded store from event order.
    fn finish(mut self) -> Self {
        let mut seen: BTreeSet<SymbolId> = BTreeSet::new();
        for event in self.events.iter().rev() {
            match event {
                ScanEvent::Read(symbol) => {
                    seen.insert(*symbol);
                }
                ScanEvent::Store(index) => {
                    self.stores[*index].later_reads = seen.clone();
                }
            }
        }
        self
    }
}

/// A declared `throws` type of a same-file callee; `Unknown` marks a type
/// name the frontend cannot resolve, which the reference matches against
/// every catch type.
#[derive(Clone)]
enum DeclaredThrow {
    Known(String),
    Unknown,
}

/// Same-file type hierarchy and `throws` declarations plus a JDK exception
/// table, standing in for classpath semantics the frontend does not have.
struct FileFacts {
    class_super: BTreeMap<String, String>,
    method_throws: BTreeMap<String, Vec<String>>,
    ctor_throws: BTreeMap<String, Vec<String>>,
}

/// Parent type for common JDK exception types (simple names). Anything not
/// listed and not declared in the file is unresolvable.
fn jdk_parent(name: &str) -> Option<&'static str> {
    Some(match name {
        "Exception" => "Throwable",
        // Checked exceptions: direct Exception subtypes.
        "RuntimeException" | "IOException" | "SQLException" | "InterruptedException"
        | "ClassNotFoundException" | "CloneNotSupportedException"
        | "ReflectiveOperationException" | "GeneralSecurityException" | "TimeoutException"
        | "ExecutionException" | "BrokenBarrierException" | "URISyntaxException"
        | "ParseException" | "DataFormatException" | "TooManyListenersException"
        | "PrinterException" | "UnsupportedFlavorException" | "BadLocationException"
        | "PropertyVetoException" | "JMException" | "RelationException"
        | "RelationServiceNotRegisteredException" | "NamingException" | "FontFormatException"
        | "SAXException" | "ParserConfigurationException" | "TransformerException"
        | "XPathException" | "DatatypeConfigurationException" | "XMLStreamException"
        | "SOAPException" | "JAXBException" | "ScriptException" | "LambdaConversionException"
        | "UnsupportedAudioFileException" | "LineUnavailableException"
        | "MidiUnavailableException" | "AlreadyBoundException" | "NotBoundException"
        | "MimeTypeParseException" | "BackingStoreException"
        | "InvalidPreferencesFormatException" => "Exception",
        "IllegalAccessException" | "InstantiationException" | "InvocationTargetException"
        | "NoSuchFieldException" | "NoSuchMethodException" => "ReflectiveOperationException",
        "AclNotFoundException" | "CertificateException" | "CertPathBuilderException"
        | "InvalidAlgorithmParameterException" | "InvalidParameterSpecException"
        | "InvalidKeySpecException" | "KeyException" | "KeyManagementException"
        | "KeyStoreException" | "LastOwnerException" | "NoSuchAlgorithmException"
        | "NoSuchProviderException" | "NoSuchPaddingException" | "SignatureException"
        | "UnrecoverableKeyException" => "GeneralSecurityException",
        "InvalidKeyException" => "KeyException",
        "CertificateEncodingException" | "CertificateExpiredException"
        | "CertificateNotYetValidException" | "CertificateParsingException"
        | "CertificateRevokedException" => "CertificateException",
        // IOException family.
        "CharConversionException" | "CharacterCodingException" | "EOFException"
        | "FileNotFoundException" | "InterruptedIOException" | "MalformedURLException"
        | "ObjectStreamException" | "ProtocolException" | "RemoteException"
        | "SocketException" | "SyncFailedException" | "UnknownHostException"
        | "UnsupportedEncodingException" | "UTFDataFormatException" | "ZipException"
        | "UnsupportedDataTypeException" | "ClosedChannelException"
        | "FileLockInterruptionException" | "FileSystemException" | "HttpRetryException"
        | "SyncException" => "IOException",
        "SocketTimeoutException" => "InterruptedIOException",
        "InvalidClassException" | "InvalidObjectException" | "NotActiveException"
        | "NotSerializableException" | "OptionalDataException" | "StreamCorruptedException"
        | "WriteAbortedException" => "ObjectStreamException",
        "ActivateFailedException" | "ServerException" | "UnknownObjectException" => {
            "RemoteException"
        }
        "BindException" | "ConnectException" | "NoRouteToHostException"
        | "PortUnreachableException" => "SocketException",
        "JarException" => "ZipException",
        "AccessDeniedException" | "AtomicMoveNotSupportedException"
        | "DirectoryNotEmptyException" | "FileAlreadyExistsException" | "NoSuchFileException" => {
            "FileSystemException"
        }
        // SQLException family.
        "BatchUpdateException" | "SerialException" | "SQLClientInfoException" | "SQLDataException"
        | "SQLFeatureNotSupportedException" | "SQLIntegrityConstraintViolationException"
        | "SQLInvalidAuthorizationSpecException" | "SQLNonTransientConnectionException"
        | "SQLRecoverableException" | "SQLSyntaxErrorException" | "SQLTimeoutException"
        | "SQLTransactionRollbackException" | "SQLTransientConnectionException" | "SQLWarning"
        | "SyncProviderException" => "SQLException",
        "RowSetWarning" => "SQLWarning",
        // JMX and naming families.
        "AttributeNotFoundException" | "BadAttributeValueExpException"
        | "BadBinaryOpValueExpException" | "BadStringOperationException"
        | "InstanceNotFoundException" | "InvalidApplicationException"
        | "InvalidAttributeValueException" | "InvalidTargetObjectTypeException" | "MBeanException"
        | "ReflectionException" | "RuntimeOperationsException" | "ServiceNotFoundException" => {
            "JMException"
        }
        "InvalidRelationIdException" | "InvalidRelationTypeException" | "InvalidRoleInfoException"
        | "InvalidRoleValueException" | "RelationNotFoundException"
        | "RelationTypeNotFoundException" | "RoleInfoNotFoundException" | "RoleNotFoundException" => {
            "RelationException"
        }
        "AuthenticationException" | "AuthenticationNotSupportedException"
        | "CannotProceedException" | "CommunicationException" | "ConfigurationException"
        | "ContextNotEmptyException" | "InsufficientResourcesException"
        | "InterruptedNamingException" | "InvalidNameException" | "LimitExceededException"
        | "LinkException" | "NameAlreadyBoundException" | "NameNotFoundException"
        | "NamingSecurityException" | "NoInitialContextException" | "NoPermissionException"
        | "NotContextException" | "OperationNotSupportedException" | "PartialResultException"
        | "ReferralException" | "ServiceUnavailableException" | "LdapException" => {
            "NamingException"
        }
        "SizeLimitExceededException" | "TimeLimitExceededException" => "LimitExceededException",
        "MarshalException" | "PropertyException" | "ValidationException" => "JAXBException",
        // RuntimeException family.
        "ArithmeticException" | "ArrayStoreException" | "ClassCastException"
        | "ConcurrentModificationException" | "IllegalArgumentException"
        | "IllegalMonitorStateException" | "IllegalStateException" | "IndexOutOfBoundsException"
        | "NegativeArraySizeException" | "NullPointerException" | "SecurityException"
        | "UnsupportedOperationException" | "NoSuchElementException" | "EmptyStackException"
        | "MissingResourceException" | "DateTimeException" | "RejectedExecutionException"
        | "CompletionException" | "UncheckedIOException" | "BufferOverflowException"
        | "BufferUnderflowException" | "ReadOnlyBufferException" | "InvalidMarkException"
        | "TypeNotPresentException" | "AnnotationTypeMismatchException"
        | "IncompleteAnnotationException" | "MalformedParameterizedTypeException"
        | "MalformedParametersException" | "WrongMethodTypeException"
        | "EnumConstantNotPresentException" | "UndeclaredThrowableException" | "DOMException"
        | "LSException" | "WebServiceException" | "DirectoryIteratorException"
        | "FileSystemLoopException" | "IllegalDirectoryStreamException"
        | "ProviderMismatchException" | "JMRuntimeException" | "RuntimeErrorException"
        | "FileSystemNotFoundException" | "ProviderNotFoundException" => "RuntimeException",
        "NumberFormatException" | "IllegalCharsetNameException" | "IllegalFormatException"
        | "PatternSyntaxException" | "ProviderException" | "UnsupportedCharsetException"
        | "InvalidPathException" | "UnresolvedAddressException"
        | "UnsupportedAddressTypeException" => "IllegalArgumentException",
        "AlreadyConnectedException" | "CancelledKeyException" | "ClosedDirectoryStreamException"
        | "ClosedFileSystemException" | "ClosedSelectorException" | "ConnectionPendingException"
        | "FormatterClosedException" | "IllegalBlockingModeException" | "IllegalSelectorException"
        | "NotYetBoundException" | "NotYetConnectedException" | "ReadPendingException"
        | "ShutdownChannelGroupException" | "WritePendingException" | "AcceptPendingException"
        | "OverlappingFileLockException" => "IllegalStateException",
        "AsynchronousCloseException" => "ClosedChannelException",
        "ClosedByInterruptException" => "AsynchronousCloseException",
        "ReadOnlyFileSystemException" => "UnsupportedOperationException",
        "ArrayIndexOutOfBoundsException" | "StringIndexOutOfBoundsException" => {
            "IndexOutOfBoundsException"
        }
        "InputMismatchException" => "NoSuchElementException",
        "DuplicateFormatFlagsException" | "FormatFlagsConversionMismatchException"
        | "IllegalFormatCodePointException" | "IllegalFormatConversionException"
        | "IllegalFormatFlagsException" | "IllegalFormatPrecisionException"
        | "IllegalFormatWidthException" | "MissingFormatArgumentException"
        | "UnknownFormatConversionException" | "UnknownFormatFlagsException" => {
            "IllegalFormatException"
        }
        // Error family.
        "Error" => "Throwable",
        "AssertionError" | "LinkageError" | "ThreadDeath" | "VirtualMachineError" | "IOError"
        | "AnnotationFormatError" | "AWTError" | "CoderMalfunctionError"
        | "FactoryConfigurationError" | "TransformerFactoryConfigurationError"
        | "ServiceConfigurationError" => "Error",
        "BootstrapMethodError" | "ClassFormatError" | "ExceptionInInitializerError"
        | "IncompatibleClassChangeError" | "NoClassDefFoundError" | "UnsatisfiedLinkError"
        | "VerifyError" => "LinkageError",
        "AbstractMethodError" | "IllegalAccessError" | "InstantiationError" | "NoSuchFieldError"
        | "NoSuchMethodError" => "IncompatibleClassChangeError",
        "InternalError" | "OutOfMemoryError" | "StackOverflowError" | "UnknownError" => {
            "VirtualMachineError"
        }
        "Throwable" | "Object" => return None,
        _ => return None,
    })
}

/// Catch parameter type names of one `catch_clause` (multi-catch yields
/// several).
fn catch_types(clause: Node<'_>, source: &str) -> Vec<String> {
    let mut types = Vec::new();
    walk_all(clause, &mut |node: Node<'_>| {
        if node.kind() == "catch_type" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let name = simple_type_name(child, source);
                if !name.is_empty() {
                    types.push(name);
                }
            }
        }
    });
    types
}

/// The simple name of a type node: the last `type_identifier` inside it.
fn simple_type_name(node: Node<'_>, source: &str) -> String {
    let mut name = String::new();
    walk_all(node, &mut |child: Node<'_>| {
        if child.kind() == "type_identifier" {
            name = node_text(child, source).to_owned();
        }
    });
    name
}

/// Normalizes a type string to its simple name (strips generics and
/// qualifiers).
fn normalize_type_name(text: &str) -> String {
    let without_generics = text.split('<').next().unwrap_or(text).trim();
    without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim()
        .to_owned()
}

impl FileFacts {
    fn build(root: Node<'_>, source: &str) -> Self {
        let mut facts = Self {
            class_super: BTreeMap::new(),
            method_throws: BTreeMap::new(),
            ctor_throws: BTreeMap::new(),
        };
        walk_all(root, &mut |node: Node<'_>| {
            match node.kind() {
                "class_declaration" | "record_declaration" | "enum_declaration" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        let class_name = node_text(name, source).to_owned();
                        let parent = node
                            .child_by_field_name("superclass")
                            .map(|superclass| simple_type_name(superclass, source))
                            .filter(|name| !name.is_empty());
                        if let Some(parent) = parent {
                            facts.class_super.insert(class_name, parent);
                        }
                    }
                }
                "method_declaration" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        let throws = throws_names(node, source);
                        facts
                            .method_throws
                            .entry(node_text(name, source).to_owned())
                            .or_insert_with(Vec::new)
                            .extend(throws);
                    }
                }
                "constructor_declaration" | "compact_constructor_declaration" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        let throws = throws_names(node, source);
                        facts
                            .ctor_throws
                            .entry(node_text(name, source).to_owned())
                            .or_insert_with(Vec::new)
                            .extend(throws);
                    }
                }
                _ => {}
            }
        });
        facts
    }

    /// `sub <: sup` over the same-file and JDK parent chains.
    fn is_subtype(&self, sub: &str, sup: &str) -> bool {
        let mut current = normalize_type_name(sub);
        let target = normalize_type_name(sup);
        for _ in 0..32 {
            if current == target {
                return true;
            }
            let Some(parent) = self
                .class_super
                .get(&current)
                .map(String::as_str)
                .or_else(|| jdk_parent(&current))
            else {
                return false;
            };
            current = parent.to_owned();
        }
        false
    }

    /// Reference runtime-catch test: `Exception` itself, `RuntimeException`
    /// subtypes, and anything not provably an `Exception` subtype
    /// (unknown types included).
    fn is_runtime_catch(&self, catch_type: &str) -> bool {
        catch_type == "Exception"
            || self.is_subtype(catch_type, "RuntimeException")
            || !self.is_subtype(catch_type, "Exception")
    }

    /// Bidirectional thrown/caught matching; unknown types match all.
    fn catch_matches(&self, thrown: &DeclaredThrow, caught: &str) -> bool {
        match thrown {
            DeclaredThrow::Unknown => true,
            DeclaredThrow::Known(thrown) => {
                self.is_subtype(thrown, caught) || self.is_subtype(caught, thrown)
            }
        }
    }

    /// Declared `throws` types for a call node; empty when the callee is
    /// unresolvable (reference: unknown symbols add no declared edges).
    fn declared_throws(&self, call: Node<'_>, source: &str) -> Vec<DeclaredThrow> {
        let names: Option<&Vec<String>> = match call.kind() {
            "method_invocation" => call
                .child_by_field_name("name")
                .and_then(|name| self.method_throws.get(node_text(name, source))),
            "object_creation_expression" => call
                .child_by_field_name("type")
                .map(|ty| simple_type_name(ty, source))
                .and_then(|name| self.ctor_throws.get(&name)),
            "explicit_constructor_invocation" => {
                let class = call
                    .child_by_field_name("constructor")
                    .and_then(|ctor| match ctor.kind() {
                        "this" => enclosing_class_name(call, source),
                        "super" => enclosing_class_name(call, source)
                            .and_then(|name| self.class_super.get(&name).cloned()),
                        _ => None,
                    });
                class.and_then(|name| self.ctor_throws.get(&name))
            }
            _ => None,
        };
        names
            .map(|list| {
                list.iter()
                    .map(|name| {
                        if self.known_type(name) {
                            DeclaredThrow::Known(name.clone())
                        } else {
                            DeclaredThrow::Unknown
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A type is known when it is declared in this file or present in the
    /// JDK table.
    fn known_type(&self, name: &str) -> bool {
        let name = normalize_type_name(name);
        self.class_super.contains_key(&name)
            || jdk_parent(&name).is_some()
            || matches!(name.as_str(), "Throwable" | "Object" | "Exception" | "RuntimeException" | "Error")
    }
}

/// `throws` type names of a method/constructor declaration.
fn throws_names(declaration: Node<'_>, source: &str) -> Vec<String> {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "throws")
        .flat_map(|throws| {
            let mut inner = throws.walk();
            throws
                .named_children(&mut inner)
                .map(|ty| simple_type_name(ty, source))
                .collect::<Vec<_>>()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// Name of the innermost class/record/enum enclosing `node`.
fn enclosing_class_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if matches!(
            parent.kind(),
            "class_declaration" | "record_declaration" | "enum_declaration"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            return Some(node_text(name, source).to_owned());
        }
        ancestor = parent.parent();
    }
    None
}

/// Byte-offset-keyed views over the semantic index: raw identifier
/// references sorted by start offset, and local declaration name spans.
struct RefTable {
    references: Vec<ByteReference>,
    locals: BTreeMap<(usize, usize), SymbolId>,
}

impl RefTable {
    fn build(semantics: &SemanticIndex) -> Self {
        let mut references = semantics.byte_references().to_vec();
        references.sort_by_key(|reference| reference.start);
        let locals = semantics
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == SymbolKind::Local)
            .map(|symbol| ((symbol.byte_start(), symbol.byte_end()), symbol.id))
            .collect();
        Self {
            references,
            locals,
        }
    }

    fn at(&self, start: usize, end: usize) -> Option<&ByteReference> {
        let index = self
            .references
            .partition_point(|reference| reference.start < start);
        self.references
            .get(index)
            .filter(|reference| reference.start == start && reference.end == end)
    }

    fn local_at(&self, start: usize, end: usize) -> Option<SymbolId> {
        self.locals.get(&(start, end)).copied()
    }
}

/// Region of a `try` statement a flow node belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Region {
    Body,
    Catch,
    Finally,
}

/// Per-`try` context: catch entries in source order, the finally entry
/// (break/continue target), and the post-try join (exceptional exit and
/// return/throw target when a finally exists).
struct TryCtx {
    catches: Vec<(Vec<String>, usize)>,
    finally_entry: Option<usize>,
    join: usize,
}

struct FlowNode {
    successors: Vec<usize>,
    predecessors: Vec<usize>,
    exceptions: Vec<usize>,
    reads: BTreeSet<SymbolId>,
    writes: BTreeSet<SymbolId>,
    stores: Vec<Store>,
    has_throw_call: bool,
    throws_declared: Vec<DeclaredThrow>,
    has_cast: bool,
    /// Try whose catches this node's exception edges resolve against.
    exc_try: Option<usize>,
    /// Try whose catches `throw` jumps and cast edges resolve against.
    jump_try: Option<usize>,
    /// Whether exception catch edges land on this node's predecessors
    /// (nodes inside catch/finally bodies) instead of the node itself.
    in_handler: bool,
    /// Exceptional exit edge target recorded at creation time.
    exc_exit: usize,
}

struct Flow<'source, 'index> {
    source: &'source str,
    lines: &'index LineIndex,
    table: &'index RefTable,
    semantics: &'index SemanticIndex,
    facts: &'index FileFacts,
    nodes: Vec<FlowNode>,
    break_targets: Vec<(Option<String>, Vec<usize>)>,
    continue_targets: Vec<(Option<String>, Vec<usize>)>,
    region_stack: Vec<(usize, Region)>,
    try_ctxs: Vec<TryCtx>,
    exit: usize,
}

impl<'source, 'index> Flow<'source, 'index> {
    fn new(
        source: &'source str,
        lines: &'index LineIndex,
        semantics: &'index SemanticIndex,
        table: &'index RefTable,
        facts: &'index FileFacts,
    ) -> Self {
        Self {
            source,
            lines,
            table,
            semantics,
            facts,
            nodes: Vec::new(),
            break_targets: Vec::new(),
            continue_targets: Vec::new(),
            region_stack: Vec::new(),
            try_ctxs: Vec::new(),
            exit: usize::MAX,
        }
    }

    /// Allocates the shared exit sink for `return` and `throw` jumps.
    fn alloc_exit(&mut self) {
        self.exit = self.alloc(None);
    }

    fn alloc(&mut self, node: Option<Node<'_>>) -> usize {
        let id = self.nodes.len();
        let mut out = ScanOut::default();
        if let Some(node) = node {
            self.scan(node, false, &mut out);
        }
        let out = out.finish();
        self.nodes.push(FlowNode {
            successors: Vec::new(),
            predecessors: Vec::new(),
            exceptions: Vec::new(),
            reads: out.reads,
            writes: out.writes,
            stores: out.stores,
            has_throw_call: out.has_throw_call,
            throws_declared: out.throws_declared,
            has_cast: out.has_cast,
            exc_try: self.exc_try(),
            jump_try: self.jump_try(),
            in_handler: self.in_handler(),
            exc_exit: self.exc_exit_target(),
        });
        id
    }

    fn connect(&mut self, incoming: &[usize], id: usize) {
        for &predecessor in incoming {
            self.nodes[predecessor].successors.push(id);
            self.nodes[id].predecessors.push(predecessor);
        }
    }

    fn edge(&mut self, from: usize, to: usize) {
        self.nodes[from].successors.push(to);
        self.nodes[to].predecessors.push(from);
    }

    /// The try whose catches resolve exception edges for nodes created now:
    /// the innermost non-finally region's try for body regions, the try
    /// below it for handler regions.
    fn exc_try(&self) -> Option<usize> {
        let effective: Vec<(usize, Region)> = self
            .region_stack
            .iter()
            .copied()
            .filter(|(_, region)| *region != Region::Finally)
            .collect();
        match effective.last() {
            Some(&(try_idx, Region::Body)) => Some(try_idx),
            Some(&(_, Region::Catch)) => effective
                .iter()
                .rev()
                .skip(1)
                .map(|(try_idx, _)| *try_idx)
                .next(),
            _ => None,
        }
    }

    /// The try whose catches resolve `throw` jumps and cast edges: the
    /// innermost non-finally region's try.
    fn jump_try(&self) -> Option<usize> {
        self.region_stack
            .iter()
            .rev()
            .find(|(_, region)| *region != Region::Finally)
            .map(|(try_idx, _)| *try_idx)
    }

    /// Whether the current position is inside a catch body (or a finally
    /// nested under one), where exception catch edges land on predecessors.
    fn in_handler(&self) -> bool {
        self.region_stack
            .iter()
            .rev()
            .find(|(_, region)| *region != Region::Finally)
            .is_some_and(|(_, region)| *region == Region::Catch)
    }

    /// Exceptional exit edge target for nodes created now: the post-try
    /// join when the innermost try has a finally, else the method exit.
    fn exc_exit_target(&self) -> usize {
        match self.region_stack.last() {
            Some(&(try_idx, _)) => {
                let ctx = &self.try_ctxs[try_idx];
                if ctx.finally_entry.is_some() {
                    ctx.join
                } else {
                    self.exit
                }
            }
            None => self.exit,
        }
    }

    /// Jump target for `return` and unmatched `throw`: the post-try join
    /// when the innermost try has a finally, else the method exit.
    fn jump_exit_target(&self) -> usize {
        self.exc_exit_target()
    }

    /// Jump targets for `break`/`continue`: the finally entry of the
    /// innermost try with a finally, else the method exit.
    fn break_continue_targets(&self) -> Vec<usize> {
        match self.region_stack.last() {
            Some(&(try_idx, _)) => self.try_ctxs[try_idx]
                .finally_entry
                .map_or_else(|| vec![self.exit], |entry| vec![entry]),
            None => vec![self.exit],
        }
    }

    /// Collects reads, writes, flaggable stores, and throwing sites from
    /// `node`'s subtree. Lambda and class bodies contribute reads
    /// (captures) but never writes or stores: their stores execute later
    /// and are analyzed as their own flow roots.
    fn scan(&self, node: Node<'_>, defer_writes: bool, out: &mut ScanOut) {
        match node.kind() {
            "lambda_expression" => {
                if let Some(body) = node.child_by_field_name("body") {
                    self.scan(body, true, out);
                }
                return;
            }
            "class_body" | "enum_body" | "interface_body" | "annotation_type_body" => {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                for child in children {
                    self.scan(child, true, out);
                }
                return;
            }
            "method_invocation" | "object_creation_expression"
            | "explicit_constructor_invocation" => {
                out.has_throw_call = true;
                out.throws_declared
                    .extend(self.facts.declared_throws(node, self.source));
            }
            "cast_expression" => out.has_cast = true,
            "assignment_expression" => {
                self.scan_assignment(node, defer_writes, out);
                return;
            }
            "update_expression" => {
                self.scan_update(node, defer_writes, out);
                return;
            }
            "identifier" => {
                self.scan_identifier(node, out);
                return;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        for child in children {
            self.scan(child, defer_writes, out);
        }
    }

    /// One identifier reference: a read unless it sits in member position
    /// or is the left side of a plain `=`.
    fn scan_identifier(&self, identifier: Node<'_>, out: &mut ScanOut) {
        if is_member_position(identifier) || !is_plain_read(identifier) {
            return;
        }
        if let Some(symbol) = self.local_symbol(identifier) {
            out.read(symbol);
        }
    }

    /// Resolves an identifier to a local or parameter symbol.
    fn local_symbol(&self, identifier: Node<'_>) -> Option<SymbolId> {
        let reference = self.table.at(identifier.start_byte(), identifier.end_byte())?;
        let symbol = reference.symbol?;
        matches!(
            self.semantics.symbols.get(symbol.0)?.kind,
            SymbolKind::Local | SymbolKind::Parameter
        )
        .then_some(symbol)
    }

    /// Resolves an identifier to a local symbol only (parameters are not
    /// local variables for this rule).
    fn local_only_symbol(&self, identifier: Node<'_>) -> Option<SymbolId> {
        let reference = self.table.at(identifier.start_byte(), identifier.end_byte())?;
        let symbol = reference.symbol?;
        matches!(self.semantics.symbols.get(symbol.0)?.kind, SymbolKind::Local)
            .then_some(symbol)
    }

    /// `x = v` stores; compound operators also read the old value. The
    /// store is flaggable for plain `=` anywhere and for compound
    /// operators at statement level.
    fn scan_assignment(&self, node: Node<'_>, defer_writes: bool, out: &mut ScanOut) {
        if let Some(right) = node.child_by_field_name("right") {
            self.scan(right, defer_writes, out);
        }
        let operator = assignment_operator(node);
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if operator != "=" {
            self.scan(left, defer_writes, out);
        }
        if defer_writes || left.kind() != "identifier" {
            return;
        }
        let Some(symbol) = self.local_only_symbol(left) else {
            return;
        };
        let flaggable = operator == "="
            || node
                .parent()
                .is_some_and(|parent| parent.kind() == "expression_statement");
        let start = operator_byte(node).unwrap_or_else(|| left.end_byte());
        let end = node
            .child_by_field_name("right")
            .map_or_else(|| left.end_byte(), |value| value.end_byte());
        out.store(Store {
            symbol,
            name: node_text(left, self.source).to_owned(),
            range: self.lines.range(self.source, start, end),
            flaggable,
            later_reads: BTreeSet::new(),
        });
    }

    /// `x++`/`++x` read their operand and are flaggable stores that never
    /// kill the variable: postfix anywhere, prefix at statement level.
    fn scan_update(&self, node: Node<'_>, defer_writes: bool, out: &mut ScanOut) {
        let Some(operand) = node.named_child(0) else {
            return;
        };
        self.scan(operand, defer_writes, out);
        if defer_writes || operand.kind() != "identifier" {
            return;
        }
        let Some(symbol) = self.local_only_symbol(operand) else {
            return;
        };
        let prefix = node
            .child(0)
            .is_some_and(|first| matches!(first.kind(), "++" | "--"));
        let flaggable = !prefix
            || node
                .parent()
                .is_some_and(|parent| parent.kind() == "expression_statement");
        out.non_killing_store(Store {
            symbol,
            name: node_text(operand, self.source).to_owned(),
            range: self.lines.range(self.source, node.start_byte(), node.end_byte()),
            flaggable,
            later_reads: BTreeSet::new(),
        });
    }

    fn sequence(&mut self, block: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let mut frontier = incoming;
        let mut cursor = block.walk();
        let children: Vec<Node<'_>> = block.named_children(&mut cursor).collect();
        for statement in children {
            frontier = self.statement(statement, frontier, depth + 1);
        }
        frontier
    }

    fn statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        if depth >= MAX_DEPTH {
            let current = self.alloc(Some(node));
            self.connect(&incoming, current);
            return vec![current];
        }
        match node.kind() {
            "block" => self.sequence(node, incoming, depth + 1),
            "local_variable_declaration" => self.declaration(node, incoming),
            "if_statement" => self.if_statement(node, incoming, depth),
            "while_statement" => self.while_statement(node, incoming, depth),
            "do_statement" => self.do_statement(node, incoming, depth),
            "for_statement" => self.for_statement(node, incoming, depth),
            "enhanced_for_statement" => self.enhanced_for_statement(node, incoming, depth),
            "switch_statement" | "switch_expression" => {
                self.switch_statement(node, incoming, depth)
            }
            "try_statement" | "try_with_resources_statement" => {
                self.try_statement(node, incoming, depth)
            }
            "synchronized_statement" => self.synchronized_statement(node, incoming, depth),
            "labeled_statement" => self.labeled_statement(node, incoming, depth),
            "break_statement" | "continue_statement" => self.jump_statement(node, incoming),
            "return_statement" => {
                let jump = self.alloc(Some(node));
                self.connect(&incoming, jump);
                let target = self.jump_exit_target();
                self.edge(jump, target);
                Vec::new()
            }
            "throw_statement" => self.throw_statement(node, incoming),
            _ => {
                let current = self.alloc(Some(node));
                self.connect(&incoming, current);
                vec![current]
            }
        }
    }

    fn if_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let condition = self.alloc(node.child_by_field_name("condition"));
        self.connect(&incoming, condition);
        let join = self.alloc(None);
        let then_end = node
            .child_by_field_name("consequence")
            .map_or_else(|| incoming.clone(), |body| {
                self.statement(body, vec![condition], depth + 1)
            });
        self.connect(&then_end, join);
        if let Some(body) = node.child_by_field_name("alternative") {
            let else_end = self.statement(body, vec![condition], depth + 1);
            self.connect(&else_end, join);
        } else {
            self.edge(condition, join);
        }
        vec![join]
    }

    fn while_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let condition = self.alloc(node.child_by_field_name("condition"));
        self.connect(&incoming, condition);
        let after = self.alloc(None);
        self.edge(condition, after);
        self.break_targets.push((None, vec![after]));
        self.continue_targets.push((self.loop_label(node), vec![condition]));
        if let Some(body) = node.child_by_field_name("body") {
            let ends = self.statement(body, vec![condition], depth + 1);
            self.connect(&ends, condition);
        }
        self.break_targets.pop();
        self.continue_targets.pop();
        vec![after]
    }

    fn do_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let after = self.alloc(None);
        self.break_targets.push((None, vec![after]));
        let condition = self.alloc(node.child_by_field_name("condition"));
        self.continue_targets.push((self.loop_label(node), vec![condition]));
        let body_start = self.alloc(None);
        self.connect(&incoming, body_start);
        let ends = node
            .child_by_field_name("body")
            .map_or_else(|| vec![body_start], |body| {
                self.statement(body, vec![body_start], depth + 1)
            });
        self.connect(&ends, condition);
        self.edge(condition, after);
        self.edge(condition, body_start);
        self.break_targets.pop();
        self.continue_targets.pop();
        vec![after]
    }

    fn for_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let mut frontier = incoming;
        let mut cursor = node.walk();
        let inits: Vec<Node<'_>> = node.children_by_field_name("init", &mut cursor).collect();
        for init in inits {
            frontier = self.statement(init, frontier, depth + 1);
        }
        let condition_field = node.child_by_field_name("condition");
        let condition = self.alloc(condition_field);
        self.connect(&frontier, condition);
        let after = self.alloc(None);
        if condition_field.is_some() {
            self.edge(condition, after);
        }
        self.break_targets.push((None, vec![after]));
        let mut update_cursor = node.walk();
        let updates: Vec<Node<'_>> = node
            .children_by_field_name("update", &mut update_cursor)
            .collect();
        let (update_start, update_end) = if updates.is_empty() {
            (condition, condition)
        } else {
            let start = self.alloc(Some(updates[0]));
            let mut frontier: Vec<usize> = vec![start];
            for update in updates.iter().skip(1) {
                frontier = self.statement(*update, frontier, depth + 1);
            }
            (start, frontier[0])
        };
        self.connect(&[update_end], condition);
        self.continue_targets
            .push((self.loop_label(node), vec![update_start]));
        let body_end = node
            .child_by_field_name("body")
            .map_or_else(|| vec![condition], |body| {
                self.statement(body, vec![condition], depth + 1)
            });
        self.connect(&body_end, update_start);
        self.break_targets.pop();
        self.continue_targets.pop();
        vec![after]
    }

    /// Registers the enhanced-`for` header as one node: it writes the loop
    /// variable and reads the iterated expression on every iteration.
    fn enhanced_for_statement(
        &mut self,
        node: Node<'_>,
        incoming: Vec<usize>,
        depth: usize,
    ) -> Vec<usize> {
        let header = self.alloc(None);
        if let Some(value) = node.child_by_field_name("value") {
            let mut out = ScanOut::default();
            self.scan(value, false, &mut out);
            let out = out.finish();
            self.nodes[header].reads.extend(out.reads);
            self.nodes[header].stores.extend(out.stores);
            self.nodes[header].has_throw_call |= out.has_throw_call;
            self.nodes[header].throws_declared.extend(out.throws_declared);
            self.nodes[header].has_cast |= out.has_cast;
        }
        if let Some(name) = node.child_by_field_name("name")
            && let Some(symbol) = self
                .table
                .local_at(name.start_byte(), name.end_byte())
                .or_else(|| declarator_symbol(self.semantics, name))
        {
            self.nodes[header].writes.insert(symbol);
        }
        self.connect(&incoming, header);
        let after = self.alloc(None);
        self.edge(header, after);
        self.break_targets.push((None, vec![after]));
        self.continue_targets.push((self.loop_label(node), vec![header]));
        if let Some(body) = node.child_by_field_name("body") {
            let ends = self.statement(body, vec![header], depth + 1);
            self.connect(&ends, header);
        }
        self.break_targets.pop();
        self.continue_targets.pop();
        vec![after]
    }

    fn switch_statement(
        &mut self,
        node: Node<'_>,
        incoming: Vec<usize>,
        depth: usize,
    ) -> Vec<usize> {
        let condition = self.alloc(node.child_by_field_name("condition"));
        self.connect(&incoming, condition);
        let join = self.alloc(None);
        self.break_targets.push((None, vec![join]));
        let Some(block) = node.child_by_field_name("body") else {
            self.edge(condition, join);
            self.break_targets.pop();
            return vec![join];
        };
        let mut frontier = vec![condition];
        let mut cursor = block.walk();
        let groups: Vec<Node<'_>> = block.named_children(&mut cursor).collect();
        for group in groups {
            if group.kind() == "switch_rule" {
                let mut rule_cursor = group.walk();
                let bodies: Vec<Node<'_>> = group
                    .named_children(&mut rule_cursor)
                    .filter(|child| child.kind() != "switch_label")
                    .collect();
                let mut rule_frontier = vec![condition];
                for body in bodies {
                    rule_frontier = self.statement(body, rule_frontier, depth + 1);
                }
                self.connect(&rule_frontier, join);
            } else {
                let mut group_cursor = group.walk();
                let statements: Vec<Node<'_>> = group
                    .named_children(&mut group_cursor)
                    .filter(|child| child.kind() != "switch_label")
                    .collect();
                for statement in statements {
                    frontier = self.statement(statement, frontier, depth + 1);
                }
            }
        }
        self.edge(condition, join);
        self.connect(&frontier, join);
        self.break_targets.pop();
        vec![join]
    }

    /// `synchronized (expr) { … }`: the body sequences normally; the lock
    /// expression rides on a jump node to the continuation.
    fn synchronized_statement(
        &mut self,
        node: Node<'_>,
        incoming: Vec<usize>,
        depth: usize,
    ) -> Vec<usize> {
        let mut frontier = incoming;
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            if child.kind() == "block" {
                frontier = self.statement(child, frontier, depth + 1);
            } else {
                let id = self.alloc(Some(child));
                self.connect(&frontier, id);
                frontier = vec![id];
            }
        }
        frontier
    }

    fn labeled_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let after = self.alloc(None);
        let label = node
            .named_child(0)
            .map(|child| node_text(child, self.source).to_owned());
        self.break_targets.push((label, vec![after]));
        let ends = node.named_child(1).map_or_else(
            || vec![after],
            |body| self.statement(body, incoming, depth + 1),
        );
        self.break_targets.pop();
        self.connect(&ends, after);
        vec![after]
    }

    /// `break`/`continue` jump to the innermost matching target — or to
    /// the finally entry / method exit of the innermost try with a
    /// finally, matching the reference's jump redirection.
    fn jump_statement(&mut self, node: Node<'_>, incoming: Vec<usize>) -> Vec<usize> {
        let jump = self.alloc(Some(node));
        self.connect(&incoming, jump);
        let label = node
            .named_child(0)
            .map(|child| node_text(child, self.source));
        let targets = if node.kind() == "break_statement" {
            &self.break_targets
        } else {
            &self.continue_targets
        };
        let matched = targets
            .iter()
            .rev()
            .find(|(name, _)| name.as_deref() == label)
            .map(|(_, target)| target.clone());
        match matched {
            Some(targets) => {
                for target in targets {
                    self.edge(jump, target);
                }
            }
            None => {
                for target in self.break_continue_targets() {
                    self.edge(jump, target);
                }
            }
        }
        Vec::new()
    }

    /// `throw expr` jumps to the last catch whose type is a supertype of
    /// the expression's type, else to the jump exit target. The expression
    /// itself is scanned on the jump node so its throwing calls get
    /// exception edges.
    fn throw_statement(&mut self, node: Node<'_>, incoming: Vec<usize>) -> Vec<usize> {
        let jump = self.alloc(Some(node));
        self.connect(&incoming, jump);
        let thrown = node
            .named_child(0)
            .and_then(|expr| self.expression_type_name(expr));
        let target = self.throw_target(thrown.as_deref());
        self.edge(jump, target);
        Vec::new()
    }

    /// The last catch (source order) of the innermost try whose type is a
    /// supertype of `thrown`, else the jump exit target.
    fn throw_target(&self, thrown: Option<&str>) -> usize {
        if let (Some(try_idx), Some(thrown)) = (self.jump_try(), thrown) {
            let ctx = &self.try_ctxs[try_idx];
            for (types, entry) in ctx.catches.iter().rev() {
                if types.iter().any(|ty| self.facts.is_subtype(thrown, ty)) {
                    return *entry;
                }
            }
        }
        self.jump_exit_target()
    }

    /// Declared type of an expression for `throw` matching: `new X()` and
    /// declared-type identifiers resolve; anything else is unknown.
    fn expression_type_name(&self, expression: Node<'_>) -> Option<String> {
        let mut expr = expression;
        while expr.kind() == "parenthesized_expression" {
            expr = expr.named_child(0)?;
        }
        match expr.kind() {
            "object_creation_expression" => expr
                .child_by_field_name("type")
                .map(|ty| simple_type_name(ty, self.source))
                .filter(|name| !name.is_empty()),
            "identifier" => self
                .table
                .at(expr.start_byte(), expr.end_byte())
                .and_then(|reference| reference.symbol)
                .and_then(|symbol| self.semantics.symbols.get(symbol.0))
                .and_then(|symbol| symbol.declared_type.clone())
                .map(|name| normalize_type_name(&name))
                .filter(|name| !name.is_empty()),
            "cast_expression" => expr
                .child_by_field_name("type")
                .map(|ty| simple_type_name(ty, self.source))
                .filter(|name| !name.is_empty()),
            _ => None,
        }
    }

    /// Models `try` bodies, `catch` regions, and `finally` with the
    /// reference's exception model. Catch entries are pre-allocated so
    /// body throwing nodes can edge to them; a marker node before the body
    /// marks locals assigned in the body and read in the catches as used
    /// at the try entry.
    fn try_statement(&mut self, node: Node<'_>, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        let join = self.alloc(None);
        let ctx_idx = self.try_ctxs.len();
        self.try_ctxs.push(TryCtx {
            catches: Vec::new(),
            finally_entry: None,
            join,
        });
        let mut cursor = node.walk();
        let clauses: Vec<Node<'_>> = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "catch_clause")
            .collect();
        for clause in &clauses {
            let entry = self.alloc(None);
            let types = catch_types(*clause, self.source);
            self.try_ctxs[ctx_idx].catches.push((types, entry));
        }
        let finally_clause = {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "finally_clause")
        };
        if finally_clause.is_some() {
            let entry = self.alloc(None);
            self.try_ctxs[ctx_idx].finally_entry = Some(entry);
            self.break_targets.push((None, vec![entry]));
            self.continue_targets.push((None, vec![entry]));
        }
        let marker = self.alloc(None);
        self.nodes[marker].reads = self.try_marker_reads(node, &clauses);
        self.connect(&incoming, marker);
        self.region_stack.push((ctx_idx, Region::Body));
        let body_end = node
            .child_by_field_name("body")
            .map_or_else(Vec::new, |body| {
                self.statement(body, vec![marker], depth + 1)
            });
        self.region_stack.pop();
        let mut ends = body_end;
        for (index, clause) in clauses.iter().enumerate() {
            let entry = self.try_ctxs[ctx_idx].catches[index].1;
            self.region_stack.push((ctx_idx, Region::Catch));
            let catch_end = clause
                .child_by_field_name("body")
                .map_or_else(|| vec![entry], |body| {
                    self.statement(body, vec![entry], depth + 1)
                });
            self.region_stack.pop();
            ends.extend(catch_end);
        }
        if let Some(finally_clause) = finally_clause {
            let entry = self.try_ctxs[ctx_idx].finally_entry.unwrap();
            self.connect(&ends, entry);
            self.region_stack.push((ctx_idx, Region::Finally));
            let finally_end = finally_clause
                .child_by_field_name("body")
                .map_or_else(|| vec![entry], |body| {
                    self.statement(body, vec![entry], depth + 1)
                });
            self.region_stack.pop();
            self.connect(&finally_end, join);
            self.break_targets.pop();
            self.continue_targets.pop();
        } else {
            self.connect(&ends, join);
        }
        vec![join]
    }

    /// Locals assigned inside the try body that are also read inside any
    /// catch clause; the reference marks them used at the try entry.
    fn try_marker_reads(&self, node: Node<'_>, clauses: &[Node<'_>]) -> BTreeSet<SymbolId> {
        let mut assigned = BTreeSet::new();
        if let Some(body) = node.child_by_field_name("body") {
            walk_all(body, &mut |child: Node<'_>| {
                if child.kind() == "assignment_expression"
                    && let Some(left) = child.child_by_field_name("left")
                    && left.kind() == "identifier"
                    && let Some(symbol) = self.local_only_symbol(left)
                {
                    assigned.insert(symbol);
                }
            });
        }
        let mut read_in_catches = BTreeSet::new();
        for clause in clauses {
            walk_all(*clause, &mut |child: Node<'_>| {
                if child.kind() == "identifier"
                    && !is_member_position(child)
                    && is_plain_read(child)
                    && let Some(symbol) = self.local_symbol(child)
                {
                    read_in_catches.insert(symbol);
                }
            });
        }
        assigned.intersection(&read_in_catches).copied().collect()
    }

    /// One node per declaration statement. Every declarator with a
    /// non-default initializer is a flaggable store; a later declarator's
    /// initializer can consume an earlier declarator's value inside the
    /// same node.
    fn declaration(&mut self, node: Node<'_>, incoming: Vec<usize>) -> Vec<usize> {
        let id = self.alloc(None);
        let mut out = ScanOut::default();
        let mut cursor = node.walk();
        let declarators: Vec<Node<'_>> = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "variable_declarator")
            .collect();
        for declarator in &declarators {
            if let Some(value) = declarator.child_by_field_name("value") {
                self.scan(value, false, &mut out);
            }
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(symbol) = self
                .table
                .local_at(name.start_byte(), name.end_byte())
                .or_else(|| declarator_symbol(self.semantics, name))
            else {
                continue;
            };
            if let Some(value) = declarator.child_by_field_name("value") {
                let flaggable = !self.is_usual_default(value);
                let range = self.assignment_range(*declarator);
                out.store(Store {
                    symbol,
                    name: node_text(name, self.source).to_owned(),
                    range,
                    flaggable,
                    later_reads: BTreeSet::new(),
                });
            }
        }
        let out = out.finish();
        self.nodes[id].reads = out.reads;
        self.nodes[id].writes = out.writes;
        self.nodes[id].stores = out.stores;
        self.nodes[id].has_throw_call = out.has_throw_call;
        self.nodes[id].throws_declared = out.throws_declared;
        self.nodes[id].has_cast = out.has_cast;
        self.connect(&incoming, id);
        vec![id]
    }

    /// Usual default initializers the reference never reports: `0`, `1`,
    /// `true`, `false`, `""`, `null`, and unary `-`/`+` of those.
    fn is_usual_default(&self, value: Node<'_>) -> bool {
        let mut expr = value;
        while expr.kind() == "parenthesized_expression" {
            let Some(inner) = expr.named_child(0) else {
                return false;
            };
            expr = inner;
        }
        match expr.kind() {
            "decimal_integer_literal" => matches!(node_text(expr, self.source), "0" | "1"),
            "true" | "false" | "null_literal" => true,
            "string_literal" => node_text(expr, self.source) == "\"\"",
            "unary_expression" => expr
                .child(0)
                .is_some_and(|op| matches!(op.kind(), "-" | "+"))
                && expr.named_child(0).is_some_and(|inner| self.is_usual_default(inner)),
            _ => false,
        }
    }

    /// Report range: from the `=` operator through the end of the stored
    /// value, matching the reference text ranges.
    fn assignment_range(&self, declarator: Node<'_>) -> Range {
        let start = operator_byte(declarator).unwrap_or_else(|| declarator.start_byte());
        let end = declarator
            .child_by_field_name("value")
            .map_or_else(|| declarator.end_byte(), |value| value.end_byte());
        self.lines.range(self.source, start, end)
    }

    /// Resolves exception edges after the whole body is built: runtime
    /// catches (on predecessors for handler nodes), declared-throw matches
    /// (on the node itself), cast edges, and the exceptional exit edge.
    fn resolve_exceptions(&mut self) {
        for id in 0..self.nodes.len() {
            let (has_throw_call, has_cast, exc_try, jump_try, in_handler, exc_exit) = {
                let node = &self.nodes[id];
                (
                    node.has_throw_call,
                    node.has_cast,
                    node.exc_try,
                    node.jump_try,
                    node.in_handler,
                    node.exc_exit,
                )
            };
            if !has_throw_call && !has_cast {
                continue;
            }
            if has_throw_call {
                self.nodes[id].exceptions.push(exc_exit);
            }
            if let Some(try_idx) = exc_try {
                self.add_catch_edges(id, try_idx, in_handler);
            }
            if has_cast && let Some(try_idx) = jump_try {
                let targets: Vec<usize> = self.try_ctxs[try_idx]
                    .catches
                    .iter()
                    .filter(|(types, _)| {
                        types
                            .iter()
                            .any(|ty| self.facts.is_subtype(ty, "ClassCastException"))
                    })
                    .map(|(_, entry)| *entry)
                    .collect();
                for target in targets {
                    self.edge(id, target);
                }
            }
        }
    }

    /// Catch edges for one throwing node: runtime catches on the edge
    /// sources (predecessors for handler nodes), declared matches on the
    /// node itself.
    fn add_catch_edges(&mut self, id: usize, try_idx: usize, in_handler: bool) {
        let runtime: Vec<usize> = self.try_ctxs[try_idx]
            .catches
            .iter()
            .filter(|(types, _)| types.iter().any(|ty| self.facts.is_runtime_catch(ty)))
            .map(|(_, entry)| *entry)
            .collect();
        let sources: Vec<usize> = if in_handler {
            self.nodes[id].predecessors.clone()
        } else {
            vec![id]
        };
        for source in sources {
            for &target in &runtime {
                if !self.nodes[source].exceptions.contains(&target) {
                    self.nodes[source].exceptions.push(target);
                }
            }
        }
        let declared: Vec<usize> = self.try_ctxs[try_idx]
            .catches
            .iter()
            .filter(|(types, _)| {
                self.nodes[id]
                    .throws_declared
                    .iter()
                    .any(|thrown| types.iter().any(|ty| self.facts.catch_matches(thrown, ty)))
            })
            .map(|(_, entry)| *entry)
            .collect();
        for target in declared {
            if !self.nodes[id].exceptions.contains(&target) {
                self.nodes[id].exceptions.push(target);
            }
        }
    }

    fn loop_label(&self, node: Node<'_>) -> Option<String> {
        node.parent()
            .filter(|parent| parent.kind() == "labeled_statement")
            .and_then(|parent| parent.named_child(0))
            .map(|label| node_text(label, self.source).to_owned())
    }

    fn solve(&self) -> Vec<BTreeSet<SymbolId>> {
        let count = self.nodes.len();
        let mut live_in: Vec<BTreeSet<SymbolId>> = vec![BTreeSet::new(); count];
        let mut live_out: Vec<BTreeSet<SymbolId>> = vec![BTreeSet::new(); count];
        let limit = count.saturating_mul(8).max(64);
        for _ in 0..limit {
            let mut changed = false;
            for id in (0..count).rev() {
                let mut out = BTreeSet::new();
                for &successor in &self.nodes[id].successors {
                    out.extend(live_in[successor].iter().copied());
                }
                for &exception in &self.nodes[id].exceptions {
                    out.extend(live_in[exception].iter().copied());
                }
                let mut input = out.clone();
                for write in &self.nodes[id].writes {
                    input.remove(write);
                }
                input.extend(self.nodes[id].reads.iter().copied());
                changed |= out != live_out[id] || input != live_in[id];
                live_out[id] = out;
                live_in[id] = input;
            }
            if !changed {
                break;
            }
        }
        live_out
    }
}

/// The operator token text of an assignment expression (`=`, `+=`, …).
fn assignment_operator(assignment: Node<'_>) -> String {
    assignment
        .children(&mut assignment.walk())
        .find(|child| !child.is_named())
        .map_or_else(|| "=".to_owned(), |child| child.kind().to_owned())
}

fn operator_byte(node: Node<'_>) -> Option<usize> {
    node.children(&mut node.walk())
        .find(|child| !child.is_named() && child.kind().contains('='))
        .map(|child| child.start_byte())
}

fn declarator_symbol(semantics: &SemanticIndex, name: Node<'_>) -> Option<SymbolId> {
    semantics
        .symbols
        .iter()
        .find(|symbol| symbol.byte_start() == name.start_byte())
        .map(|symbol| symbol.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::parse;

    fn findings(source: &str) -> Vec<(String, Range)> {
        let tree = parse(source).expect("valid Java fixture");
        let lines = LineIndex::new(source);
        let semantics = SemanticIndex::build(tree.root_node(), source, &lines);
        check(tree.root_node(), source, &lines, &semantics)
            .into_iter()
            .map(|issue| (issue.message, issue.range))
            .collect()
    }

    #[test]
    fn never_read_declarations_are_reported() {
        let source = concat!(
            "class A {\n",
            "  int f() {\n",
            "    Foo unused = bar();\n",
            "    return 1;\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].0,
            "Remove this useless assignment to local variable \"unused\"."
        );
    }

    #[test]
    fn non_default_declaration_killed_by_reassignment_is_reported() {
        let source = "class A { int f() { int x = g(); x = 2; return x; } }";
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].0.contains("\"x\""));
    }

    #[test]
    fn usual_default_declarations_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  int f() {\n",
            "    int a = 0;\n",
            "    int b = 1;\n",
            "    boolean c = true;\n",
            "    boolean d = false;\n",
            "    String e = \"\";\n",
            "    Object f = null;\n",
            "    int g = -1;\n",
            "    int h = 2;\n",
            "    return 1;\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 1, "only the non-default initializer is dead");
        assert!(findings[0].0.contains("\"h\""));
    }

    #[test]
    fn read_after_assignment_stays_silent() {
        let source = concat!(
            "class A {\n",
            "  int f(int a) {\n",
            "    a = g();\n",
            "    return a;\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }

    #[test]
    fn runtime_catch_read_keeps_store_live() {
        // Probe-verified: a RuntimeException catch is a runtime catch, so
        // the throwing `return g()` reaches it and `isEmpty = false` lives.
        let source = concat!(
            "class A {\n",
            "  int f() {\n",
            "    boolean isEmpty = true;\n",
            "    try {\n",
            "      peek();\n",
            "      isEmpty = false;\n",
            "      return g();\n",
            "    } catch (RuntimeException e) {\n",
            "      if (isEmpty) { return -1; }\n",
            "      throw e;\n",
            "    }\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }

    #[test]
    fn checked_catch_unreachable_from_unresolved_call_flags_store() {
        // The pinned Streams.parse oracle shape: `ADAPTER.read` is
        // unresolvable, so only the runtime catch (NumberFormatException)
        // is reachable; `isEmpty = false` is dead while the catch-read
        // keeps `isEmpty = true` live through the try marker.
        let source = concat!(
            "class A {\n",
            "  int parse() {\n",
            "    boolean isEmpty = true;\n",
            "    try {\n",
            "      JsonToken unused = reader.peek();\n",
            "      isEmpty = false;\n",
            "      return ADAPTER.read(reader);\n",
            "    } catch (EOFException e) {\n",
            "      if (isEmpty) { return -1; }\n",
            "      throw e;\n",
            "    } catch (IOException e) {\n",
            "      throw e;\n",
            "    } catch (NumberFormatException e) {\n",
            "      throw e;\n",
            "    }\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 2, "unused and isEmpty = false are dead");
        assert!(findings.iter().any(|(m, _)| m.contains("\"isEmpty\"")));
        assert!(findings.iter().any(|(m, _)| m.contains("\"unused\"")));
        let is_empty = findings
            .iter()
            .find(|(m, _)| m.contains("\"isEmpty\""))
            .unwrap();
        assert_eq!(is_empty.1.start.line, 6);
        assert_eq!(is_empty.1.start.column, 14);
        assert_eq!(is_empty.1.end.column, 21);
    }

    #[test]
    fn declared_throws_reaches_subtype_catch() {
        // Probe-verified: a same-file callee's declared IOException
        // bidirectionally matches catch (EOFException), keeping the store
        // live through the checked catch's read.
        let source = concat!(
            "class A {\n",
            "  void p() throws IOException {}\n",
            "  int f() throws IOException {\n",
            "    boolean x = true;\n",
            "    try {\n",
            "      p();\n",
            "      x = false;\n",
            "      p();\n",
            "    } catch (EOFException e) {\n",
            "      if (x) { return -1; }\n",
            "      throw e;\n",
            "    } catch (IOException e) {\n",
            "      throw e;\n",
            "    }\n",
            "    return 0;\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }

    #[test]
    fn catch_read_marks_pre_try_store_live_even_when_catch_unreachable() {
        // Probe-verified: the try element marks locals assigned in the
        // body and read in catches as used at the try entry, so `x = true`
        // lives while `x = false` stays dead (IOException is checked and
        // unreachable from the unresolvable `g()`).
        let source = concat!(
            "class A {\n",
            "  int f() {\n",
            "    boolean x = true;\n",
            "    try {\n",
            "      x = false;\n",
            "      g();\n",
            "    } catch (IOException e) {\n",
            "      if (x) { return -1; }\n",
            "    }\n",
            "    return 0;\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].0.contains("\"x\""));
        assert_eq!(findings[0].1.start.line, 5);
    }

    #[test]
    fn statement_compound_and_updates_are_reported() {
        // Probe-verified: statement-level `+=`, postfix `x++`, and prefix
        // `++y` are all reported when the variable is dead.
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    int x = 0;\n",
            "    x += 1;\n",
            "    int y = 0;\n",
            "    y++;\n",
            "    int z = 0;\n",
            "    ++z;\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|(m, _)| m.contains("\"x\"")));
        assert!(findings.iter().any(|(m, _)| m.contains("\"y\"")));
        assert!(findings.iter().any(|(m, _)| m.contains("\"z\"")));
    }

    #[test]
    fn nested_plain_assignment_is_reported() {
        let source = "class A { void f() { int x = 0; g(x = 1); } }";
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].0.contains("\"x\""));
    }

    #[test]
    fn try_with_resources_and_finally_reads_skip_the_method() {
        let resources = concat!(
            "class A {\n",
            "  int f() {\n",
            "    int dead = g();\n",
            "    try (AutoCloseable a = null) {\n",
            "      peek();\n",
            "    } catch (Exception e) {\n",
            "      return -1;\n",
            "    }\n",
            "    return 1;\n",
            "  }\n",
            "}"
        );
        assert!(findings(resources).is_empty());
        let finally_reads = concat!(
            "class A {\n",
            "  int f() {\n",
            "    boolean x = true;\n",
            "    int dead = g();\n",
            "    try {\n",
            "      peek();\n",
            "    } finally {\n",
            "      if (x) { dead = 0; }\n",
            "    }\n",
            "    return 1;\n",
            "  }\n",
            "}"
        );
        assert!(findings(finally_reads).is_empty());
    }

    #[test]
    fn unresolved_identifier_name_exempts_same_named_local() {
        // The reference exempts a local when ANY unresolved identifier in
        // the method shares its name; a forward reference leaves `thing`
        // unresolved, so both stores stay silent.
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    g(thing);\n",
            "    int thing = 1;\n",
            "    thing = 2;\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }

    #[test]
    fn loop_carried_reads_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  int f() {\n",
            "    int total = 0;\n",
            "    for (int i = 0; i < 3; i++) {\n",
            "      total = total + i;\n",
            "    }\n",
            "    return total;\n",
            "  }\n",
            "}"
        );
        assert!(findings(source).is_empty());
    }

    #[test]
    fn range_spans_operator_through_value_end() {
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    int unused = g();\n",
            "  }\n",
            "}"
        );
        let findings = findings(source);
        assert_eq!(findings.len(), 1);
        let range = &findings[0].1;
        assert_eq!(range.start.line, 3);
        assert_eq!(range.start.column, 15);
        assert_eq!(range.end.column, 20);
    }
}
