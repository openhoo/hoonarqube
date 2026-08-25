use crate::rules::shared::argument_expression;
use crate::rules::shared::duplicated_key_name;
use crate::support::IssueSink;
use crate::support::unparenthesized;
use oxc_ast::ast::ArrowFunctionExpression;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Class;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FormalParameter;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::MemberExpression;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast::ast::NewExpression;
use oxc_ast::ast::ObjectExpression;
use oxc_ast::ast::ObjectProperty;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyDefinition;
use oxc_ast::ast::ReturnStatement;
use oxc_ast::ast::Statement;
use oxc_ast::ast::StringLiteral;
use oxc_ast::ast::TSAnyKeyword;
use oxc_ast::ast::TSEnumDeclaration;
use oxc_ast::ast::TSInterfaceDeclaration;
use oxc_ast::ast::TSIntersectionType;
use oxc_ast::ast::TSNamespaceDeclaration;
use oxc_ast::ast::TSNonNullExpression;
use oxc_ast::ast::TSPropertySignature;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAliasDeclaration;
use oxc_ast::ast::TSTypeAssertion;
use oxc_ast::ast::TSTypeLiteral;
use oxc_ast::ast::TSTypeParameter;
use oxc_ast::ast::TSUnionType;
use oxc_ast::ast::TemplateLiteral;
use oxc_ast::ast::TryStatement;
use oxc_ast::ast::VariableDeclarator;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_await_expression,
    walk_call_expression, walk_class, walk_formal_parameter, walk_import_declaration,
    walk_logical_expression, walk_member_expression, walk_method_definition, walk_new_expression,
    walk_object_property, walk_property_definition, walk_return_statement, walk_statement,
    walk_string_literal, walk_template_literal, walk_try_statement, walk_ts_any_keyword,
    walk_ts_enum_declaration, walk_ts_interface_declaration, walk_ts_intersection_type,
    walk_ts_namespace_declaration, walk_ts_non_null_expression, walk_ts_property_signature,
    walk_ts_type_alias_declaration, walk_ts_type_assertion, walk_ts_type_literal,
    walk_ts_type_parameter, walk_ts_union_type, walk_variable_declarator,
};
use oxc_span::GetSpan;

pub(crate) fn type_is_primitive_keyword(ts_type: &TSType<'_>) -> bool {
    matches!(
        ts_type,
        TSType::TSStringKeyword(_)
            | TSType::TSNumberKeyword(_)
            | TSType::TSBooleanKeyword(_)
            | TSType::TSBigIntKeyword(_)
            | TSType::TSSymbolKeyword(_)
            | TSType::TSUndefinedKeyword(_)
            | TSType::TSNullKeyword(_)
            | TSType::TSVoidKeyword(_)
            | TSType::TSNeverKeyword(_)
            | TSType::TSIntrinsicKeyword(_)
    )
}

pub(crate) struct TsTypeCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
    /// Enclosing class names, innermost last (`S6565`).
    pub(crate) class_stack: Vec<String>,
    /// Constructor nesting depth (`S7059`).
    pub(crate) constructor_depth: u32,
    /// Depth of enclosing try statements that have a catch or finally
    /// handler (`S4326` return-await exemption).
    pub(crate) try_guard_depth: u32,
}

impl<'a> Visit<'a> for TsTypeCollector<'_, '_> {
    fn visit_ts_enum_declaration(&mut self, it: &TSEnumDeclaration<'a>) {
        self.check_enum_members(it);
        walk_ts_enum_declaration(self, it);
    }

    fn visit_ts_union_type(&mut self, it: &TSUnionType<'a>) {
        self.check_s4622_ts_union_type(it);
        walk_ts_union_type(self, it);
    }

    fn visit_ts_intersection_type(&mut self, it: &TSIntersectionType<'a>) {
        self.check_s4335_ts_intersection_type(it);
        walk_ts_intersection_type(self, it);
    }

    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        self.check_s6564_ts_type_alias_declaration(it);
        walk_ts_type_alias_declaration(self, it);
    }

    fn visit_ts_type_parameter(&mut self, it: &TSTypeParameter<'a>) {
        self.check_s6569_ts_type_parameter(it);
        self.check_s4157_ts_type_parameter(it);
        walk_ts_type_parameter(self, it);
    }

    fn visit_ts_non_null_expression(&mut self, it: &TSNonNullExpression<'a>) {
        self.check_s2966_ts_non_null_expression(it);
        walk_ts_non_null_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.check_s3257_variable_declarator(it);
        self.check_s4327_variable_declarator(it);
        self.check_s6590_variable_declarator(it);
        walk_variable_declarator(self, it);
    }

    fn visit_ts_type_assertion(&mut self, it: &TSTypeAssertion<'a>) {
        self.check_s4137_ts_type_assertion(it);
        walk_ts_type_assertion(self, it);
    }

    fn visit_ts_namespace_declaration(&mut self, it: &TSNamespaceDeclaration<'a>) {
        self.check_s4156_ts_namespace_declaration(it);
        walk_ts_namespace_declaration(self, it);
    }

    fn visit_ts_any_keyword(&mut self, it: &TSAnyKeyword) {
        self.check_s4204_ts_any_keyword(it);
        walk_ts_any_keyword(self, it);
    }

    fn visit_ts_property_signature(&mut self, it: &TSPropertySignature<'a>) {
        self.check_s4782_ts_property_signature(it);
        walk_ts_property_signature(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        self.check_s4798_formal_parameter(it);
        walk_formal_parameter(self, it);
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        self.check_s4323_ts_interface_declaration(it);
        self.check_s6759_ts_interface_declaration(it);
        walk_ts_interface_declaration(self, it);
    }

    fn visit_ts_type_literal(&mut self, it: &TSTypeLiteral<'a>) {
        self.check_single_call_signature(&it.members, it.span());
        self.check_overload_grouping(&it.members);
        walk_ts_type_literal(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        if let Some(id) = &it.id {
            self.class_stack.push(id.name.to_string());
        }
        walk_class(self, it);
        if it.id.is_some() {
            self.class_stack.pop();
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if it.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
            walk_method_definition(self, it);
            self.constructor_depth -= 1;
        } else {
            walk_method_definition(self, it);
        }
        self.check_return_type_annotations(&it.value.params, it.value.return_type.as_deref());
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if let Statement::FunctionDeclaration(function) = it {
            self.check_return_type_annotations(&function.params, function.return_type.as_deref());
        }
        walk_statement(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_return_type_annotations(&it.params, it.return_type.as_deref());
        walk_arrow_function_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_s6568_logical_expression(it);
        walk_logical_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_s7059_call_expression(it);
        walk_call_expression(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        self.check_s1444_property_definition(it);
        walk_property_definition(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.check_s4326_return_await(it);
        walk_return_statement(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        // `return await` inside a try statement with a catch or finally
        // handler preserves rejection-handling semantics; those regions are
        // exempt from the `S4326` return-await finding.
        let guarded = it.handler.is_some() || it.finalizer.is_some();
        if guarded {
            self.try_guard_depth += 1;
        }
        walk_try_statement(self, it);
        if guarded {
            self.try_guard_depth -= 1;
        }
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.check_s7059_await_expression(it);
        self.check_s4326_await_expression(it);
        walk_await_expression(self, it);
    }
}

/// Hash algorithms `S2612` flags inside `createHash` calls.
pub(crate) const WEAK_HASH_ALGORITHMS: [&str; 2] = ["md5", "sha1"];

/// The wider deprecated-hash family `S4790` flags.
pub(crate) const WEAK_HASH_FAMILY: [&str; 4] = ["md2", "md4", "md5", "sha1"];

/// Encryption APIs whose mere use `S4787` asks a developer to review.
pub(crate) const ENCRYPT_API_NAMES: [&str; 6] = [
    "createCipheriv",
    "createDecipheriv",
    "publicEncrypt",
    "privateDecrypt",
    "generateKeyPair",
    "generateKeyPairSync",
];

/// TLS protocol versions `S4423` flags in string literals.
pub(crate) const WEAK_TLS_PROTOCOLS: [&str; 4] = ["sslv2", "sslv3", "tlsv1", "tlsv1.0"];

/// Elliptic curves `S4426` considers too weak for key generation.
pub(crate) const WEAK_EC_CURVES: [&str; 8] = [
    "secp112r1",
    "secp128r1",
    "secp160r1",
    "secp192r1",
    "prime192v1",
    "prime192v2",
    "prime192v3",
    "sect163r1",
];

/// Cipher families `S5547` considers broken.
pub(crate) const WEAK_CIPHER_FAMILIES: [&str; 6] = ["des", "rc2", "rc4", "bf", "blowfish", "idea"];

/// Shell-interpreter child-process sinks `S4721` flags.
pub(crate) const SHELL_EXEC_NAMES: [&str; 2] = ["exec", "execSync"];

/// Process-launching APIs whose bare executable name `S4036` flags.
pub(crate) const PATH_LOOKUP_APIS: [&str; 6] = [
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
];

/// JWT algorithms `S5659` rejects for signing and verification.
pub(crate) const WEAK_JWT_ALGORITHMS: [&str; 1] = ["none"];

/// Angular sanitizer bypass methods `S6268` flags.
pub(crate) const ANGULAR_BYPASS_METHODS: [&str; 5] = [
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustStyle",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
];

/// CSP fetch directives (helmet's camelCase keys) whose disabling `S5728` flags.
pub(crate) const CSP_FETCH_DIRECTIVES: [&str; 10] = [
    "defaultSrc",
    "scriptSrc",
    "styleSrc",
    "imgSrc",
    "connectSrc",
    "fontSrc",
    "objectSrc",
    "mediaSrc",
    "frameSrc",
    "workerSrc",
];

/// Referrer-Policy values `S5736` considers unsafe.
pub(crate) const UNSAFE_REFERRER_POLICIES: [&str; 2] = ["unsafe-url", "no-referrer-when-downgrade"];

/// Archive-extraction entry points `S5042` asks developers to review.
pub(crate) const ARCHIVE_EXTRACT_APIS: [&str; 5] =
    ["unzip", "unzipSync", "untar", "extract", "extractAllTo"];

/// Cleartext transport modules `S5332` flags on import and `require`.
pub(crate) const CLEARTEXT_MODULES: [&str; 2] = ["http", "ws"];

/// Identifier fragments whose presence in logged arguments `S5757` flags.
pub(crate) const SENSITIVE_DATA_FRAGMENTS: [&str; 6] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
];

/// First call argument as a string-literal value, if it is one.
pub(crate) fn first_string_argument<'a>(call: &'a CallExpression<'_>) -> Option<&'a str> {
    let argument = call.arguments.first()?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Value of a static or quoted-string key inside an object literal.
pub(crate) fn object_property<'a, 'b>(
    object: &'a ObjectExpression<'b>,
    key: &str,
) -> Option<&'a Expression<'b>> {
    object.properties.iter().find_map(|property| {
        let ObjectPropertyKind::ObjectProperty(inner) = property else {
            return None;
        };
        match duplicated_key_name(&inner.key) {
            Some(name) if name == key => Some(&inner.value),
            _ => None,
        }
    })
}

/// String value of an object-literal key, if it holds a string literal.
pub(crate) fn string_property<'a>(object: &'a ObjectExpression<'_>, key: &str) -> Option<&'a str> {
    match object_property(object, key)? {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Boolean value of an object-literal key, if it holds a boolean literal.
pub(crate) fn boolean_property(object: &ObjectExpression<'_>, key: &str) -> Option<bool> {
    match object_property(object, key)? {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

/// String-literal value of the call argument at `index`, if it is one.
pub(crate) fn string_argument_at<'a>(
    call: &'a CallExpression<'_>,
    index: usize,
) -> Option<&'a str> {
    let argument = call.arguments.get(index)?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Numeric value of an object-literal key, if it holds a numeric literal.
pub(crate) fn number_property(object: &ObjectExpression<'_>, key: &str) -> Option<f64> {
    match object_property(object, key)? {
        Expression::NumericLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

/// Security-hotspot collector: sink tables and option-object inspections.
pub(crate) struct SecurityHotspotCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
}

/// Modules whose imports `S4818` flags as raw socket surfaces.
pub(crate) const RAW_SOCKET_MODULES: [&str; 2] = ["net", "dgram"];

impl<'a> Visit<'a> for SecurityHotspotCollector<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_hash_sink(it);
        self.check_encrypt_api(it);
        self.check_key_generation(it);
        self.check_cipher_mode(it);
        self.check_weak_cipher(it);
        self.check_shell_exec(it);
        self.check_math_random(it);
        self.check_jwt_algorithms(it);
        self.check_angular_bypass(it);
        self.check_message_handler(it);
        self.check_window_open(it);
        self.check_sensitive_log(it);
        self.check_error_middleware(it);
        self.check_cors_wildcard(it);
        self.check_cleartext_require(it);
        self.check_cookie_options(it);
        self.check_xml_parser(it);
        self.check_upload_limits(it);
        self.check_body_parser_limit(it);
        self.check_helmet_config(it);
        self.check_header_call(it);
        self.check_csrf_disabled(it);
        self.check_archive_extraction(it);
        self.check_xpath_usage(it);
        self.check_socket_require(it);
        self.check_s3_create_bucket(it);
        walk_call_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_tls_protocol_literal(it);
        self.check_cleartext_scheme(it);
        self.check_vue_v_html_string(&it.value, it.span());
        walk_string_literal(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_sensitive_permission(it);
        self.check_forwarded_header_trust(it);
        self.check_command_line_arguments(it);
        self.check_standard_input_reads(it);
        walk_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.check_tls_validation_disabled(it);
        walk_assignment_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_s5332_import_declaration(it);
        walk_import_declaration(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        self.check_option_property(it);
        walk_object_property(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.check_new_upload(it);
        self.check_new_xpath_evaluator(it);
        self.check_new_raw_socket(it);
        self.check_new_s3_bucket_command(it);
        walk_new_expression(self, it);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        self.check_vue_v_html_template(it);
        walk_template_literal(self, it);
    }
}
