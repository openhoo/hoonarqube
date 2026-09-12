#!/usr/bin/env node
'use strict';

/*
 * Hoonarqube's bounded TypeScript semantic helper.
 *
 * This file is deliberately a small JSON-lines-free, one-request/one-response
 * process.  The Rust side owns lifecycle, limits, source snapshots, and cache
 * keys; this helper owns only TypeScript's compiler API.  It never downloads a
 * package and never emits findings.  All offsets in the response are UTF-8
 * byte offsets so they can be consumed directly by the Oxc-based Rust rules.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PROTOCOL_VERSION = 1;
const EXPECTED_COMPILER_VERSION = '6.0.3';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalPath(file) {
  return path.normalize(path.resolve(file));
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = stable(value[key]);
      return result;
    }, {});
  }
  return value;
}

function requestFingerprint(request, diagnostics = []) {
  return stableDigest({
    protocol: PROTOCOL_VERSION,
    root: request.root,
    tsconfig: request.tsconfig,
    tsconfig_digest: request.tsconfig_digest,
    typescript_package: request.typescript_package,
    expected_compiler_version: request.expected_compiler_version,
    helper_digest: request.helper_digest,
    dependency_whitelist: [...(request.dependency_whitelist || [])].sort(),
    files: (request.files || []).map(item => ({ path: item.path, digest: item.digest })).sort((a, b) => a.path.localeCompare(b.path)),
    diagnostics,
  });
}
function stableDigest(value) {
  return sha256(JSON.stringify(stable(value)));
}

function readRequest() {
  const input = fs.readFileSync(0, 'utf8');
  if (input.length > 64 * 1024 * 1024) {
    throw new Error('semantic helper request exceeds 64 MiB');
  }
  return JSON.parse(input);
}

function diagnostic(code, message, file, start, end, category = 'error') {
  const item = { code, message, category };
  if (file) item.path = canonicalPath(file);
  if (Number.isInteger(start)) item.start = start;
  if (Number.isInteger(end)) item.end = end;
  return item;
}

function flattenMessage(message) {
  if (typeof message === 'string') return message;
  if (!message) return '';
  let result = message.messageText || '';
  let next = message.next;
  while (next && next.length) {
    result += `\n${next.map(flattenMessage).join('\n')}`;
    next = undefined;
  }
  return result;
}

function packageName(moduleName) {
  const parts = moduleName.split('/');
  return moduleName.startsWith('@') ? `${parts[0] || ''}/${parts[1] || ''}` : parts[0] || '';
}

function utf16ToUtf8(source, offset) {
  const bounded = Math.max(0, Math.min(Number(offset) || 0, source.length));
  return Buffer.byteLength(source.slice(0, bounded), 'utf8');
}

function span(source, nodeOrStart, maybeEnd) {
  const start = typeof nodeOrStart === 'number' ? nodeOrStart : nodeOrStart.getStart();
  const end = typeof nodeOrStart === 'number' ? maybeEnd : nodeOrStart.end;
  return { start: utf16ToUtf8(source, start), end: utf16ToUtf8(source, end) };
}

function asPath(value, base) {
  if (!value) return undefined;
  return canonicalPath(path.isAbsolute(value) ? value : path.resolve(base, value));
}

function loadTypescript(request, diagnostics) {
  const projectRoot = canonicalPath(request.root || process.cwd());
  const packageRoot = request.typescript_package ? canonicalPath(request.typescript_package) : undefined;
  let resolved;
  try {
    if (packageRoot) {
      const directCandidates = [
        packageRoot,
        path.join(packageRoot, 'typescript'),
      ];
      for (const candidate of directCandidates) {
        const packageJsonPath = path.join(candidate, 'package.json');
        if (!fs.existsSync(packageJsonPath)) continue;
        try {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          if (packageJson.name !== 'typescript') continue;
          resolved = require.resolve(candidate);
          break;
        } catch { /* try the next explicit package candidate */ }
      }
      if (!resolved) {
        resolved = require.resolve('typescript', { paths: [packageRoot, projectRoot] });
      }
    } else {
      resolved = require.resolve('typescript', { paths: [projectRoot] });
    }
  } catch (error) {
    diagnostics.push(diagnostic(
      'TS_HELPER_MISSING_COMPILER',
      `Unable to resolve the project-local TypeScript package: ${error.message}`,
    ));
    return undefined;
  }

  let ts;
  try {
    ts = require(resolved);
  } catch (error) {
    diagnostics.push(diagnostic('TS_HELPER_LOAD_COMPILER', `Unable to load TypeScript: ${error.message}`));
    return undefined;
  }
  const version = String(ts.version || '');
  const expected = request.expected_compiler_version || EXPECTED_COMPILER_VERSION;
  if (version !== expected) {
    diagnostics.push(diagnostic(
      'TS_HELPER_COMPILER_VERSION',
      `TypeScript ${expected} is required, but ${version || '<unknown>'} was loaded.`,
    ));
    return undefined;
  }
  return { ts, version, resolved };
}

function makeSnapshots(request, diagnostics) {
  const snapshots = new Map();
  const files = Array.isArray(request.files) ? request.files : [];
  for (const item of files) {
    if (!item || typeof item.path !== 'string' || typeof item.content !== 'string') {
      diagnostics.push(diagnostic('TS_HELPER_INVALID_SOURCE', 'Every source snapshot needs a path and string content.'));
      continue;
    }
    const file = canonicalPath(item.path);
    if (snapshots.has(file)) {
      diagnostics.push(diagnostic('TS_HELPER_DUPLICATE_SOURCE', `Duplicate source snapshot: ${file}`, file));
      continue;
    }
    const digest = sha256(item.content);
    if (item.digest && item.digest !== digest) {
      diagnostics.push(diagnostic('TS_HELPER_SOURCE_DIGEST', `Source snapshot digest mismatch: ${file}`, file));
      continue;
    }
    snapshots.set(file, { path: file, content: item.content, digest });
  }
  return snapshots;
}

function readConfig(ts, request, snapshots, diagnostics) {
  const tsconfig = request.tsconfig ? canonicalPath(request.tsconfig) : undefined;
  if (!tsconfig) {
    return {
      fileNames: [...snapshots.keys()],
      options: {
        allowJs: true,
        checkJs: true,
        noEmit: true,
        skipLibCheck: true,
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.NodeJs,
        jsx: ts.JsxEmit.ReactJSX,
      },
      projectReferences: undefined,
      configFiles: [],
    };
  }

  // Let TypeScript resolve both relative and package-based extends entries.
  // The parser host records the files that TypeScript actually reads instead
  // of maintaining a second, necessarily incomplete resolver.
  const configFiles = new Map();
  const configTextCache = new Map();
  const recordConfigFile = (file, text) => {
    if (typeof text !== 'string') return;
    const canonical = canonicalPath(file);
    const basename = path.basename(canonical).toLowerCase();
    configFiles.set(canonical, {
      path: canonical,
      digest: sha256(text),
      kind: basename === 'package.json' ? 'package-manifest' : 'tsconfig',
    });
  };
  const projectRoot = path.dirname(tsconfig);
  const realpath = file => {
    try {
      const resolved = ts.sys.realpath ? ts.sys.realpath(file) : file;
      return canonicalPath(resolved || file);
    } catch {
      return canonicalPath(file);
    }
  };
  const getFileSystemEntries = directory => {
    const files = new Set();
    const directories = new Set();
    const canonicalDirectory = canonicalPath(directory);
    try {
      for (const dirent of fs.readdirSync(directory, { withFileTypes: true })) {
        const name = typeof dirent === 'string' ? dirent : dirent.name;
        if (name === '.' || name === '..') continue;
        const fullPath = path.join(directory, name);
        let stat;
        if (typeof dirent === 'string' || dirent.isSymbolicLink()) {
          try { stat = fs.statSync(fullPath); } catch { continue; }
        } else {
          stat = dirent;
        }
        if (stat.isFile()) files.add(name);
        else if (stat.isDirectory()) directories.add(name);
      }
    } catch { /* virtual snapshots may be the only entries */ }
    const prefix = canonicalDirectory.endsWith(path.sep)
      ? canonicalDirectory
      : `${canonicalDirectory}${path.sep}`;
    for (const snapshotPath of snapshots.keys()) {
      if (path.dirname(snapshotPath) === canonicalDirectory) {
        files.add(path.basename(snapshotPath));
      } else if (snapshotPath.startsWith(prefix)) {
        const rest = snapshotPath.slice(prefix.length);
        const separator = rest.indexOf(path.sep);
        if (separator < 0) files.add(rest);
        else if (separator > 0) directories.add(rest.slice(0, separator));
      }
    }
    return {
      files: [...files].sort(),
      directories: [...directories].sort(),
    };
  };
  const readDirectory = (directory, extensions, excludes, includes, depth) => {
    const absoluteDirectory = path.isAbsolute(directory)
      ? directory
      : path.resolve(projectRoot, directory);
    return ts.matchFiles(
      absoluteDirectory,
      extensions,
      excludes,
      includes,
      ts.sys.useCaseSensitiveFileNames,
      projectRoot,
      depth,
      getFileSystemEntries,
      realpath,
    );
  };
  if (Object.prototype.hasOwnProperty.call(request, 'tsconfig_content')) {
    configTextCache.set(
      tsconfig,
      typeof request.tsconfig_content === 'string' ? request.tsconfig_content : undefined,
    );
  }
  let parsingConfig = tsconfig;
  const configHost = {
    useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames,
    readDirectory,
    fileExists(file) {
      const canonical = canonicalPath(file);
      if (configTextCache.has(canonical)) return configTextCache.get(canonical) !== undefined;
      if (snapshots.has(canonical)) return true;
      try { return fs.statSync(canonical).isFile(); } catch { return false; }
    },
    readFile(file) {
      const canonical = canonicalPath(file);
      if (configTextCache.has(canonical)) {
        const text = configTextCache.get(canonical);
        recordConfigFile(canonical, text);
        return text;
      }
      let text;
      if (snapshots.has(canonical)) {
        text = snapshots.get(canonical).content;
      } else {
        try { text = fs.readFileSync(canonical, 'utf8'); } catch { text = undefined; }
      }
      configTextCache.set(canonical, text);
      recordConfigFile(canonical, text);
      return text;
    },
    onUnRecoverableConfigFileDiagnostic(item) {
      diagnostics.push(configDiagnostic(ts, item, item?.file?.fileName || parsingConfig));
    },
    getCurrentDirectory() {
      return projectRoot;
    },
  };
  const readConfigFile = configHost.readFile(tsconfig);
  if (readConfigFile === undefined) {
    diagnostics.push(diagnostic('TS_HELPER_MISSING_TSCONFIG', `Cannot read tsconfig: ${tsconfig}`, tsconfig));
    return undefined;
  }
  if (request.tsconfig_digest && request.tsconfig_digest !== sha256(readConfigFile)) {
    diagnostics.push(diagnostic('TS_HELPER_TSCONFIG_DIGEST', `tsconfig digest mismatch: ${tsconfig}`, tsconfig));
    return undefined;
  }

  const optionsToExtend = {
    allowJs: true,
    checkJs: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const extendedConfigCache = new Map();
  const parsedConfigResults = new Map();
  const parsedConfigs = new Set();
  const parseConfig = configFile => {
    const canonical = canonicalPath(configFile);
    if (parsedConfigResults.has(canonical)) return parsedConfigResults.get(canonical);
    const previous = parsingConfig;
    parsingConfig = canonical;
    try {
      const parsed = ts.getParsedCommandLineOfConfigFile(
        canonical,
        optionsToExtend,
        configHost,
        extendedConfigCache,
      );
      parsedConfigResults.set(canonical, parsed);
      for (const error of parsed?.errors || []) {
        diagnostics.push(configDiagnostic(ts, error, error.file?.fileName || canonical));
      }
      return parsed;
    } finally {
      parsingConfig = previous;
    }
  };

  const parsed = parseConfig(tsconfig);
  if (!parsed) return undefined;
  parsedConfigs.add(tsconfig);

  // `parseJsonConfigFileContent` returns normalized project-reference paths,
  // while `resolveProjectReferencePath` is the TypeScript-supported conversion
  // from either a directory form or a file form to its config filename.
  function collectProjectReferences(parsedConfig) {
    for (const reference of parsedConfig.projectReferences || []) {
      let referenceConfig;
      try {
        referenceConfig = canonicalPath(ts.resolveProjectReferencePath(reference));
      } catch (error) {
        diagnostics.push(diagnostic(
          'TS_HELPER_PROJECT_REFERENCE_PATH',
          `Unable to resolve project reference ${reference?.originalPath || reference?.path}: ${error.message}`,
        ));
        continue;
      }
      if (parsedConfigs.has(referenceConfig)) continue;
      parsedConfigs.add(referenceConfig);
      const referenceText = configHost.readFile(referenceConfig);
      const referenceParsed = parseConfig(referenceConfig);
      if (!referenceParsed) {
        if (referenceText === undefined) {
          diagnostics.push(diagnostic(
            'TS_HELPER_MISSING_PROJECT_REFERENCE',
            `Cannot read project reference tsconfig: ${referenceConfig}`,
            referenceConfig,
          ));
        }
        continue;
      }
      collectProjectReferences(referenceParsed);
    }
  }
  collectProjectReferences(parsed);

  return {
    fileNames: parsed.fileNames.map(canonicalPath),
    options: parsed.options,
    projectReferences: parsed.projectReferences,
    configFiles: [...configFiles.values()].sort((left, right) => left.path.localeCompare(right.path)),
    raw: parsed.raw,
    getParsedCommandLine: parseConfig,
  };
}

function configDiagnostic(ts, item, file) {
  return diagnostic(
    `TS_CONFIG_${item.code || 'ERROR'}`,
    flattenMessage(item.messageText),
    file,
    item.start === undefined ? undefined : item.start,
    item.start === undefined ? undefined : item.start + (item.length || 0),
    item.category === ts.DiagnosticCategory.Error ? 'error' : 'warning',
  );
}

function makeHost(ts, config, snapshots, diagnostics) {
  const base = ts.createCompilerHost(config.options, true);
  const originals = {
    fileExists: base.fileExists.bind(base),
    readFile: base.readFile.bind(base),
    getSourceFile: base.getSourceFile.bind(base),
  };
  const snapshotMap = snapshots;
  base.fileExists = file => {
    const canonical = canonicalPath(file);
    return snapshotMap.has(canonical) || originals.fileExists(file);
  };
  base.readFile = file => {
    const canonical = canonicalPath(file);
    const snapshot = snapshotMap.get(canonical);
    return snapshot ? snapshot.content : originals.readFile(file);
  };
  base.getSourceFile = (file, languageVersion, onError, shouldCreateNewSourceFile) => {
    const canonical = canonicalPath(file);
    const snapshot = snapshotMap.get(canonical);
    if (snapshot) {
      return ts.createSourceFile(file, snapshot.content, languageVersion, true, ts.getScriptKindFromFileName(file));
    }
    return originals.getSourceFile(file, languageVersion, onError, shouldCreateNewSourceFile);
  };
  base.realpath = file => {
    try { return canonicalPath(ts.sys.realpath ? ts.sys.realpath(file) : file); } catch { return canonicalPath(file); }
  };
  if (typeof config.getParsedCommandLine === 'function') {
    base.getParsedCommandLine = config.getParsedCommandLine;
  }
  base.onUnRecoverableConfigFileDiagnostic = () => {};
  return base;
}

function symbolKey(ts, checker, symbol) {
  let target = symbol;
  if (target && (target.flags & ts.SymbolFlags.Alias)) {
    try { target = checker.getAliasedSymbol(target); } catch { /* unresolved aliases remain unresolved */ }
  }
  const declaration = target && target.declarations && target.declarations[0];
  const file = declaration && declaration.getSourceFile();
  const id = declaration ? `${canonicalPath(file.fileName)}:${declaration.pos}:${declaration.end}` : '<unknown>';
  return { id, symbol: target, declaration };
}

function jsDocDeprecated(ts, symbol, declaration) {
  const tags = [];
  try { tags.push(...(symbol?.getJsDocTags?.() || [])); } catch { /* old compiler */ }
  if (declaration) {
    try {
      for (const tag of ts.getJSDocTags(declaration)) tags.push({ name: tag.tagName.text, comment: tag.comment });
    } catch { /* declaration may be synthetic */ }
  }
  const deprecated = tags.find(tag => tag.name === 'deprecated');
  if (!deprecated) return undefined;
  return typeof deprecated.comment === 'string' ? deprecated.comment : flattenMessage(deprecated.comment) || '@deprecated';
}

function typeFlags(ts, type) {
  if (!type) return [];
  const names = [];
  const flags = ts.TypeFlags;
  for (const [name, flag] of Object.entries(flags)) {
    if (typeof flag === 'number' && (type.flags & flag) !== 0 && Number.isInteger(flag)) names.push(name);
  }
  return [...new Set(names)].sort();
}

function flattenTypes(ts, type) {
  if (!type) return [];
  if (type.isUnion?.()) return type.types.flatMap(t => flattenTypes(ts, t));
  return [{ flags: typeFlags(ts, type), text: undefined }];
}

function typeInfo(ts, checker, type) {
  const info = {
    text: type ? checker.typeToString(type) : '<unknown>',
    flags: typeFlags(ts, type),
    constituents: [],
    has_null: false,
    has_undefined: false,
    has_object: false,
    has_primitive: false,
    has_falsy_primitive: false,
    has_any: false,
    has_unknown: false,
    has_never: false,
    has_type_parameter: false,
    is_union: Boolean(type?.isUnion?.()),
  };
  const values = type?.isUnion?.() ? type.types : (type ? [type] : []);
  for (const item of values) {
    const flags = typeFlags(ts, item);
    const text = checker.typeToString(item);
    info.constituents.push({ flags, text });
    const f = item.flags || 0;
    if (f & ts.TypeFlags.Null) info.has_null = true;
    if (f & ts.TypeFlags.Undefined) info.has_undefined = true;
    if (f & ts.TypeFlags.Any) info.has_any = true;
    if (f & ts.TypeFlags.Unknown) info.has_unknown = true;
    if (f & ts.TypeFlags.Never) info.has_never = true;
    if (f & ts.TypeFlags.TypeParameter) info.has_type_parameter = true;
    if (f & (ts.TypeFlags.Object | ts.TypeFlags.NonPrimitive)) info.has_object = true;
    if (f & (ts.TypeFlags.StringLike | ts.TypeFlags.NumberLike | ts.TypeFlags.BooleanLike | ts.TypeFlags.BigIntLike | ts.TypeFlags.ESSymbolLike)) {
      info.has_primitive = true;
    }
    if (f & (ts.TypeFlags.String | ts.TypeFlags.Number | ts.TypeFlags.Boolean | ts.TypeFlags.BigInt | ts.TypeFlags.EnumLike | ts.TypeFlags.BooleanLiteral | ts.TypeFlags.NumberLiteral | ts.TypeFlags.StringLiteral | ts.TypeFlags.BigIntLiteral)) {
      info.has_falsy_primitive = true;
    }
  }
  return info;
}

function truthySafeTypeInfo(info) {
  return !info.has_primitive
    && !info.has_any
    && !info.has_unknown
    && !info.has_type_parameter;
}

function typeAcceptsFalsyPrimitive(checker, type) {
  return checker.isTypeAssignableTo(checker.getNumberLiteralType(0), type)
    || checker.isTypeAssignableTo(checker.getFalseType(), type)
    || checker.isTypeAssignableTo(checker.getStringLiteralType(''), type)
    || checker.isTypeAssignableTo(
      checker.getBigIntLiteralType({ negative: false, base10Value: '0' }),
      type,
    );
}

function objectOrNullishTypeInfo(info, checker, type) {
  return Boolean((info.has_null || info.has_undefined)
    && info.has_object
    && truthySafeTypeInfo(info)
    && !typeAcceptsFalsyPrimitive(checker, type));
}

function isGenericCall(ts, checker, node) {
  let call = node;
  if (ts.isNonNullExpression(call)) call = call.expression;
  if (!ts.isCallExpression(call) && !ts.isNewExpression(call)) return false;
  const signature = checker.getResolvedSignature(call);
  if (!signature) return false;
  if ((signature.typeParameters?.length || 0) > 0) return true;
  const declaration = signature.getDeclaration?.();
  return Boolean(declaration?.typeParameters?.length);
}

function resolvedModule(ts, moduleName, sourceFile, config, host) {
  try {
    const result = ts.resolveModuleName(moduleName, sourceFile.fileName, config.options, host);
    return result && result.resolvedModule;
  } catch {
    return undefined;
  }
}

function nearestPackageInfo(fileName, root) {
  const manifests = [];
  let current = path.dirname(fileName);
  const stop = canonicalPath(root);
  while (true) {
    const manifest = path.join(current, 'package.json');
    try {
      const text = fs.readFileSync(manifest, 'utf8');
      const json = JSON.parse(text);
      manifests.push({ path: canonicalPath(manifest), digest: sha256(text), json });
    } catch { /* no manifest here */ }
    if (current === stop || current === path.dirname(current)) break;
    current = path.dirname(current);
  }
  return manifests;
}

function dependencyDeclared(name, manifests) {
  for (const manifest of manifests) {
    const json = manifest.json || {};
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      if (json[field] && Object.prototype.hasOwnProperty.call(json[field], name)) return true;
    }
    const workspaces = json.workspaces;
    if (Array.isArray(workspaces) && workspaces.some(pattern => typeof pattern === 'string' && (pattern === name || pattern.includes(name)))) return true;
    if (workspaces && Array.isArray(workspaces.packages) && workspaces.packages.some(pattern => typeof pattern === 'string' && pattern.includes(name))) return true;
  }
  return false;
}

function pureQuickfixExpression(ts, node) {
  if (!node) return true;
  switch (node.kind) {
    case ts.SyntaxKind.NumericLiteral:
    case ts.SyntaxKind.StringLiteral:
    case ts.SyntaxKind.BigIntLiteral:
    case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
    case ts.SyntaxKind.TrueKeyword:
    case ts.SyntaxKind.FalseKeyword:
    case ts.SyntaxKind.NullKeyword:
    case ts.SyntaxKind.ThisKeyword:
      return true;
    case ts.SyntaxKind.ParenthesizedExpression:
    case ts.SyntaxKind.AsExpression:
    case ts.SyntaxKind.TypeAssertionExpression:
    case ts.SyntaxKind.NonNullExpression:
      return pureQuickfixExpression(ts, node.expression);
    case ts.SyntaxKind.PrefixUnaryExpression:
      return [ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.ExclamationToken, ts.SyntaxKind.TildeToken].includes(node.operator)
        && pureQuickfixExpression(ts, node.operand);
    case ts.SyntaxKind.ArrayLiteralExpression:
      return node.elements.every(element => element.kind !== ts.SyntaxKind.SpreadElement
        && pureQuickfixExpression(ts, element));
    case ts.SyntaxKind.ObjectLiteralExpression:
      return node.properties.every(property => property.kind === ts.SyntaxKind.PropertyAssignment
        && property.name?.kind !== ts.SyntaxKind.ComputedPropertyName
        && pureQuickfixExpression(ts, property.initializer));
    case ts.SyntaxKind.ExpressionStatement:
      return pureQuickfixExpression(ts, node.expression);
    default:
      return false;
  }
}

function moduleSideEffectFree(ts, program, sourceFile, config, host, active = new Set(), memo = new Map()) {
  const sourcePath = canonicalPath(sourceFile.fileName);
  if (memo.has(sourcePath)) return memo.get(sourcePath);
  if (sourceFile.isDeclarationFile) {
    memo.set(sourcePath, undefined);
    return undefined;
  }
  if (active.has(sourcePath)) return undefined;
  active.add(sourcePath);
  const finish = result => {
    active.delete(sourcePath);
    memo.set(sourcePath, result);
    return result;
  };
  const resolveSource = moduleName => {
    const resolved = resolvedModule(ts, moduleName, sourceFile, config, host);
    const resolvedPath = resolved?.resolvedFileName ? canonicalPath(resolved.resolvedFileName) : undefined;
    if (!resolvedPath) return undefined;
    const target = program.getSourceFile(resolvedPath) || program.getSourceFile(path.normalize(resolvedPath));
    if (!target) return undefined;
    return moduleSideEffectFree(ts, program, target, config, host, active, memo);
  };
  const isTypeOnlyImport = statement => {
    if (!statement.importClause) return false;
    if (statement.importClause.isTypeOnly) return true;
    const bindings = statement.importClause.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) return false;
    return bindings.elements.length > 0 && bindings.elements.every(element => element.isTypeOnly);
  };
  const isTypeOnlyExport = statement => {
    if (statement.isTypeOnly || statement.exportClause?.isTypeOnly) return true;
    return Boolean(statement.exportClause
      && ts.isNamedExports(statement.exportClause)
      && statement.exportClause.elements.length > 0
      && statement.exportClause.elements.every(element => element.isTypeOnly));
  };
  let unknown = false;
  for (const statement of sourceFile.statements) {
    if (statement.kind === ts.SyntaxKind.EmptyStatement
      || statement.kind === ts.SyntaxKind.InterfaceDeclaration
      || statement.kind === ts.SyntaxKind.TypeAliasDeclaration
      || statement.kind === ts.SyntaxKind.NamespaceExportDeclaration) continue;
    if (ts.isImportDeclaration(statement)) {
      if (isTypeOnlyImport(statement)) continue;
      if (!statement.importClause) return finish(false);
      const nested = resolveSource(statement.moduleSpecifier.text);
      if (nested === false) return finish(false);
      if (nested === undefined) unknown = true;
      continue;
    }
    if (ts.isExportDeclaration(statement)) {
      if (!statement.moduleSpecifier || isTypeOnlyExport(statement)) continue;
      const nested = resolveSource(statement.moduleSpecifier.text);
      if (nested === false) return finish(false);
      if (nested === undefined) unknown = true;
      continue;
    }
    if (ts.isFunctionDeclaration(statement)
      && !statement.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.Decorator)) continue;
    if (ts.isVariableStatement(statement)) {
      if (statement.declarationList.declarations.every(declaration => !declaration.initializer || pureQuickfixExpression(ts, declaration.initializer))) continue;
      return finish(false);
    }
    if (ts.isExpressionStatement(statement) && pureQuickfixExpression(ts, statement.expression)) continue;
    if (ts.isExportAssignment(statement) && pureQuickfixExpression(ts, statement.expression)) continue;
    if (ts.isModuleDeclaration(statement)
      && statement.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.DeclareKeyword)) continue;
    return finish(false);
  }
  return finish(unknown ? undefined : true);
}

function resolvedModuleSideEffectFree(ts, program, resolvedPath, config, host) {
  const sourceFile = program.getSourceFile(resolvedPath) || program.getSourceFile(path.normalize(resolvedPath));
  return sourceFile ? moduleSideEffectFree(ts, program, sourceFile, config, host) : undefined;
}

function collectImports(ts, checker, program, sourceFile, config, host, root) {
  const imports = [];
  const add = (moduleNode, owner, kind, localSpan) => {
    if (!moduleNode || !ts.isStringLiteral(moduleNode)) return;
    const moduleName = moduleNode.text;
    const normalizedModule = moduleName.split('?')[0].split('#')[0];
    const resolved = resolvedModule(ts, normalizedModule, sourceFile, config, host);
    const resolvedPath = resolved?.resolvedFileName ? canonicalPath(resolved.resolvedFileName) : undefined;
    const sideEffectFree = resolvedPath
      ? resolvedModuleSideEffectFree(ts, program, resolvedPath, config, host)
      : undefined;
    const manifests = nearestPackageInfo(sourceFile.fileName, root);
    const packageId = packageName(normalizedModule);
    const external = !normalizedModule.startsWith('.') && !normalizedModule.startsWith('/') && !normalizedModule.startsWith('#');
    const builtins = require('node:module').builtinModules;
    const dependencyExempt = builtins.includes(normalizedModule) || builtins.includes(packageId) || normalizedModule.startsWith('node:') || normalizedModule.startsWith('data:') || normalizedModule.startsWith('file:') || normalizedModule.startsWith('npm:');
    // S6627 applies the pinned literal module-specifier test to the raw
    // string, independently of TypeScript resolution or package existence.
    const internalModulePath = moduleName.includes('node_modules');
    // S4328 reports only ImportDeclaration/require nodes; ineligible import
    // forms intentionally carry no diagnostic span rather than a fallback.
    const diagnosticSpan = kind === 'import'
      ? span(sourceFile.text, owner.getStart(sourceFile), owner.getStart(sourceFile) + 'import'.length)
      : kind === 'require'
        ? span(sourceFile.text, owner.expression)
        : undefined;
    imports.push({
      kind,
      module: moduleName,
      span: span(sourceFile.text, owner),
      diagnostic_span: diagnosticSpan,
      module_span: span(sourceFile.text, moduleNode),
      local_span: localSpan,
      package: packageId,
      external,
      declared_dependency: dependencyDeclared(packageId, manifests),
      resolved: Boolean(resolvedPath),
      resolved_path: resolvedPath,
      side_effect_free: sideEffectFree,
      external_library: Boolean(resolved?.isExternalLibraryImport),
      internal: internalModulePath,
      internal_reason: internalModulePath ? 'module-path' : undefined,
      dependency_exempt: dependencyExempt,
      unresolved_reason: resolvedPath ? undefined : (external ? 'missing-or-unresolved-external' : 'missing-user-module'),
      manifests: manifests.map(item => ({ path: item.path, digest: item.digest })),
    });
  };

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement)) add(statement.moduleSpecifier, statement, 'import');
    if (ts.isExportDeclaration(statement) && statement.moduleSpecifier) add(statement.moduleSpecifier, statement, 'reexport');
    if (ts.isImportEqualsDeclaration(statement) && ts.isExternalModuleReference(statement.moduleReference)) {
      add(statement.moduleReference.expression, statement, 'import-equals');
    }
  }
  function visit(node) {
    if (ts.isCallExpression(node) && node.arguments.length === 1 && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
      const argument = node.arguments[0];
      if (ts.isStringLiteral(argument)) add(argument, node, 'require');
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return imports;
}

function quickfixTypeParts(type) {
  return type?.isUnion?.() ? type.types : (type ? [type] : []);
}

function quickfixEveryTypeFlag(ts, type, flag) {
  const parts = quickfixTypeParts(type);
  return parts.length > 0 && parts.every(item => Boolean(item.flags & flag));
}
function quickfixTypeAt(checker, node) {
  try {
    return checker.getTypeAtLocation(node);
  } catch {
    return undefined;
  }
}

function quickfixSignature(checker, node) {
  try {
    return checker.getResolvedSignature(node);
  } catch {
    return undefined;
  }
}

function quickfixSymbol(checker, node) {
  try {
    return checker.getSymbolAtLocation(node);
  } catch {
    return undefined;
  }
}
function quickfixScriptValueSymbol(ts, checker, sourceFile, name) {
  if (!sourceFile || ts.isExternalModule(sourceFile)) return undefined;
  const nameNodes = [];
  const addBindingNames = bindingName => {
    if (ts.isIdentifier(bindingName)) {
      nameNodes.push(bindingName);
      return;
    }
    if (ts.isObjectBindingPattern(bindingName) || ts.isArrayBindingPattern(bindingName)) {
      for (const element of bindingName.elements || []) {
        if (ts.isBindingElement(element)) addBindingNames(element.name);
      }
    }
  };
  try {
    for (const statement of sourceFile.statements || []) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations || []) {
          addBindingNames(declaration.name);
        }
      } else if (ts.isFunctionDeclaration(statement)
        || ts.isClassDeclaration(statement)
        || ts.isEnumDeclaration(statement)
        || ts.isModuleDeclaration(statement)) {
        addBindingNames(statement.name);
      }
    }
  } catch {
    return null;
  }
  const matches = [];
  for (const nameNode of nameNodes) {
    const symbol = quickfixSymbol(checker, nameNode);
    if (!symbol || String(symbol.escapedName) !== name || !(symbol.flags & ts.SymbolFlags.Value)) continue;
    const declarations = symbol.declarations || [];
    if (!declarations.some(declaration => {
      try { return declaration.getSourceFile() === sourceFile; } catch { return false; }
    })) continue;
    if (!matches.includes(symbol)) matches.push(symbol);
  }
  return matches.length > 1 ? null : matches[0];
}

function quickfixVisibleValueSymbol(ts, checker, sourceFile, node, name) {
  const scriptSymbol = quickfixScriptValueSymbol(ts, checker, sourceFile, name);
  if (scriptSymbol !== undefined) return scriptSymbol;
  let symbol;
  try {
    symbol = typeof checker.resolveName === 'function'
      ? checker.resolveName(name, node, ts.SymbolFlags.Value, false)
      : undefined;
  } catch {
    return null;
  }
  if (symbol) return symbol;
  let symbols;
  try {
    symbols = checker.getSymbolsInScope(node, ts.SymbolFlags.Value);
  } catch {
    return null;
  }
  const matches = (symbols || []).filter(item => (
    item && String(item.escapedName) === name
  ));
  return matches.length === 1 ? matches[0] : null;
}

function quickfixDefaultLibraryValue(ts, checker, program, sourceFile, node, name) {
  const symbol = quickfixVisibleValueSymbol(ts, checker, sourceFile, node, name);
  if (!symbol || (symbol.flags & ts.SymbolFlags.Alias)) return false;
  const declarations = symbol.declarations || [];
  const valueDeclaration = symbol.valueDeclaration;
  if (!valueDeclaration || !ts.isVariableDeclaration(valueDeclaration) || declarations.length === 0) {
    return false;
  }
  if (declarations.filter(declaration => ts.isVariableDeclaration(declaration)).length !== 1) {
    return false;
  }
  if (typeof program?.isSourceFileDefaultLibrary !== 'function') return false;
  return declarations.every(declaration => {
    let declarationSource;
    try {
      declarationSource = declaration.getSourceFile();
    } catch {
      return false;
    }
    if (!declarationSource || declarationSource.isDeclarationFile !== true) return false;
    try {
      return program.isSourceFileDefaultLibrary(declarationSource) === true;
    } catch {
      return false;
    }
  });
}

function quickfixSymbolType(checker, symbol, node) {
  try {
    return checker.getTypeOfSymbolAtLocation(symbol, node);
  } catch {
    return undefined;
  }
}
function quickfixDeclarationSignature(checker, node) {
  try {
    return checker.getSignatureFromDeclaration(node);
  } catch {
    return undefined;
  }
}
function nullishLiteralKind(ts, node) {
  if (node && node.kind === ts.SyntaxKind.NullKeyword) return 'null';
  if (ts.isIdentifier(node) && node.text === 'undefined') return 'undefined';
  return undefined;
}

function nullishComparisonParts(ts, checker, source, condition) {
  const comparisons = [];
  const unwrap = node => ts.isParenthesizedExpression(node) ? unwrap(node.expression) : node;
  function collect(node) {
    const current = unwrap(node);
    if (ts.isBinaryExpression(current)) {
      const kindLeft = nullishLiteralKind(ts, current.left);
      const kindRight = nullishLiteralKind(ts, current.right);
      const kind = kindLeft || kindRight;
      if (kind && Boolean(kindLeft) !== Boolean(kindRight)) {
        comparisons.push({
          checked: kindLeft ? current.right : current.left,
          kind,
          notEqual: current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
            || current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken,
          strict: current.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
            || current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken,
        });
        return;
      }
      if (current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || current.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        collect(current.left);
        collect(current.right);
      }
    }
  }
  collect(condition);
  if (comparisons.length === 0) return undefined;
  const first = comparisons[0];
  if (comparisons.length === 1) {
    return {
      checked: first.checked,
      checkedText: source.slice(first.checked.getStart(), first.checked.end),
      notEqual: first.notEqual,
      strict: first.strict,
      compound: false,
      kind: first.kind,
    };
  }
  if (!ts.isBinaryExpression(unwrap(condition)) || comparisons.length !== 2) return undefined;
  const root = unwrap(condition);
  const sameSubject = comparisons.every(item => {
    const left = quickfixSymbol(checker, first.checked);
    const right = quickfixSymbol(checker, item.checked);
    return Boolean(left && right && left === right);
  });
  const sameDirection = comparisons.every(item => item.notEqual === first.notEqual);
  const expectedDirection = root.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
    ? first.notEqual
    : !first.notEqual;
  if (!sameSubject || !sameDirection || !expectedDirection) return undefined;
  return {
    checked: first.checked,
    checkedText: source.slice(first.checked.getStart(), first.checked.end),
    notEqual: first.notEqual,
    strict: comparisons.every(item => item.strict),
    compound: true,
    kind: first.kind,
  };
}

function quickfixArrayKind(ts, checker, type) {
  if (!type || !(checker.isArrayType?.(type) || checker.isTupleType?.(type))) return undefined;
  let element;
  try {
    element = checker.getIndexTypeOfType(type, ts.IndexKind.Number);
  } catch {
    return undefined;
  }
  if (!element || element.isUnion?.()) return undefined;
  if (element.flags & ts.TypeFlags.NumberLike) return 'number';
  if (element.flags & ts.TypeFlags.StringLike) return 'string';
  if (element.flags & ts.TypeFlags.BigIntLike) return 'bigint';
  return undefined;
}

function quickfixProperty(node, ts, source) {
  if (ts.isPropertyAccessExpression(node)) {
    return { object: node.expression, property: node.name, propertyText: node.name.text, propertyNode: node.name };
  }
  if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) {
    return {
      object: node.expression,
      property: node.argumentExpression,
      propertyText: node.argumentExpression.text,
      propertyNode: node.argumentExpression,
    };
  }
  return undefined;
}

function quickfixSubjectSpan(source, subject) {
  return Number.isInteger(subject?.start) && Number.isInteger(subject?.end)
    ? span(source, subject.start, subject.end)
    : span(source, subject);
}

function quickfixFact(source, ruleKey, subject, id, message, edits) {
  return {
    rule_key: ruleKey,
    subject_span: quickfixSubjectSpan(source, subject),
    actions: [{
      id,
      message,
      edits: edits.map(edit => ({
        span: span(source, edit.start, edit.end),
        replacement: edit.replacement,
      })),
    }],
  };
}
function quickfixFactWithActions(source, ruleKey, subject, actions) {
  return {
    rule_key: ruleKey,
    subject_span: quickfixSubjectSpan(source, subject),
    actions: actions.map(action => ({
      id: action.id,
      message: action.message,
      edits: action.edits.map(edit => ({
        span: span(source, edit.start, edit.end),
        replacement: edit.replacement,
      })),
    })),
  };
}
function quickfixNoAction(source, ruleKey, subject) {
  return { rule_key: ruleKey, subject_span: quickfixSubjectSpan(source, subject), actions: [] };
}

function quickfixBooleanType(ts, type) {
  return quickfixEveryTypeFlag(ts, type, ts.TypeFlags.BooleanLike);
}

function quickfixStringType(ts, type) {
  return quickfixEveryTypeFlag(ts, type, ts.TypeFlags.StringLike);
}

function quickfixHasJsx(ts, node) {
  let found = false;
  function visit(child) {
    if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child) || ts.isJsxFragment(child)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  }
  visit(node);
  return found;
}

function collectQuickfixes(ts, checker, program, sourceFile, config) {
  const source = sourceFile.text;
  const facts = [];
  const add = fact => facts.push(fact);
  const text = node => source.slice(node.getStart(sourceFile), node.end);
  const unwrap = node => {
    let current = node;
    while (ts.isParenthesizedExpression(current)) current = current.expression;
    return current;
  };
  const isLogicalConditionRoot = node => {
    let container = node.parent;
    while (container && ts.isParenthesizedExpression(container)) container = container.parent;
    return Boolean(
      (container && ts.isIfStatement(container) && container.expression === node)
        || (container && ts.isWhileStatement(container) && container.expression === node)
        || (container && ts.isDoStatement(container) && container.expression === node)
        || (container && ts.isForStatement(container) && container.condition === node)
        || (container && ts.isConditionalExpression(container) && container.condition === node),
    );
  };


  function collectS1125(node) {
    if (ts.isBinaryExpression(node)) {
      const equality = node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken
        || node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
        || node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
        || node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      const logical = node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || node.operatorToken.kind === ts.SyntaxKind.BarBarToken;
      if (equality || logical) {
        for (const [booleanNode, other] of [[node.left, node.right], [node.right, node.left]]) {
          if (logical && booleanNode === node.right && !isLogicalConditionRoot(node)) continue;
          const literal = unwrap(booleanNode);
          const isBooleanLiteral = literal.kind === ts.SyntaxKind.TrueKeyword
            || literal.kind === ts.SyntaxKind.FalseKeyword;
          if (!isBooleanLiteral) continue;
          const otherType = quickfixTypeAt(checker, other);
          const eligible = logical
            ? quickfixBooleanType(ts, otherType)
            : quickfixBooleanType(ts, otherType);
          if (equality) {
            const inequality = node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
              || node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
            const negate = (inequality && literal.kind === ts.SyntaxKind.TrueKeyword)
              || (!inequality && literal.kind === ts.SyntaxKind.FalseKeyword);
            const otherText = text(other);
            add(eligible
              ? quickfixFact(source, 'S1125', literal, 's1125-remove-boolean', 'Remove the unnecessary boolean literal', [{
                start: node.getStart(sourceFile),
                end: node.end,
                replacement: negate ? `!${otherText}` : otherText,
              }])
              : quickfixNoAction(source, 'S1125', literal));
          } else {
            const replacement = node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
              ? (literal.kind === ts.SyntaxKind.TrueKeyword ? text(other) : 'false')
              : (literal.kind === ts.SyntaxKind.TrueKeyword ? 'true' : text(other));
            add(eligible
              ? quickfixFact(source, 'S1125', literal, 's1125-remove-boolean', 'Remove the unnecessary boolean literal', [{
                start: node.getStart(sourceFile),
                end: node.end,
                replacement,
              }])
              : quickfixNoAction(source, 'S1125', literal));
          }
        }
      }
    }
    if (ts.isPrefixUnaryExpression(node)
      && node.operator === ts.SyntaxKind.ExclamationToken) {
      const literal = unwrap(node.operand);
      const isBooleanLiteral = literal.kind === ts.SyntaxKind.TrueKeyword
        || literal.kind === ts.SyntaxKind.FalseKeyword;
      if (isBooleanLiteral) {
        add(quickfixFact(source, 'S1125', literal, 's1125-remove-boolean', 'Remove the unnecessary boolean literal', [{
          start: node.getStart(sourceFile),
          end: node.end,
          replacement: literal.kind === ts.SyntaxKind.TrueKeyword ? 'false' : 'true',
        }]));
      }
    }
  }

  function collectS2871AndS4043(node) {
    if (!ts.isCallExpression(node)) return;
    const member = quickfixProperty(node.expression, ts, source);
    if (!member) return;
    const kind = quickfixArrayKind(ts, checker, quickfixTypeAt(checker, member.object));
    const s2871Subject = ts.isElementAccessExpression(node.expression)
      ? { start: node.expression.getStart(sourceFile), end: node.expression.end }
      : member.propertyNode;
    if (node.arguments.length === 0 && (member.propertyText === 'sort' || member.propertyText === 'toSorted')) {
      const action = kind === 'number'
        ? { id: 's2871-suggest-numeric-order', message: 'Add a comparator function to sort in ascending order', replacement: '(a, b) => (a - b)' }
        : kind === 'string'
          ? { id: 's2871-suggest-language-sensitive-order', message: 'Add a comparator function to sort in ascending language-sensitive order', replacement: '(a, b) => a.localeCompare(b)' }
          : kind === 'bigint'
            ? { id: 's2871-suggest-numeric-order', message: 'Add a comparator function to sort in ascending order', replacement: '(a, b) => {\n  if (a < b) {\n    return -1;\n  } else if (a > b) {\n    return 1;\n  } else {\n    return 0;\n  }\n}' }
            : undefined;
      const close = node.getLastToken(sourceFile);
      add(action && close
        ? quickfixFact(source, 'S2871', s2871Subject, action.id, action.message, [{
          start: close.getStart(sourceFile),
          end: close.getStart(sourceFile),
          replacement: action.replacement,
        }])
        : quickfixNoAction(source, 'S2871', s2871Subject));
    }
    const captured = (ts.isVariableDeclaration(node.parent)
      && node.parent.initializer === node
      && ts.isIdentifier(node.parent.name))
      || (ts.isBinaryExpression(node.parent)
        && node.parent.right === node
        && node.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken);
    if (captured && (member.propertyText === 'sort' || member.propertyText === 'reverse')) {
      const suggested = member.propertyText === 'sort' ? 'toSorted' : 'toReversed';
      const propertyText = text(member.propertyNode);
      const replacement = propertyText.startsWith('"')
        ? `"${suggested}"`
        : propertyText.startsWith("'") ? `'${suggested}'` : suggested;
      add(kind
        ? quickfixFact(source, 'S4043', node, 's4043-suggest-method', 'Replace with the non-mutating method', [{
          start: member.propertyNode.getStart(sourceFile),
          end: member.propertyNode.end,
          replacement,
        }])
        : quickfixNoAction(source, 'S4043', node));
    }
  }

  function collectS4623(node) {
    if (!ts.isCallExpression(node) || node.arguments.length === 0) return;
    const last = node.arguments[node.arguments.length - 1];
    if (!ts.isIdentifier(last) || last.text !== 'undefined') return;
    const signature = quickfixSignature(checker, node);
    const parameter = signature?.parameters?.[node.arguments.length - 1];
    let eligible = false;
    if (parameter) {
      const declaration = parameter.valueDeclaration || parameter.declarations?.[0];
      const type = quickfixSymbolType(checker, parameter, node);
      eligible = Boolean(declaration?.questionToken || declaration?.initializer
        || quickfixTypeParts(type).some(item => Boolean(item.flags & ts.TypeFlags.Undefined)));
    }
    const open = source.indexOf('(', node.expression.end);
    const close = node.end > 0 && source[node.end - 1] === ')' ? node.end - 1 : -1;
    const edits = node.arguments.length === 1 && open >= 0 && close > open
      ? [{ start: open + 1, end: close, replacement: '' }]
      : node.arguments.length > 1
        ? [{ start: node.arguments[node.arguments.length - 2].end, end: last.end, replacement: '' }]
        : undefined;
    add(eligible && edits
      ? quickfixFact(source, 'S4623', last, 's4623-remove-undefined-argument', 'Remove this redundant argument', edits)
      : quickfixNoAction(source, 'S4623', last));
  }
  function collectS4782(node) {
    if ((!ts.isPropertySignature(node) && !ts.isPropertyDeclaration(node))
      || !node.questionToken
      || !node.type) return;
    const typeNode = node.type.kind === ts.SyntaxKind.ParenthesizedType
      ? node.type.type
      : node.type;
    if (!typeNode || !ts.isUnionTypeNode(typeNode)) return;
    const undefinedIndexes = typeNode.types
      .map((item, index) => item.kind === ts.SyntaxKind.UndefinedKeyword ? index : -1)
      .filter(index => index >= 0);
    if (undefinedIndexes.length !== 1) return;
    const subject = node.questionToken;
    if (config?.options?.exactOptionalPropertyTypes === true) {
      add(quickfixNoAction(source, 'S4782', subject));
      return;
    }
    const undefinedIndex = undefinedIndexes[0];
    const undefinedNode = typeNode.types[undefinedIndex];
    const actions = [{
      id: 's4782-remove-optional-marker',
      message: 'Remove "?" operator',
      edits: [{ start: subject.getStart(sourceFile), end: subject.end, replacement: '' }],
    }];
    if (typeNode.types.length === 2) {
      const other = typeNode.types[undefinedIndex === 0 ? 1 : 0];
      const edits = [{
        start: typeNode.getStart(sourceFile),
        end: typeNode.end,
        replacement: text(other),
      }];
      if (typeNode !== node.type) {
        const open = node.type.getStart(sourceFile);
        const close = node.type.end - 1;
        if (source[open] === '(' && source[close] === ')') {
          edits.unshift({ start: open, end: open + 1, replacement: '' });
          edits.push({ start: close, end: close + 1, replacement: '' });
        }
      }
      actions.push({
        id: 's4782-remove-undefined-type',
        message: 'Remove "undefined" type annotation',
        edits,
      });
    } else if (undefinedIndex === 0) {
      const next = typeNode.types[1];
      actions.push({
        id: 's4782-remove-undefined-type',
        message: 'Remove "undefined" type annotation',
        edits: [{ start: undefinedNode.getStart(sourceFile), end: next.getStart(sourceFile), replacement: '' }],
      });
    } else {
      const previous = typeNode.types[undefinedIndex - 1];
      actions.push({
        id: 's4782-remove-undefined-type',
        message: 'Remove "undefined" type annotation',
        edits: [{ start: previous.end, end: undefinedNode.end, replacement: '' }],
      });
    }
    add(quickfixFactWithActions(source, 'S4782', subject, actions));
  }

  function isJsxConditionalChild(node) {
    if (!ts.isBinaryExpression(node)
      || node.operatorToken.kind !== ts.SyntaxKind.AmpersandAmpersandToken) return false;
    const expression = node.parent;
    if (!expression || !ts.isJsxExpression(expression) || expression.expression !== node) return false;
    const owner = expression.parent;
    return Boolean(owner
      && (ts.isJsxElement(owner) || ts.isJsxFragment(owner)));
  }

  function collectS6439(node) {
    if (!isJsxConditionalChild(node)) return;
    const right = node.right;
    if (!ts.isJsxElement(right) && !ts.isJsxSelfClosingElement(right) && !ts.isJsxFragment(right)) return;
    let left = node.left;
    while (ts.isParenthesizedExpression(left)) left = left.expression;
    const literal = left.kind === ts.SyntaxKind.NumericLiteral
      || left.kind === ts.SyntaxKind.StringLiteral
      || left.kind === ts.SyntaxKind.BigIntLiteral;
    const leftType = quickfixTypeAt(checker, left);
    const identifierNumber = ts.isIdentifier(left)
      && Boolean(leftType?.flags & ts.TypeFlags.NumberLike);
    if (!literal && !identifierNumber) return;
    const leftText = text(left);
    add(quickfixFact(source, 'S6439', left, 's6439-convert-to-boolean', 'Convert the conditional to a boolean', [{
      start: left.getStart(sourceFile),
      end: left.end,
      replacement: `!!(${leftText})`,
    }]));
  }


  function collectS6594(node) {
    if (!ts.isCallExpression(node) || node.arguments.length !== 1) return;
    const member = quickfixProperty(node.expression, ts, source);
    const argument = node.arguments[0];
    if (!member || member.propertyText !== 'match' || !ts.isRegularExpressionLiteral(argument)) return;
    const resultUsedOnlyForLength = () => {
      let parent = node.parent;
      while (parent && ts.isParenthesizedExpression(parent)) parent = parent.parent;
      if (ts.isPropertyAccessExpression(parent)
        && parent.expression === node
        && parent.name.text === 'length') return true;
      if (!ts.isVariableDeclaration(parent)
        || parent.initializer !== node
        || !ts.isIdentifier(parent.name)) return false;
      const symbol = quickfixSymbol(checker, parent.name);
      if (!symbol) return false;
      let sawReference = false;
      let onlyLength = true;
      function visitReference(candidate) {
        if (ts.isIdentifier(candidate)
          && candidate !== parent.name
          && quickfixSymbol(checker, candidate) === symbol) {
          sawReference = true;
          const owner = candidate.parent;
          if (!(ts.isPropertyAccessExpression(owner)
            && owner.expression === candidate
            && owner.name.text === 'length')) {
            onlyLength = false;
          }
        }
        ts.forEachChild(candidate, visitReference);
      }
      visitReference(sourceFile);
      return sawReference && onlyLength;
    };
    if (resultUsedOnlyForLength()) return;
    const receiverType = quickfixTypeAt(checker, member.object);
    const regexText = text(argument);
    const flags = regexText.slice(regexText.lastIndexOf('/') + 1);
    const eligible = quickfixStringType(ts, receiverType) && !flags.includes('g');
    const standardRegExp = eligible
      && quickfixDefaultLibraryValue(ts, checker, program, sourceFile, node, 'RegExp');
    const replacement = standardRegExp
      ? `RegExp(${regexText}).exec(${text(member.object)})`
      : undefined;
    add(eligible && replacement
      ? quickfixFact(source, 'S6594', member.propertyNode, 's6594-use-regexp-exec', 'Replace with "RegExp.exec()"', [{
        start: node.getStart(sourceFile),
        end: node.end,
        replacement,
      }])
      : quickfixNoAction(source, 'S6594', member.propertyNode));
  }

  function collectS4322(node) {
    if (!ts.isFunctionDeclaration(node) && !ts.isMethodDeclaration(node)) return;
    if (node.type && node.type.kind !== ts.SyntaxKind.BooleanKeyword) return;
    if (node.parameters.length !== 1 || !node.body) return;
    const parameter = node.parameters[0];
    const parameterName = parameter && ts.isIdentifier(parameter.name) ? parameter.name : undefined;
    const ordinaryParameter = Boolean(parameter
      && !parameter.dotDotDotToken
      && parameter.type
      && ts.isTypeReferenceNode(parameter.type)
      && ts.isIdentifier(parameter.type.typeName));
    if (!parameterName || !ordinaryParameter) return;
    const [statement] = ts.isBlock(node.body) && node.body.statements.length === 1 ? node.body.statements : [];
    if (!statement || !ts.isReturnStatement(statement) || !statement.expression) return;
    const unwrapExpression = expression => ts.isParenthesizedExpression(expression)
      ? unwrapExpression(expression.expression)
      : expression;
    const castFrom = expression => {
      const current = unwrapExpression(expression);
      if (ts.isAsExpression(current) || ts.isTypeAssertionExpression(current)) {
        return { expression: current.expression, type: current.type };
      }
      return undefined;
    };
    const castFromMember = expression => {
      const current = unwrapExpression(expression);
      if (!ts.isPropertyAccessExpression(current) && !ts.isElementAccessExpression(current)) return undefined;
      return castFrom(current.expression);
    };
    const condition = unwrapExpression(statement.expression);
    if (!ts.isBinaryExpression(condition)) return;
    const undefinedLeft = ts.isIdentifier(condition.left) && condition.left.text === 'undefined';
    const undefinedRight = ts.isIdentifier(condition.right) && condition.right.text === 'undefined';
    const inequality = condition.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
      || condition.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
    if (!inequality || undefinedLeft === undefinedRight) return;
    const cast = castFromMember(undefinedLeft ? condition.right : condition.left);
    if (!cast) return;
    const castType = quickfixTypeAt(checker, cast.type);
    if (!castType || (castType.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown))) return;
    const castExpression = unwrapExpression(cast.expression);
    const castBase = castExpression;
    const parameterSymbol = quickfixSymbol(checker, parameterName);
    const castSymbol = ts.isIdentifier(castBase) && quickfixSymbol(checker, castBase);
    const eligible = Boolean(parameterSymbol && castSymbol && parameterSymbol === castSymbol);
    const predicate = `: ${text(cast.expression)} is ${text(cast.type)}`;
    if (node.type) {
      const typeStart = node.type.getStart(sourceFile);
      const colon = source.lastIndexOf(':', typeStart);
      const annotationStart = colon >= 0 && /^[\s]*$/.test(source.slice(colon + 1, typeStart))
        ? colon
        : typeStart;
      const annotationSubject = { start: annotationStart, end: node.type.end };
      add(eligible
        ? quickfixFact(source, 'S4322', annotationSubject, 's4322-use-type-predicate', 'Use type predicate', [{
          start: annotationStart,
          end: node.type.end,
          replacement: predicate,
        }])
        : quickfixNoAction(source, 'S4322', annotationSubject));
    } else if (node.name) {
      const closeParen = node.getChildren(sourceFile).find(child =>
        child.kind === ts.SyntaxKind.CloseParenToken
        && child.getStart(sourceFile) >= node.parameters.end);
      add(eligible && closeParen
        ? quickfixFact(source, 'S4322', node.name, 's4322-use-type-predicate', 'Use type predicate', [{
          start: closeParen.end,
          end: closeParen.end,
          replacement: predicate,
        }])
        : quickfixNoAction(source, node.name));
    }
  }

  function collectS6759(node) {
    if (!ts.isFunctionDeclaration(node)
      || !node.name
      || !/^[A-Z]/.test(node.name.text)
      || node.parameters.length > 1
      || !node.parameters[0]?.type
      || !node.body
      || !quickfixHasJsx(ts, node.body)) return;
    const parameter = node.parameters[0];
    const type = parameter.type;
    if (ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName) && type.typeName.text === 'Readonly') return;
    const signature = quickfixDeclarationSignature(checker, node);
    const returnType = signature?.getReturnType?.();
    const parameterType = quickfixTypeAt(checker, parameter);
    const checkerEligible = Boolean(
      returnType
      && !(returnType.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown))
      && parameterType
      && !(parameterType.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)),
    );
    const oldText = text(type);
    add(checkerEligible
      ? quickfixFact(source, 'S6759', parameter, 's6759-mark-props-readonly', 'Mark the props as read-only', [{
        start: type.getStart(sourceFile),
        end: type.end,
        replacement: `Readonly<${oldText}>`,
      }])
      : quickfixNoAction(source, 'S6759', parameter));
  }

  function visit(node) {
    collectS1125(node);
    collectS2871AndS4043(node);
    collectS4623(node);
    collectS4782(node);
    collectS6439(node);
    collectS6594(node);
    collectS4322(node);
    collectS6759(node);
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return facts;
}

function collectFacts(ts, checker, program, sourceFile, config, host, root, diagnostics) {
  let quickfixes = [];
  try {
    quickfixes = collectQuickfixes(ts, checker, program, sourceFile, config);
  } catch (error) {
    diagnostics.push(diagnostic('TS_HELPER_QUICKFIX_FACTS', `Unable to collect compiler quick-fix facts: ${error.message}`, sourceFile.fileName));
  }
  const deprecated = [];
  const deprecatedSeen = new Set();
  const assertions = [];
  const nullish = [];
  const usages = [];
  const source = sourceFile.text;
  const strictNullChecks = config.options.strictNullChecks === true
    || (config.options.strict === true && config.options.strictNullChecks !== false);
  function addDeprecated(node, symbol, message) {
    const itemSpan = span(source, node);
    const key = `${itemSpan.start}:${itemSpan.end}`;
    if (deprecatedSeen.has(key)) return;
    deprecatedSeen.add(key);
    deprecated.push({ span: itemSpan, message, symbol: symbol.id, declaration_path: symbol.declaration ? canonicalPath(symbol.declaration.getSourceFile().fileName) : undefined });
  }
  const isConditionalTest = (container, expression) => {
    if (!container) return false;
    return Boolean(
      (ts.isIfStatement(container) && container.expression === expression)
        || (ts.isWhileStatement(container) && container.expression === expression)
        || (ts.isDoStatement(container) && container.expression === expression)
        || (ts.isForStatement(container) && container.condition === expression)
        || (ts.isConditionalExpression(container) && container.condition === expression),
    );
  };
  const logicalOperator = node => {
    if (!node || !ts.isBinaryExpression(node)) return undefined;
    if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return 'and';
    if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) return 'or';
    return undefined;
  };
  const mixedLogicalExpression = (node, parent) => {
    const rootOperator = logicalOperator(node);
    if (!rootOperator) return false;
    let hasAnd = rootOperator === 'and';
    let hasOr = rootOperator === 'or';
    let ancestor = parent;
    while (ancestor && logicalOperator(ancestor)) {
      if (logicalOperator(ancestor) === 'and') hasAnd = true;
      if (logicalOperator(ancestor) === 'or') hasOr = true;
      ancestor = ancestor.parent;
    }
    function visitLogicalChild(child) {
      const operator = logicalOperator(child);
      if (!operator) return;
      if (operator === 'and') hasAnd = true;
      if (operator === 'or') hasOr = true;
      ts.forEachChild(child, visitLogicalChild);
    }
    ts.forEachChild(node, visitLogicalChild);
    return hasAnd && hasOr;
  };
  const unwrapReference = node => {
    let current = node;
    while (current && ts.isParenthesizedExpression(current)) current = current.expression;
    return current;
  };
  const stableReference = node => {
    const current = unwrapReference(node);
    if (!current) return false;
    if (ts.isIdentifier(current) || current.kind === ts.SyntaxKind.ThisKeyword) return true;
    if (!ts.isPropertyAccessExpression(current) || current.questionDotToken) return false;
    const propertySymbol = quickfixSymbol(checker, current.name);
    const declarations = propertySymbol?.declarations || [];
    if (!propertySymbol || declarations.length === 0
      || declarations.some(declaration => ts.isGetAccessorDeclaration(declaration)
        || ts.isSetAccessorDeclaration(declaration))) return false;
    const receiver = unwrapReference(current.expression);
    return Boolean(receiver && (ts.isIdentifier(receiver) || receiver.kind === ts.SyntaxKind.ThisKeyword));
  };
  const bareIdentifierReference = node => {
    const current = unwrapReference(node);
    return Boolean(current && ts.isIdentifier(current));
  };
  const referenceSubject = node => {
    const current = unwrapReference(node);
    if (!current || !stableReference(current)) return undefined;
    const location = ts.isIdentifier(current)
      ? current
      : ts.isPropertyAccessExpression(current) ? current.name : undefined;
    const symbol = quickfixSymbol(checker, location);
    if (!symbol) return undefined;
    return {
      node: current,
      symbol,
      text: source.slice(current.getStart(sourceFile), current.end),
    };
  };
  const sameReference = (left, right) => {
    const first = referenceSubject(left);
    const second = referenceSubject(right);
    return Boolean(first && second && first.text === second.text && first.symbol === second.symbol);
  };
  const objectOrNullishGuard = node => {
    const type = quickfixTypeAt(checker, node);
    const info = typeInfo(ts, checker, type);
    return { info, ok: objectOrNullishTypeInfo(info, checker, type) };
  };

  function visit(node, parent, inConditionalTest = false, inMixedLogical = false) {
    if (ts.isIdentifier(node) || ts.isPrivateIdentifier?.(node)) {
      let symbol;
      try { symbol = checker.getSymbolAtLocation(node); } catch { symbol = undefined; }
      if (symbol) {
        const target = symbolKey(ts, checker, symbol);
        const deprecation = jsDocDeprecated(ts, target.symbol, target.declaration);
        const isDeclarationName = Boolean(target.declaration && target.declaration.name === node);
        // S1874's pinned implementation consumes TypeScript suggestion
        // diagnostics for import/export specifiers.  Keep the traversal's
        // symbol/usages metadata, but do not duplicate either alias half with
        // a raw JSDoc fact; all other references retain fallback coverage.
        const isImportOrExportBinding = Boolean(
          parent && (ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)),
        );
        if (deprecation && !isDeclarationName && !isImportOrExportBinding) addDeprecated(node, target, deprecation);
        usages.push({ span: span(source, node), name: node.text || node.escapedText, symbol: target.id, declaration_path: target.declaration ? canonicalPath(target.declaration.getSourceFile().fileName) : undefined });
      }
    }

    if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) {
      const sourceType = checker.getTypeAtLocation(node.expression);
      const targetType = checker.getTypeAtLocation(node);
      const sourceInfo = typeInfo(ts, checker, sourceType);
      const targetInfo = typeInfo(ts, checker, targetType);
      let equivalent = false;
      try {
        equivalent = checker.isTypeAssignableTo(sourceType, targetType) && checker.isTypeAssignableTo(targetType, sourceType);
      } catch {
        equivalent = sourceInfo.text === targetInfo.text;
      }
      const genericCall = isGenericCall(ts, checker, node.expression);
      const sourceTop = sourceType.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown);
      const targetTop = targetType.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown);
      const sameTop = sourceTop !== 0 && sourceTop === targetTop;
      const topTypeCompatible = (sourceTop === 0 && targetTop === 0) || sameTop;
      const unnecessary = equivalent && topTypeCompatible && !genericCall;
      assertions.push({
        kind: ts.isAsExpression(node) ? 'as' : 'angle',
        span: span(source, node),
        expression_span: span(source, node.expression),
        source: sourceInfo,
        target: targetInfo,
        equivalent,
        generic_call: genericCall,
        unnecessary,
        strict_null_checks: strictNullChecks,
      });
    } else if (ts.isNonNullExpression(node)) {
      const sourceType = checker.getTypeAtLocation(node.expression);
      const sourceInfo = typeInfo(ts, checker, sourceType);
      const genericCall = isGenericCall(ts, checker, node);
      const canContainNullish = sourceInfo.has_null || sourceInfo.has_undefined;
      assertions.push({
        kind: 'non-null',
        span: span(source, node),
        expression_span: span(source, node.expression),
        source: sourceInfo,
        target: sourceInfo,
        equivalent: !canContainNullish,
        generic_call: genericCall,
        unnecessary: !canContainNullish && !genericCall,
        strict_null_checks: strictNullChecks,
      });
    }

    if (ts.isBinaryExpression(node) && (node.operatorToken.kind === ts.SyntaxKind.BarBarToken || node.operatorToken.kind === ts.SyntaxKind.BarBarEqualsToken)) {
      const leftType = checker.getTypeAtLocation(node.left);
      const info = typeInfo(ts, checker, leftType);
      const hasNullish = info.has_null || info.has_undefined;
      const objectAndNullish = hasNullish && info.has_object;
      const mixedLogical = inMixedLogical || mixedLogicalExpression(node, parent);
      const currentTest = inConditionalTest || isConditionalTest(parent, node);
      const onlyNullish = hasNullish
        && !info.has_object
        && !info.has_primitive
        && !info.has_any
        && !info.has_unknown;
      const report = node.operatorToken.kind === ts.SyntaxKind.BarBarToken
        && onlyNullish
        && !currentTest
        && !mixedLogical;
      nullish.push({
        kind: node.operatorToken.kind === ts.SyntaxKind.BarBarEqualsToken ? 'logical-or-assignment' : 'logical-or',
        span: span(source, node),
        left_span: span(source, node.left),
        right_span: span(source, node.right),
        left: info,
        report,
        reason: report ? 'nullish-type' : (objectAndNullish ? 'nullable-object' : 'not-nullish-or-incomplete'),
      });
    }

    if (ts.isConditionalExpression(node)) {
      const condition = node.condition;
      const params = nullishComparisonParts(ts, checker, source, condition);
      if (params) {
        const checked = params.checked;
        const trueText = source.slice(node.whenTrue.getStart(sourceFile), node.whenTrue.end);
        const falseText = source.slice(node.whenFalse.getStart(sourceFile), node.whenFalse.end);
        const identityBranch = params.notEqual ? trueText : falseText;
        const fallbackBranch = params.notEqual ? node.whenFalse : node.whenTrue;
        const matches = identityBranch === params.checkedText;
        const info = typeInfo(ts, checker, quickfixTypeAt(checker, checked));
        const coversOppositeNullish = params.compound
          || !params.strict
          || (params.kind === 'undefined' ? !info.has_null : !info.has_undefined);
        const report = matches
          && coversOppositeNullish
          && (info.has_null || info.has_undefined)
          && !info.has_any
          && !info.has_unknown;
        if (matches) {
          nullish.push({
            kind: 'conditional',
            span: span(source, node),
            left_span: span(source, checked),
            right_span: span(source, fallbackBranch),
            left: info,
            report,
            reason: report ? 'nullish-identity-check' : 'conditional-type-not-proven',
          });
        }
      } else {
        const subject = referenceSubject(node.condition);
        if (subject && bareIdentifierReference(node.condition) && sameReference(node.condition, node.whenTrue)) {
          const guard = objectOrNullishGuard(subject.node);
          if (guard.ok) {
            nullish.push({
              kind: 'conditional',
              span: span(source, node),
              left_span: span(source, subject.node),
              right_span: span(source, node.whenFalse),
              left: guard.info,
              report: true,
              reason: 'nullish-truthiness-identity',
            });
          }
        }
      }
    }

    if (ts.isIfStatement(node) && !node.elseStatement) {
      const negation = unwrapReference(node.expression);
      if (ts.isPrefixUnaryExpression(negation)
        && negation.operator === ts.SyntaxKind.ExclamationToken) {
        const subject = referenceSubject(negation.operand);
        const body = node.thenStatement;
        const statements = ts.isBlock(body) ? body.statements : [body];
        if (subject && statements.length === 1 && ts.isExpressionStatement(statements[0])) {
          const expression = statements[0].expression;
          if (ts.isBinaryExpression(expression)
            && expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
            && sameReference(negation.operand, expression.left)) {
            const guard = objectOrNullishGuard(subject.node);
            if (guard.ok) {
              nullish.push({
                kind: 'nullish-assignment',
                span: span(source, node),
                left_span: span(source, expression.left),
                right_span: span(source, expression.right),
                left: guard.info,
                report: true,
                reason: 'nullish-truthiness-assignment',
              });
            }
          }
        }
      }
    }

    ts.forEachChild(node, child => visit(
      child,
      node,
      inConditionalTest || isConditionalTest(node, child),
      inMixedLogical || Boolean(logicalOperator(node) && logicalOperator(child) && logicalOperator(node) !== logicalOperator(child)),
    ));
  }
  visit(sourceFile, undefined);

  // TypeScript exposes deprecation findings as suggestion diagnostics.  They
  // are the authoritative range/message source used by SonarJS S1874; symbol
  // traversal above supplies alias/local-shadowing facts for projects where
  // the compiler does not surface a suggestion diagnostic.
  if (typeof checker.getSuggestionDiagnostics === 'function') {
    try {
      const suggestions = checker.getSuggestionDiagnostics(sourceFile) || [];
      for (const item of suggestions) {
        if (item.reportsDeprecated !== true || item.start === undefined) continue;
        const itemSpan = span(source, item.start, item.start + (item.length || 0));
        const message = flattenMessage(item.messageText);
        const key = `${itemSpan.start}:${itemSpan.end}`;
        if (!deprecatedSeen.has(key)) {
          deprecatedSeen.add(key);
          deprecated.push({ span: itemSpan, message, diagnostic: true });
        } else {
          const existing = deprecated.find(item => item.span.start === itemSpan.start && item.span.end === itemSpan.end);
          if (existing) {
            existing.message = message;
            existing.diagnostic = true;
          }
        }
      }
    } catch (error) {
      diagnostics.push(diagnostic('TS_HELPER_SUGGESTION_DIAGNOSTICS', `Unable to collect deprecation diagnostics: ${error.message}`, sourceFile.fileName, undefined, undefined, 'warning'));
    }
  }

  return { deprecated, assertions, nullish, usages, quickfixes };
}

function moduleKind(ts, sourceFile) {
  const file = sourceFile.fileName.toLowerCase();
  if (file.endsWith('.cjs') || file.endsWith('.cts')) return 'cjs';
  if (file.endsWith('.mjs') || file.endsWith('.mts')) return 'esm';
  if (!ts.isExternalModule(sourceFile)) return 'script';
  if (sourceFile.impliedNodeFormat === ts.ModuleKind.CommonJS) return 'cjs';
  return 'esm';
}

function analyzeFile(ts, checker, program, sourceFile, config, host, request, diagnostics) {
  const root = request.root || path.dirname(sourceFile.fileName);
  const source = sourceFile.text;
  const facts = collectFacts(ts, checker, program, sourceFile, config, host, root, diagnostics);
  const imports = collectImports(ts, checker, program, sourceFile, config, host, root);
  return {
    path: canonicalPath(sourceFile.fileName),
    source_digest: sha256(source),
    language: /\.(?:ts|tsx|mts|cts|d\.ts)$/i.test(sourceFile.fileName) ? 'typescript' : 'javascript',
    module_kind: moduleKind(ts, sourceFile),
    facts,
    imports,
  };
}

function main() {
  const request = readRequest();
  const diagnostics = [];
  if (request.schema_version !== PROTOCOL_VERSION) {
    diagnostics.push(diagnostic('TS_HELPER_PROTOCOL', `Unsupported helper protocol ${request.schema_version}; expected ${PROTOCOL_VERSION}.`));
  }
  const snapshots = makeSnapshots(request, diagnostics);
  const compiler = loadTypescript(request, diagnostics);
  if (!compiler || diagnostics.some(item => item.category === 'error')) {
    return { schema_version: PROTOCOL_VERSION, complete: false, compiler_version: compiler?.version, files: [], dependencies: [], diagnostics, fingerprint: requestFingerprint(request, diagnostics) };
  }
  const { ts, version } = compiler;
  const config = readConfig(ts, request, snapshots, diagnostics);
  if (!config) {
    return { schema_version: PROTOCOL_VERSION, complete: false, compiler_version: version, files: [], dependencies: [], diagnostics, fingerprint: requestFingerprint(request, diagnostics) };
  }
  const host = makeHost(ts, config, snapshots, diagnostics);
  const rootNames = [...new Set([...config.fileNames, ...snapshots.keys()])];
  const projectReferences = (config.projectReferences || []).filter(reference => {
    let referenceConfig;
    try {
      referenceConfig = canonicalPath(ts.resolveProjectReferencePath(reference));
    } catch {
      return true;
    }
    const referenceRoot = path.dirname(referenceConfig);
    return ![...snapshots.keys()].some(file => (
      file === referenceConfig || file.startsWith(`${referenceRoot}${path.sep}`)
    ));
  });
  let program;
  try {
    program = ts.createProgram({
      rootNames,
      options: config.options,
      projectReferences: projectReferences.length > 0 ? projectReferences : undefined,
      host,
    });
  } catch (error) {
    diagnostics.push(diagnostic('TS_HELPER_PROGRAM', `Unable to create TypeScript program: ${error.message}`));
    return { schema_version: PROTOCOL_VERSION, complete: false, compiler_version: version, files: [], dependencies: [], diagnostics, fingerprint: requestFingerprint(request, diagnostics) };
  }
  const checker = program.getTypeChecker();
  const requested = [...snapshots.keys()].sort();
  const files = [];
  for (const file of requested) {
    const sourceFile = program.getSourceFile(file) || program.getSourceFile(path.normalize(file));
    if (!sourceFile) {
      diagnostics.push(diagnostic('TS_HELPER_MISSING_SOURCE', `TypeScript did not create a source file for ${file}.`, file));
      continue;
    }
    files.push(analyzeFile(ts, checker, program, sourceFile, config, host, request, diagnostics));
  }
  const dependencies = [];
  const manifests = new Map();
  for (const file of files) {
    for (const item of nearestPackageInfo(file.path, request.root)) {
      manifests.set(item.path, {
        path: item.path,
        digest: item.digest,
        kind: 'package-manifest',
      });
    }
    for (const importFact of file.imports) {
      for (const item of importFact.manifests || []) {
        manifests.set(item.path, {
          ...item,
          kind: item.kind || 'package-manifest',
        });
      }
      if (importFact.resolved_path) {
        for (const item of nearestPackageInfo(importFact.resolved_path, request.root)) {
          manifests.set(item.path, {
            path: item.path,
            digest: item.digest,
            kind: 'package-manifest',
          });
        }
      }
    }
  }
  for (const item of manifests.values()) dependencies.push(item);
  for (const file of files) {
    for (const importFact of file.imports) {
      if (!importFact.resolved_path) continue;
      try {
        const text = fs.readFileSync(importFact.resolved_path, 'utf8');
        dependencies.push({ path: canonicalPath(importFact.resolved_path), digest: sha256(text), kind: 'resolved-module' });
      } catch { /* unresolved/generated modules remain explicit import facts */ }
    }
  }
  for (const sourceFile of program.getSourceFiles()) {
    if (sourceFile.isDeclarationFile && sourceFile.hasNoDefaultLib && sourceFile.fileName.includes(`${path.sep}node_modules${path.sep}`)) continue;
    if (program.isSourceFileDefaultLibrary?.(sourceFile)) continue;
    dependencies.push({ path: canonicalPath(sourceFile.fileName), digest: sha256(sourceFile.text), kind: 'program-source' });
  }
  for (const file of config.fileNames) {
    try {
      const text = fs.readFileSync(file, 'utf8');
      dependencies.push({ path: canonicalPath(file), digest: sha256(text), kind: 'source' });
    } catch { /* source snapshots are already represented by files */ }
  }
  for (const item of config.configFiles || []) dependencies.push({ ...item, kind: item.kind || 'tsconfig' });
  const uniqueDependencies = [...new Map(dependencies.map(item => [`${item.kind || 'manifest'}:${item.path}`, item])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || String(a.kind || '').localeCompare(String(b.kind || '')));
  const complete = diagnostics.every(item => item.category !== 'error') && files.length === requested.length;
  const fingerprint = stableDigest({
    protocol: PROTOCOL_VERSION,
    compiler: { version, resolved: compiler.resolved },
    options: config.options,
    helper_digest: request.helper_digest,
    dependency_whitelist: [...(request.dependency_whitelist || [])].sort(),
    config_files: config.configFiles,
    dependencies: uniqueDependencies,
    files: files.map(file => ({ path: file.path, source_digest: file.source_digest })),
  });
  return { schema_version: PROTOCOL_VERSION, complete, compiler_version: version, compiler_path: compiler.resolved, options: config.options, files, dependencies: uniqueDependencies, diagnostics, fingerprint };
}

try {
  process.stdout.write(JSON.stringify(main()));
} catch (error) {
  process.stdout.write(JSON.stringify({ schema_version: PROTOCOL_VERSION, complete: false, files: [], dependencies: [], diagnostics: [diagnostic('TS_HELPER_FATAL', error && error.stack ? error.stack : String(error))], fingerprint: stableDigest({ fatal: String(error) }) }));
  process.exitCode = 0;
}
