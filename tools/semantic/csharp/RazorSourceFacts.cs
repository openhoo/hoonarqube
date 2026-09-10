using System.Collections;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

internal static class RazorSourceFactsAdapter
{
    private const int MaxReflectionNodes = 2_000_000;
    private static string? loadedIdentity;
    private static Assembly? razorAssembly;
    private static object? componentDirectives;

    internal sealed class AnalysisResult
    {
        public bool Success { get; init; }
        public string Code { get; init; } = "razor_parser_unavailable";
        public string Message { get; init; } = "The SDK Razor parser could not be loaded.";
        public MetricsData Metrics { get; init; } = new();
        public List<int> CodeLineNumbers { get; init; } = new();
    }

    internal sealed class MetricsData
    {
        public int Lines { get; init; }
        public int CodeLines { get; init; }
        public int CommentLines { get; init; }
    }

    internal static AnalysisResult Analyze(
        string path,
        string source,
        CSharpParseOptions? csharpParseOptions = null,
        string? requestedSdkPath = null)
    {
        try
        {
            var sdkPath = ResolveSdkPath(requestedSdkPath);
            if (sdkPath is null)
            {
                return Failure("razor_sdk_missing", "The SDK containing Microsoft.CodeAnalysis.Razor.Compiler.dll is unavailable.");
            }
            var assemblyPath = Path.Combine(
                sdkPath,
                "Sdks",
                "Microsoft.NET.Sdk.Razor",
                "source-generators",
                "Microsoft.CodeAnalysis.Razor.Compiler.dll");
            if (!File.Exists(assemblyPath))
            {
                return Failure("razor_parser_unavailable", "The installed SDK has no version-bound Razor compiler assembly.");
            }
            var assembly = LoadRazorAssembly(assemblyPath);
            var identity = $"{assembly.FullName}|{FileVersion(assemblyPath)}|{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath)))}";
            if (loadedIdentity is not null && !string.Equals(loadedIdentity, identity, StringComparison.Ordinal))
            {
                return Failure("razor_api_mismatch", "The Razor compiler assembly identity changed during one helper invocation.");
            }
            loadedIdentity = identity;
            razorAssembly = assembly;

            var sourceDocumentType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorSourceDocument");
            var propertiesType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorSourceDocumentProperties");
            var parserOptionsType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorParserOptions");
            var languageVersionType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorLanguageVersion");
            var fileKindType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorFileKind");
            var syntaxTreeType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorSyntaxTree");
            var classifiedVisitorType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.Legacy.ClassifiedSpanVisitor");
            var sourcePropertiesCreate = RequiredMethod(
                propertiesType,
                "Create",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static,
                typeof(string),
                typeof(string));
            var sourceDocumentCreate = RequiredMethod(
                sourceDocumentType,
                "Create",
                BindingFlags.Public | BindingFlags.Static,
                typeof(SourceText),
                propertiesType);
            var sourceProperties = sourcePropertiesCreate.Invoke(null, new object[] { path, path });
            var sourceText = SourceText.From(source, Encoding.UTF8);
            var sourceDocument = sourceDocumentCreate.Invoke(null, new[] { sourceText, sourceProperties! });

            var latestValue = languageVersionType.GetProperty("Latest", BindingFlags.Public | BindingFlags.Static)?.GetValue(null)
                ?? languageVersionType.GetField("Latest", BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
            var componentMember = fileKindType.GetField("Component", BindingFlags.Public | BindingFlags.Static)?.GetValue(null)
                ?? fileKindType.GetProperty("Component", BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
            if (componentMember is null)
            {
                return Failure("razor_api_mismatch", "RazorFileKind.Component is unavailable.");
            }
            var directiveType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.DirectiveDescriptor");
            if (componentDirectives is null)
            {
                componentDirectives = CreateComponentDirectives(assembly, fileKindType, componentMember, directiveType);
            }
            var directives = componentDirectives;
            if (directives is null)
            {
                return Failure("razor_api_mismatch", "The SDK component directive set could not be obtained.");
            }
            var parserCreate = parserOptionsType
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(method => method.Name == "Create")
                .FirstOrDefault(method =>
                {
                    var parameters = method.GetParameters();
                    return parameters.Length == 3
                        && parameters[0].ParameterType == languageVersionType
                        && (parameters[1].ParameterType == fileKindType
                            || (parameters[1].ParameterType == typeof(string) && componentMember is string))
                        && parameters[2].ParameterType.IsGenericType
                        && parameters[2].ParameterType.GetGenericTypeDefinition() == typeof(Action<>);
                });
            if (latestValue is null || !languageVersionType.IsInstanceOfType(latestValue) || parserCreate is null)
            {
                return Failure("razor_api_mismatch", "RazorParserOptions.Create or RazorLanguageVersion.Latest has an incompatible signature.");
            }
            var builderType = parserCreate.GetParameters()[2].ParameterType.GetGenericArguments()[0];
            var actionType = parserCreate.GetParameters()[2].ParameterType;
            var builderParameter = Expression.Parameter(builderType, "builder");
            var configure = typeof(RazorSourceFactsAdapter).GetMethod(
                nameof(ConfigureParserOptions),
                BindingFlags.NonPublic | BindingFlags.Static);
            if (configure is null)
            {
                return Failure("razor_api_mismatch", "The Razor parser option adapter is unavailable.");
            }
            var body = Expression.Call(
                configure,
                Expression.Convert(builderParameter, typeof(object)),
                Expression.Constant(csharpParseOptions ?? new CSharpParseOptions(LanguageVersion.LatestMajor), typeof(CSharpParseOptions)),
                Expression.Constant(directives, typeof(object)));
            var configureDelegate = Expression.Lambda(actionType, body, builderParameter).Compile();
            var parserFileKind = parserCreate.GetParameters()[1].ParameterType == fileKindType
                ? componentMember
                : componentMember as string;
            if (parserFileKind is null)
            {
                return Failure("razor_api_mismatch", "RazorFileKind.Component has an incompatible value.");
            }
            var parserOptions = parserCreate.Invoke(null, new[] { latestValue, parserFileKind, configureDelegate });
            var parse = syntaxTreeType
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .FirstOrDefault(method =>
                {
                    if (method.Name != "Parse")
                    {
                        return false;
                    }
                    var parameters = method.GetParameters();
                    return parameters.Length == 2
                        && parameters[0].ParameterType == sourceDocumentType
                        && parameters[1].ParameterType == parserOptionsType;
                });
            var diagnosticsProperty = syntaxTreeType.GetProperty("Diagnostics", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            var rootProperty = syntaxTreeType.GetProperty("Root", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (parse is null || diagnosticsProperty is null || rootProperty is null)
            {
                return Failure("razor_api_mismatch", "RazorSyntaxTree.Parse, Diagnostics, or Root has an incompatible signature.");
            }
            var syntaxTree = parse.Invoke(null, new[] { sourceDocument!, parserOptions! });
            if (syntaxTree is null)
            {
                return Failure("razor_parser_failed", "RazorSyntaxTree.Parse returned no syntax tree.");
            }
            var diagnosticValue = diagnosticsProperty.GetValue(syntaxTree);
            if (diagnosticValue is not IEnumerable diagnostics)
            {
                return Failure("razor_api_mismatch", "RazorSyntaxTree.Diagnostics returned an incompatible value.");
            }
            var diagnosticList = diagnostics.Cast<object>().ToList();
            if (diagnosticList.Count > 0)
            {
                return Failure("razor_parser_diagnostic", DescribeDiagnostics(diagnosticList));
            }
            var root = rootProperty.GetValue(syntaxTree);
            if (root is null)
            {
                return Failure("razor_api_mismatch", "RazorSyntaxTree.Root returned no root node.");
            }
            var visitRoot = RequiredMethod(
                classifiedVisitorType,
                "VisitRoot",
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static,
                syntaxTreeType);
            if (visitRoot.ReturnType == typeof(void))
            {
                return Failure("razor_api_mismatch", "ClassifiedSpanVisitor.VisitRoot must return classified spans.");
            }
            var classified = visitRoot.Invoke(null, new[] { syntaxTree });
            if (classified is not IEnumerable classifiedSpans)
            {
                return Failure("razor_api_mismatch", "ClassifiedSpanVisitor.VisitRoot did not return an enumerable span set.");
            }
            var candidates = new List<Interval>();
            var comments = new List<Interval>();
            var classifiedMask = new bool[source.Length];
            foreach (var classifiedSpan in classifiedSpans.Cast<object>())
            {
                var span = ReadSpan(classifiedSpan, "Span");
                var blockSpan = ReadSpan(classifiedSpan, "BlockSpan");
                var spanKind = ReadName(classifiedSpan, "SpanKind");
                var blockKind = ReadName(classifiedSpan, "BlockKind");
                if (span is null)
                {
                    return Failure("razor_api_mismatch", "A classified Razor span had no valid Span member.");
                }
                Mark(classifiedMask, span.Value, source.Length);
                if (spanKind is "Code" or "Markup" or "Transition" or "MetaCode")
                {
                    candidates.Add(span.Value);
                }
                if (spanKind is "Comment" || blockKind is "Comment" or "HtmlComment")
                {
                    var comment = (blockSpan ?? span).Value;
                    comments.Add(comment);
                    Mark(classifiedMask, comment, source.Length);
                }
            }
            var commentTokens = ReadCSharpCommentTokens(root);
            comments.AddRange(commentTokens);
            if (!classifiedMask.Any(value => value) && source.Any(character => !char.IsWhiteSpace(character)))
            {
                return Failure("razor_classification_missing", "The SDK Razor parser returned no classified spans for non-empty source.");
            }
            var codeMask = new bool[source.Length];
            var commentMask = new bool[source.Length];
            foreach (var interval in candidates)
            {
                Mark(codeMask, interval, source.Length);
            }
            foreach (var interval in comments)
            {
                Mark(commentMask, interval, source.Length);
                Clear(codeMask, interval, source.Length);
                Mark(classifiedMask, interval, source.Length);
            }
            for (var index = 0; index < source.Length; index++)
            {
                if (!char.IsWhiteSpace(source[index]) && !classifiedMask[index] && !commentMask[index])
                {
                    return Failure("razor_classification_incomplete", "The SDK Razor parser left non-whitespace source outside classified spans.");
                }
            }
            var codeLines = new List<int>();
            var commentLines = 0;
            var lines = PhysicalLineCount(source);
            for (var lineIndex = 0; lineIndex < lines; lineIndex++)
            {
                var line = sourceText.Lines[lineIndex];
                var code = false;
                var comment = false;
                for (var index = line.Start; index < line.End; index++)
                {
                    if (codeMask[index] && !char.IsWhiteSpace(source[index]))
                    {
                        code = true;
                    }
                    if (commentMask[index] && !char.IsWhiteSpace(source[index]))
                    {
                        comment = true;
                    }
                }
                if (code)
                {
                    codeLines.Add(lineIndex + 1);
                }
                else if (comment)
                {
                    commentLines++;
                }
            }
            return new AnalysisResult
            {
                Success = true,
                Code = "",
                Message = "",
                Metrics = new MetricsData
                {
                    Lines = lines,
                    CodeLines = codeLines.Count,
                    CommentLines = commentLines,
                },
                CodeLineNumbers = codeLines,
            };
        }
        catch (RazorApiMismatchException exception)
        {
            return Failure("razor_api_mismatch", exception.Message);
        }
        catch (TargetInvocationException exception)
        {
            return Failure("razor_parser_failed", exception.InnerException?.Message ?? exception.Message);
        }
        catch (Exception exception)
        {
            return Failure("razor_parser_unavailable", exception.Message);
        }
    }

    private static void ConfigureParserOptions(object builder, CSharpParseOptions parseOptions, object directives)
    {
        var builderType = builder.GetType();
        var useRoslyn = builderType.GetProperty("UseRoslynTokenizer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        var csharpOptions = builderType.GetProperty("CSharpParseOptions", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        var directivesProperty = builderType.GetProperty("Directives", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (useRoslyn is null || csharpOptions is null || directivesProperty is null
            || !useRoslyn.CanWrite || !csharpOptions.CanWrite || !directivesProperty.CanWrite
            || !directivesProperty.PropertyType.IsInstanceOfType(directives))
        {
            throw new RazorApiMismatchException("RazorParserOptions.Builder lacks the required tokenizer, CSharpParseOptions, or directives properties.");
        }
        useRoslyn.SetValue(builder, true);
        csharpOptions.SetValue(builder, parseOptions);
        directivesProperty.SetValue(builder, directives);
    }

    private static object CreateComponentDirectives(
        Assembly assembly,
        Type fileKindType,
        object componentMember,
        Type directiveType)
    {
        var projectEngineType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorProjectEngine");
        var configurationType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorConfiguration");
        var fileSystemType = RequiredType(assembly, "Microsoft.AspNetCore.Razor.Language.RazorProjectFileSystem");
        var configuration = ReadStaticValue(configurationType, "Default");
        var fileSystem = ReadStaticValue(fileSystemType, "Empty");
        if (configuration is null || fileSystem is null)
        {
            throw new RazorApiMismatchException("The SDK Razor project engine has no default configuration or empty file system.");
        }

        var createEngine = projectEngineType
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .FirstOrDefault(method =>
            {
                if (method.Name != "Create")
                {
                    return false;
                }
                var parameters = method.GetParameters();
                return parameters.Length == 2
                    && parameters[0].ParameterType == configurationType
                    && parameters[1].ParameterType == fileSystemType;
            });
        if (createEngine is null)
        {
            throw new RazorApiMismatchException("RazorProjectEngine.Create has no default configuration/file-system overload.");
        }
        var projectEngine = createEngine.Invoke(null, new[] { configuration, fileSystem });
        if (projectEngine is null)
        {
            throw new RazorApiMismatchException("RazorProjectEngine.Create returned no project engine.");
        }

        var engineProperty = projectEngineType.GetProperty(
            "Engine",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        var engine = engineProperty?.GetValue(projectEngine);
        var featuresProperty = engine?.GetType().GetProperty(
            "Features",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (featuresProperty?.GetValue(engine) is not IEnumerable features)
        {
            throw new RazorApiMismatchException("RazorProjectEngine.Engine.Features returned no feature sequence.");
        }
        var directivesFeature = features
            .Cast<object>()
            .FirstOrDefault(feature =>
                string.Equals(
                    feature.GetType().FullName,
                    "Microsoft.AspNetCore.Razor.Language.ConfigureDirectivesFeature",
                    StringComparison.Ordinal))
            ?? features
                .Cast<object>()
                .FirstOrDefault(feature => feature.GetType()
                    .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                    .Any(method => method.Name == "GetDirectives" && method.GetParameters().Length == 1));
        if (directivesFeature is null)
        {
            throw new RazorApiMismatchException("The SDK Razor project engine has no ConfigureDirectivesFeature.");
        }

        var getDirectives = directivesFeature.GetType()
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .FirstOrDefault(method =>
            {
                if (method.Name != "GetDirectives")
                {
                    return false;
                }
                var parameters = method.GetParameters();
                return parameters.Length == 1
                    && parameters[0].ParameterType.IsGenericType
                    && parameters[0].ParameterType.GetGenericTypeDefinition() == typeof(Nullable<>)
                    && parameters[0].ParameterType.GetGenericArguments()[0] == fileKindType;
            });
        if (getDirectives is null)
        {
            throw new RazorApiMismatchException("ConfigureDirectivesFeature.GetDirectives has no RazorFileKind overload.");
        }
        var directivesValue = getDirectives.Invoke(directivesFeature, new[] { componentMember });
        if (directivesValue is not IEnumerable directives)
        {
            throw new RazorApiMismatchException("ConfigureDirectivesFeature.GetDirectives returned no directive sequence.");
        }

        var descriptorValues = directives.Cast<object>().ToList();
        if (descriptorValues.Count == 0 || descriptorValues.Any(value => !directiveType.IsInstanceOfType(value)))
        {
            throw new RazorApiMismatchException("ConfigureDirectivesFeature returned an incompatible component directive set.");
        }
        var names = descriptorValues
            .Select(value => ReadName(value, "Directive"))
            .ToHashSet(StringComparer.Ordinal);
        foreach (var required in new[]
        {
            "code",
            "page",
            "inject",
            "attribute",
            "layout",
            "implements",
            "namespace",
            "typeparam",
            "rendermode",
        })
        {
            if (!names.Contains(required))
            {
                throw new RazorApiMismatchException($"The SDK component directive set does not contain @{required}.");
            }
        }

        // @using is a C# keyword handled by CSharpCodeParser's default keyword map,
        // not by ConfigureDirectivesFeature. It is intentionally absent from this
        // descriptor set so the built-in ParseUsingKeyword path remains authoritative.
        return directivesValue;
    }

    private static object? ReadStaticValue(Type type, string name)
    {
        var property = type.GetProperty(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
        if (property?.GetMethod is not null)
        {
            return property.GetValue(null);
        }
        return type.GetField(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)?.GetValue(null);
    }

    private static string DescribeDiagnostics(IReadOnlyList<object> diagnostics)
    {
        var descriptions = new List<string>(diagnostics.Count);
        foreach (var diagnostic in diagnostics)
        {
            var id = ReadName(diagnostic, "Id");
            var severity = ReadName(diagnostic, "Severity");
            var messageMethod = diagnostic.GetType()
                .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .FirstOrDefault(method => method.Name == "GetMessage" && method.GetParameters().Length == 0);
            if (messageMethod is null)
            {
                throw new RazorApiMismatchException("RazorDiagnostic.GetMessage has no parameterless overload.");
            }
            var message = messageMethod.Invoke(diagnostic, null)?.ToString() ?? "";
            descriptions.Add($"{id} [{severity}] {message} (span: {DescribeDiagnosticSpan(diagnostic)})");
        }
        return $"The SDK Razor parser reported {descriptions.Count} diagnostic(s): {string.Join("; ", descriptions)}";
    }

    private static string DescribeDiagnosticSpan(object diagnostic)
    {
        var spanProperty = diagnostic.GetType().GetProperty(
            "Span",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (spanProperty is null)
        {
            throw new RazorApiMismatchException("RazorDiagnostic.Span is unavailable.");
        }
        var span = spanProperty.GetValue(diagnostic);
        if (span is null)
        {
            return "<none>";
        }
        var spanType = span.GetType();
        var path = spanType.GetProperty("FilePath", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?.GetValue(span)?.ToString() ?? "<unknown>";
        var absoluteIndex = spanType.GetProperty("AbsoluteIndex", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?.GetValue(span)?.ToString() ?? "?";
        var lineIndex = spanType.GetProperty("LineIndex", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?.GetValue(span)?.ToString() ?? "?";
        var characterIndex = spanType.GetProperty("CharacterIndex", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?.GetValue(span)?.ToString() ?? "?";
        var length = spanType.GetProperty("Length", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?.GetValue(span)?.ToString() ?? "?";
        return $"{path} index={absoluteIndex}, length={length}, line={lineIndex}, character={characterIndex}";
    }

    private static List<Interval> ReadCSharpCommentTokens(object root)
    {
        var result = new List<Interval>();
        var children = RequiredParameterlessMethod(root.GetType(), "ChildNodesAndTokens");
        if (children.Invoke(root, null) is not IEnumerable rootValues)
        {
            throw new InvalidOperationException("Razor syntax root returned no child sequence.");
        }
        var stack = new Stack<object>(rootValues.Cast<object>());
        var visited = 0;
        while (stack.Count > 0)
        {
            if (++visited > MaxReflectionNodes)
            {
                throw new InvalidOperationException("Razor syntax tree exceeded the bounded reflection traversal limit.");
            }
            var value = stack.Pop();
            var valueType = value.GetType();
            var isToken = valueType.GetProperty("IsToken", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                ?? throw new InvalidOperationException("Razor syntax node lacks IsToken.");
            if ((bool)isToken.GetValue(value)!)
            {
                var token = RequiredParameterlessMethod(valueType, "AsToken").Invoke(value, null)
                    ?? throw new InvalidOperationException("Razor syntax node lacks AsToken.");
                if (string.Equals(ReadName(token, "Kind"), "CSharpComment", StringComparison.Ordinal))
                {
                    var span = ReadSpan(token, "Span") ?? throw new InvalidOperationException("Razor comment token lacks Span.");
                    result.Add(span);
                }
                continue;
            }
            var node = RequiredParameterlessMethod(valueType, "AsNode").Invoke(value, null)
                ?? throw new InvalidOperationException("Razor syntax node lacks AsNode.");
            var nodeChildren = RequiredParameterlessMethod(node.GetType(), "ChildNodesAndTokens");
            if (nodeChildren.Invoke(node, null) is not IEnumerable nodeValues)
            {
                throw new InvalidOperationException("Razor syntax node returned no child sequence.");
            }
            foreach (var child in nodeValues.Cast<object>())
            {
                stack.Push(child);
            }
        }
        return result;
    }

    private static string ReadName(object value, string propertyName)
    {
        var property = value.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Razor syntax member {propertyName} is unavailable.");
        return property.GetValue(value)?.ToString() ?? "";
    }

    private static Interval? ReadSpan(object value, string propertyName)
    {
        var property = value.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Razor syntax member {propertyName} is unavailable.");
        var span = property.GetValue(value);
        if (span is null)
        {
            return null;
        }
        var spanType = span.GetType();
        var startValue = spanType.GetProperty("AbsoluteIndex", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(span)
            ?? spanType.GetProperty("Start", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(span);
        var length = spanType.GetProperty("Length", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(span);
        if (startValue is not int start || length is not int count || start < 0 || count < 0)
        {
            throw new InvalidOperationException("Razor span has an incompatible index/length shape.");
        }
        return new Interval(start, count);
    }

    private static void Mark(bool[] mask, Interval interval, int length)
    {
        var start = Math.Clamp(interval.Start, 0, length);
        var end = Math.Clamp(interval.Start + interval.Length, start, length);
        for (var index = start; index < end; index++)
        {
            mask[index] = true;
        }
    }

    private static void Clear(bool[] mask, Interval interval, int length)
    {
        var start = Math.Clamp(interval.Start, 0, length);
        var end = Math.Clamp(interval.Start + interval.Length, start, length);
        for (var index = start; index < end; index++)
        {
            mask[index] = false;
        }
    }

    private static Type RequiredType(Assembly assembly, string name) =>
        assembly.GetType(name, throwOnError: false, ignoreCase: false)
        ?? throw new InvalidOperationException($"Required Razor type {name} is unavailable.");

    private static MethodInfo RequiredMethod(Type type, string name, BindingFlags flags, params Type[] parameterTypes) =>
        type.GetMethod(name, flags, binder: null, parameterTypes, modifiers: null)
        ?? throw new InvalidOperationException($"Required Razor method {type.FullName}.{name} is unavailable.");
    private static MethodInfo RequiredParameterlessMethod(Type type, string name)
    {
        var methods = type
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(method => method.Name == name && !method.IsGenericMethod && method.GetParameters().Length == 0)
            .ToArray();
        return methods.Length == 1
            ? methods[0]
            : throw new InvalidOperationException($"Required Razor method {type.FullName}.{name} has {methods.Length} non-generic parameterless overloads.");
    }

    private static Assembly LoadRazorAssembly(string path)
    {
        if (razorAssembly is not null && string.Equals(razorAssembly.Location, path, StringComparison.OrdinalIgnoreCase))
        {
            return razorAssembly;
        }
        return AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
    }

    private static string FileVersion(string path) =>
        FileVersionInfo.GetVersionInfo(path).FileVersion
        ?? AssemblyName.GetAssemblyName(path).Version?.ToString()
        ?? "unknown";

    private static string? ResolveSdkPath(string? requestedSdkPath)
    {
        static bool HasRazorCompiler(string path) =>
            File.Exists(Path.Combine(
                path,
                "Sdks",
                "Microsoft.NET.Sdk.Razor",
                "source-generators",
                "Microsoft.CodeAnalysis.Razor.Compiler.dll"));

        if (!string.IsNullOrWhiteSpace(requestedSdkPath))
        {
            return HasRazorCompiler(requestedSdkPath) ? Path.GetFullPath(requestedSdkPath) : null;
        }
        var configured = Environment.GetEnvironmentVariable("HOONARQUBE_DOTNET_SDK");
        if (!string.IsNullOrWhiteSpace(configured) && Directory.Exists(configured) && HasRazorCompiler(configured))
        {
            return Path.GetFullPath(configured);
        }
        foreach (var root in new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Environment.GetEnvironmentVariable("DOTNET_ROOT_X64"),
            "/usr/share/dotnet",
            "/usr/local/share/dotnet",
        }.Where(root => !string.IsNullOrWhiteSpace(root)))
        {
            if (!Directory.Exists(Path.Combine(root!, "sdk")))
            {
                continue;
            }
            var sdk = Directory.GetDirectories(Path.Combine(root!, "sdk"))
                .OrderByDescending(path => path, StringComparer.Ordinal)
                .FirstOrDefault(HasRazorCompiler);
            if (sdk is not null)
            {
                return sdk;
            }
        }
        return null;
    }

    private static int PhysicalLineCount(string source)
    {
        if (source.Length == 0)
        {
            return 0;
        }
        var terminators = 0;
        var bytes = Encoding.UTF8.GetBytes(source);
        for (var index = 0; index < bytes.Length; index++)
        {
            if (bytes[index] == (byte)'\n')
            {
                terminators++;
            }
            else if (bytes[index] == (byte)'\r' && (index + 1 == bytes.Length || bytes[index + 1] != (byte)'\n'))
            {
                terminators++;
            }
        }
        return source.EndsWith('\n') || source.EndsWith('\r') ? terminators : terminators + 1;
    }

    private static AnalysisResult Failure(string code, string message) => new() { Code = code, Message = message };

    private sealed class RazorApiMismatchException : InvalidOperationException
    {
        public RazorApiMismatchException(string message)
            : base(message)
        {
        }
    }

    private readonly record struct Interval(int Start, int Length);
}
