using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.Text;

internal static class Program
{
    private const int SchemaVersion = 2;
    private const string HelperVersion = "hoonarqube-csharp-roslyn-v1";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
        WriteIndented = false,
    };

    public static async Task<int> Main()
    {
        var input = await Console.In.ReadToEndAsync();
        HelperResponse response;
        try
        {
            var request = JsonSerializer.Deserialize<HelperRequest>(input, JsonOptions);
            response = request is null
                ? Incomplete(Diagnostic("request_invalid", "The compiler helper request was empty or invalid.", null))
                : await Analyze(request);
        }
        catch (Exception exception)
        {
            response = Incomplete(Diagnostic("helper_exception", exception.Message, null));
        }

        await Console.Out.WriteAsync(JsonSerializer.Serialize(response, JsonOptions));
        return response.Status == SemanticStatus.Complete ? 0 : 2;
    }

    private static async Task<HelperResponse> Analyze(HelperRequest request)
    {
        if (request.SchemaVersion != SchemaVersion)
        {
            return Incomplete(Diagnostic("schema_unsupported", $"Unsupported semantic schema {request.SchemaVersion}.", null));
        }

        var diagnostics = ValidateRequest(request);
        if (diagnostics.Count > 0)
        {
            return Incomplete(diagnostics);
        }
        var sourceManifest = CanonicalManifest(request.Sources);
        if (!string.Equals(sourceManifest, request.ProjectManifestDigest, StringComparison.Ordinal))
        {
            return Incomplete(Diagnostic("project_manifest_mismatch", "The helper computed a different complete source manifest.", request.Project));
        }
        if (!request.TrustedEvaluation)
        {
            return Incomplete(Diagnostic("evaluation_not_trusted", "Trusted MSBuild project evaluation is required.", request.Project));
        }
        if (!File.Exists(request.Project))
        {
            return Incomplete(Diagnostic("project_missing", "The configured project or solution does not exist.", request.Project));
        }

        if (request.IncludeRazorGenerated && !request.TrustedBuild)
        {
            return Incomplete(Diagnostic("build_not_trusted", "Generated Razor analysis requires explicit trusted build permission.", request.Project));
        }
        return await RunWorkspaceAnalysis(request);
    }

    private static async Task<HelperResponse> RunWorkspaceAnalysis(HelperRequest request)
    {
        var sdkPath = ResolveSdkPath();
        if (sdkPath is null)
        {
            return Incomplete(Diagnostic("sdk_missing", "No installed SDK with coherent Roslyn/MSBuild workspace assemblies was found.", request.Project));
        }
        ConfigureAssemblyResolution(sdkPath);
        return await RunRegisteredWorkspace(request, sdkPath);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<HelperResponse> RunRegisteredWorkspace(HelperRequest request, string sdkPath)
    {
        try
        {
            MSBuildLocator.RegisterMSBuildPath(sdkPath);
        }
        catch (Exception exception)
        {
            return Incomplete(Diagnostic("msbuild_registration_failed", exception.Message, sdkPath));
        }

        using var workspace = MSBuildWorkspace.Create();
        var workspaceDiagnostics = new List<SemanticDiagnostic>();
        RegisterWorkspaceFailedHandler(workspace, workspaceDiagnostics);
        Solution solution;
        try
        {
            solution = (request.Project.EndsWith(".sln", StringComparison.OrdinalIgnoreCase)
                || request.Project.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase))
                ? await workspace.OpenSolutionAsync(request.Project)
                : (await workspace.OpenProjectAsync(request.Project)).Solution;
        }
        catch (Exception exception)
        {
            return Incomplete(Diagnostic("workspace_open_failed", exception.Message, request.Project));
        }
        if (workspaceDiagnostics.Count > 0)
        {
            return Incomplete(workspaceDiagnostics);
        }

        var projects = solution.Projects
            .Where(project => project.Language == LanguageNames.CSharp)
            .OrderBy(project => NormalizePath(project.FilePath ?? project.Name), StringComparer.Ordinal)
            .ToList();
        if (projects.Count == 0)
        {
            return Incomplete(Diagnostic("project_missing", "The workspace loaded no C# projects.", request.Project));
        }

        var sourceByPath = request.Sources
            .GroupBy(source => NormalizePath(source.Path), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);
        if (sourceByPath.Count != request.Sources.Count)
        {
            return Incomplete(Diagnostic("source_duplicate", "A source snapshot path occurred more than once.", request.Project));
        }
        var sourcePaths = sourceByPath.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var owners = BuildSourceOwners(projects);
        var resolvedOwners = new Dictionary<string, List<Project>>(StringComparer.OrdinalIgnoreCase);
        var deferredMappedSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in request.Sources)
        {
            var path = NormalizePath(source.Path);
            if (!owners.TryGetValue(path, out var sourceOwners) || sourceOwners.Count == 0)
            {
                if (Path.GetExtension(path).Equals(".razor", StringComparison.OrdinalIgnoreCase))
                {
                    deferredMappedSources.Add(path);
                    continue;
                }
                return Incomplete(Diagnostic(
                    "source_not_in_project",
                    "A supplied source snapshot is not owned by any evaluated workspace project.",
                    source.Path));
            }
            var hintedOwners = string.IsNullOrWhiteSpace(source.Project)
                ? new List<Project>()
                : sourceOwners
                    .Where(owner => SameProject(owner, source.Project!))
                    .ToList();
            resolvedOwners[path] = hintedOwners.Count > 0 ? hintedOwners : sourceOwners;
        }

        foreach (var source in request.Sources)
        {
            var path = NormalizePath(source.Path);
            if (!resolvedOwners.TryGetValue(path, out var sourceOwners))
            {
                continue;
            }
            foreach (var owner in sourceOwners)
            {
                foreach (var document in owner.Documents.Where(document => SamePath(document.FilePath, path)))
                {
                    solution = solution.WithDocumentText(document.Id, SourceText.From(source.Source, Encoding.UTF8));
                }
                foreach (var document in owner.AdditionalDocuments.Where(document => SamePath(document.FilePath, path)))
                {
                    solution = solution.WithAdditionalDocumentText(document.Id, SourceText.From(source.Source, Encoding.UTF8));
                }
            }
        }
        projects = solution.Projects
            .Where(project => project.Language == LanguageNames.CSharp)
            .OrderBy(project => NormalizePath(project.FilePath ?? project.Name), StringComparer.Ordinal)
            .ToList();
        projects = projects
            .Select(project => ApplyRequestOptions(project, request))
            .ToList();

        var projectCompilations = new List<ProjectCompilationModel>();
        var allModels = new Dictionary<SyntaxTree, SemanticModel>();
        foreach (var project in projects)
        {
            CSharpCompilation? compilation;
            try
            {
                compilation = await project.GetCompilationAsync() as CSharpCompilation;
            }
            catch (Exception exception)
            {
                return Incomplete(Diagnostic("compilation_failed", exception.Message, project.FilePath));
            }
            if (compilation is null)
            {
                return Incomplete(Diagnostic("compilation_missing", "The workspace returned no C# compilation.", project.FilePath));
            }
            var compilerErrors = compilation.GetDiagnostics()
                .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)
                .Take(32)
                .ToList();
            if (compilerErrors.Count > 0)
            {
                return Incomplete(compilerErrors.Select(diagnostic => Diagnostic(
                    "compiler_diagnostic",
                    diagnostic.ToString(),
                    diagnostic.Location.IsInSource ? diagnostic.Location.SourceTree?.FilePath : project.FilePath)).ToList());
            }

            var generatedDocuments = new List<Document>();
            if (request.IncludeRazorGenerated)
            {
                try
                {
                    generatedDocuments.AddRange(await project.GetSourceGeneratedDocumentsAsync());
                }
                catch (Exception exception)
                {
                    return Incomplete(Diagnostic("generator_failed", exception.Message, project.FilePath));
                }
            }
            var generatedTrees = new List<SyntaxTree>();
            var generatedTreePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var generated in generatedDocuments)
            {
                try
                {
                    var tree = await generated.GetSyntaxTreeAsync();
                    if (tree is null)
                    {
                        return Incomplete(Diagnostic("generator_failed", "A source-generated document had no syntax tree.", generated.FilePath));
                    }
                    var generatedPath = tree.FilePath;
                    if (string.IsNullOrWhiteSpace(generatedPath))
                    {
                        return Incomplete(Diagnostic("generator_failed", "A source-generated document had no source path.", generated.FilePath));
                    }
                    if (generatedTreePaths.Add(NormalizePath(generatedPath)))
                    {
                        generatedTrees.Add(tree);
                    }
                }
                catch (Exception exception)
                {
                    return Incomplete(Diagnostic("generator_failed", exception.Message, generated.FilePath));
                }
            }
            var projectDocumentPaths = project.Documents
                .Select(document => document.FilePath)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => NormalizePath(path!))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var treePath = tree.FilePath;
                if (string.IsNullOrWhiteSpace(treePath))
                {
                    return Incomplete(Diagnostic("tree_path_missing", "A workspace compilation syntax tree had no source path.", project.FilePath));
                }
                var path = NormalizePath(treePath!);
                if (!sourcePaths.Contains(path)
                    && (!projectDocumentPaths.Contains(path) || IsGeneratedPath(path))
                    && generatedTreePaths.Add(path))
                {
                    generatedTrees.Add(tree);
                }
            }
            var suppliedTrees = compilation.SyntaxTrees
                .Select(tree => (Tree: tree, Path: tree.FilePath))
                .Where(item => !string.IsNullOrWhiteSpace(item.Path)
                    && sourcePaths.Contains(NormalizePath(item.Path!))
                    && Path.GetExtension(item.Path!).Equals(".cs", StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Tree)
                .ToList();
            foreach (var source in request.Sources.Where(source =>
                Path.GetExtension(source.Path).Equals(".cs", StringComparison.OrdinalIgnoreCase)
                && resolvedOwners[NormalizePath(source.Path)].Any(owner => owner.Id == project.Id)))
            {
                if (!suppliedTrees.Any(tree => SamePath(tree.FilePath, source.Path)))
                {
                    return Incomplete(Diagnostic("source_not_compiled", "A supplied C# snapshot was not present in its owning workspace compilation.", source.Path));
                }
            }
            foreach (var document in project.Documents)
            {
                var documentPath = document.FilePath;
                if (string.IsNullOrWhiteSpace(documentPath))
                {
                    return Incomplete(Diagnostic("document_path_missing", "A workspace project document had no source path.", project.FilePath));
                }
                if (!Path.GetExtension(documentPath).Equals(".cs", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                var path = NormalizePath(documentPath);
                if (!sourcePaths.Contains(path) && !IsGeneratedPath(path))
                {
                    return Incomplete(Diagnostic("source_snapshot_missing", "The complete project source snapshot set is missing a workspace C# document.", documentPath));
                }
            }
            foreach (var document in project.AdditionalDocuments)
            {
                var documentPath = document.FilePath;
                if (string.IsNullOrWhiteSpace(documentPath))
                {
                    return Incomplete(Diagnostic("document_path_missing", "A workspace additional document had no source path.", project.FilePath));
                }
                if (Path.GetExtension(documentPath).Equals(".razor", StringComparison.OrdinalIgnoreCase)
                    && !sourcePaths.Contains(NormalizePath(documentPath))
                    && !IsGeneratedPath(NormalizePath(documentPath)))
                {
                    return Incomplete(Diagnostic("source_snapshot_missing", "The complete project source snapshot set is missing a workspace Razor document.", documentPath));
                }
            }
            var models = new Dictionary<SyntaxTree, SemanticModel>();
            foreach (var tree in compilation.SyntaxTrees)
            {
                try
                {
                    models[tree] = compilation.GetSemanticModel(tree);
                    allModels[tree] = models[tree];
                }
                catch (Exception exception)
                {
                    return Incomplete(Diagnostic("semantic_model_failed", exception.Message, tree.FilePath));
                }
            }
            projectCompilations.Add(new ProjectCompilationModel(project, compilation, suppliedTrees, generatedTrees, models));
            AddMappedSourceOwners(project, compilation.SyntaxTrees.Concat(generatedTrees), deferredMappedSources, resolvedOwners);
        }
        foreach (var sourcePath in deferredMappedSources
            .Where(path => !resolvedOwners.TryGetValue(path, out var sourceOwners) || sourceOwners.Count == 0))
        {
            var source = request.Sources.First(source => SamePath(source.Path, sourcePath));
            return Incomplete(Diagnostic(
                "source_not_in_project",
                "A supplied source snapshot is not owned by any evaluated workspace project or trusted generated-source mapping.",
                source.Path));
        }
        if (workspaceDiagnostics.Count > 0)
        {
            return Incomplete(workspaceDiagnostics);
        }

        var razorSources = request.Sources
            .Where(source => Path.GetExtension(source.Path).Equals(".razor", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var facts = new SemanticFacts
        {
            SourceDigests = request.Sources
                .OrderBy(source => NormalizePath(source.Path), StringComparer.Ordinal)
                .ToDictionary(source => NormalizePath(source.Path), source => source.ContentDigest, StringComparer.OrdinalIgnoreCase),
        };
        var razorParseOptions = projectCompilations
            .Select(project => project.Project.ParseOptions as CSharpParseOptions)
            .FirstOrDefault();
        foreach (var source in razorSources)
        {
            var razor = RazorSourceFactsAdapter.Analyze(source.Path, source.Source, razorParseOptions, sdkPath);
            if (!razor.Success)
            {
                return Incomplete(Diagnostic(razor.Code, razor.Message, source.Path));
            }
            facts.RazorSourceFacts[NormalizePath(source.Path)] = new RazorSourceFact
            {
                Metrics = new RazorMetrics
                {
                    Lines = razor.Metrics.Lines,
                    CodeLines = razor.Metrics.CodeLines,
                    CommentLines = razor.Metrics.CommentLines,
                },
                CodeLineNumbers = razor.CodeLineNumbers,
            };
        }
        var allAnalyzedTrees = new List<(SyntaxTree Tree, string ProjectPath)>();
        foreach (var project in projectCompilations)
        {
            var projectTypes = AllNamedTypes(project.Compilation.Assembly.GlobalNamespace).ToList();
            foreach (var type in projectTypes)
            {
                foreach (var declarationReference in type.DeclaringSyntaxReferences)
                {
                    if (declarationReference.SyntaxTree is null
                        || !allModels.TryGetValue(declarationReference.SyntaxTree, out var model)
                        || declarationReference.GetSyntax() is not TypeDeclarationSyntax declaration
                        || declaration.Identifier.IsMissing)
                    {
                        continue;
                    }
                    var sourcePath = NormalizePath(declaration.SyntaxTree.FilePath!);
                    if (facts.SourceDigests.ContainsKey(sourcePath))
                    {
                        facts.Types.Add(BuildTypeFact(type, declaration, model, sourcePath, projectTypes));
                    }
                }
            }
            foreach (var tree in project.Trees)
            {
                if (!project.Models.TryGetValue(tree, out var model)
                    || !facts.SourceDigests.ContainsKey(NormalizePath(tree.FilePath!)))
                {
                    continue;
                }
                var implementers = BuildImplementerMap(projectTypes);
                CollectCastFacts(tree, model, facts, implementers);
                CollectRefObjectFacts(tree, model, facts);
                CollectBaseTypeFacts(tree, model, facts, project.Compilation);
                CollectVarianceFacts(tree, model, facts);
            }
            allAnalyzedTrees.AddRange(project.Trees.Select(tree => (tree, project.Project.FilePath ?? project.Project.Name)));
            allAnalyzedTrees.AddRange(project.GeneratedTrees.Select(tree => (tree, project.Project.FilePath ?? project.Project.Name)));
            var blazorResult = CollectBlazorFacts(
                project.Trees,
                request.IncludeRazorGenerated ? project.GeneratedTrees : Array.Empty<SyntaxTree>(),
                project.Compilation,
                project.Models,
                request.Sources,
                project.Project.FilePath ?? project.Project.Name,
                facts);
            if (!blazorResult.Success)
            {
                return Incomplete(blazorResult.Diagnostics);
            }
            var redundantCastFacts = new List<CompilerRedundantCastFact>();
            facts.QuickFixes.AddRange(QuickFixPlanner.Collect(project.Compilation, project.Models, sourcePaths, redundantCastFacts));
            foreach (var redundantCast in redundantCastFacts)
            {
                var sourceTree = project.Models.Keys.FirstOrDefault(tree =>
                    StringComparer.OrdinalIgnoreCase.Equals(NormalizePath(tree.FilePath!), redundantCast.SourcePath));
                if (sourceTree is null
                    || !TrySemanticSpan(sourceTree, redundantCast.StartByte, redundantCast.EndByte, out var span))
                {
                    return Incomplete(Diagnostic(
                        "quickfix_span_invalid",
                        "The compiler helper emitted an invalid S1905 span.",
                        redundantCast.SourcePath));
                }
                facts.RedundantCasts.Add(new RedundantCastFact
                {
                    SourcePath = redundantCast.SourcePath,
                    Span = span,
                    Message = redundantCast.Message,
                });
            }
        }
        if (request.IncludeRazorGenerated && razorSources.Count > 0)
        {
            var generatorDiagnostics = ValidateGeneratedRazorCoverage(razorSources, allAnalyzedTrees);
            if (generatorDiagnostics.Count > 0)
            {
                return Incomplete(generatorDiagnostics);
            }
        }
        var referenceInputs = projectCompilations
            .SelectMany(project => project.Project.MetadataReferences
                .OfType<PortableExecutableReference>()
                .Select(reference => reference.FilePath)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => new { Path = NormalizePath(path!), Digest = DigestFile(path!) }))
            .Distinct()
            .OrderBy(input => input.Path, StringComparer.Ordinal)
            .ToList();
        var referenceDigest = DigestObject(referenceInputs);
        var dependencyInputs = projectCompilations
            .Select(project => new
            {
                Path = NormalizePath(project.Project.FilePath ?? project.Project.Name),
                project.Project.AssemblyName,
                TargetFramework = GuessTargetFramework(project.Project),
                Defines = (project.Project.ParseOptions as CSharpParseOptions)?.PreprocessorSymbolNames.OrderBy(value => value, StringComparer.Ordinal).ToArray() ?? Array.Empty<string>(),
                LanguageVersion = (project.Project.ParseOptions as CSharpParseOptions)?.LanguageVersion.ToString() ?? "",
                Nullable = (project.Project.CompilationOptions as CSharpCompilationOptions)?.NullableContextOptions.ToString() ?? "",
                Documents = project.Project.Documents
                    .Select(document => document.FilePath)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Select(path => NormalizePath(path!))
                    .OrderBy(value => value, StringComparer.Ordinal)
                    .ToArray(),
                AdditionalDocuments = project.Project.AdditionalDocuments
                    .Select(document => document.FilePath)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Select(path => NormalizePath(path!))
                    .OrderBy(value => value, StringComparer.Ordinal)
                    .ToArray(),
                AnalyzerConfigs = project.Project.AnalyzerConfigDocuments
                    .Select(document => document.FilePath)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Select(path => new { Path = NormalizePath(path!), Digest = DigestFile(path!) })
                    .OrderBy(value => value.Path, StringComparer.Ordinal)
                    .ToArray(),
                References = project.Project.MetadataReferences.OfType<PortableExecutableReference>().Select(reference => NormalizePath(reference.FilePath ?? "")).OrderBy(value => value, StringComparer.Ordinal).ToArray(),
            })
            .OrderBy(input => input.Path, StringComparer.Ordinal)
            .ToList();
        var dependencyDigest = DigestObject(new { Projects = dependencyInputs, References = referenceInputs, Facts = facts });
        var compilerInputs = LoadedAssemblyFingerprints(sdkPath);
        compilerInputs.Add(new { Name = "sdk", Path = sdkPath, Digest = DigestDirectory(sdkPath) });
        var compilerDigest = DigestObject(new
        {
            Assemblies = compilerInputs,
            request.ProjectManifestDigest,
            Dependency = dependencyDigest,
        });
        var compilerVersion = typeof(CSharpCompilation).Assembly.GetName().Version?.ToString() ?? "unknown";
        var targetFrameworks = projectCompilations.Select(project => GuessTargetFramework(project.Project))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (!string.IsNullOrWhiteSpace(request.TargetFramework)
            && targetFrameworks.Any(value => !string.Equals(value, request.TargetFramework, StringComparison.OrdinalIgnoreCase)))
        {
            return Incomplete(Diagnostic("target_framework_mismatch", "Requested target framework does not match the workspace project references.", request.Project));
        }
        var compiler = new CompilerFingerprint
        {
            HelperVersion = HelperVersion,
            CompilerVersion = compilerVersion,
            CompilerDigest = compilerDigest,
            SdkVersion = Path.GetFileName(sdkPath),
            TargetFramework = targetFrameworks.Count == 1 ? targetFrameworks[0] : targetFrameworks.Count == 0 ? "workspace" : "multiple",
            Defines = projectCompilations
                .SelectMany(project => (project.Project.ParseOptions as CSharpParseOptions)?.PreprocessorSymbolNames ?? ImmutableArray<string>.Empty)
                .Concat(request.Defines)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToList(),
            LanguageVersion = request.LanguageVersion ?? projectCompilations
                .Select(project => (project.Project.ParseOptions as CSharpParseOptions)?.LanguageVersion.ToString() ?? "")
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "workspace",
            Nullable = projectCompilations
                .Select(project => (project.Project.CompilationOptions as CSharpCompilationOptions)?.NullableContextOptions.ToString() ?? "")
                .Distinct(StringComparer.Ordinal)
                .SingleOrDefault() ?? "per-project",
            ProjectDigest = request.ProjectManifestDigest,
            ReferenceDigest = referenceDigest,
            DependencyDigest = dependencyDigest,
        };
        return new HelperResponse
        {
            SchemaVersion = SchemaVersion,
            Status = SemanticStatus.Complete,
            Compiler = compiler,
            DependencyFingerprint = dependencyDigest,
            Facts = facts,
        };
    }

    private static List<SemanticDiagnostic> ValidateRequest(HelperRequest request)
    {
        var diagnostics = new List<SemanticDiagnostic>();
        if (!request.TrustedEvaluation)
        {
            diagnostics.Add(Diagnostic("evaluation_not_trusted", "Trusted project evaluation is required.", request.Project));
        }
        if (!File.Exists(request.Project))
        {
            diagnostics.Add(Diagnostic("project_missing", "The configured project or solution does not exist.", request.Project));
        }
        if (request.Sources.Count == 0)
        {
            diagnostics.Add(Diagnostic("sources_missing", "The complete source snapshot set is empty.", null));
        }
        var duplicatePaths = request.Sources
            .GroupBy(source => NormalizePath(source.Path), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() != 1)
            .Select(group => group.Key)
            .ToList();
        foreach (var duplicatePath in duplicatePaths)
        {
            diagnostics.Add(Diagnostic("source_duplicate", "A source path occurred more than once.", duplicatePath));
        }
        foreach (var source in request.Sources)
        {
            var digest = Digest(source.Source);
            if (!string.Equals(digest, source.ContentDigest, StringComparison.Ordinal))
            {
                diagnostics.Add(Diagnostic("source_digest_invalid", "The source snapshot digest does not match its text.", source.Path));
            }
        }
        return diagnostics;
    }


    private static IEnumerable<INamedTypeSymbol> AllNamedTypes(INamespaceSymbol @namespace)
    {
        foreach (var type in @namespace.GetTypeMembers())
        {
            foreach (var nested in AllNamedTypes(type))
            {
                yield return nested;
            }
        }
        foreach (var nestedNamespace in @namespace.GetNamespaceMembers())
        {
            foreach (var type in AllNamedTypes(nestedNamespace))
            {
                yield return type;
            }
        }
    }

    private static IEnumerable<INamedTypeSymbol> AllNamedTypes(INamedTypeSymbol type)
    {
        yield return type;
        foreach (var nested in type.GetTypeMembers())
        {
            foreach (var descendant in AllNamedTypes(nested))
            {
                yield return descendant;
            }
        }
    }

    private static Project ApplyRequestOptions(Project project, HelperRequest request)
    {
        if (project.ParseOptions is CSharpParseOptions parseOptions)
        {
            var symbols = parseOptions.PreprocessorSymbolNames
                .Concat(request.Defines)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            parseOptions = parseOptions.WithPreprocessorSymbols(symbols);
            if (!string.IsNullOrWhiteSpace(request.LanguageVersion)
                && TryParseLanguageVersion(request.LanguageVersion, out var requestedLanguage))
            {
                parseOptions = parseOptions.WithLanguageVersion(requestedLanguage);
            }
            project = project.WithParseOptions(parseOptions);
        }
        if (request.Nullable != NullableMode.Enable
            && project.CompilationOptions is CSharpCompilationOptions compilationOptions)
        {
            project = project.WithCompilationOptions(compilationOptions.WithNullableContextOptions(request.Nullable switch
            {
                NullableMode.Disable => NullableContextOptions.Disable,
                NullableMode.Warnings => NullableContextOptions.Warnings,
                NullableMode.Annotations => NullableContextOptions.Annotations,
                _ => NullableContextOptions.Enable,
            }));
        }
        return project;
    }

    private static bool TryParseLanguageVersion(string value, out LanguageVersion languageVersion)
    {
        if (Enum.TryParse(value, true, out languageVersion))
        {
            return true;
        }
        languageVersion = value.Trim().ToLowerInvariant() switch
        {
            "latest" or "latestmajor" => LanguageVersion.LatestMajor,
            "preview" => LanguageVersion.Preview,
            _ => LanguageVersion.LatestMajor,
        };
        return value.Trim().Equals("latest", StringComparison.OrdinalIgnoreCase)
            || value.Trim().Equals("latestmajor", StringComparison.OrdinalIgnoreCase)
            || value.Trim().Equals("preview", StringComparison.OrdinalIgnoreCase)
            || double.TryParse(value, out _);
    }

    private static string? ResolveSdkPath()
    {
        var candidates = new List<string>();
        var configured = Environment.GetEnvironmentVariable("HOONARQUBE_DOTNET_SDK");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            candidates.Add(configured);
        }

        var compiledSdkPath = CompiledSdkPath();
        if (!string.IsNullOrWhiteSpace(compiledSdkPath))
        {
            candidates.Add(compiledSdkPath);
        }

        return candidates
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(path =>
                File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "Microsoft.CodeAnalysis.dll"))
                && File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "Microsoft.CodeAnalysis.CSharp.dll"))
                && File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "Microsoft.CodeAnalysis.Workspaces.dll"))
                && File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "Microsoft.CodeAnalysis.CSharp.Workspaces.dll"))
                && File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "Microsoft.CodeAnalysis.Workspaces.MSBuild.dll"))
                && File.Exists(Path.Combine(path, "DotnetTools", "dotnet-format", "BuildHost-netcore", "Microsoft.Build.Locator.dll")));
    }

    // With no explicit override, the project embeds MSBuildToolsPath so runtime
    // loading uses the SDK that supplied the helper's compile-time references.
    private static string? CompiledSdkPath()
    {
        const string metadataKey = "Hoonarqube.BuildSdkPath";
        return typeof(Program)
            .Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, metadataKey, StringComparison.Ordinal))
            ?.Value;
    }

    private static void ConfigureAssemblyResolution(string sdkPath)
    {
        var formatPath = Path.Combine(sdkPath, "DotnetTools", "dotnet-format");
        var buildHostPath = Path.Combine(formatPath, "BuildHost-netcore");
        var razorPath = Path.Combine(sdkPath, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators");
        AssemblyLoadContext.Default.Resolving += (_, name) =>
        {
            if (name.Name is null)
            {
                return null;
            }
            if (name.Name.StartsWith("Microsoft.Build.", StringComparison.Ordinal)
                && !string.Equals(name.Name, "Microsoft.Build.Locator", StringComparison.Ordinal))
            {
                return null;
            }
            var path = name.Name == "Microsoft.Build.Locator"
                ? Path.Combine(buildHostPath, name.Name + ".dll")
                : File.Exists(Path.Combine(razorPath, name.Name + ".dll"))
                    ? Path.Combine(razorPath, name.Name + ".dll")
                    : Path.Combine(formatPath, name.Name + ".dll");
            return File.Exists(path)
                ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path)
                : null;
        };
    }

    private static void RegisterWorkspaceFailedHandler(MSBuildWorkspace workspace, ICollection<SemanticDiagnostic> diagnostics)
    {
        workspace.RegisterWorkspaceFailedHandler(diagnostic =>
            diagnostics.Add(Diagnostic(
                "workspace_failed",
                diagnostic.ToString() ?? "Workspace failure reported without a message.",
                null)));
    }

    private static bool SameProject(Project project, string hint)
    {
        return SamePath(project.FilePath, hint)
            || string.Equals(project.Name, hint, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, List<Project>> BuildSourceOwners(IEnumerable<Project> projects)
    {
        var owners = new Dictionary<string, List<Project>>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in projects)
        {
            foreach (var document in project.Documents.Concat(project.AdditionalDocuments))
            {
                if (string.IsNullOrWhiteSpace(document.FilePath))
                {
                    continue;
                }
                var path = NormalizePath(document.FilePath);
                if (!owners.TryGetValue(path, out var values))
                {
                    values = new List<Project>();
                    owners[path] = values;
                }
                if (!values.Any(candidate => candidate.Id == project.Id))
                {
                    values.Add(project);
                }
            }
        }
        return owners;
    }

    private static void AddMappedSourceOwners(
        Project project,
        IEnumerable<SyntaxTree> trees,
        IReadOnlySet<string> deferredMappedSources,
        IDictionary<string, List<Project>> resolvedOwners)
    {
        if (deferredMappedSources.Count == 0)
        {
            return;
        }
        foreach (var tree in trees)
        {
            foreach (var node in tree.GetRoot().DescendantNodesAndSelf())
            {
                var mappedPath = ResolveMappedPath(node.GetLocation().GetMappedLineSpan().Path, project.FilePath);
                if (mappedPath is null || !deferredMappedSources.Contains(mappedPath))
                {
                    continue;
                }
                if (!resolvedOwners.TryGetValue(mappedPath, out var owners))
                {
                    owners = new List<Project>();
                    resolvedOwners[mappedPath] = owners;
                }
                if (!owners.Any(owner => owner.Id == project.Id))
                {
                    owners.Add(project);
                }
            }
        }
    }

    private static string? ResolveMappedPath(string? mappedPath, string? projectPath)
    {
        if (string.IsNullOrWhiteSpace(mappedPath))
        {
            return null;
        }
        if (Path.IsPathRooted(mappedPath))
        {
            return NormalizePath(mappedPath);
        }
        if (string.IsNullOrWhiteSpace(projectPath))
        {
            return null;
        }
        var projectDirectory = Path.GetDirectoryName(NormalizePath(projectPath));
        return string.IsNullOrWhiteSpace(projectDirectory)
            ? null
            : NormalizePath(Path.Combine(projectDirectory, mappedPath));
    }

    private static bool SamePath(string? left, string? right) =>
        !string.IsNullOrWhiteSpace(left)
        && !string.IsNullOrWhiteSpace(right)
        && string.Equals(NormalizePath(left), NormalizePath(right), StringComparison.OrdinalIgnoreCase);

    private static string GuessTargetFramework(Project project)
    {
        foreach (var reference in project.MetadataReferences.OfType<PortableExecutableReference>())
        {
            var path = reference.FilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }
            var segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            for (var index = 0; index + 1 < segments.Length; index++)
            {
                if (string.Equals(segments[index], "ref", StringComparison.OrdinalIgnoreCase)
                    && segments[index + 1].StartsWith("net", StringComparison.OrdinalIgnoreCase))
                {
                    return segments[index + 1];
                }
            }
        }
        return "";
    }

    private static List<object> LoadedAssemblyFingerprints(string sdkPath)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sdkRoot = Path.GetFullPath(sdkPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var helperPath = typeof(Program).Assembly.Location;
        var isRelevant = (string path) =>
            string.Equals(path, helperPath, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(sdkRoot, StringComparison.OrdinalIgnoreCase);
        void AddAssembly(Assembly assembly)
        {
            var path = assembly.Location;
            if (!string.IsNullOrWhiteSpace(path) && isRelevant(path))
            {
                paths.Add(Path.GetFullPath(path));
            }
        }
        foreach (var assembly in new[]
        {
            typeof(Program).Assembly,
            typeof(CSharpCompilation).Assembly,
            typeof(MSBuildWorkspace).Assembly,
            typeof(MSBuildLocator).Assembly,
        }.Distinct())
        {
            AddAssembly(assembly);
        }
        foreach (var assembly in AssemblyLoadContext.Default.Assemblies)
        {
            AddAssembly(assembly);
        }
        void AddDirectoryAssemblies(string directory)
        {
            if (!Directory.Exists(directory))
            {
                return;
            }
            foreach (var path in Directory.EnumerateFiles(directory, "*.dll", SearchOption.TopDirectoryOnly))
            {
                paths.Add(Path.GetFullPath(path));
            }
        }
        var formatPath = Path.Combine(sdkPath, "DotnetTools", "dotnet-format");
        var buildHostPath = Path.Combine(formatPath, "BuildHost-netcore");
        var razorPath = Path.Combine(sdkPath, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators");
        AddDirectoryAssemblies(formatPath);
        AddDirectoryAssemblies(buildHostPath);
        AddDirectoryAssemblies(razorPath);
        return paths
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path =>
            {
                var loaded = AssemblyLoadContext.Default.Assemblies
                    .FirstOrDefault(assembly => string.Equals(assembly.Location, path, StringComparison.OrdinalIgnoreCase));
                return new
                {
                    Name = loaded?.GetName().Name ?? Path.GetFileNameWithoutExtension(path),
                    FullName = loaded?.FullName ?? "",
                    Path = path,
                    Digest = DigestFile(path),
                };
            })
            .Cast<object>()
            .ToList();
    }

    private static string DigestDirectory(string sdkPath)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = new[]
        {
            Path.Combine(sdkPath, "DotnetTools", "dotnet-format"),
            Path.Combine(sdkPath, "DotnetTools", "dotnet-format", "BuildHost-netcore"),
            Path.Combine(sdkPath, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators"),
        };
        foreach (var root in roots)
        {
            if (!Directory.Exists(root))
            {
                continue;
            }
            foreach (var pattern in new[] { "*.dll", "*.deps.json", "*.runtimeconfig.json" })
            {
                foreach (var path in Directory.EnumerateFiles(root, pattern, SearchOption.TopDirectoryOnly))
                {
                    paths.Add(Path.GetFullPath(path));
                }
            }
        }
        return DigestObject(paths
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path => new { Path = path, Digest = DigestFile(path) })
            .ToArray());
    }

    private static List<SemanticDiagnostic> ValidateGeneratedRazorCoverage(
        IReadOnlyList<SourceSnapshot> sources,
        IEnumerable<(SyntaxTree Tree, string ProjectPath)> analyzedTrees)
    {
        var trees = analyzedTrees.ToList();
        var diagnostics = new List<SemanticDiagnostic>();
        foreach (var source in sources)
        {
            var found = false;
            foreach (var (tree, projectPath) in trees)
            {
                var root = tree.GetRoot();
                foreach (var node in root.DescendantNodesAndSelf())
                {
                    var mapped = node.GetLocation().GetMappedLineSpan();
                    var mappedPath = ResolveMappedPath(mapped.Path, projectPath);
                    if (SamePath(mappedPath, source.Path))
                    {
                        found = true;
                        break;
                    }
                }
                if (found)
                {
                    break;
                }
            }
            if (!found)
            {
                diagnostics.Add(Diagnostic(
                    "generated_mapping_missing",
                    "The Razor source generator returned no generated document mapped to the supplied Razor source.",
                    source.Path));
            }
        }
        return diagnostics;
    }

    private static TypeFact BuildTypeFact(INamedTypeSymbol type, TypeDeclarationSyntax declaration, SemanticModel model, string sourcePath, IReadOnlyCollection<INamedTypeSymbol> allTypes)
    {
        var dependencies = new DependencyCollector(model, declaration, type).Collect();
        return new TypeFact
        {
            Id = TypeId(type),
            DisplayName = DisplayName(type),
            MetadataName = type.MetadataName,
            Namespace = type.ContainingNamespace?.ToDisplayString() ?? "",
            RootNamespace = RootNamespace(type),
            SourcePath = sourcePath,
            Span = Span(declaration.Identifier.GetLocation()),
            Kind = type.IsRecord ? "record" : type.TypeKind switch
            {
                TypeKind.Struct => "struct",
                TypeKind.Interface => "interface",
                _ => "class",
            },
            IsInterface = type.TypeKind == TypeKind.Interface,
            IsClass = type.TypeKind == TypeKind.Class,
            IsStruct = type.TypeKind == TypeKind.Struct,
            IsSealed = type.IsSealed,
            IsAbstract = type.IsAbstract,
            BaseChain = BaseChain(type),
            Interfaces = type.Interfaces.Select(ToRef).ToList(),
            Dependencies = dependencies.OrderBy(value => value, StringComparer.Ordinal).ToList(),
        };
    }

    private static List<SemanticTypeRef> BaseChain(INamedTypeSymbol type)
    {
        var result = new List<SemanticTypeRef>();
        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            result.Add(ToRef(current));
        }
        return result;
    }

    private static void CollectCastFacts(SyntaxTree tree, SemanticModel model, SemanticFacts facts, IReadOnlyDictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> implementers)
    {
        var root = tree.GetRoot();
        foreach (var cast in root.DescendantNodes().OfType<CastExpressionSyntax>())
        {
            AddCast(cast.Type, cast.Expression, cast.GetLocation(), model, facts, implementers);
        }
        foreach (var expression in root.DescendantNodes().OfType<BinaryExpressionSyntax>().Where(node => node.IsKind(SyntaxKind.AsExpression)))
        {
            AddCast(expression.Right, expression.Left, expression.Right.GetLocation(), model, facts, implementers);
        }
    }

    private static void AddCast(ExpressionSyntax targetSyntax, ExpressionSyntax expressionSyntax, Location location, SemanticModel model, SemanticFacts facts, IReadOnlyDictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> implementers)
    {
        var interfaceType = model.GetTypeInfo(targetSyntax).Type as INamedTypeSymbol;
        var expressionType = model.GetTypeInfo(expressionSyntax).Type as INamedTypeSymbol;
        if (interfaceType is null || expressionType is null || interfaceType.TypeKind != TypeKind.Interface)
        {
            return;
        }
        var impossible = ConcreteImplementationExists(interfaceType, implementers)
            && ExpressionTypeRelevant(expressionType, implementers)
            && !DerivesOrImplements(expressionType, interfaceType)
            && implementers.TryGetValue(interfaceType, out var candidates)
            && !candidates.Any(candidate => DerivesOrImplements(candidate, expressionType));
        if (!impossible)
        {
            return;
        }
        var interfaceName = interfaceType.ToMinimalDisplayString(model, targetSyntax.SpanStart);
        var expressionName = expressionType.ToMinimalDisplayString(model, targetSyntax.SpanStart);
        facts.Casts.Add(new CastFact
        {
            SourcePath = NormalizePath(location.SourceTree?.FilePath ?? ""),
            Span = Span(targetSyntax.GetLocation()),
            InterfaceType = ToRef(interfaceType),
            ExpressionType = ToRef(expressionType),
            ExpressionIsInterface = expressionType.TypeKind == TypeKind.Interface,
            Impossible = true,
            Message = expressionType.TypeKind == TypeKind.Interface
                ? $"Review this cast; in this project there's no type that implements both '{expressionName}' and '{interfaceName}'."
                : $"Review this cast; in this project there's no type that extends '{expressionName}' and implements '{interfaceName}'.",
        });
    }

    private static void CollectRefObjectFacts(SyntaxTree tree, SemanticModel model, SemanticFacts facts)
    {
        foreach (var method in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var methodSymbol = model.GetDeclaredSymbol(method);
            if (methodSymbol is null || method.Identifier.IsMissing)
            {
                continue;
            }
            foreach (var parameter in methodSymbol.Parameters.Where(parameter => parameter.RefKind == RefKind.Ref && parameter.Type.SpecialType == SpecialType.System_Object))
            {
                var syntaxParameter = method.ParameterList.Parameters.FirstOrDefault(candidate => candidate.Identifier.ValueText == parameter.Name);
                if (syntaxParameter is null)
                {
                    continue;
                }
                facts.RefObjectParameters.Add(new RefObjectParameterFact
                {
                    SourcePath = NormalizePath(tree.FilePath!),
                    MethodSpan = Span(method.Identifier.GetLocation()),
                    ParameterSpan = Span(syntaxParameter.GetLocation()),
                    MethodId = methodSymbol.GetDocumentationCommentId() ?? methodSymbol.ToDisplayString(),
                    ParameterId = parameter.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                    ParameterName = parameter.Name,
                    Message = "Make this method generic and replace the 'object' parameter with a type parameter.",
                    SecondaryMessage = "Replace this parameter with a type parameter.",
                });
            }
        }
    }

    private static void CollectBaseTypeFacts(SyntaxTree tree, SemanticModel model, SemanticFacts facts, CSharpCompilation compilation)
    {
        foreach (var method in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var methodSymbol = model.GetDeclaredSymbol(method);
            if (methodSymbol is null
                || methodSymbol.Parameters.Length == 0
                || methodSymbol.IsOverride
                || methodSymbol.IsVirtual
                || IsInterfaceMember(methodSymbol)
                || IsControllerAction(methodSymbol)
                || IsEventHandler(methodSymbol))
            {
                continue;
            }
            var parameters = methodSymbol.Parameters
                .Where(IsTrackedParameter)
                .GroupBy(parameter => parameter.Name, StringComparer.Ordinal)
                .ToDictionary(
                    group => group.Key,
                    group => new BaseTypeParameterData(group.First(), methodSymbol.DeclaredAccessibility),
                    StringComparer.Ordinal);
            foreach (var identifier in method.DescendantNodes().OfType<IdentifierNameSyntax>())
            {
                var key = identifier.Identifier.ValueText;
                if (!parameters.TryGetValue(key, out var parameter) || !parameter.ShouldReportOn)
                {
                    continue;
                }
                if (identifier.Parent is EqualsValueClauseSyntax or AssignmentExpressionSyntax)
                {
                    parameter.ShouldReportOn = false;
                    continue;
                }
                var symbolUsedAs = FindParameterUseAsType(identifier, model);
                if (symbolUsedAs is not null && !IsNestedGeneric(symbolUsedAs))
                {
                    parameter.AddUsage(symbolUsedAs);
                }
            }
            foreach (var parameter in parameters.Values)
            {
                if (!parameter.ShouldReportOn || parameter.Parameter.Type is not INamedTypeSymbol declared)
                {
                    continue;
                }
                var suggested = FindMostGeneralType(parameter, declared, methodSymbol.DeclaredAccessibility, compilation);
                if (SymbolEqualityComparer.Default.Equals(suggested, declared) || IsIgnoredBaseType(suggested, compilation))
                {
                    continue;
                }
                facts.BaseTypeSuggestions.Add(new BaseTypeSuggestionFact
                {
                    SourcePath = NormalizePath(tree.FilePath!),
                    Span = Span(parameter.Parameter.Locations.First()),
                    MethodId = methodSymbol.GetDocumentationCommentId() ?? methodSymbol.ToDisplayString(),
                    ParameterId = parameter.Parameter.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                    ParameterName = parameter.Parameter.Name,
                    DeclaredType = ToRef(declared),
                    SuggestedType = ToRef(suggested),
                    Safe = true,
                    Message = $"Consider using more general type '{suggested.ToDisplayString()}' instead of '{declared.ToDisplayString()}'.",
                });
            }
        }
    }

    private static bool IsEventHandler(IMethodSymbol method) =>
        method.ReturnsVoid
        && method.Parameters.Length == 2
        && method.Parameters[0].Type.SpecialType == SpecialType.System_Object
        && method.Parameters[1].Type is INamedTypeSymbol eventArgs
        && eventArgs.BaseType?.ToDisplayString() == "System.EventArgs";

    private static bool IsControllerAction(IMethodSymbol method)
    {
        if (method.GetAttributes().Any(attribute => attribute.AttributeClass?.Name is
            "HttpGetAttribute" or "HttpPostAttribute" or "HttpPutAttribute" or "HttpDeleteAttribute"
            or "HttpPatchAttribute" or "AcceptVerbsAttribute" or "NonActionAttribute"))
        {
            return true;
        }
        for (var current = method.ContainingType; current is not null; current = current.BaseType)
        {
            if (current.MetadataName is "Controller" or "ControllerBase"
                || current.ToDisplayString().EndsWith(".Controller", StringComparison.Ordinal)
                || current.ToDisplayString().EndsWith(".ControllerBase", StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsTrackedParameter(IParameterSymbol parameter) =>
        parameter.Type is not IArrayTypeSymbol
        && !parameter.Type.IsValueType
        && parameter.Type.SpecialType != SpecialType.System_String;

    private static bool IsInterfaceMember(IMethodSymbol method)
    {
        if (method.ExplicitInterfaceImplementations.Length > 0)
        {
            return true;
        }
        var containingType = method.ContainingType;
        return containingType.AllInterfaces
            .SelectMany(@interface => @interface.GetMembers(method.Name))
            .Any(member => SymbolEqualityComparer.Default.Equals(
                containingType.FindImplementationForInterfaceMember(member),
                method));
    }

    private static bool IsNestedGeneric(ITypeSymbol type) =>
        type is INamedTypeSymbol { IsGenericType: true } named
        && named.TypeArguments.Any(argument => argument is INamedTypeSymbol { IsGenericType: true });

    private static ITypeSymbol? FindParameterUseAsType(IdentifierNameSyntax identifier, SemanticModel model)
    {
        var callSite = model.GetEnclosingSymbol(identifier.SpanStart)?.ContainingAssembly;
        var parent = GetFirstNonParenthesizedParent(identifier);
        return parent switch
        {
            ConditionalAccessExpressionSyntax conditionalAccess => HandleConditionalAccess(conditionalAccess, identifier, model, callSite),
            MemberAccessExpressionSyntax memberAccess => GetFirstNonParenthesizedParent(memberAccess) is InvocationExpressionSyntax invocation
                ? HandleInvocation(identifier, model.GetSymbolInfo(invocation).Symbol, model, callSite)
                : HandlePropertyOrField(identifier, model.GetSymbolInfo(memberAccess).Symbol, callSite),
            ArgumentSyntax => model.GetTypeInfo(identifier).ConvertedType,
            ElementAccessExpressionSyntax elementAccess => HandlePropertyOrField(identifier, model.GetSymbolInfo(elementAccess).Symbol, callSite),
            _ => null,
        };
    }

    private static SyntaxNode GetFirstNonParenthesizedParent(SyntaxNode node)
    {
        var parent = node.Parent;
        while (parent is ParenthesizedExpressionSyntax)
        {
            parent = parent.Parent;
        }
        return parent ?? node;
    }

    private static ITypeSymbol? HandleConditionalAccess(
        ConditionalAccessExpressionSyntax conditionalAccess,
        SyntaxNode identifier,
        SemanticModel model,
        IAssemblySymbol? callSite)
    {
        var expression = conditionalAccess.WhenNotNull is ConditionalAccessExpressionSyntax subsequent
            ? subsequent.Expression
            : conditionalAccess.WhenNotNull;
        return expression switch
        {
            MemberBindingExpressionSyntax binding when binding.Name is not null
                => HandlePropertyOrField(identifier, model.GetSymbolInfo(binding.Name).Symbol, callSite),
            InvocationExpressionSyntax { Expression: MemberBindingExpressionSyntax binding }
                => HandleInvocation(identifier, model.GetSymbolInfo(binding).Symbol, model, callSite),
            _ => null,
        };
    }

    private static ITypeSymbol? HandlePropertyOrField(
        SyntaxNode identifier,
        ISymbol? symbol,
        IAssemblySymbol? callSite)
    {
        if (symbol is not IPropertySymbol property)
        {
            return FindOriginatingSymbol(symbol, callSite);
        }
        var parent = GetFirstNonParenthesizedParent(identifier);
        var grandParent = GetFirstNonParenthesizedParent(parent);
        var accessor = grandParent is AssignmentExpressionSyntax ? property.SetMethod : property.GetMethod;
        return FindOriginatingSymbol(accessor, callSite);
    }

    private static ITypeSymbol? HandleInvocation(
        SyntaxNode invokedOn,
        ISymbol? symbol,
        SemanticModel model,
        IAssemblySymbol? callSite)
    {
        if (symbol is not IMethodSymbol method)
        {
            return null;
        }
        return method.IsExtensionMethod
            ? model.GetTypeInfo(invokedOn).ConvertedType
            : FindOriginatingSymbol(method, callSite);
    }

    private static INamedTypeSymbol? FindOriginatingSymbol(ISymbol? member, IAssemblySymbol? callSite)
    {
        if (member is null)
        {
            return null;
        }
        var containingType = FindOriginatingInterface(member, callSite);
        if (containingType is not null)
        {
            return containingType;
        }
        var overriddenType = member switch
        {
            IMethodSymbol method => method.OverriddenMethod?.ContainingType,
            IPropertySymbol property => property.OverriddenProperty?.ContainingType,
            IEventSymbol @event => @event.OverriddenEvent?.ContainingType,
            _ => null,
        };
        return overriddenType is not null && IsNotInternalOrSameAssembly(overriddenType, callSite)
            ? overriddenType
            : member.ContainingType;
    }

    private static INamedTypeSymbol? FindOriginatingInterface(ISymbol member, IAssemblySymbol? callSite)
    {
        if (member.ContainingType is not INamedTypeSymbol containingType)
        {
            return null;
        }
        foreach (var @interface in containingType.AllInterfaces)
        {
            foreach (var interfaceMember in @interface.GetMembers(member.Name))
            {
                if (SymbolEqualityComparer.Default.Equals(
                        containingType.FindImplementationForInterfaceMember(interfaceMember),
                        member)
                    && IsNotInternalOrSameAssembly(@interface, callSite))
                {
                    return interfaceMember.ContainingType;
                }
            }
        }
        return null;
    }

    private static bool IsNotInternalOrSameAssembly(INamedTypeSymbol type, IAssemblySymbol? callSite) =>
        type.DeclaredAccessibility != Accessibility.Internal
        || SymbolEqualityComparer.Default.Equals(type.ContainingAssembly, callSite);

    private static INamedTypeSymbol FindMostGeneralType(
        BaseTypeParameterData parameter,
        INamedTypeSymbol declared,
        Accessibility methodAccessibility,
        CSharpCompilation compilation)
    {
        foreach (var usage in parameter.UsedAs
            .Where(usage => usage.Value > 1 && IsIEnumerableType(usage.Key, compilation))
            .Select(usage => usage.Key)
            .ToList())
        {
            parameter.UsedAs.Remove(usage);
        }
        if (parameter.UsedAs.Count == 0)
        {
            return declared;
        }
        var mostGeneral = declared;
        for (var current = declared.BaseType; current is not null; current = current.BaseType)
        {
            if (DerivesOrImplementsAll(current, parameter.UsedAs.Keys, methodAccessibility))
            {
                mostGeneral = current;
            }
        }
        while (mostGeneral.Interfaces.FirstOrDefault(@interface =>
                   DerivesOrImplementsAll(@interface, parameter.UsedAs.Keys, methodAccessibility))
            is { } @interface)
        {
            mostGeneral = @interface;
        }
        return mostGeneral;
    }

    private static bool DerivesOrImplementsAll(
        INamedTypeSymbol candidate,
        IEnumerable<ITypeSymbol> usages,
        Accessibility methodAccessibility) =>
        usages.All(usage => DerivesOrImplements(candidate, usage))
        && IsConsistentAccessibility(candidate.DeclaredAccessibility, methodAccessibility);

    private static bool IsConsistentAccessibility(Accessibility candidate, Accessibility method) => method switch
    {
        Accessibility.Private => true,
        Accessibility.ProtectedAndInternal => candidate != Accessibility.Private,
        Accessibility.ProtectedOrInternal => candidate is Accessibility.Public or Accessibility.Internal or Accessibility.ProtectedOrInternal,
        Accessibility.Protected => candidate is Accessibility.Public or Accessibility.Protected,
        Accessibility.Internal => candidate is Accessibility.Public or Accessibility.Internal,
        Accessibility.Public => candidate == Accessibility.Public,
        _ => false,
    };

    private static bool IsIEnumerableType(ITypeSymbol type, CSharpCompilation compilation) =>
        SymbolEqualityComparer.Default.Equals(
            type.OriginalDefinition,
            compilation.GetTypeByMetadataName("System.Collections.Generic.IEnumerable`1"))
        || SymbolEqualityComparer.Default.Equals(
            type.OriginalDefinition,
            compilation.GetTypeByMetadataName("System.Collections.IEnumerable"));

    private static bool IsIgnoredBaseType(ITypeSymbol type, CSharpCompilation compilation) =>
        type.SpecialType is SpecialType.System_Object or SpecialType.System_ValueType or SpecialType.System_Enum
        || type.Name.StartsWith("_", StringComparison.Ordinal)
        || IsCollectionOfKeyValuePair(type, compilation);

    private static bool IsCollectionOfKeyValuePair(ITypeSymbol type, CSharpCompilation compilation) =>
        type is INamedTypeSymbol named
        && named.TypeArguments.FirstOrDefault() is INamedTypeSymbol keyValuePair
        && SymbolEqualityComparer.Default.Equals(
            named.OriginalDefinition,
            compilation.GetTypeByMetadataName("System.Collections.Generic.ICollection`1"))
        && SymbolEqualityComparer.Default.Equals(
            keyValuePair.OriginalDefinition,
            compilation.GetTypeByMetadataName("System.Collections.Generic.KeyValuePair`2"));

    private static void CollectVarianceFacts(SyntaxTree tree, SemanticModel model, SemanticFacts facts)
    {
        foreach (var declaration in tree.GetRoot().DescendantNodes().Where(node => node is TypeDeclarationSyntax or DelegateDeclarationSyntax))
        {
            var symbol = model.GetDeclaredSymbol(declaration) as INamedTypeSymbol;
            if (symbol is null || (symbol.TypeKind != TypeKind.Interface && symbol.TypeKind != TypeKind.Delegate))
            {
                continue;
            }
            foreach (var parameter in symbol.TypeParameters.Where(parameter => parameter.Variance == VarianceKind.None))
            {
                var variance = new VarianceUse();
                foreach (var member in symbol.GetMembers())
                {
                    CollectMemberVariance(member, parameter, variance);
                }
                foreach (var inherited in symbol.AllInterfaces.SelectMany(@interface => @interface.GetMembers()))
                {
                    CollectMemberVariance(inherited, parameter, variance);
                }
                // A type parameter appearing in a base interface/delegate
                // argument must satisfy that base's declared variance too.
                foreach (var baseInterface in symbol.Interfaces)
                {
                    CollectTypeVariance(baseInterface, parameter, VariancePosition.Output, variance);
                }
                foreach (var constraint in parameter.ConstraintTypes)
                {
                    CollectTypeVariance(constraint, parameter, VariancePosition.Both, variance);
                }
                var suggested = variance.Input && !variance.Output ? "in" : variance.Output && !variance.Input ? "out" : "";
                if (suggested.Length == 0)
                {
                    continue;
                }
                var syntaxParameter = declaration switch
                {
                    TypeDeclarationSyntax typeDeclaration => typeDeclaration.TypeParameterList?.Parameters.FirstOrDefault(candidate => candidate.Identifier.ValueText == parameter.Name),
                    DelegateDeclarationSyntax delegateDeclaration => delegateDeclaration.TypeParameterList?.Parameters.FirstOrDefault(candidate => candidate.Identifier.ValueText == parameter.Name),
                    _ => null,
                };
                if (syntaxParameter is null)
                {
                    continue;
                }
                facts.GenericVariance.Add(new GenericVarianceFact
                {
                    SourcePath = NormalizePath(tree.FilePath!),
                    Span = Span(syntaxParameter.Identifier.GetLocation()),
                    OwnerId = TypeId(symbol),
                    ParameterId = parameter.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                    ParameterName = parameter.Name,
                    CurrentVariance = "none",
                    SuggestedVariance = suggested,
                    Safe = true,
                    Message = $"Add the '{suggested}' keyword to parameter '{parameter.Name}' to make it '{(suggested == "in" ? "contravariant" : "covariant")}'.",
                });
            }
        }
    }

    private static void CollectMemberVariance(ISymbol member, ITypeParameterSymbol parameter, VarianceUse variance)
    {
        switch (member)
        {
            case IMethodSymbol method:
                CollectTypeVariance(method.ReturnType, parameter, VariancePosition.Output, variance);
                foreach (var methodParameter in method.Parameters)
                {
                    var position = methodParameter.RefKind == RefKind.None
                        ? VariancePosition.Input
                        : VariancePosition.Both;
                    CollectTypeVariance(methodParameter.Type, parameter, position, variance);
                }
                break;
            case IPropertySymbol property:
                if (property.GetMethod is not null)
                {
                    CollectTypeVariance(property.Type, parameter, VariancePosition.Output, variance);
                }
                if (property.SetMethod is not null)
                {
                    CollectTypeVariance(property.Type, parameter, VariancePosition.Input, variance);
                }
                foreach (var indexParameter in property.Parameters)
                {
                    CollectTypeVariance(indexParameter.Type, parameter, VariancePosition.Input, variance);
                }
                break;
            case IEventSymbol @event:
                CollectTypeVariance(@event.Type, parameter, VariancePosition.Input, variance);
                break;
        }
    }

    private static void CollectTypeVariance(ITypeSymbol type, ITypeParameterSymbol parameter, VariancePosition position, VarianceUse variance)
    {
        if (SymbolEqualityComparer.Default.Equals(type, parameter))
        {
            variance.Input |= position is VariancePosition.Input or VariancePosition.Both;
            variance.Output |= position is VariancePosition.Output or VariancePosition.Both;
            return;
        }
        if (type is IArrayTypeSymbol array)
        {
            CollectTypeVariance(array.ElementType, parameter, position, variance);
            return;
        }
        if (type is not INamedTypeSymbol named)
        {
            return;
        }
        for (var index = 0; index < named.TypeArguments.Length && index < named.TypeParameters.Length; index++)
        {
            var nestedPosition = named.TypeParameters[index].Variance switch
            {
                VarianceKind.In => Flip(position),
                VarianceKind.Out => position,
                _ => VariancePosition.Both,
            };
            CollectTypeVariance(named.TypeArguments[index], parameter, nestedPosition, variance);
        }
    }

    private static VariancePosition Flip(VariancePosition position) => position switch
    {
        VariancePosition.Input => VariancePosition.Output,
        VariancePosition.Output => VariancePosition.Input,
        _ => VariancePosition.Both,
    };

    private static (bool Success, List<SemanticDiagnostic> Diagnostics) CollectBlazorFacts(
        IReadOnlyList<SyntaxTree> sourceTrees,
        IReadOnlyList<SyntaxTree> generatedTrees,
        CSharpCompilation compilation,
        IReadOnlyDictionary<SyntaxTree, SemanticModel> models,
        IReadOnlyList<SourceSnapshot> sources,
        string projectPath,
        SemanticFacts facts)
    {
        var builderType = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder");
        if (builderType is null)
        {
            return (true, new List<SemanticDiagnostic>());
        }
        var sourcePaths = sources
            .Select(source => NormalizePath(source.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var seenTrees = new HashSet<SyntaxTree>();
        foreach (var (tree, generated) in sourceTrees
            .Select(tree => (Tree: tree, Generated: false))
            .Concat(generatedTrees.Select(tree => (Tree: tree, Generated: true))))
        {
            if (!seenTrees.Add(tree) || !models.TryGetValue(tree, out var model))
            {
                continue;
            }
            foreach (var lambda in tree.GetRoot().DescendantNodes().OfType<LambdaExpressionSyntax>())
            {
                if (!InsideLoop(lambda) || !InsideRenderTreeAttribute(lambda, model, builderType))
                {
                    continue;
                }
                var mapped = lambda.GetLocation().GetMappedLineSpan();
                var mappedPath = ResolveMappedPath(mapped.Path, projectPath);
                var mappedRazor = mappedPath is not null
                    && mappedPath.EndsWith(".razor", StringComparison.OrdinalIgnoreCase)
                    && sourcePaths.Contains(mappedPath);
                string sourcePath;
                SemanticSpan sourceSpan;
                if (generated)
                {
                    if (!mappedRazor)
                    {
                        return (false, new List<SemanticDiagnostic>
                        {
                            Diagnostic("generated_mapping_missing", "A reportable generated Blazor lambda had no reliable Razor source mapping.", tree.FilePath),
                        });
                    }
                    sourcePath = mappedPath!;
                    sourceSpan = Span(mapped);
                }
                else
                {
                    sourcePath = NormalizePath(tree.FilePath ?? projectPath);
                    if (mappedRazor)
                    {
                        sourcePath = mappedPath!;
                        sourceSpan = Span(mapped);
                    }
                    else
                    {
                        sourceSpan = Span(lambda.GetLocation());
                    }
                    if (!sourcePaths.Contains(sourcePath))
                    {
                        continue;
                    }
                }
                var invocation = lambda.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                var symbol = invocation is null ? null : model.GetSymbolInfo(invocation.Expression).Symbol as IMethodSymbol;
                facts.BlazorLambdas.Add(new BlazorLambdaFact
                {
                    GeneratedPath = NormalizePath(tree.FilePath ?? projectPath),
                    GeneratedSpan = Span(lambda.GetLocation()),
                    SourcePath = sourcePath,
                    SourceSpan = sourceSpan,
                    InvocationSymbolId = symbol?.GetDocumentationCommentId() ?? symbol?.ToDisplayString() ?? "",
                    InvocationMember = symbol?.Name ?? "",
                    ContainingType = symbol?.ContainingType.ToDisplayString() ?? "",
                    Message = "Avoid using lambda expressions in loops in Blazor markup.",
                });
            }
        }
        return (true, new List<SemanticDiagnostic>());
    }

    private static bool InsideLoop(LambdaExpressionSyntax lambda) => lambda.AncestorsAndSelf().Any(node =>
        node is BlockSyntax block && block.Parent is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax or DoStatementSyntax);

    private static bool InsideRenderTreeAttribute(LambdaExpressionSyntax lambda, SemanticModel model, INamedTypeSymbol builderType)
    {
        foreach (var invocation in lambda.AncestorsAndSelf().OfType<InvocationExpressionSyntax>())
        {
            var name = invocation.Expression switch
            {
                MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.ValueText,
                _ => "",
            };
            if (name is not ("AddAttribute" or "AddMultipleAttributes"))
            {
                continue;
            }
            if (model.GetSymbolInfo(invocation.Expression).Symbol is IMethodSymbol method
                && SymbolEqualityComparer.Default.Equals(method.ContainingType, builderType))
            {
                return true;
            }
        }
        return false;
    }

    private static Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> BuildImplementerMap(IReadOnlyCollection<INamedTypeSymbol> types)
    {
        var map = new Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>(SymbolEqualityComparer.Default);
        foreach (var type in types)
        {
            if (type.TypeKind == TypeKind.Interface)
            {
                Add(type, type);
            }
            foreach (var @interface in type.AllInterfaces)
            {
                Add(@interface, type);
            }
        }
        return map;

        void Add(INamedTypeSymbol key, INamedTypeSymbol value)
        {
            if (!map.TryGetValue(key, out var values))
            {
                values = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                map.Add(key, values);
            }
            values.Add(value);
        }
    }

    private static bool ConcreteImplementationExists(INamedTypeSymbol type, IReadOnlyDictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> map) =>
        map.TryGetValue(type, out var implementers) && implementers.Any(IsConcrete);

    private static bool ExpressionTypeRelevant(INamedTypeSymbol type, IReadOnlyDictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> map) =>
        !type.IsSealed
        && type.SpecialType != SpecialType.System_Object
        && (type.TypeKind != TypeKind.Interface || ConcreteImplementationExists(type, map));

    private static bool IsConcrete(INamedTypeSymbol type) => type.TypeKind is TypeKind.Class or TypeKind.Struct;

    private static bool DerivesOrImplements(INamedTypeSymbol candidate, ITypeSymbol target)
    {
        if (SymbolEqualityComparer.Default.Equals(candidate, target))
        {
            return true;
        }
        return candidate.BaseType is not null && DerivesOrImplements(candidate.BaseType, target)
            || target is INamedTypeSymbol namedTarget
                && candidate.AllInterfaces.Any(@interface => SymbolEqualityComparer.Default.Equals(@interface, namedTarget));
    }

    private static bool IsAccessible(INamedTypeSymbol candidate, Accessibility methodAccessibility) => candidate.DeclaredAccessibility is Accessibility.Public or Accessibility.Internal or Accessibility.ProtectedOrInternal or Accessibility.Protected;

    private static SemanticTypeRef ToRef(INamedTypeSymbol type) => new()
    {
        Id = TypeId(type),
        DisplayName = DisplayName(type),
        MetadataName = type.MetadataName,
        Namespace = type.ContainingNamespace?.ToDisplayString() ?? "",
        RootNamespace = RootNamespace(type),
        IsInterface = type.TypeKind == TypeKind.Interface,
        IsClass = type.TypeKind == TypeKind.Class,
        IsStruct = type.TypeKind == TypeKind.Struct,
        IsSealed = type.IsSealed,
    };

    private static string TypeId(INamedTypeSymbol type) => $"{type.ContainingAssembly?.Identity.ToString() ?? "unknown"}|{type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}";

    private static string DisplayName(INamedTypeSymbol type) => type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat).Replace("global::", "", StringComparison.Ordinal);

    private static string RootNamespace(INamedTypeSymbol type)
    {
        var namespaces = new Stack<string>();

        for (var current = type.ContainingNamespace; current is not null && !current.IsGlobalNamespace; current = current.ContainingNamespace)
        {
            namespaces.Push(current.Name);
        }
        return namespaces.Count == 0 ? "" : namespaces.Peek();
    }

    private static SemanticSpan Span(Location location)
    {
        var lineSpan = location.GetLineSpan();
        return Span(lineSpan);
    }

    private static SemanticSpan Span(FileLinePositionSpan lineSpan) => new()
    {
        StartLine = lineSpan.StartLinePosition.Line + 1,
        StartColumn = lineSpan.StartLinePosition.Character,
        EndLine = lineSpan.EndLinePosition.Line + 1,
        EndColumn = lineSpan.EndLinePosition.Character,
    };

    private static bool TrySemanticSpan(SyntaxTree tree, int startByte, int endByte, out SemanticSpan span)
    {
        span = default;
        var text = tree.GetText().ToString();
        var start = Utf16OffsetFromUtf8(text, startByte);
        var end = Utf16OffsetFromUtf8(text, endByte);
        if (start < 0 || end < start)
        {
            return false;
        }
        span = Span(Location.Create(tree, TextSpan.FromBounds(start, end)));
        return true;
    }

    private static int Utf16OffsetFromUtf8(string text, int byteOffset)
    {
        if (byteOffset < 0)
        {
            return -1;
        }
        var bytes = 0;
        for (var position = 0; position < text.Length;)
        {
            if (bytes == byteOffset)
            {
                return position;
            }
            var width = position + 1 < text.Length && char.IsSurrogatePair(text[position], text[position + 1]) ? 2 : 1;
            var next = bytes + Encoding.UTF8.GetByteCount(text.AsSpan(position, width));
            if (byteOffset < next)
            {
                return -1;
            }
            bytes = next;
            position += width;
        }
        return bytes == byteOffset ? text.Length : -1;
    }

    private static string NormalizePath(string path) => Path.GetFullPath(path);

    private static bool IsGeneratedPath(string path) =>
        path.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".razor.cs", StringComparison.OrdinalIgnoreCase);

    private static string CanonicalManifest(IReadOnlyList<SourceSnapshot> sources)
    {
        var entries = sources
            .Select(source => (
                Path: NormalizePath(source.Path),
                Project: source.Project is null ? "" : NormalizePath(source.Project),
                Digest: source.ContentDigest))
            .ToList();
        entries.Sort((left, right) =>
        {
            var pathComparison = Encoding.UTF8.GetBytes(left.Path).AsSpan()
                .SequenceCompareTo(Encoding.UTF8.GetBytes(right.Path));
            return pathComparison != 0
                ? pathComparison
                : Encoding.UTF8.GetBytes(left.Project).AsSpan()
                    .SequenceCompareTo(Encoding.UTF8.GetBytes(right.Project));
        });
        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes("hoonarqube-csharp-manifest-v2\0"));
        Span<byte> length = stackalloc byte[sizeof(ulong)];
        foreach (var entry in entries)
        {
            var path = Encoding.UTF8.GetBytes(entry.Path);
            var project = Encoding.UTF8.GetBytes(entry.Project);
            var digest = Encoding.UTF8.GetBytes(entry.Digest);
            BinaryPrimitives.WriteUInt64LittleEndian(length, (ulong)path.Length);
            stream.Write(length);
            stream.Write(path);
            BinaryPrimitives.WriteUInt64LittleEndian(length, (ulong)project.Length);
            stream.Write(length);
            stream.Write(project);
            BinaryPrimitives.WriteUInt64LittleEndian(length, (ulong)digest.Length);
            stream.Write(length);
            stream.Write(digest);
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static string DigestStrings(IEnumerable<string> values) => DigestObject(values.ToList());

    private static string DigestObject(object value) => Digest(JsonSerializer.Serialize(value, JsonOptions));

    private static string Digest(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string DigestFile(string path)
    {
        try
        {
            return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
        }
        catch
        {
            return "missing";
        }
    }

    private static SemanticDiagnostic Diagnostic(string code, string message, string? path) => new() { Code = code, Message = message, Path = path };

    private static HelperResponse Incomplete(params SemanticDiagnostic[] diagnostics) => Incomplete(diagnostics.ToList());

    private static HelperResponse Incomplete(IEnumerable<SemanticDiagnostic> diagnostics) => new()
    {
        SchemaVersion = SchemaVersion,
        Status = SemanticStatus.Incomplete,
        Diagnostics = diagnostics.ToList(),
        Compiler = new CompilerFingerprint(),
        Facts = new SemanticFacts(),
    };


    private sealed class DependencyCollector : CSharpSyntaxWalker
    {
        private readonly SemanticModel model;
        private readonly SyntaxNode ownerDeclaration;
        private readonly INamedTypeSymbol owner;
        private readonly HashSet<INamedTypeSymbol> dependentTypes = new(SymbolEqualityComparer.Default);

        public DependencyCollector(SemanticModel model, SyntaxNode ownerDeclaration, INamedTypeSymbol owner)
        {
            this.model = model;
            this.ownerDeclaration = ownerDeclaration;
            this.owner = owner;
        }

        public List<string> Collect()
        {
            Visit(ownerDeclaration);
            return dependentTypes
                .Where(IsTrackedType)
                .Where(type => !SymbolEqualityComparer.Default.Equals(type, owner))
                .Select(TypeId)
                .ToList();
        }

        public override void Visit(SyntaxNode? node)
        {
            if (node is null || node is TypeSyntax || node != ownerDeclaration && node is TypeDeclarationSyntax)
            {
                return;
            }
            if (OwnedTypeSyntax(node) is { } typeSyntax)
            {
                AddTypeSyntax(typeSyntax);
            }
            base.Visit(node);
        }

        public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)
        {
            if (node.Initializer is not null)
            {
                var typeInfo = model.GetTypeInfo(node.Initializer.Value);
                Add(typeInfo.Type);
                Add(typeInfo.ConvertedType);
            }
            base.VisitVariableDeclarator(node);
        }

        public override void VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
        {
            if (!IsSimpleNameChain(node.Expression))
            {
                base.VisitMemberAccessExpression(node);
                return;
            }
            if (model.GetSymbolInfo(node.Expression).Symbol is INamedTypeSymbol symbol)
            {
                Add(symbol);
                return;
            }
            base.VisitMemberAccessExpression(node);
        }

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            if (IsNameOf(node))
            {
                return;
            }
            var genericName = node.Expression switch
            {
                GenericNameSyntax generic => generic,
                MemberAccessExpressionSyntax { Name: GenericNameSyntax generic } => generic,
                _ => null,
            };
            if (genericName is not null)
            {
                foreach (var argument in genericName.TypeArgumentList.Arguments)
                {
                    AddTypeSyntax(argument);
                }
            }
            base.VisitInvocationExpression(node);
        }

        private void AddTypeSyntax(TypeSyntax typeSyntax)
        {
            if (typeSyntax is PredefinedTypeSyntax)
            {
                return;
            }
            var symbol = model.GetSymbolInfo(typeSyntax).Symbol;
            if (symbol is not null)
            {
                Add(symbol);
                return;
            }
            var typeInfo = model.GetTypeInfo(typeSyntax);
            Add(typeInfo.Type);
            Add(typeInfo.ConvertedType);
        }

        private void Add(ISymbol? symbol)
        {
            switch (symbol)
            {
                case IAliasSymbol alias:
                    Add(alias.Target);
                    break;
                case IArrayTypeSymbol array:
                    Add(array.ElementType);
                    break;
                case IPointerTypeSymbol pointer:
                    Add(pointer.PointedAtType);
                    break;
                case INamedTypeSymbol named:
                    Add(named);
                    break;
            }
        }

        private void Add(ITypeSymbol? type) => Add(type as ISymbol);

        private void Add(INamedTypeSymbol named)
        {
            dependentTypes.Add(named.OriginalDefinition);
            if (named.ContainingType is not null)
            {
                Add(named.ContainingType);
            }
            if (!named.IsGenericType)
            {
                return;
            }
            if (named.IsUnboundGenericType)
            {
                foreach (var parameter in named.TypeParameters)
                {
                    foreach (var constraint in parameter.ConstraintTypes)
                    {
                        Add(constraint);
                    }
                }
            }
            else
            {
                foreach (var argument in named.TypeArguments.OfType<INamedTypeSymbol>())
                {
                    Add(argument);
                }
            }
        }

        private static bool IsSimpleNameChain(ExpressionSyntax expression)
        {
            var current = expression;
            while (current is MemberAccessExpressionSyntax memberAccess)
            {
                current = memberAccess.Expression;
            }
            return current is TypeSyntax;
        }

        private static bool IsNameOf(InvocationExpressionSyntax invocation) =>
            invocation.Expression is IdentifierNameSyntax identifier
            && identifier.Identifier.ValueText == "nameof";

        private static TypeSyntax? OwnedTypeSyntax(SyntaxNode node) => node switch
        {
            BaseFieldDeclarationSyntax { Declaration: { } declaration } => declaration.Type,
            BasePropertyDeclarationSyntax property => property.Type,
            ConversionOperatorDeclarationSyntax conversion => conversion.Type,
            DelegateDeclarationSyntax @delegate => @delegate.ReturnType,
            MethodDeclarationSyntax method => method.ReturnType,
            OperatorDeclarationSyntax @operator => @operator.ReturnType,
            ParenthesizedLambdaExpressionSyntax lambda => lambda.ReturnType,
            SimpleLambdaExpressionSyntax lambda => lambda.Parameter.Type,
            CatchDeclarationSyntax declaration => declaration.Type,
            ParameterSyntax parameter => parameter.Type,
            VariableDeclarationSyntax declaration => declaration.Type,
            CatchClauseSyntax { Declaration: { } declaration } => declaration.Type,
            FixedStatementSyntax { Declaration: { } declaration } => declaration.Type,
            ForEachStatementSyntax @foreach => @foreach.Type,
            ForStatementSyntax { Declaration: { } declaration } => declaration.Type,
            LocalDeclarationStatementSyntax { Declaration: { } declaration } => declaration.Type,
            UsingStatementSyntax { Declaration: { } declaration } => declaration.Type,
            BinaryExpressionSyntax
            {
                RawKind: (int)SyntaxKind.IsExpression or (int)SyntaxKind.AsExpression,
                Right: TypeSyntax type,
            } => type,
            CastExpressionSyntax cast => cast.Type,
            DefaultExpressionSyntax @default => @default.Type,
            ObjectCreationExpressionSyntax creation => creation.Type,
            RefValueExpressionSyntax refValue => refValue.Type,
            SizeOfExpressionSyntax sizeOf => sizeOf.Type,
            StackAllocArrayCreationExpressionSyntax stackAlloc => stackAlloc.Type,
            TypeOfExpressionSyntax typeOf => typeOf.Type,
            AttributeSyntax attribute => attribute.Name,
            BaseTypeSyntax baseType => baseType.Type,
            TypeConstraintSyntax constraint => constraint.Type,
            UsingDirectiveSyntax @using => @using.NamespaceOrType,
            FromClauseSyntax from => from.Type,
            JoinClauseSyntax join => join.Type,
            LocalFunctionStatementSyntax localFunction => localFunction.ReturnType,
            DeclarationExpressionSyntax declarationExpression => declarationExpression.Type,
            DeclarationPatternSyntax declarationPattern => declarationPattern.Type,
            RecursivePatternSyntax recursivePattern when recursivePattern.Type is not null => recursivePattern.Type,
            RefTypeSyntax refType => refType.Type,
            TupleElementSyntax tupleElement => tupleElement.Type,
            TypeSyntax type => type,
            _ => null,
        };

        private static bool IsTrackedType(INamedTypeSymbol type) =>
            type.TypeKind != TypeKind.Enum && !Ignored(type);

        private static bool Ignored(INamedTypeSymbol type)
        {
            if (type.SpecialType is SpecialType.System_Void or SpecialType.System_Boolean or SpecialType.System_Byte
                or SpecialType.System_SByte or SpecialType.System_Int16 or SpecialType.System_UInt16
                or SpecialType.System_Int32 or SpecialType.System_UInt32 or SpecialType.System_Int64
                or SpecialType.System_UInt64 or SpecialType.System_IntPtr or SpecialType.System_UIntPtr
                or SpecialType.System_Char or SpecialType.System_Single or SpecialType.System_Double
                or SpecialType.System_String or SpecialType.System_Object)
            {
                return true;
            }
            var display = type.OriginalDefinition
                .ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                .Replace("global::", "", StringComparison.Ordinal);
            return display is "System.Threading.Tasks.Task" or "System.Lazy<T>" or "System.Action" or "System.Func"
                || display.StartsWith("System.Threading.Tasks.Task<", StringComparison.Ordinal)
                || display.StartsWith("System.Threading.Tasks.ValueTask<", StringComparison.Ordinal)
                || display.StartsWith("System.Action<", StringComparison.Ordinal)
                || display.StartsWith("System.Func<", StringComparison.Ordinal)
                || display.StartsWith("System.Lazy<", StringComparison.Ordinal);
        }
    }

    private sealed class BaseTypeParameterData
    {
        public BaseTypeParameterData(IParameterSymbol parameter, Accessibility methodAccessibility)
        {
            Parameter = parameter;
            _ = methodAccessibility;
        }

        public IParameterSymbol Parameter { get; }
        public bool ShouldReportOn { get; set; } = true;
        public Dictionary<ITypeSymbol, int> UsedAs { get; } = new(SymbolEqualityComparer.Default);

        public void AddUsage(ITypeSymbol type)
        {
            UsedAs[type] = UsedAs.TryGetValue(type, out var count) ? count + 1 : 1;
        }
    }

    private sealed class VarianceUse
    {
        public bool Input { get; set; }
        public bool Output { get; set; }
    }

    private enum VariancePosition
    {
        Input,
        Output,
        Both,
    }

    private sealed class ProjectCompilationModel
    {
        public ProjectCompilationModel(
            Project project,
            CSharpCompilation compilation,
            List<SyntaxTree> trees,
            List<SyntaxTree> generatedTrees,
            Dictionary<SyntaxTree, SemanticModel> models)
        {
            Project = project;
            Compilation = compilation;
            Trees = trees;
            GeneratedTrees = generatedTrees;
            Models = models;
        }

        public Project Project { get; }
        public CSharpCompilation Compilation { get; }
        public List<SyntaxTree> Trees { get; }
        public List<SyntaxTree> GeneratedTrees { get; }
        public Dictionary<SyntaxTree, SemanticModel> Models { get; }
    }

    private sealed class RazorSourceFact
    {
        public RazorMetrics Metrics { get; set; } = new();
        public List<int> CodeLineNumbers { get; set; } = new();
    }

    private sealed class RazorMetrics
    {
        public int Lines { get; set; }
        public int CodeLines { get; set; }
        public int CommentLines { get; set; }
    }
    private enum SemanticStatus
    {
        Complete,
        Incomplete,
    }

    private enum NullableMode
    {
        Disable,
        Enable,
        Warnings,
        Annotations,
    }

    private sealed class HelperRequest
    {
        public int SchemaVersion { get; set; }
        public string Project { get; set; } = "";
        public string? TargetFramework { get; set; }
        public List<string> Defines { get; set; } = new();
        public string? LanguageVersion { get; set; }
        public NullableMode Nullable { get; set; }
        public bool TrustedEvaluation { get; set; }
        public bool TrustedBuild { get; set; }
        public bool IncludeRazorGenerated { get; set; }
        public string ProjectManifestDigest { get; set; } = "";
        public List<SourceSnapshot> Sources { get; set; } = new();
    }

    private sealed class SourceSnapshot
    {
        public string Path { get; set; } = "";
        public string Source { get; set; } = "";
        public string ContentDigest { get; set; } = "";
        public string? Project { get; set; }
    }

    private sealed class HelperResponse
    {
        public int SchemaVersion { get; set; }
        public SemanticStatus Status { get; set; }
        public List<SemanticDiagnostic> Diagnostics { get; set; } = new();
        public CompilerFingerprint Compiler { get; set; } = new();
        public string DependencyFingerprint { get; set; } = "";
        public SemanticFacts Facts { get; set; } = new();
    }

    private sealed class SemanticDiagnostic
    {
        public string Code { get; set; } = "";
        public string Message { get; set; } = "";
        public string? Path { get; set; }
    }

    private sealed class CompilerFingerprint
    {
        public string HelperVersion { get; set; } = "";
        public string CompilerVersion { get; set; } = "";
        public string CompilerDigest { get; set; } = "";
        public string SdkVersion { get; set; } = "";
        public string TargetFramework { get; set; } = "";
        public List<string> Defines { get; set; } = new();
        public string LanguageVersion { get; set; } = "";
        public string Nullable { get; set; } = "";
        public string ProjectDigest { get; set; } = "";
        public string ReferenceDigest { get; set; } = "";
        public string DependencyDigest { get; set; } = "";
    }

    private sealed class SemanticFacts
    {
        public Dictionary<string, string> SourceDigests { get; set; } = new();
        public Dictionary<string, RazorSourceFact> RazorSourceFacts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<TypeFact> Types { get; set; } = new();
        public List<CastFact> Casts { get; set; } = new();
        public List<RedundantCastFact> RedundantCasts { get; set; } = new();
        public List<BaseTypeSuggestionFact> BaseTypeSuggestions { get; set; } = new();
        public List<GenericVarianceFact> GenericVariance { get; set; } = new();
        public List<RefObjectParameterFact> RefObjectParameters { get; set; } = new();
        public List<BlazorLambdaFact> BlazorLambdas { get; set; } = new();
        public List<CompilerQuickFixFact> QuickFixes { get; set; } = new();
    }

    private sealed class SemanticTypeRef
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string MetadataName { get; set; } = "";
        public string Namespace { get; set; } = "";
        public string RootNamespace { get; set; } = "";
        public bool IsInterface { get; set; }
        public bool IsClass { get; set; }
        public bool IsStruct { get; set; }
        public bool IsSealed { get; set; }
    }

    private sealed class TypeFact
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string MetadataName { get; set; } = "";
        public string Namespace { get; set; } = "";
        public string RootNamespace { get; set; } = "";
        public string SourcePath { get; set; } = "";
        public SemanticSpan Span { get; set; }
        public string Kind { get; set; } = "";
        public bool IsInterface { get; set; }
        public bool IsClass { get; set; }
        public bool IsStruct { get; set; }
        public bool IsSealed { get; set; }
        public bool IsAbstract { get; set; }
        public List<SemanticTypeRef> BaseChain { get; set; } = new();
        public List<SemanticTypeRef> Interfaces { get; set; } = new();
        public List<string> Dependencies { get; set; } = new();
    }

    private sealed class CastFact
    {
        public string SourcePath { get; set; } = "";
        public SemanticSpan Span { get; set; }
        public SemanticTypeRef InterfaceType { get; set; } = new();
        public SemanticTypeRef ExpressionType { get; set; } = new();
        public bool ExpressionIsInterface { get; set; }
        public bool Impossible { get; set; }
        public string Message { get; set; } = "";
    }

    private sealed class RedundantCastFact
    {
        public string SourcePath { get; set; } = "";
        public SemanticSpan Span { get; set; }
        public string Message { get; set; } = "";
    }

    private sealed class BaseTypeSuggestionFact
    {
        public string SourcePath { get; set; } = "";
        public SemanticSpan Span { get; set; }
        public string MethodId { get; set; } = "";
        public string ParameterId { get; set; } = "";
        public string ParameterName { get; set; } = "";
        public SemanticTypeRef DeclaredType { get; set; } = new();
        public SemanticTypeRef SuggestedType { get; set; } = new();
        public bool Safe { get; set; }
        public string Message { get; set; } = "";
    }

    private sealed class GenericVarianceFact
    {
        public string SourcePath { get; set; } = "";
        public SemanticSpan Span { get; set; }
        public string OwnerId { get; set; } = "";
        public string ParameterId { get; set; } = "";
        public string ParameterName { get; set; } = "";
        public string CurrentVariance { get; set; } = "";
        public string SuggestedVariance { get; set; } = "";
        public bool Safe { get; set; }
        public string Message { get; set; } = "";
    }

    private sealed class RefObjectParameterFact
    {
        public string SourcePath { get; set; } = "";
        public SemanticSpan MethodSpan { get; set; }
        public SemanticSpan ParameterSpan { get; set; }
        public string MethodId { get; set; } = "";
        public string ParameterId { get; set; } = "";
        public string ParameterName { get; set; } = "";
        public string Message { get; set; } = "";
        public string SecondaryMessage { get; set; } = "";
    }

    private sealed class BlazorLambdaFact
    {
        public string GeneratedPath { get; set; } = "";
        public SemanticSpan GeneratedSpan { get; set; }
        public string SourcePath { get; set; } = "";
        public SemanticSpan SourceSpan { get; set; }
        public string InvocationSymbolId { get; set; } = "";
        public string InvocationMember { get; set; } = "";
        public string ContainingType { get; set; } = "";
        public string Message { get; set; } = "";
    }

    private readonly record struct SemanticSpan
    {
        public int StartLine { get; init; }
        public int StartColumn { get; init; }
        public int EndLine { get; init; }
        public int EndColumn { get; init; }
    }
}
