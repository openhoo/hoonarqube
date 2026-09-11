using System.Text;
using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.Operations;

// This module is intentionally independent of SonarAnalyzer assemblies.  The
// only inputs are the caller's CSharpCompilation and its already-created
// semantic models.  The upstream source used for the provider contracts is
// SonarSource/sonar-dotnet commit 842fee9569f61c426f48218c3733b3fad124fd78.
internal static class QuickFixPlanner
{
    internal static List<CompilerQuickFixFact> Collect(
        CSharpCompilation compilation,
        IReadOnlyDictionary<SyntaxTree, SemanticModel> models,
        IReadOnlySet<string> editablePaths,
        List<CompilerRedundantCastFact>? redundantCastFacts = null)
    {
        var facts = new List<CompilerQuickFixFact>();
        var proofFacts = redundantCastFacts ?? new List<CompilerRedundantCastFact>();
        var trees = models.Keys
            .Where(tree => IsEditable(tree, editablePaths))
            .OrderBy(tree => NormalizePath(tree.FilePath), StringComparer.Ordinal)
            .ToList();

        foreach (var tree in trees)
        {
            var model = models[tree];
            var root = tree.GetRoot();
            CollectS1006(compilation, tree, root, model, facts);
            CollectS1155(compilation, tree, root, model, facts);
            CollectS1172(tree, root, model, models, facts);
            CollectS1185(tree, root, model, facts);
            CollectS1186(compilation, tree, root, model, facts);
            CollectS1905(compilation, tree, root, model, facts, proofFacts);
            CollectS1939(tree, root, model, facts);
            CollectS2219(compilation, tree, root, model, facts);
            CollectS2328(tree, root, model, models, facts);
            CollectS2737(tree, root, facts);
            CollectS2933(tree, root, model, models, facts);
            CollectS2934(compilation, tree, root, model, models, editablePaths, facts);
            CollectS2955(tree, root, model, facts);
            CollectS3005(compilation, tree, root, model, facts);
            CollectS3169(compilation, tree, root, model, facts);
            CollectS3217(compilation, tree, root, model, facts);
            CollectS3234(compilation, tree, root, model, facts);
            CollectS3240(tree, root, model, facts);
            CollectS3253(tree, root, model, facts);
            CollectS3254(tree, root, model, facts);
            CollectS3262(tree, root, model, facts);
            CollectS3265(compilation, tree, root, model, models, editablePaths, facts);
            CollectS3440(tree, root, model, facts);
            CollectS3447(tree, root, model, facts);
            CollectS3450(compilation, tree, root, model, facts);
            CollectS3451(compilation, tree, root, model, facts);
            CollectS3456(compilation, tree, root, model, facts);
            CollectS3600(tree, root, model, facts);
            CollectS3604(tree, root, model, models, facts);
            CollectS4201(tree, root, model, facts);
            CollectS4581(compilation, tree, root, model, facts);
            CollectS6610(compilation, tree, root, model, facts);
            CollectS6613(compilation, tree, root, model, facts);
            CollectS6961(compilation, tree, root, model, facts);

            // These are compiler proof facts for existing native planners.  No
            // semantic action is invented here; quickfix.rs owns their exact
            // source-only edit once the proof span is accepted.
            CollectS1125(tree, root, model, facts);
            CollectS1128(compilation, tree, root, model, models, facts);
            CollectS1940(tree, root, model, facts);
            CollectS2333(tree, root, model, models, facts);
            CollectS2761(tree, root, model, facts);
        }

        // The remaining proof-only rules need all source trees to establish
        // project identity.  Their facts are still anchored in one editable
        // source, so a native planner can consume them without a cross-file
        // edit set.
        foreach (var tree in trees)
        {
            var model = models[tree];
            var root = tree.GetRoot();
            CollectS2933Project(tree, root, model, models, facts);
            CollectS3005Project(tree, root, model, facts);
            CollectS3169Project(compilation, tree, root, model, facts);
            CollectS3234Project(compilation, tree, root, model, facts);
            CollectS3262Project(tree, root, model, facts);
            CollectS3447Project(tree, root, model, facts);
            CollectS3600Project(tree, root, model, facts);
            CollectS6610Project(compilation, tree, root, model, facts);
            CollectS6613Project(compilation, tree, root, model, facts);
        }

        facts.Sort((left, right) =>
        {
            var path = StringComparer.Ordinal.Compare(left.SourcePath, right.SourcePath);
            if (path != 0) return path;
            var start = left.StartByte.CompareTo(right.StartByte);
            if (start != 0) return start;
            var end = left.EndByte.CompareTo(right.EndByte);
            if (end != 0) return end;
            return StringComparer.Ordinal.Compare(left.RuleKey, right.RuleKey);
        });
        return facts;
    }

    private static void CollectS1006(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (model.GetDeclaredSymbol(parameter) is not IParameterSymbol parameterSymbol
                || parameterSymbol.ContainingSymbol is not IMethodSymbol method)
            {
                continue;
            }

            if (method.MethodKind == MethodKind.ExplicitInterfaceImplementation
                || method.ExplicitInterfaceImplementations.Length > 0)
            {
                if (parameter.Default is not null)
                {
                    AddFact(facts, tree, "csharpsquid:S1006", parameter.Default.Span,
                        Action("csharp.s1006.remove-explicit-interface-default", "Remove default parameter value from explicit interface implementation", Edit(tree, RemoveInlineTrivia(tree, parameter.Default.Span), "")));
                }
                continue;
            }

            var overridden = OverriddenOrInterfaceMember(method);
            if (overridden is null)
            {
                continue;
            }
            var position = ParameterIndex(method, parameterSymbol);
            if (position < 0 || position >= overridden.Parameters.Length)
            {
                continue;
            }
            var overriddenParameter = overridden.Parameters[position];
            if (parameter.Default is not null && !overriddenParameter.HasExplicitDefaultValue)
            {
                AddFact(facts, tree, "csharpsquid:S1006", parameter.Default.Span,
                    Action("csharp.s1006.synchronize-default", "Synchronize default parameter value", Edit(tree, RemoveInlineTrivia(tree, parameter.Default.Span), "")));
                continue;
            }
            if (parameter.Default is null && overriddenParameter.HasExplicitDefaultValue)
            {
                var defaultSyntax = DefaultClause(overriddenParameter);
                if (defaultSyntax is null)
                {
                    continue;
                }
                var replacement = " " + defaultSyntax.ToFullString();
                AddFact(facts, tree, "csharpsquid:S1006", parameter.Identifier.Span,
                    Action("csharp.s1006.synchronize-default", "Synchronize default parameter value", Edit(tree, new TextSpan(parameter.Span.End, 0), replacement)));
                continue;
            }
            if (parameter.Default is { Value: { } value }
                && overriddenParameter.HasExplicitDefaultValue
                && !SameDefault(parameter.Default, overriddenParameter, model))
            {
                var defaultSyntax = DefaultClause(overriddenParameter);
                if (defaultSyntax is null)
                {
                    continue;
                }
                AddFact(facts, tree, "csharpsquid:S1006", value.Span,
                    Action("csharp.s1006.synchronize-default", "Synchronize default parameter value", Edit(tree, value.Span, defaultSyntax.Value.ToFullString())));
            }
        }
    }

    private static void CollectS1155(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            var count = CountSide(binary, model, compilation);
            if (count is null)
            {
                continue;
            }
            var countNode = count.Value.Node;
            var method = count.Value.Method;
            if (method is null)
            {
                continue;
            }

            ExpressionSyntax any;
            if (method.ReducedFrom is null)
            {
                if (countNode is not InvocationExpressionSyntax staticCount
                    || staticCount.ArgumentList.Arguments.Count == 0)
                {
                    continue;
                }
                var source = staticCount.ArgumentList.Arguments[0].Expression;
                any = SyntaxFactory.InvocationExpression(
                    SyntaxFactory.MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression,
                        source,
                        SyntaxFactory.IdentifierName("Any")),
                    SyntaxFactory.ArgumentList(staticCount.ArgumentList.Arguments.RemoveAt(0)));
            }
            else if (countNode is InvocationExpressionSyntax invocation
                && invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                any = invocation.WithExpression(memberAccess.WithName(SyntaxFactory.IdentifierName("Any")));
            }
            else
            {
                continue;
            }

            var name = CountName(countNode);
            if (name is null)
            {
                continue;
            }
            var replacement = SyntaxFactory.PrefixUnaryExpression(SyntaxKind.LogicalNotExpression, any)
                .WithTriviaFrom(binary)
                .ToFullString();
            AddFact(facts, tree, "csharpsquid:S1155", name.Value.Span,
                Action("csharp.s1155.use-any", "Use Any() instead.", Edit(tree, binary.Span, replacement)));
        }
    }

    private static void CollectS1172(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (model.GetDeclaredSymbol(parameter) is not IParameterSymbol parameterSymbol
                || parameterSymbol.ContainingSymbol is not IMethodSymbol method
                || !IsRemovableParameter(method, parameter, model, root)
                || HasProjectReference(method, models))
            {
                continue;
            }
            if (ParameterIsRead(parameterSymbol, method, model, parameter.Parent?.Parent))
            {
                continue;
            }
            if (parameter.Parent is not ParameterListSyntax parameterList)
            {
                continue;
            }
            var rewrittenParameterList = parameterList.RemoveNode(parameter, SyntaxRemoveOptions.KeepLeadingTrivia | SyntaxRemoveOptions.AddElasticMarker);
            if (rewrittenParameterList is null)
            {
                continue;
            }
            var replacement = rewrittenParameterList.ToString().TrimEnd(' ', '\t');
            AddFact(facts, tree, "csharpsquid:S1172", parameter.Span,
                Action("csharp.s1172.remove-unused-parameter", "Remove unused parameter", Edit(tree, parameterList.Span, replacement)));
        }
    }

    private static void CollectS1185(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var methodSyntax in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (model.GetDeclaredSymbol(methodSyntax) is not IMethodSymbol method || method.OverriddenMethod is null || methodSyntax.Body is null || methodSyntax.Body.Statements.Count != 1 || methodSyntax.AttributeLists.Count != 0 || !methodSyntax.Modifiers.Any(SyntaxKind.OverrideKeyword) || !ForwardsToBase(methodSyntax, method, model))
            {
                continue;
            }
            AddFact(facts, tree, "csharpsquid:S1185", methodSyntax.Span,
                Action("csharp.s1185.remove-forwarding-override", "Remove redundant override", Edit(tree, RemoveInlineTrivia(tree, methodSyntax.Span), "")));
        }
    }

    private static void CollectS1186(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        if (compilation.GetTypeByMetadataName("System.NotSupportedException") is null)
        {
            return;
        }
        foreach (var member in root.DescendantNodes().Where(node => node is MethodDeclarationSyntax or OperatorDeclarationSyntax))
        {
            var body = member switch
            {
                MethodDeclarationSyntax method => method.Body,
                OperatorDeclarationSyntax op => op.Body,
                _ => null,
            };
            if (body is null || body.Statements.Count != 0 || HasAttributeLists(member))
            {
                continue;
            }
            var name = member switch
            {
                MethodDeclarationSyntax method => method.Identifier,
                OperatorDeclarationSyntax op => op.OperatorToken,
                _ => default,
            };
            if (name == default)
            {
                continue;
            }
            var unqualified = model.LookupNamespacesAndTypes(body.CloseBraceToken.SpanStart)
                .OfType<INamedTypeSymbol>()
                .Any(symbol => symbol.Name == "NotSupportedException" && symbol.ContainingNamespace?.ToDisplayString() == "System");
            var exceptionName = unqualified ? "NotSupportedException" : "System.NotSupportedException";
            var eol = SourceText(tree).ToString().Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var indent = LineIndent(SourceText(tree).ToString(), body.SpanStart);
            var commentBody = "{" + eol + indent + "    // Method intentionally left empty." + eol + indent + "}";
            var throwBody = "{" + eol + indent + "    throw new " + exceptionName + "();" + eol + indent + "}";
            AddFact(facts, tree, "csharpsquid:S1186", name.Span,
                Action("csharp.s1186.add-not-supported-throw", "Throw NotSupportedException", Edit(tree, body.Span, throwBody)),
                Action("csharp.s1186.add-empty-method-comment", "Add comment", Edit(tree, body.Span, commentBody)));
        }
    }
    private static void CollectS1905(
        CSharpCompilation compilation,
        SyntaxTree tree,
        SyntaxNode root,
        SemanticModel model,
        List<CompilerQuickFixFact> facts,
        List<CompilerRedundantCastFact> redundantCastFacts)
    {
        // RedundantCastCodeFix intentionally delegates CastExpression fixes
        // to IDE0004.  We still emit the compiler-proven finding, but do not
        // manufacture an S1905 action for that syntax shape.
        foreach (var cast in root.DescendantNodes().OfType<CastExpressionSyntax>())
        {
            var expression = cast.Expression;
            while (expression is ParenthesizedExpressionSyntax parenthesized)
            {
                expression = parenthesized.Expression;
            }
            var expressionKind = expression.Kind().ToString();
            if (cast.Expression.IsKind(SyntaxKind.DefaultLiteralExpression)
                || expressionKind is "StackAllocArrayCreationExpression" or "ImplicitStackAllocArrayCreationExpression")
            {
                continue;
            }

            var expressionInfo = model.GetTypeInfo(cast.Expression);
            var castInfo = model.GetTypeInfo(cast.Type);
            if (expressionInfo.Type is not { } expressionType
                || castInfo.Type is not { } castType
                || !SameTypeIgnoringNullability(expressionType, castType)
                || !FlowStateEquals(expressionInfo, cast.Type, castType))
            {
                continue;
            }

            AddRedundantCastFact(
                redundantCastFacts,
                tree,
                cast.Type.Span,
                RedundantCastMessage(model, castType, cast.Expression.SpanStart));
        }

        foreach (var asExpression in root.DescendantNodes().OfType<BinaryExpressionSyntax>().Where(node => node.IsKind(SyntaxKind.AsExpression)))
        {
            var expression = asExpression.Left;
            while (expression is ParenthesizedExpressionSyntax parenthesized)
            {
                expression = parenthesized.Expression;
            }
            var expressionKind = expression.Kind().ToString();
            if (expressionKind is "StackAllocArrayCreationExpression" or "ImplicitStackAllocArrayCreationExpression")
            {
                continue;
            }
            var expressionInfo = model.GetTypeInfo(asExpression.Left);
            var castInfo = model.GetTypeInfo(asExpression.Right);
            if (expressionInfo.Type is not { } expressionType
                || castInfo.Type is not { } castType
                || !SameTypeIgnoringNullability(expressionType, castType)
                || !FlowStateEquals(expressionInfo, asExpression.Right, castType))
            {
                continue;
            }

            var message = RedundantCastMessage(model, castType, asExpression.SpanStart);
            var diagnosticSpan = TextSpan.FromBounds(asExpression.OperatorToken.SpanStart, asExpression.Right.Span.End);
            AddRedundantCastFact(redundantCastFacts, tree, diagnosticSpan, message);
            AddFact(
                facts,
                tree,
                "csharpsquid:S1905",
                diagnosticSpan,
                Action(
                    "csharp.s1905.remove-redundant-cast",
                    "Remove redundant cast",
                    Edit(tree, asExpression.Span, asExpression.Left.WithTriviaFrom(asExpression).ToFullString())));
        }

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (!TryGetEnumerableCast(invocation, model, compilation, out var method, out var collection, out var castType))
            {
                continue;
            }
            var elementType = GetElementType(model, collection);
            if (elementType is null
                || !SameTypeWithNullability(elementType, castType)
                || elementType.NullableAnnotation != castType.NullableAnnotation
                || (method.Name == "OfType" && CanHaveNullValue(castType)))
            {
                continue;
            }

            var methodCalledAsStatic = method.MethodKind == MethodKind.Ordinary;
            var diagnosticSpan = methodCalledAsStatic
                ? invocation.Expression.Span
                : invocation.Expression is MemberAccessExpressionSyntax member
                    ? TextSpan.FromBounds(member.OperatorToken.SpanStart, invocation.Span.End)
                    : default;
            if (diagnosticSpan == default)
            {
                continue;
            }

            var message = RedundantCastMessage(model, castType, invocation.SpanStart);
            var trustedEnumerableMethod = IsTrustedEnumerableMethod(method, compilation);
            if (methodCalledAsStatic)
            {
                var argument = invocation.ArgumentList.Arguments.FirstOrDefault()?.Expression;
                if (argument is null)
                {
                    continue;
                }
                // Keep the compiler-backed diagnostic for parity, but only
                // project the removal action for the framework implementation.
                AddRedundantCastFact(redundantCastFacts, tree, diagnosticSpan, message);
                if (!trustedEnumerableMethod)
                {
                    continue;
                }
                AddFact(
                    facts,
                    tree,
                    "csharpsquid:S1905",
                    diagnosticSpan,
                    Action(
                        "csharp.s1905.remove-redundant-cast",
                        "Remove redundant cast",
                        Edit(tree, invocation.Span, argument.ToFullString())));
            }
            else if (invocation.Expression is MemberAccessExpressionSyntax extension)
            {
                // Keep the compiler-backed diagnostic for parity, but only
                // project the removal action for the framework implementation.
                AddRedundantCastFact(redundantCastFacts, tree, diagnosticSpan, message);
                if (!trustedEnumerableMethod)
                {
                    continue;
                }
                AddFact(
                    facts,
                    tree,
                    "csharpsquid:S1905",
                    diagnosticSpan,
                    Action(
                        "csharp.s1905.remove-redundant-cast",
                        "Remove redundant cast",
                        Edit(tree, invocation.Span, extension.Expression.ToFullString())));
            }
        }
    }

    private static void AddRedundantCastFact(
        List<CompilerRedundantCastFact> facts,
        SyntaxTree tree,
        TextSpan span,
        string message)
    {
        var text = SourceText(tree);
        if (span.Start < 0 || span.End > text.Length || span.Start > span.End)
        {
            return;
        }
        facts.Add(new CompilerRedundantCastFact
        {
            SourcePath = NormalizePath(tree.FilePath),
            StartByte = Utf8Offset(text, span.Start),
            EndByte = Utf8Offset(text, span.End),
            Message = message,
        });
    }

    private static string RedundantCastMessage(SemanticModel model, ITypeSymbol castType, int position) =>
        $"Remove this unnecessary cast to '{castType.ToMinimalDisplayString(model, position)}'.";

    private static bool SameTypeIgnoringNullability(ITypeSymbol left, ITypeSymbol right)
    {
        if (!SymbolEqualityComparer.Default.Equals(left, right))
        {
            return false;
        }
        if (left is INamedTypeSymbol leftNamed && right is INamedTypeSymbol rightNamed)
        {
            if (leftNamed.TypeArguments.Length != rightNamed.TypeArguments.Length)
            {
                return false;
            }
            for (var index = 0; index < leftNamed.TypeArguments.Length; index++)
            {
                if (!SameTypeIgnoringNullability(leftNamed.TypeArguments[index], rightNamed.TypeArguments[index]))
                {
                    return false;
                }
            }
        }
        return true;
    }

    private static bool SameTypeWithNullability(ITypeSymbol left, ITypeSymbol right) =>
        SameTypeIgnoringNullability(left, right)
        && left.NullableAnnotation == right.NullableAnnotation
        && InnerNullabilityEquals(left, right);
    private static bool FlowStateEquals(TypeInfo expressionInfo, SyntaxNode castTypeExpression, ITypeSymbol castType)
    {
        var castingToNullable = castTypeExpression.IsKind(SyntaxKind.NullableType)
            || castType.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T;
        return expressionInfo.Nullability.FlowState switch
        {
            NullableFlowState.None => true,
            NullableFlowState.MaybeNull => castingToNullable,
            NullableFlowState.NotNull => !castingToNullable,
            _ => true,
        } && TypeArgumentsNullabilityEquals(expressionInfo.Type, castType);
    }

    private static bool TypeArgumentsNullabilityEquals(ITypeSymbol? expressionType, ITypeSymbol castType)
    {
        if (expressionType is null)
        {
            return false;
        }
        if (expressionType is INamedTypeSymbol expressionNamed && castType is INamedTypeSymbol castNamed)
        {
            if (expressionNamed.TypeArguments.Length != castNamed.TypeArguments.Length)
            {
                return false;
            }
            for (var index = 0; index < expressionNamed.TypeArguments.Length; index++)
            {
                if (!InnerNullabilityEquals(expressionNamed.TypeArguments[index], castNamed.TypeArguments[index]))
                {
                    return false;
                }
            }
        }
        return true;
    }

    private static bool InnerNullabilityEquals(ITypeSymbol? expressionType, ITypeSymbol castType)
    {
        if (expressionType is null || expressionType.NullableAnnotation != castType.NullableAnnotation)
        {
            return false;
        }
        return TypeArgumentsNullabilityEquals(expressionType, castType);
    }

    private static bool CanHaveNullValue(ITypeSymbol type) =>
        type.IsReferenceType || type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T;

    private static bool TryGetEnumerableCast(
        InvocationExpressionSyntax invocation,
        SemanticModel model,
        CSharpCompilation compilation,
        out IMethodSymbol method,
        out ExpressionSyntax collection,
        out ITypeSymbol castType)
    {
        method = null!;
        collection = null!;
        castType = null!;
        if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol symbol
            || symbol.Name is not ("Cast" or "OfType")
            || symbol.ReturnType is not INamedTypeSymbol returnType
            || returnType.TypeArguments.Length != 1)
        {
            return false;
        }

        var definition = symbol.ReducedFrom ?? symbol;
        if (definition.Parameters.Length == 0)
        {
            return false;
        }
        var genericEnumerable = compilation.GetTypeByMetadataName("System.Collections.Generic.IEnumerable`1");
        var nonGenericEnumerable = compilation.GetTypeByMetadataName("System.Collections.IEnumerable");
        if (!definition.IsExtensionMethod
            || genericEnumerable is null
            || nonGenericEnumerable is null
            || !SymbolEqualityComparer.Default.Equals(returnType.OriginalDefinition, genericEnumerable)
            || definition.Parameters[0].Type is not INamedTypeSymbol receiver
            || !SymbolEqualityComparer.Default.Equals(receiver, nonGenericEnumerable))
        {
            return false;
        }

        if (symbol.MethodKind == MethodKind.ReducedExtension)
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member)
            {
                return false;
            }
            collection = member.Expression;
        }
        else
        {
            collection = invocation.ArgumentList.Arguments.FirstOrDefault()?.Expression!;
            if (collection is null)
            {
                return false;
            }
        }
        castType = returnType.TypeArguments[0];
        method = symbol;

        return true;
    }
    private static bool IsTrustedEnumerableMethod(IMethodSymbol method, CSharpCompilation compilation)
    {
        var enumerable = compilation.GetTypeByMetadataName("System.Linq.Enumerable");
        if (enumerable is null)
        {
            return false;
        }

        var definition = method.ReducedFrom ?? method;
        var methodAssembly = definition.ContainingAssembly;
        var enumerableAssembly = enumerable.ContainingAssembly;
        return methodAssembly is not null
            && enumerableAssembly is not null
            && SymbolEqualityComparer.Default.Equals(definition.ContainingType, enumerable)
            && SymbolEqualityComparer.Default.Equals(methodAssembly, enumerableAssembly)
            && methodAssembly.Identity.Equals(enumerableAssembly.Identity);
    }


    private static ITypeSymbol? GetElementType(SemanticModel model, ExpressionSyntax collection) =>
        model.GetTypeInfo(collection).Type switch
        {
            INamedTypeSymbol { TypeArguments: { Length: 1 } typeArguments } => typeArguments[0],
            IArrayTypeSymbol { Rank: 1 } arrayType => arrayType.ElementType,
            _ => null,
        };


    private static void CollectS1939(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var declaration in root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>())
        {
            if (declaration.BaseList is null || model.GetDeclaredSymbol(declaration) is not INamedTypeSymbol owner)
            {
                continue;
            }
            var seen = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
            for (var index = 0; index < declaration.BaseList.Types.Count; index++)
            {
                var baseType = declaration.BaseList.Types[index];
                var symbol = model.GetTypeInfo(baseType.Type).Type;
                if (symbol is null)
                {
                    continue;
                }
                var redundant = !seen.Add(symbol) && !SymbolEqualityComparer.Default.Equals(symbol, owner);
                if (!redundant && symbol is INamedTypeSymbol inherited)
                {
                    for (var priorIndex = 0; priorIndex < index; priorIndex++)
                    {
                        if (model.GetTypeInfo(declaration.BaseList.Types[priorIndex].Type).Type is INamedTypeSymbol prior
                            && prior.AllInterfaces.Any(candidate => SymbolEqualityComparer.Default.Equals(candidate, inherited)))
                        {
                            redundant = true;
                            break;
                        }
                    }
                }
                if (redundant)
                {
                    var end = baseType.Span.End;
                    if (end < SourceText(tree).Length && SourceText(tree)[end] == ',') end++;
                    var replacement = RemoveBaseType(declaration, index);
                    AddFact(facts, tree, "csharpsquid:S1939", new TextSpan(baseType.SpanStart, end - baseType.SpanStart),
                        Action("csharp.s1939.remove-redundant-inheritance-entry", "Remove redundant declaration.", Edit(tree, declaration.BaseList.Span, replacement)));
                }
            }
        }
    }

    private static void CollectS2219(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() is not (SyntaxKind.EqualsExpression or SyntaxKind.NotEqualsExpression)) continue;
            if (!GetTypeAndTypeof(binary, model, out var receiver, out var targetType, out var typeofSyntax)) continue;
            // GetType throws for a null receiver while an is-pattern returns
            // false.  Nullable flow state is the compiler's proof that this
            // particular receiver is non-null at the call site; annotations
            // or a static reference type alone are not enough.
            if (model.GetTypeInfo(receiver).Nullability.FlowState != NullableFlowState.NotNull) continue;
            if (!targetType.IsSealed || targetType.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T) continue;
            var replacement = receiver.WithoutTrivia().ToFullString()
                + (binary.IsKind(SyntaxKind.NotEqualsExpression) ? " is not " : " is ")
                + typeofSyntax.Type.WithoutTrivia().ToFullString();
            AddFact(facts, tree, "csharpsquid:S2219", binary.Span,
                Action("csharp.s2219.use-is-pattern", "Simplify type checking.", Edit(tree, binary.Span, replacement)));
        }
    }

    private static void CollectS2328(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var methodSyntax in root.DescendantNodes().OfType<MethodDeclarationSyntax>().Where(method => method.Identifier.ValueText == "GetHashCode"))
        {
            if (model.GetDeclaredSymbol(methodSyntax) is not IMethodSymbol method || method.OverriddenMethod is not { } overridden || overridden.ContainingType?.SpecialType != SpecialType.System_Object || method.Parameters.Length != 0)
            {
                continue;
            }
            var mutable = ReferencedMutableFields(methodSyntax, method, model);
            var declarations = new List<(IFieldSymbol Field, FieldDeclarationSyntax Declaration)>();
            foreach (var field in mutable)
            {
                if (!TryGetSingleEditableDeclaration(field, tree, models, out var declaration))
                {
                    declarations.Clear();
                    break;
                }
                declarations.Add((field, declaration));
            }
            if (declarations.Count != mutable.Count || declarations.Count == 0) continue;
            declarations.Sort((left, right) =>
            {
                var path = StringComparer.Ordinal.Compare(NormalizePath(left.Declaration.SyntaxTree.FilePath), NormalizePath(right.Declaration.SyntaxTree.FilePath));
                return path != 0 ? path : left.Declaration.SpanStart.CompareTo(right.Declaration.SpanStart);
            });
            var edits = new List<CompilerQuickFixEdit>(declarations.Count);
            foreach (var (_, declaration) in declarations)
            {
                var type = declaration.Declaration.Type;
                edits.Add(Edit(tree, type.Span, $"readonly {type.ToString().TrimEnd(' ', '\t')}"));
            }
            AddFact(facts, tree, "csharpsquid:S2328", methodSyntax.Identifier.Span,
                Action("csharp.s2328.remove-mutable-hash-reference", "Make field 'readonly'", edits.ToArray()));
        }
    }

    private static void CollectS2737(SyntaxTree tree, SyntaxNode root, List<CompilerQuickFixFact> facts)
    {
        foreach (var clause in root.DescendantNodes().OfType<CatchClauseSyntax>())
        {
            if (clause.Block.Statements.Count != 1 || clause.Block.Statements[0] is not ThrowStatementSyntax { Expression: null } || clause.Parent is not TryStatementSyntax tryStatement)
            {
                continue;
            }
            string replacement;
            if (tryStatement.Catches.Count == 1 && tryStatement.Finally is null)
            {
                replacement = string.Concat(tryStatement.Block.Statements.Select(statement => statement.ToFullString())).TrimEnd();
                AddFact(facts, tree, "csharpsquid:S2737", clause.Span,
                    Action("csharp.s2737.remove-redundant-catch", "Remove redundant catch.", Edit(tree, tryStatement.Span, replacement)));
            }
            else
            {
                var newTry = tryStatement.RemoveNode(clause, SyntaxRemoveOptions.KeepNoTrivia);
                if (newTry is not null)
                {
                    AddFact(facts, tree, "csharpsquid:S2737", clause.Span,
                        Action("csharp.s2737.remove-redundant-catch", "Remove redundant catch.", Edit(tree, tryStatement.Span, newTry.ToFullString().TrimEnd())));
                }
            }
        }
    }

    private static void CollectS2933(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        // The project-wide pass below emits the proof-only facts.  Keeping this
        // method as a no-op documents that no local approximation is accepted.
    }

    private static void CollectS2934(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, IReadOnlySet<string> editablePaths, List<CompilerQuickFixFact> facts)
    {
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is not MemberAccessExpressionSyntax memberAccess
                || model.GetSymbolInfo(memberAccess.Expression).Symbol is not IFieldSymbol field
                || model.GetSymbolInfo(memberAccess).Symbol is not IPropertySymbol
                || !field.IsReadOnly
                || field.Type is not ITypeParameterSymbol typeParameter
                || !GenericParameterMightBeValueType(typeParameter)
                || IsInsideConstructorDeclaration(memberAccess, field.ContainingType, model))
            {
                continue;
            }
            var remove = new List<CompilerQuickFixEdit>();
            if (assignment.Parent is ExpressionStatementSyntax statement)
            {
                remove.Add(Edit(tree, RemoveStatementTrivia(tree, statement.Span), ""));
            }

            var constraintEdits = GenericClassConstraintEdits(typeParameter, tree, models, editablePaths);
            var actions = new List<CompilerQuickFixAction>();
            if (constraintEdits is not null && constraintEdits.Count > 0)
            {
                actions.Add(new CompilerQuickFixAction { Id = "csharp.s2934.add-reference-constraint", Message = "Add reference type constraint", Edits = constraintEdits });
            }
            if (remove.Count > 0)
            {
                actions.Add(new CompilerQuickFixAction { Id = "csharp.s2934.remove-useless-assignment", Message = "Remove assignment", Edits = remove });
            }
            AddFact(facts, tree, "csharpsquid:S2934", memberAccess.Span, actions.ToArray());
        }
    }

    private static void CollectS2955(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() is not (SyntaxKind.EqualsExpression or SyntaxKind.NotEqualsExpression)) continue;
            var value = binary.Left.IsKind(SyntaxKind.NullLiteralExpression) ? binary.Right : binary.Right.IsKind(SyntaxKind.NullLiteralExpression) ? binary.Left : null;
            if (value is not IdentifierNameSyntax identifier || model.GetTypeInfo(value).Type is not ITypeParameterSymbol typeParameter || HasReferenceOrValueConstraint(typeParameter)) continue;
            var valueText = value.WithoutTrivia().ToFullString();
            var replacement = binary.IsKind(SyntaxKind.NotEqualsExpression)
                ? $"!object.Equals({valueText}, default({typeParameter.Name}))"
                : $"object.Equals({valueText}, default({typeParameter.Name}))";
            AddFact(facts, tree, "csharpsquid:S2955", binary.Left.IsKind(SyntaxKind.NullLiteralExpression) ? binary.Left.Span : binary.Right.Span,
                Action("csharp.s2955.use-default-value", "Change null checking.", Edit(tree, binary.Span, replacement)));
        }
    }

    private static void CollectS3005(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var threadStatic = FrameworkType(compilation, "System.ThreadStaticAttribute");
        if (threadStatic is null) return;
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (field.Modifiers.Any(SyntaxKind.StaticKeyword)) continue;
            foreach (var attribute in field.AttributeLists.SelectMany(list => list.Attributes))
            {
                if (!IsAttribute(attribute, model, threadStatic)
                    || attribute.Parent is not AttributeListSyntax list
                    || list.Attributes.Count != 1) continue;
                AddFact(facts, tree, "csharpsquid:S3005", attribute.Span,
                    Action("csharp.s3005.remove-threadstatic", "Remove 'ThreadStatic' attribute", Edit(tree, IncludeFollowingSpace(tree, list.Span), "")));
            }
        }
    }
    private static void CollectS3169(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        // S3169 requires the complete project pass below so its action is
        // backed by the same exact Enumerable symbols as its proof.
    }
    private static void CollectS3217(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var enumerable = compilation.GetTypeByMetadataName("System.Linq.Enumerable");
        if (enumerable is null) return;
        foreach (var each in root.DescendantNodes().OfType<ForEachStatementSyntax>())
        {
            if (each.Type is null || model.GetTypeInfo(each.Type).Type is null || model.GetTypeInfo(each.Expression).Type is not INamedTypeSymbol collectionType || collectionType.TypeArguments.Length == 0) continue;
            var element = collectionType.TypeArguments[0];
            var loopType = model.GetTypeInfo(each.Type).Type;
            if (SymbolEqualityComparer.Default.Equals(element, loopType) || element.SpecialType == SpecialType.System_Object) continue;
            var ofType = SyntaxFactory.InvocationExpression(
                SyntaxFactory.MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, each.Expression, SyntaxFactory.GenericName(SyntaxFactory.Identifier("OfType"), SyntaxFactory.TypeArgumentList(SyntaxFactory.SingletonSeparatedList<TypeSyntax>(each.Type.WithoutTrivia())))),
                SyntaxFactory.ArgumentList());
            var edits = new List<CompilerQuickFixEdit>();
            if (!HasLinqInScope(each, model))
            {
                var usingEdit = LinqUsingEdit(tree, each);
                if (usingEdit is null) continue;
                edits.Add(usingEdit);
            }
            edits.Add(Edit(tree, each.Expression.Span, ofType.ToString()));
            AddFact(facts, tree, "csharpsquid:S3217", each.Type.Span,
                new CompilerQuickFixAction { Id = "csharp.s3217.change-foreach-type", Message = "Filter collection for the expected type", Edits = edits });
        }
    }

    private static CompilerQuickFixEdit? LinqUsingEdit(SyntaxTree tree, ForEachStatementSyntax anchor)
    {
        if (tree.GetRoot() is not CompilationUnitSyntax unit) return null;
        var source = SourceText(tree).ToString();
        var eol = source.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var replacement = $"using System.Linq;{eol}";

        CompilerQuickFixEdit InsertAtLineStart(int position)
        {
            var lineStart = source.LastIndexOf('\n', Math.Max(0, position - 1));
            lineStart = lineStart < 0 ? 0 : lineStart + 1;
            var indentation = source.Substring(lineStart, position - lineStart);
            if (indentation.All(char.IsWhiteSpace))
            {
                return Edit(tree, new TextSpan(lineStart, 0), indentation + replacement);
            }
            return Edit(tree, new TextSpan(position, 0), replacement);
        }

        var namespaceWithUsing = anchor.AncestorsAndSelf()
            .OfType<BaseNamespaceDeclarationSyntax>()
            .FirstOrDefault(candidate => candidate.Usings.Count > 0);
        if (namespaceWithUsing is not null)
        {
            return InsertAtLineStart(namespaceWithUsing.Usings[0].SpanStart);
        }
        if (unit.Usings.Count > 0)
        {
            return InsertAtLineStart(unit.Usings[0].SpanStart);
        }
        var firstMember = unit.Members.FirstOrDefault();
        return InsertAtLineStart(firstMember?.SpanStart ?? source.Length);
    }

    private static void CollectS3234(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (!TryGetValidS3234Invocation(compilation, invocation, model, out var statement)) continue;
            AddFact(facts, tree, "csharpsquid:S3234", invocation.Span,
                Action("csharp.s3234.remove-suppress-finalize", "Remove useless 'SuppressFinalize' call.", Edit(tree, RemoveInlineTrivia(tree, statement.Span), "")));
        }
    }

    private static bool TryGetValidS3234Invocation(
        CSharpCompilation compilation,
        InvocationExpressionSyntax invocation,
        SemanticModel model,
        out ExpressionStatementSyntax statement)
    {
        statement = null!;
        if (invocation.Parent is not ExpressionStatementSyntax expressionStatement
            || model.GetOperation(invocation) is not IInvocationOperation operation
            || operation.TargetMethod.Name != "SuppressFinalize"
            || operation.TargetMethod.ContainingType is not INamedTypeSymbol containingType
            || !SymbolEqualityComparer.Default.Equals(containingType, FrameworkType(compilation, "System.GC"))
            || operation.Arguments.Length != 1
            || operation.Arguments[0].Value.Syntax is not ThisExpressionSyntax
            || invocation.FirstAncestorOrSelf<ClassDeclarationSyntax>() is not { } declaration
            || model.GetDeclaredSymbol(declaration) is not INamedTypeSymbol type
            || !type.IsSealed
            || HasFinalizer(type))
        {
            return false;
        }
        statement = expressionStatement;
        return true;
    }

    private static bool HasFinalizer(INamedTypeSymbol type)
    {
        for (var current = type;
            current is not null && current.SpecialType != SpecialType.System_Object;
            current = current.BaseType)
        {
            if (current.GetMembers().OfType<IMethodSymbol>().Any(member => member.MethodKind == MethodKind.Destructor))
            {
                return true;
            }
        }
        return false;
    }
    private static void CollectS3240(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            if (ifStatement.Else is null || ifStatement.Condition is null || !SimpleBranch(ifStatement.Statement) || !SimpleBranch(ifStatement.Else.Statement)) continue;
            var branches = BranchStatements(ifStatement);
            if (branches.Count != 2) continue;
            if (branches.Any(statement => statement is not ReturnStatementSyntax && statement is not ExpressionStatementSyntax)) continue;
            if (branches.Any(statement => statement is ExpressionStatementSyntax expression && model.GetOperation(expression.Expression) is null)) continue;
            var replacement = ConditionalReplacement(ifStatement);
            if (replacement is null) continue;
            AddFact(facts, tree, "csharpsquid:S3240", new TextSpan(ifStatement.SpanStart, 2),
                Action("csharp.s3240.simplify-condition", "Simplify condition", Edit(tree, ifStatement.Span, replacement.WithoutLeadingTrivia().WithoutTrailingTrivia().ToFullString())));
        }
    }

    private static void CollectS3253(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var ctor in root.DescendantNodes().OfType<ConstructorDeclarationSyntax>())
        {
            if (ctor.ParameterList.Parameters.Count != 0 || ctor.Body is null || ctor.Body.Statements.Count != 0 || ctor.Initializer is not null || ctor.Modifiers.Any(SyntaxKind.PrivateKeyword) || ctor.AttributeLists.Count != 0) continue;
            if (model.GetDeclaredSymbol(ctor) is not IMethodSymbol symbol || symbol.DeclaredAccessibility == Accessibility.Private) continue;
            AddFact(facts, tree, "csharpsquid:S3253", ctor.Span,
                Action("csharp.s3253.remove-redundant-constructor", "Remove this redundant constructor.", Edit(tree, RemoveInlineTrivia(tree, ctor.Span), "")));
        }
    }

    private static void CollectS3254(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var argumentList in root.DescendantNodes().OfType<ArgumentListSyntax>())
        {
            if (argumentList.Parent is BaseTypeSyntax
                || IsInExpressionTree(argumentList, model)
                || argumentList.Arguments.Count == 0)
            {
                continue;
            }
            var mappings = BindArguments(argumentList, model);
            if (mappings is null)
            {
                continue;
            }
            var redundant = new List<ArgumentBinding>();
            foreach (var mapping in mappings.AsEnumerable().Reverse().Where(mapping => mapping.Parameter.HasExplicitDefaultValue))
            {
                var syntax = mapping.Syntax;
                if (DefaultMatches(mapping, model))
                {
                    redundant.Add(mapping);
                }
                else if (syntax.NameColon is null)
                {
                    break;
                }
            }
            if (redundant.Count == 0)
            {
                continue;
            }

            var allRedundant = redundant
                .Select(argument => argument.Syntax)
                .OfType<ArgumentSyntax>()
                .ToHashSet();
            var removableWithoutNamed = new HashSet<ArgumentSyntax>();
            var canBeRemovedWithoutNamed = true;
            foreach (var mapping in mappings.AsEnumerable().Reverse())
            {
                if (mapping.Syntax is not ArgumentSyntax argument)
                {
                    continue;
                }
                if (allRedundant.Contains(argument))
                {
                    if (canBeRemovedWithoutNamed)
                    {
                        removableWithoutNamed.Add(argument);
                    }
                }
                else if (argument.NameColon is null)
                {
                    canBeRemovedWithoutNamed = false;
                }
            }

            var actions = new List<CompilerQuickFixAction>();
            var plain = RemoveArguments(argumentList, removableWithoutNamed);
            if (plain is not null && removableWithoutNamed.Count > 0)
            {
                actions.Add(new CompilerQuickFixAction
                {
                    Id = "csharp.s3254.remove-default-argument",
                    Message = "Remove redundant arguments",
                    Edits = new List<CompilerQuickFixEdit> { Edit(tree, argumentList.Span, plain) },
                });
            }
            if (allRedundant.Except(removableWithoutNamed).Any())
            {
                var named = RemoveArgumentsAndName(argumentList, mappings, allRedundant, model);
                if (named is not null)
                {
                    actions.Add(new CompilerQuickFixAction
                    {
                        Id = "csharp.s3254.remove-default-arguments-with-names",
                        Message = "Remove redundant arguments with adding named arguments",
                        Edits = new List<CompilerQuickFixEdit> { Edit(tree, argumentList.Span, named) },
                    });
                }
            }
            if (actions.Count > 0)
            {
                foreach (var argument in allRedundant)
                {
                    AddFact(facts, tree, "csharpsquid:S3254", argument.Span, actions.ToArray());
                }
            }
        }
    }

    private static void CollectS3262(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var declaration in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (model.GetDeclaredSymbol(declaration) is not IMethodSymbol method
                || OverriddenOrInterfaceMember(method) is not IMethodSymbol overridden
                || declaration.ParameterList.Parameters.Count != method.Parameters.Length
                || overridden.Parameters.Length != method.Parameters.Length)
            {
                continue;
            }
            for (var index = 0; index < method.Parameters.Length; index++)
            {
                var baseParameter = overridden.Parameters[index];
                var parameter = method.Parameters[index];
                if (!baseParameter.IsParams
                    || declaration.ParameterList.Parameters[index].Modifiers.Any(SyntaxKind.ParamsKeyword)
                    || baseParameter.Type is not IArrayTypeSymbol baseArray
                    || parameter.Type is not IArrayTypeSymbol parameterArray
                    || !SymbolEqualityComparer.Default.Equals(baseArray.ElementType, parameterArray.ElementType))
                {
                    continue;
                }
                var syntaxParameter = declaration.ParameterList.Parameters[index];
                AddFact(facts, tree, "csharpsquid:S3262", syntaxParameter.Span,
                    Action("csharp.s3262.add-params", "Add the 'params' modifier", Edit(tree, new TextSpan(syntaxParameter.Type?.SpanStart ?? syntaxParameter.SpanStart, 0), "params ")));
            }
        }
    }
    private static void CollectS3265(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, IReadOnlySet<string> editablePaths, List<CompilerQuickFixFact> facts)
    {
        var flagsAttribute = compilation.GetTypeByMetadataName("System.FlagsAttribute");
        var ignoredEnum = compilation.GetTypeByMetadataName("System.Reflection.MethodImplAttributes");
        if (flagsAttribute is null)
        {
            return;
        }

        foreach (var operationSyntax in root.DescendantNodes().Where(node =>
            node is BinaryExpressionSyntax binary && binary.Kind() is SyntaxKind.BitwiseOrExpression or SyntaxKind.BitwiseAndExpression or SyntaxKind.ExclusiveOrExpression
            || node is AssignmentExpressionSyntax assignment && assignment.Kind() is SyntaxKind.AndAssignmentExpression or SyntaxKind.OrAssignmentExpression or SyntaxKind.ExclusiveOrAssignmentExpression))
        {
            var operation = model.GetSymbolInfo(operationSyntax).Symbol as IMethodSymbol;
            if (operation is null
                || operation.MethodKind != MethodKind.BuiltinOperator
                || operation.ReturnType.TypeKind != TypeKind.Enum
                || operation.ReturnType.GetAttributes().Any(attribute => SymbolEqualityComparer.Default.Equals(attribute.AttributeClass, flagsAttribute))
                || ignoredEnum is not null && SymbolEqualityComparer.Default.Equals(operation.ReturnType, ignoredEnum))
            {
                continue;
            }

            var declaration = operation.ReturnType.DeclaringSyntaxReferences
                .Select(reference => reference.GetSyntax())
                .OfType<EnumDeclarationSyntax>()
                .FirstOrDefault();
            if (declaration is null || declaration.SyntaxTree != tree || !IsEditable(declaration.SyntaxTree, editablePaths))
            {
                // The DTO carries offsets for one source path only.  Do not
                // truncate the provider's cross-document enum edit.
                continue;
            }

            var flagsName = flagsAttribute.ToMinimalDisplayString(model, declaration.SpanStart);
            if (flagsName.EndsWith("Attribute", StringComparison.Ordinal))
            {
                flagsName = flagsName[..^"Attribute".Length];
            }
            var eol = SourceText(tree).ToString().Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var flagsList = SyntaxFactory.AttributeList(
                SyntaxFactory.SingletonSeparatedList(
                    SyntaxFactory.Attribute(SyntaxFactory.ParseName(flagsName))))
                .WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.EndOfLine(eol)));
            var updated = declaration.AddAttributeLists(flagsList);
            var operatorSpan = operationSyntax switch
            {
                BinaryExpressionSyntax binary => binary.OperatorToken.Span,
                AssignmentExpressionSyntax assignment => assignment.OperatorToken.Span,
                _ => default,
            };
            if (operatorSpan == default)
            {
                continue;
            }
            var replacement = updated.ToString();
            if (replacement.EndsWith(eol, StringComparison.Ordinal))
            {
                replacement = replacement[..^eol.Length];
            }
            AddFact(facts, tree, "csharpsquid:S3265", operatorSpan,
                Action("csharp.s3265.add-flags-attribute", "Add [Flags] to enum declaration", Edit(tree, declaration.Span, replacement)));
        }
    }
    private static void CollectS3440(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            if (ifStatement.Else is not null
                || ifStatement.Parent is ElseClauseSyntax
                || ifStatement.FirstAncestorOrSelf<AccessorDeclarationSyntax>() is { Keyword.ValueText: "set" or "init" }
                || ifStatement.Statement is not BlockSyntax block
                || block.Statements.Count != 1
                || block.Statements[0] is not ExpressionStatementSyntax { Expression: AssignmentExpressionSyntax assignment }
                || !assignment.IsKind(SyntaxKind.SimpleAssignmentExpression))
            {
                continue;
            }
            var condition = ifStatement.Condition;
            if (condition is null) continue;
            condition = UnwrapParentheses(condition);
            if (condition is not BinaryExpressionSyntax binaryCondition
                || !binaryCondition.IsKind(SyntaxKind.NotEqualsExpression)
                || model.GetSymbolInfo(assignment.Left).Symbol is IPropertySymbol
                || !MatchingAssignment(binaryCondition, assignment, model))
            {
                continue;
            }
            var replacement = block.Statements[0].WithTriviaFrom(ifStatement).ToFullString().TrimEnd();
            AddFact(facts, tree, "csharpsquid:S3440", binaryCondition.Span,
                Action("csharp.s3440.remove-useless-condition", "Remove redundant conditional.", Edit(tree, ifStatement.Span, replacement)));
        }

        foreach (var switchExpression in root.DescendantNodes().OfType<SwitchExpressionSyntax>())
        {
            var parent = switchExpression.Parent;
            while (parent is ParenthesizedExpressionSyntax parenthesized)
            {
                parent = parenthesized.Parent;
            }
            if (parent is not AssignmentExpressionSyntax || switchExpression.Arms.Count != 1)
            {
                continue;
            }
            var arm = switchExpression.Arms[0];
            var matches = arm.Pattern switch
            {
                DiscardPatternSyntax => true,
                ConstantPatternSyntax constant when arm.WhenClause is null
                    && MatchingExpression(constant.Expression, arm.Expression, model) => true,
                UnaryPatternSyntax { Pattern: ConstantPatternSyntax constant } unary
                    when unary.IsKind(SyntaxKind.NotPattern)
                    && arm.WhenClause is null
                    && MatchingExpression(constant.Expression, arm.Expression, model) => true,
                _ => false,
            };
            if (!matches)
            {
                continue;
            }
            AddFact(facts, tree, "csharpsquid:S3440", arm.Pattern.Span,
                Action("csharp.s3440.remove-useless-condition", "Remove redundant conditional.", Edit(tree, switchExpression.Span, arm.Expression.WithTriviaFrom(switchExpression).ToFullString())));
        }
    }
    private static void CollectS3447(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts) { }
    private static void CollectS3450(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var optional = FrameworkType(compilation, "System.Runtime.InteropServices.OptionalAttribute");
        var defaultParameter = FrameworkType(compilation, "System.Runtime.InteropServices.DefaultParameterValueAttribute");
        if (optional is null || defaultParameter is null) return;
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            var attribute = parameter.AttributeLists.SelectMany(list => list.Attributes).FirstOrDefault(attribute => IsAttribute(attribute, model, defaultParameter));
            if (attribute is null || parameter.AttributeLists.SelectMany(list => list.Attributes).Any(candidate => IsAttribute(candidate, model, optional))) continue;
            var list = attribute.Parent as AttributeListSyntax;
            if (list is null) continue;
            var optionalName = MinimalAttributeName(optional, model, list.SpanStart);
            var newList = list.AddAttributes(SyntaxFactory.Attribute(SyntaxFactory.ParseName(optionalName)));
            var separatorIndex = newList.Attributes.SeparatorCount - 1;
            if (separatorIndex >= 0)
            {
                var separator = newList.Attributes.GetSeparator(separatorIndex)
                    .WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space));
                newList = newList.WithAttributes(newList.Attributes.ReplaceSeparator(
                    newList.Attributes.GetSeparator(separatorIndex),
                    separator));
            }
            AddFact(facts, tree, "csharpsquid:S3450", attribute.Span,
                Action("csharp.s3450.add-optional-attribute", "Add missing 'Optional' attribute", Edit(tree, list.Span, newList.ToString().TrimEnd(' ', '\t'))));
        }
    }

    private static void CollectS3451(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var optionalAttribute = FrameworkType(compilation, "System.Runtime.InteropServices.OptionalAttribute");
        var sourceAttribute = FrameworkType(compilation, "System.ComponentModel.DefaultValueAttribute");
        var targetAttribute = FrameworkType(compilation, "System.Runtime.InteropServices.DefaultParameterValueAttribute");
        if (optionalAttribute is null || sourceAttribute is null || targetAttribute is null) return;
        foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>())
        {
            if (attribute.ArgumentList?.Arguments.Count != 1
                || !IsAttribute(attribute, model, sourceAttribute)
                || attribute.Parent?.Parent is not ParameterSyntax parameter
                || !parameter.AttributeLists.SelectMany(list => list.Attributes).Any(candidate => IsAttribute(candidate, model, optionalAttribute))) continue;
            var name = MinimalAttributeName(targetAttribute, model, attribute.SpanStart);
            AddFact(facts, tree, "csharpsquid:S3451", attribute.Span,
                Action("csharp.s3451.use-default-parameter-value-attribute", "Change to '[DefaultParameterValue]'", Edit(tree, attribute.Name.Span, name)));
        }
    }
    private static void CollectS3456(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var stringType = compilation.GetSpecialType(SpecialType.System_String);
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member || member.Name.Identifier.ValueText != "ToCharArray" || invocation.ArgumentList.Arguments.Count != 0 || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || !SymbolEqualityComparer.Default.Equals(method.ContainingType, stringType)) continue;
            var parent = invocation.Parent;
            var relevant = parent is ElementAccessExpressionSyntax || parent is ForEachStatementSyntax;
            if (!relevant) continue;
            var receiver = member.Expression;
            AddFact(facts, tree, "csharpsquid:S3456", member.Name.Span,
                Action("csharp.s3456.remove-tochararray", "Remove this redundant 'ToCharArray' call.", Edit(tree, invocation.Span, receiver.ToFullString())));
        }
    }

    private static void CollectS3600(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts) { }
    private static void CollectS3604(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (field.Declaration.Variables.Count != 1) continue;
            var variable = field.Declaration.Variables[0];
            if (variable.Initializer is not EqualsValueClauseSyntax initializer) continue;
            var constant = model.GetConstantValue(initializer.Value);
            if (!constant.HasValue) continue;
            if (model.GetDeclaredSymbol(variable) is not IFieldSymbol symbol) continue;
            if (symbol.IsStatic || symbol.IsConst || IsDefaultFieldInitializer(symbol.Type, constant.Value)) continue;

            var containing = symbol.ContainingType;
            if (containing.DeclaringSyntaxReferences
                .Select(reference => reference.GetSyntax())
                .OfType<ClassDeclarationSyntax>()
                .Any(declaration => declaration.ParameterList is not null))
            {
                // Primary constructors are intentionally outside this
                // proof: their generated/implicit body may initialize a
                // member in ways that are not represented by a declaration
                // constructor.
                continue;
            }
            var constructors = containing.Constructors
                .Where(constructor => !constructor.IsImplicitlyDeclared)
                .SelectMany(constructor => constructor.DeclaringSyntaxReferences
                    .Select(reference => reference.GetSyntax())
                    .OfType<ConstructorDeclarationSyntax>()
                    .Select(syntax => (Symbol: constructor, Syntax: syntax)))
                .ToList();
            if (constructors.Count == 0
                || containing.Constructors.Any(constructor => constructor.IsPartialDefinition && constructor.PartialImplementationPart is null)
                || !constructors.All(constructor => models.TryGetValue(constructor.Syntax.SyntaxTree, out var constructorModel)
                    && IsSymbolFirstSetInCfg(symbol, constructor.Syntax, constructorModel!)))
            {
                continue;
            }
            AddFact(facts, tree, "csharpsquid:S3604", initializer.Span,
                Action("csharp.s3604.remove-redundant-initializer", "Remove redundant initializer", Edit(tree, RemoveInitializerTrivia(tree, variable, initializer), "")));
        }
    }
    private static bool IsDefaultFieldInitializer(ITypeSymbol type, object? value)
    {
        if (value is null)
        {
            return type.IsReferenceType
                || type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T;
        }

        if (type.TypeKind == TypeKind.Enum)
        {
            return IsZeroConstant(value);
        }

        return type.SpecialType switch
        {
            SpecialType.System_Boolean => value is bool boolean && !boolean,
            SpecialType.System_Char => value is char character && character == '\0',
            SpecialType.System_SByte
                or SpecialType.System_Byte
                or SpecialType.System_Int16
                or SpecialType.System_UInt16
                or SpecialType.System_Int32
                or SpecialType.System_UInt32
                or SpecialType.System_Int64
                or SpecialType.System_UInt64
                or SpecialType.System_Single
                or SpecialType.System_Double
                or SpecialType.System_Decimal => IsZeroConstant(value),
            _ => false,
        };
    }

    private static bool IsZeroConstant(object value) =>
        value switch
        {
            sbyte number => number == 0,
            byte number => number == 0,
            short number => number == 0,
            ushort number => number == 0,
            int number => number == 0,
            uint number => number == 0,
            long number => number == 0,
            ulong number => number == 0,
            float number => number == 0,
            double number => number == 0,
            decimal number => number == 0,
            _ => false,
        };

    private static void CollectS4201(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var logical in root.DescendantNodes().OfType<BinaryExpressionSyntax>().Where(binary => binary.Kind() is SyntaxKind.LogicalAndExpression or SyntaxKind.LogicalOrExpression))
        {
            var sides = new[] { logical.Left, logical.Right };
            foreach (var candidate in sides.OfType<BinaryExpressionSyntax>())
            {
                var other = sides.First(side => !ReferenceEquals(side, candidate));
                var expected = logical.IsKind(SyntaxKind.LogicalAndExpression) ? SyntaxKind.NotEqualsExpression : SyntaxKind.EqualsExpression;
                if (!candidate.IsKind(expected) || !IsIdentifierNullComparison(candidate, model) || !PatternMatches(other, candidate, logical, model)) continue;
                AddFact(facts, tree, "csharpsquid:S4201", candidate.Span,
                    Action("csharp.s4201.remove-redundant-null-check", "Remove this unnecessary null check", Edit(tree, logical.Span, other.ToString())));
            }
        }
    }

    private static void CollectS4581(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var guid = compilation.GetTypeByMetadataName("System.Guid");
        if (guid is null) return;
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            if (creation.ArgumentList?.Arguments.Count != 0 || !SymbolEqualityComparer.Default.Equals(model.GetTypeInfo(creation).Type, guid)) continue;
            var useShortName = CanUseUnqualifiedGuidName(model, creation.Type.SpanStart, guid);
            var guidName = useShortName
                ? (NameSyntax)SyntaxFactory.IdentifierName("Guid")
                : SyntaxFactory.QualifiedName(
                    SyntaxFactory.AliasQualifiedName(
                        SyntaxFactory.IdentifierName("global"),
                        SyntaxFactory.IdentifierName("System")),
                    SyntaxFactory.IdentifierName("Guid"));
            var replacement = SyntaxFactory.MemberAccessExpression(
                SyntaxKind.SimpleMemberAccessExpression,
                guidName,
                SyntaxFactory.IdentifierName("Empty"));
            AddFact(facts, tree, "csharpsquid:S4581", creation.Span,
                Action("csharp.s4581.use-guid-empty", "Use 'Guid.Empty'.", Edit(tree, creation.Span, replacement.ToFullString())));
        }
    }

    private static bool CanUseUnqualifiedGuidName(SemanticModel model, int position, INamedTypeSymbol guid)
    {
        var identifier = SyntaxFactory.IdentifierName("Guid");
        var typeSymbolInfo = model.GetSpeculativeSymbolInfo(position, identifier, SpeculativeBindingOption.BindAsTypeOrNamespace);
        var typeInfo = model.GetSpeculativeTypeInfo(position, identifier, SpeculativeBindingOption.BindAsTypeOrNamespace);
        if (typeSymbolInfo.CandidateReason != CandidateReason.None
            || typeSymbolInfo.CandidateSymbols.Length != 0
            || !SymbolEqualityComparer.Default.Equals(typeInfo.Type, guid))
        {
            return false;
        }

        var expressionSymbolInfo = model.GetSpeculativeSymbolInfo(position, identifier, SpeculativeBindingOption.BindAsExpression);
        if (expressionSymbolInfo.CandidateReason != CandidateReason.None || expressionSymbolInfo.CandidateSymbols.Length != 0)
        {
            return false;
        }

        var typeSymbol = typeSymbolInfo.Symbol is IAliasSymbol typeAlias ? typeAlias.Target : typeSymbolInfo.Symbol;
        var expressionSymbol = expressionSymbolInfo.Symbol is IAliasSymbol expressionAlias ? expressionAlias.Target : expressionSymbolInfo.Symbol;
        return SymbolEqualityComparer.Default.Equals(typeSymbol, guid)
            && SymbolEqualityComparer.Default.Equals(expressionSymbol, guid);
    }

    private static void CollectS6610(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts) { }
    private static void CollectS6613(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts) { }
    private static void CollectS6961(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var controller = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.Controller");
        var controllerBase = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.ControllerBase");
        if (controller is null || controllerBase is null) return;
        foreach (var declaration in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            if (model.GetDeclaredSymbol(declaration) is not INamedTypeSymbol type || declaration.BaseList is null) continue;
            var baseType = declaration.BaseList.Types.FirstOrDefault(candidate => SymbolEqualityComparer.Default.Equals(model.GetTypeInfo(candidate.Type).Type, controller));
            if (baseType is null || UsesControllerOnlyApi(declaration, model, controller)) continue;
            var anchor = baseType.Type;
            AddFact(facts, tree, "csharpsquid:S6961", anchor.Span,
                Action("csharp.s6961.change-to-controllerbase", "Inherit from ControllerBase instead of Controller.", Edit(tree, anchor.Span, "ControllerBase")));
        }
    }

    private static void CollectS1125(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() is not (SyntaxKind.EqualsExpression or SyntaxKind.NotEqualsExpression) || model.GetOperation(binary) is not Microsoft.CodeAnalysis.Operations.IBinaryOperation operation || operation.OperatorMethod is not null) continue;
            var literal = binary.Left.IsKind(SyntaxKind.TrueLiteralExpression) || binary.Left.IsKind(SyntaxKind.FalseLiteralExpression) ? binary.Left : binary.Right.IsKind(SyntaxKind.TrueLiteralExpression) || binary.Right.IsKind(SyntaxKind.FalseLiteralExpression) ? binary.Right : null;
            var other = ReferenceEquals(literal, binary.Left) ? binary.Right : binary.Left;
            if (literal is null || model.GetTypeInfo(other).Type?.SpecialType != SpecialType.System_Boolean) continue;
            var span = literal.SpanStart < binary.OperatorToken.SpanStart ? new TextSpan(literal.SpanStart, binary.OperatorToken.Span.End - literal.SpanStart) : new TextSpan(binary.OperatorToken.SpanStart, literal.Span.End - binary.OperatorToken.SpanStart);
            AddFact(facts, tree, "csharpsquid:S1125", span);
        }
    }

    private static void CollectS1128(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var directive in root.DescendantNodes().OfType<UsingDirectiveSyntax>())
        {
            if (directive.GlobalKeyword != default || directive.StaticKeyword != default || directive.Alias is not null || !UsingIsUnused(directive, root, model)) continue;
            AddFact(facts, tree, "csharpsquid:S1128", directive.Span);
        }
    }

    private static void CollectS1940(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var unary in root.DescendantNodes().OfType<PrefixUnaryExpressionSyntax>())
        {
            if (!unary.IsKind(SyntaxKind.LogicalNotExpression) || unary.Operand is not ParenthesizedExpressionSyntax { Expression: BinaryExpressionSyntax binary } || binary.Kind() is not (SyntaxKind.EqualsExpression or SyntaxKind.NotEqualsExpression)) continue;
            if (model.GetOperation(binary) is Microsoft.CodeAnalysis.Operations.IBinaryOperation operation && operation.OperatorMethod is null)
            {
                AddFact(facts, tree, "csharpsquid:S1940", unary.Span);
            }
        }
    }

    private static void CollectS2333(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var declaration in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            if (!declaration.Modifiers.Any(SyntaxKind.PartialKeyword) || model.GetDeclaredSymbol(declaration) is not INamedTypeSymbol symbol || symbol.DeclaringSyntaxReferences.Length != 1)
            {
                continue;
            }
            var modifier = declaration.Modifiers.First(token => token.IsKind(SyntaxKind.PartialKeyword));
            AddFact(facts, tree, "csharpsquid:S2333", modifier.Span);
        }
        foreach (var member in root.DescendantNodes().Where(node => node is MethodDeclarationSyntax or PropertyDeclarationSyntax or IndexerDeclarationSyntax or EventDeclarationSyntax or EventFieldDeclarationSyntax))
        {
            var modifiers = ModifiersOf(member);
            if (!modifiers.Any(SyntaxKind.SealedKeyword) || member.Parent is not TypeDeclarationSyntax owner || !owner.Modifiers.Any(SyntaxKind.SealedKeyword)) continue;
            var modifier = modifiers.First(token => token.IsKind(SyntaxKind.SealedKeyword));
            AddFact(facts, tree, "csharpsquid:S2333", modifier.Span);
        }
        foreach (var declaration in root.DescendantNodes().Where(node => node is MethodDeclarationSyntax or ConstructorDeclarationSyntax or OperatorDeclarationSyntax or ConversionOperatorDeclarationSyntax))
        {
            var modifiers = ModifiersOf(declaration);
            if (!modifiers.Any(SyntaxKind.UnsafeKeyword) || (HasUnsafeContext(declaration) || !ContainsUnsafeConstruct(declaration))) continue;
            AddFact(facts, tree, "csharpsquid:S2333", modifiers.First(token => token.IsKind(SyntaxKind.UnsafeKeyword)).Span);
        }
        foreach (var unsafeStatement in root.DescendantNodes().OfType<UnsafeStatementSyntax>())
        {
            if ((HasUnsafeContext(unsafeStatement) || !ContainsUnsafeConstruct(unsafeStatement)) && unsafeStatement.UnsafeKeyword != default)
            {
                AddFact(facts, tree, "csharpsquid:S2333", unsafeStatement.UnsafeKeyword.Span);
            }
        }
        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            var rank = AccessibilityRank(property.Modifiers);
            var accessors = property.AccessorList?.Accessors ?? default;
            if (rank == 0 || accessors.Count == 0 || accessors.Any(accessor => AccessibilityRank(accessor.Modifiers) != rank)) continue;
            foreach (var accessor in accessors)
            {
                var modifier = accessor.Modifiers.FirstOrDefault(token => AccessibilityRank(new SyntaxTokenList(token)) == rank);
                if (modifier != default) AddFact(facts, tree, "csharpsquid:S2333", accessor.Span);
            }
        }
    }

    private static void CollectS2761(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var outer in root.DescendantNodes().OfType<PrefixUnaryExpressionSyntax>())
        {
            if (outer.Parent is PrefixUnaryExpressionSyntax parent && parent.OperatorToken.Kind() == outer.OperatorToken.Kind()) continue;
            if (outer.Operand is not PrefixUnaryExpressionSyntax inner || inner.OperatorToken.Kind() != outer.OperatorToken.Kind() || outer.OperatorToken.Kind() is not (SyntaxKind.ExclamationToken or SyntaxKind.TildeToken)) continue;
            var operandType = model.GetTypeInfo(inner.Operand).Type;
            var valid = outer.IsKind(SyntaxKind.LogicalNotExpression) ? operandType?.SpecialType == SpecialType.System_Boolean : IsIntegralOrEnum(operandType);
            if (valid && model.GetOperation(outer) is Microsoft.CodeAnalysis.Operations.IUnaryOperation operation && operation.OperatorMethod is null)
            {
                AddFact(facts, tree, "csharpsquid:S2761", new TextSpan(outer.OperatorToken.SpanStart, inner.OperatorToken.Span.End - outer.OperatorToken.SpanStart));
            }
        }
    }

    private static void CollectS2933Project(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts)
    {
        foreach (var fieldDeclaration in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (fieldDeclaration.Declaration.Variables.Count != 1 || fieldDeclaration.Modifiers.Any(token => token.IsKind(SyntaxKind.ReadOnlyKeyword) || token.IsKind(SyntaxKind.ConstKeyword)) || fieldDeclaration.AttributeLists.Count != 0 || model.GetDeclaredSymbol(fieldDeclaration.Declaration.Variables[0]) is not IFieldSymbol field || field.DeclaredAccessibility != Accessibility.Private || field.ContainingType.DeclaringSyntaxReferences.Length > 1) continue;
            var writes = FieldWrites(field, model, models);
            if (writes.Count == 0 && fieldDeclaration.Declaration.Variables[0].Initializer is null || writes.Any(write => !IsConstructorWrite(write, field))) continue;
            if (writes.Any(write => write.Syntax is ArgumentSyntax argument && argument.RefOrOutKeyword != default)) continue;
            AddFact(facts, tree, "csharpsquid:S2933", fieldDeclaration.Declaration.Variables[0].Identifier.Span);
        }
    }

    private static void CollectS3005Project(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var attributeType = FrameworkType(model.Compilation, "System.ThreadStaticAttribute");
        if (attributeType is null) return;
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (field.Modifiers.Any(SyntaxKind.StaticKeyword)) continue;
            var attribute = field.AttributeLists.SelectMany(list => list.Attributes).FirstOrDefault(candidate => IsAttribute(candidate, model, attributeType));
            if (attribute is null
                || attribute.Parent is AttributeListSyntax list && list.Attributes.Count == 1) continue;
            AddFact(facts, tree, "csharpsquid:S3005", attribute.Span);
        }
    }

    private static void CollectS3169Project(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var enumerable = FrameworkType(compilation, "System.Linq.Enumerable");
        if (enumerable is null) return;
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member
                || member.Name.Identifier.ValueText is not ("OrderBy" or "OrderByDescending")
                || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method
                || !SymbolEqualityComparer.Default.Equals(method.ContainingType, enumerable)
                || method.Name != member.Name.Identifier.ValueText
                || !HasBoundInvocationArguments(invocation, model))
            {
                continue;
            }
            if (member.Expression is not InvocationExpressionSyntax previous
                || previous.Expression is not MemberAccessExpressionSyntax previousMember
                || previousMember.Name.Identifier.ValueText is not ("OrderBy" or "OrderByDescending")
                || model.GetSymbolInfo(previous).Symbol is not IMethodSymbol previousMethod
                || !SymbolEqualityComparer.Default.Equals(previousMethod.ContainingType, enumerable)
                || previousMethod.Name != previousMember.Name.Identifier.ValueText
                || !HasBoundInvocationArguments(previous, model))
            {
                continue;
            }
            var replacement = member.Name.Identifier.ValueText == "OrderBy"
                ? "ThenBy"
                : "ThenByDescending";
            if (!BindsToFrameworkOrderingReplacement(invocation, member, replacement, enumerable, model))
            {
                continue;
            }
            AddFact(
                facts,
                tree,
                "csharpsquid:S3169",
                member.Name.Span,
                Action(
                    "csharp.s3169.change-orderby-to-thenby",
                    "Change 'OrderBy' to 'ThenBy'",
                    Edit(tree, member.Name.Identifier.Span, replacement)));
        }
    }

    private static void CollectS3234Project(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (!TryGetValidS3234Invocation(compilation, invocation, model, out _)) continue;
            AddFact(facts, tree, "csharpsquid:S3234", invocation.Span);
        }
    }

    private static void CollectS3262Project(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (model.GetDeclaredSymbol(parameter) is not IParameterSymbol symbol
                || symbol.ContainingSymbol is not IMethodSymbol method
                || OverriddenOrInterfaceMember(method) is not { } overridden) continue;
            var index = ParameterIndex(method, symbol);
            if (index < 0
                || index >= overridden.Parameters.Length
                || !overridden.Parameters[index].IsParams
                || parameter.Modifiers.Any(SyntaxKind.ParamsKeyword)
                || parameter.Type is null
                || overridden.Parameters[index].Type is not IArrayTypeSymbol baseArray
                || parameter.Type is not ArrayTypeSyntax currentArray
                || model.GetTypeInfo(currentArray.ElementType).Type is not ITypeSymbol element
                || !SymbolEqualityComparer.Default.Equals(baseArray.ElementType, element)) continue;
            AddFact(facts, tree, "csharpsquid:S3262", parameter.Span);
        }
    }

    private static void CollectS3447Project(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var optional = FrameworkType(model.Compilation, "System.Runtime.InteropServices.OptionalAttribute");
        if (optional is null) return;
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (parameter.Modifiers.All(token => !token.IsKind(SyntaxKind.RefKeyword) && !token.IsKind(SyntaxKind.OutKeyword))) continue;
            var attribute = parameter.AttributeLists.SelectMany(list => list.Attributes).FirstOrDefault(candidate => IsAttribute(candidate, model, optional));
            if (attribute is null) continue;
            AddFact(facts, tree, "csharpsquid:S3447", attribute.Name.Span);
        }
    }

    private static void CollectS3600Project(SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (!parameter.Modifiers.Any(SyntaxKind.ParamsKeyword) || model.GetDeclaredSymbol(parameter) is not IParameterSymbol symbol || symbol.ContainingSymbol is not IMethodSymbol method || method.OverriddenMethod is not { } overridden) continue;
            var index = ParameterIndex(method, symbol);
            if (index < 0 || index >= overridden.Parameters.Length || overridden.Parameters[index].IsParams) continue;
            var modifier = parameter.Modifiers.First(token => token.IsKind(SyntaxKind.ParamsKeyword));
            AddFact(facts, tree, "csharpsquid:S3600", modifier.Span);
        }
    }
    private static bool HasBoundInvocationArguments(InvocationExpressionSyntax invocation, SemanticModel model)
    {
        if (invocation.ArgumentList.Arguments.Count == 0
            || model.GetOperation(invocation) is not IInvocationOperation operation
            || operation.Arguments.Any(argument => argument.Value.Kind == OperationKind.Invalid))
        {
            return false;
        }
        return invocation.ArgumentList.Arguments.All(argument =>
            model.GetOperation(argument.Expression) is { } value
            && value.Kind != OperationKind.Invalid);
    }
    private static bool BindsToFrameworkOrderingReplacement(
        InvocationExpressionSyntax invocation,
        MemberAccessExpressionSyntax member,
        string replacement,
        INamedTypeSymbol enumerable,
        SemanticModel model)
    {
        var replacementToken = SyntaxFactory.Identifier(replacement).WithTriviaFrom(member.Name.Identifier);
        var replacementName = member.Name.ReplaceToken(member.Name.Identifier, replacementToken);
        var speculativeNode = invocation.ReplaceNode(member.Name, replacementName);
        if (speculativeNode is not InvocationExpressionSyntax speculativeInvocation
            || model.GetSpeculativeSymbolInfo(
                    invocation.SpanStart,
                    speculativeInvocation,
                    SpeculativeBindingOption.BindAsExpression)
                .Symbol is not IMethodSymbol target)
        {
            return false;
        }
        return target.Name == replacement
            && SymbolEqualityComparer.Default.Equals(target.ContainingType, enumerable);
    }

    private static void CollectS6610Project(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var stringType = compilation.GetSpecialType(SpecialType.System_String);
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member || member.Name.Identifier.ValueText is not ("StartsWith" or "EndsWith") || invocation.ArgumentList.Arguments.Count != 1 || invocation.ArgumentList.Arguments[0].Expression is not LiteralExpressionSyntax literal || !literal.IsKind(SyntaxKind.StringLiteralExpression) || literal.Token.ValueText.Length != 1 || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || !SymbolEqualityComparer.Default.Equals(method.ContainingType, stringType) || method.Parameters[0].Type.SpecialType != SpecialType.System_String) continue;
            AddFact(facts, tree, "csharpsquid:S6610", member.Name.Span);
        }
    }

    private static void CollectS6613Project(CSharpCompilation compilation, SyntaxTree tree, SyntaxNode root, SemanticModel model, List<CompilerQuickFixFact> facts)
    {
        var linkedList = compilation.GetTypeByMetadataName("System.Collections.Generic.LinkedList`1");
        var enumerable = compilation.GetTypeByMetadataName("System.Linq.Enumerable");
        if (linkedList is null || enumerable is null) return;
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax member || member.Name.Identifier.ValueText is not ("First" or "Last") || invocation.ArgumentList.Arguments.Count != 0 || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || !SymbolEqualityComparer.Default.Equals(method.ContainingType, enumerable) || model.GetTypeInfo(member.Expression).Type is not INamedTypeSymbol receiver || !SymbolEqualityComparer.Default.Equals(receiver.OriginalDefinition, linkedList)) continue;
            AddFact(facts, tree, "csharpsquid:S6613", member.Name.Span);
        }
    }

    private static void CollectS2933ProjectUnused(SyntaxTree tree, SyntaxNode root, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, List<CompilerQuickFixFact> facts) { }

    private static bool IsEditable(SyntaxTree tree, IReadOnlySet<string> paths)
    {
        var normalized = NormalizePath(tree.FilePath);
        return paths.Contains(tree.FilePath) || paths.Contains(normalized) || paths.Any(path => StringComparer.OrdinalIgnoreCase.Equals(NormalizePath(path), normalized));
    }

    private static string NormalizePath(string path) => string.IsNullOrWhiteSpace(path) ? "" : Path.GetFullPath(path);

    private static SourceText SourceText(SyntaxTree tree) => tree.GetText();

    private static CompilerQuickFixEdit Edit(SyntaxTree tree, TextSpan span, string replacement)
    {
        var text = SourceText(tree);
        return new CompilerQuickFixEdit
        {
            StartByte = Utf8Offset(text, span.Start),
            EndByte = Utf8Offset(text, span.End),
            Replacement = replacement,
        };
    }

    private static void AddFact(List<CompilerQuickFixFact> facts, SyntaxTree tree, string key, TextSpan span, params CompilerQuickFixAction[] actions)
    {
        var text = SourceText(tree);
        if (span.Start < 0 || span.End > text.Length || span.Start > span.End) return;
        var normalizedActions = actions.ToList();
        foreach (var action in normalizedActions)
        {
            action.Edits = action.Edits
                .OrderBy(edit => edit.StartByte)
                .ThenBy(edit => edit.EndByte)
                .ToList();
        }
        facts.Add(new CompilerQuickFixFact
        {
            SourcePath = NormalizePath(tree.FilePath),
            RuleKey = key,
            StartByte = Utf8Offset(text, span.Start),
            EndByte = Utf8Offset(text, span.End),
            Actions = normalizedActions,
        });
    }

    private static CompilerQuickFixAction Action(string id, string message, params CompilerQuickFixEdit[] edits) =>
        new()
        {
            Id = id,
            Message = message,
            Edits = edits
                .OrderBy(edit => edit.StartByte)
                .ThenBy(edit => edit.EndByte)
                .ToList(),
        };

    private static int Utf8Offset(SourceText text, int position) => Encoding.UTF8.GetByteCount(text.ToString(new TextSpan(0, position)));

    private static int ParameterIndex(IMethodSymbol method, IParameterSymbol parameter) => method.Parameters.IndexOf(parameter);
    private static IMethodSymbol? OverriddenOrInterfaceMember(IMethodSymbol method)
    {
        if (method.OverriddenMethod is { } overridden)
        {
            return overridden;
        }
        foreach (var interfaceType in method.ContainingType.AllInterfaces)
        {
            foreach (var member in interfaceType.GetMembers(method.Name).OfType<IMethodSymbol>())
            {
                if (SymbolEqualityComparer.Default.Equals(
                    method.ContainingType.FindImplementationForInterfaceMember(member),
                    method))
                {
                    return member;
                }
            }
        }
        return null;
    }

    private static EqualsValueClauseSyntax? DefaultClause(IParameterSymbol parameter) => parameter.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is ParameterSyntax syntax ? syntax.Default : null;

    private static bool SameDefault(EqualsValueClauseSyntax syntax, IParameterSymbol parameter, SemanticModel model) =>
        model.GetConstantValue(syntax.Value) is { HasValue: true } value
        && Equals(value.Value, parameter.ExplicitDefaultValue);

    private static bool IsRemovableParameter(IMethodSymbol method, ParameterSyntax parameter, SemanticModel model, SyntaxNode root)
    {
        if (method.DeclaredAccessibility != Accessibility.Private
            || method.ExplicitInterfaceImplementations.Length != 0
            || method.OverriddenMethod is not null
            || method.PartialDefinitionPart is not null
            || method.PartialImplementationPart is not null
            || method.IsVirtual
            || method.IsAbstract
            || method.IsExtern
            || method.IsVararg
            || method.Name == "Main"
            || method.GetAttributes().Length != 0
            || parameter.AttributeLists.Count != 0)
        {
            return false;
        }
        return parameter.Parent?.Parent is MethodDeclarationSyntax or ConstructorDeclarationSyntax;
    }

    private static bool HasProjectReference(IMethodSymbol method, IReadOnlyDictionary<SyntaxTree, SemanticModel> models)
    {
        foreach (var (tree, model) in models)
        {
            var root = tree.GetRoot();
            foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (model.GetOperation(invocation) is Microsoft.CodeAnalysis.Operations.IInvocationOperation operation
                    && SymbolEqualityComparer.Default.Equals(operation.TargetMethod, method))
                {
                    return true;
                }
            }
            foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
            {
                if (model.GetOperation(creation) is Microsoft.CodeAnalysis.Operations.IObjectCreationOperation operation
                    && SymbolEqualityComparer.Default.Equals(operation.Constructor, method))
                {
                    return true;
                }
            }
            foreach (var creation in root.DescendantNodes().OfType<ImplicitObjectCreationExpressionSyntax>())
            {
                if (model.GetOperation(creation) is Microsoft.CodeAnalysis.Operations.IObjectCreationOperation operation
                    && SymbolEqualityComparer.Default.Equals(operation.Constructor, method))
                {
                    return true;
                }
            }
            foreach (var initializer in root.DescendantNodes().OfType<ConstructorInitializerSyntax>())
            {
                if (model.GetSymbolInfo(initializer).Symbol is IMethodSymbol target
                    && SymbolEqualityComparer.Default.Equals(target, method))
                {
                    return true;
                }
            }
            foreach (var name in root.DescendantNodes().OfType<SimpleNameSyntax>())
            {
                if (model.GetSymbolInfo(name).Symbol is IMethodSymbol target
                    && SymbolEqualityComparer.Default.Equals(target, method))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static bool ParameterIsRead(IParameterSymbol parameter, IMethodSymbol method, SemanticModel model, SyntaxNode? callable)
    {
        if (callable is null) return false;
        foreach (var identifier in callable.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            if (identifier.Span == parameter.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax().Span) continue;
            if (SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(identifier).Symbol, parameter)) return true;
        }
        return false;
    }

    private static bool ForwardsToBase(MethodDeclarationSyntax syntax, IMethodSymbol method, SemanticModel model)
    {
        var statement = syntax.Body!.Statements[0];
        var invocation = statement switch
        {
            ReturnStatementSyntax { Expression: InvocationExpressionSyntax returned } => returned,
            ExpressionStatementSyntax { Expression: InvocationExpressionSyntax called } => called,
            _ => null,
        };
        if (invocation?.Expression is not MemberAccessExpressionSyntax member || member.Expression is not BaseExpressionSyntax || member.Name.Identifier.ValueText != method.Name || invocation.ArgumentList.Arguments.Count != method.Parameters.Length) return false;
        if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol target || !SymbolEqualityComparer.Default.Equals(target, method.OverriddenMethod)) return false;
        return invocation.ArgumentList.Arguments.Select(argument => argument.Expression).Zip(syntax.ParameterList.Parameters, (argument, parameter) => argument is IdentifierNameSyntax identifier && identifier.Identifier.ValueText == parameter.Identifier.ValueText).All(value => value);
    }

    private readonly record struct CountCandidate(SyntaxNode Node, IMethodSymbol? Method);

    private static CountCandidate? CountSide(BinaryExpressionSyntax binary, SemanticModel model, CSharpCompilation compilation)
    {
        var leftZero = IsZero(binary.Left);
        var rightZero = IsZero(binary.Right);
        if (!leftZero && !rightZero) return null;
        var countNode = leftZero ? binary.Right : binary.Left;
        var validOperator = leftZero
            ? binary.IsKind(SyntaxKind.EqualsExpression) || binary.IsKind(SyntaxKind.GreaterThanOrEqualExpression)
            : binary.IsKind(SyntaxKind.EqualsExpression) || binary.IsKind(SyntaxKind.LessThanOrEqualExpression);
        if (!validOperator || countNode is not InvocationExpressionSyntax invocation
            || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method
            || !IsCountExtension(method, compilation))
        {
            return null;
        }
        return new CountCandidate(countNode, method);
    }

    private static bool IsCountExtension(IMethodSymbol method, CSharpCompilation compilation)
    {
        var definition = method.ReducedFrom ?? method;
        if (!definition.IsExtensionMethod || definition.Name != "Count" || definition.Parameters.Length == 0)
        {
            return false;
        }
        var receiver = definition.Parameters[0].Type as INamedTypeSymbol;
        if (receiver is null)
        {
            return false;
        }
        var enumerable = compilation.GetTypeByMetadataName("System.Collections.Generic.IEnumerable`1");
        var queryable = compilation.GetTypeByMetadataName("System.Linq.IQueryable`1");
        if ((enumerable is null || !SymbolEqualityComparer.Default.Equals(receiver.OriginalDefinition, enumerable))
            && (queryable is null || !SymbolEqualityComparer.Default.Equals(receiver.OriginalDefinition, queryable)))
        {
            return false;
        }
        return SymbolEqualityComparer.Default.Equals(definition.ContainingType, compilation.GetTypeByMetadataName("System.Linq.Enumerable"))
            || SymbolEqualityComparer.Default.Equals(definition.ContainingType, compilation.GetTypeByMetadataName("System.Linq.Queryable"));
    }

    private static bool IsZero(ExpressionSyntax expression) => expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.NumericLiteralExpression) && literal.Token.ValueText == "0";


    private static SyntaxToken? CountName(SyntaxNode count) => count switch
    {
        InvocationExpressionSyntax invocation when invocation.Expression is MemberAccessExpressionSyntax member => member.Name.Identifier,
        _ => null,
    };


    private static bool GetTypeAndTypeof(BinaryExpressionSyntax binary, SemanticModel model, out ExpressionSyntax receiver, out ITypeSymbol targetType, out TypeOfExpressionSyntax typeofSyntax)
    {
        receiver = null!;
        targetType = null!;
        typeofSyntax = null!;
        if (binary.Left is InvocationExpressionSyntax leftInvocation && binary.Right is TypeOfExpressionSyntax rightTypeof && IsGetType(leftInvocation, model, out receiver)) typeofSyntax = rightTypeof;
        else if (binary.Right is InvocationExpressionSyntax rightInvocation && binary.Left is TypeOfExpressionSyntax leftTypeof && IsGetType(rightInvocation, model, out receiver)) typeofSyntax = leftTypeof;
        else return false;
        targetType = model.GetTypeInfo(typeofSyntax.Type).Type!;
        return targetType is not null;
    }

    private static bool IsGetType(InvocationExpressionSyntax invocation, SemanticModel model, out ExpressionSyntax receiver)
    {
        receiver = null!;
        if (invocation.ArgumentList.Arguments.Count != 0 || invocation.Expression is not MemberAccessExpressionSyntax member || member.Name.Identifier.ValueText != "GetType" || model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || method.ContainingType?.SpecialType != SpecialType.System_Object) return false;
        receiver = member.Expression;
        return true;
    }

    private static bool IsIntegralOrEnum(ITypeSymbol? type) => type is { TypeKind: TypeKind.Enum } || type?.SpecialType is SpecialType.System_Byte or SpecialType.System_SByte or SpecialType.System_Int16 or SpecialType.System_UInt16 or SpecialType.System_Int32 or SpecialType.System_UInt32 or SpecialType.System_Int64 or SpecialType.System_UInt64 or SpecialType.System_IntPtr or SpecialType.System_UIntPtr;

    private static bool HasReferenceOrValueConstraint(ITypeParameterSymbol parameter) => parameter.HasReferenceTypeConstraint || parameter.HasValueTypeConstraint || parameter.HasNotNullConstraint;
    private static bool GenericParameterMightBeValueType(ITypeParameterSymbol parameter) =>
        !parameter.HasReferenceTypeConstraint
        && !parameter.HasValueTypeConstraint
        && parameter.ConstraintTypes.All(MightBeValueType);

    private static bool MightBeValueType(ITypeSymbol type) =>
        type.TypeKind == TypeKind.Interface || type is ITypeParameterSymbol parameter && GenericParameterMightBeValueType(parameter);

    private static bool IsInsideConstructorDeclaration(SyntaxNode expression, INamedTypeSymbol currentType, SemanticModel model) =>
        model.GetEnclosingSymbol(expression.SpanStart) is IMethodSymbol
        {
            MethodKind: MethodKind.Constructor,
            ContainingType: { } containingType
        } constructor
        && SymbolEqualityComparer.Default.Equals(constructor.ContainingType, currentType);

    private static List<CompilerQuickFixEdit>? GenericClassConstraintEdits(ITypeParameterSymbol typeParameter, SyntaxTree issueTree, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, IReadOnlySet<string> editablePaths)
    {
        var declarations = typeParameter.DeclaringSyntaxReferences
            .Select(reference => reference.GetSyntax())
            .OfType<TypeParameterSyntax>()
            .Select(parameter => (Parameter: parameter, Owner: parameter.AncestorsAndSelf().OfType<ClassDeclarationSyntax>().FirstOrDefault()))
            .Where(item => item.Owner is not null)
            .GroupBy(item => item.Owner!.SpanStart)
            .Select(group => group.First().Owner!)
            .ToList();
        // The wire format carries edit offsets for one source only.  A
        // partial generic type therefore gets this action only when every
        // declaration can be updated in the diagnosed source atomically.
        if (declarations.Count == 0
            || declarations.Any(owner => owner.SyntaxTree != issueTree
                || !models.ContainsKey(owner.SyntaxTree)
                || !IsEditable(owner.SyntaxTree, editablePaths)))
        {
            return null;
        }

        var edits = new List<CompilerQuickFixEdit>();
        foreach (var owner in declarations.OrderBy(owner => owner.SpanStart))
        {
            var existing = owner.ConstraintClauses.FirstOrDefault(clause => clause.Name.Identifier.ValueText == typeParameter.Name);
            if (existing is not null)
            {
                if (existing.Constraints.Any(constraint => constraint is ClassOrStructConstraintSyntax classConstraint && classConstraint.ClassOrStructKeyword.IsKind(SyntaxKind.ClassKeyword)))
                {
                    continue;
                }
                edits.Add(Edit(issueTree, new TextSpan(existing.Constraints[0].SpanStart, 0), "class, "));
                continue;
            }
            var hasExistingConstraints = owner.ConstraintClauses.Count > 0;
            var insertion = hasExistingConstraints
                ? owner.ConstraintClauses[0].SpanStart
                : owner.BaseList?.Span.End ?? owner.TypeParameterList!.Span.End;
            edits.Add(Edit(issueTree, new TextSpan(insertion, 0), $"{(hasExistingConstraints ? "" : " ")}where {typeParameter.Name} : class "));
        }
        return edits.Count == 0 ? null : edits;
    }

    private static bool HasLinqInScope(SyntaxNode node, SemanticModel model)
    {
        return model.LookupNamespacesAndTypes(node.SpanStart)
            .OfType<INamedTypeSymbol>()
            .Any(symbol => symbol.Name == "Enumerable" && symbol.ContainingNamespace?.ToDisplayString() == "System.Linq");
    }
    private static string RemoveBaseType(BaseTypeDeclarationSyntax declaration, int index)
    {
        var baseList = declaration.BaseList!;
        var newBaseList = baseList.RemoveNode(baseList.Types[index], SyntaxRemoveOptions.KeepNoTrivia);
        return newBaseList is not null && newBaseList.Types.Count > 0 ? newBaseList.ToFullString() : "";
    }


    private static bool TryGetSingleEditableDeclaration(IFieldSymbol field, SyntaxTree issueTree, IReadOnlyDictionary<SyntaxTree, SemanticModel> models, out FieldDeclarationSyntax declaration)
    {
        declaration = null!;
        var syntax = field.DeclaringSyntaxReferences.Select(reference => reference.GetSyntax()).OfType<VariableDeclaratorSyntax>().FirstOrDefault();
        if (syntax?.Parent?.Parent is not FieldDeclarationSyntax fieldDeclaration || fieldDeclaration.Declaration.Variables.Count != 1 || fieldDeclaration.SyntaxTree != issueTree) return false;
        declaration = fieldDeclaration;
        return true;
    }

    private static HashSet<IFieldSymbol> ReferencedMutableFields(MethodDeclarationSyntax syntax, IMethodSymbol method, SemanticModel model)
    {
        var result = new HashSet<IFieldSymbol>(SymbolEqualityComparer.Default);
        foreach (var identifier in syntax.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            if (model.GetSymbolInfo(identifier).Symbol is IFieldSymbol field && !field.IsReadOnly && !field.IsConst) result.Add(field);
        }
        return result;
    }


    [Flags]
    private enum FieldFlowState
    {
        None = 0,
        Unassigned = 1,
        Assigned = 2,
        Unsafe = 4,
    }

    private static bool IsSymbolFirstSetInCfg(IFieldSymbol field, ConstructorDeclarationSyntax declaration, SemanticModel model)
    {
        if (declaration.Initializer?.ThisOrBaseKeyword.IsKind(SyntaxKind.ThisKeyword) == true)
        {
            return true;
        }
        if (model.GetOperation(declaration) is not IConstructorBodyOperation operation)
        {
            return false;
        }
        ControlFlowGraph? graph;
        try
        {
            graph = ControlFlowGraph.Create(operation);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        if (graph is null) return false;

        var entry = graph.Blocks.FirstOrDefault(block => block.Kind == BasicBlockKind.Entry);
        var exit = graph.Blocks.FirstOrDefault(block => block.Kind == BasicBlockKind.Exit);
        if (entry is null || exit is null || !exit.IsReachable) return false;
        var incoming = new FieldFlowState[graph.Blocks.Length];
        var outgoing = new FieldFlowState[graph.Blocks.Length];
        incoming[entry.Ordinal] = FieldFlowState.Unassigned;

        bool changed;
        do
        {
            changed = false;
            foreach (var block in graph.Blocks)
            {
                if (!block.IsReachable) continue;
                var state = block == entry
                    ? FieldFlowState.Unassigned
                    : block.Predecessors
                        .Where(branch => branch.Source.IsReachable)
                        .Aggregate(FieldFlowState.None, (current, branch) => current | outgoing[branch.Source.Ordinal]);
                if (state == FieldFlowState.None) continue;
                if (incoming[block.Ordinal] != state)
                {
                    incoming[block.Ordinal] = state;
                    changed = true;
                }
                var next = TransferOperations(block.Operations, state, field);
                if (block.BranchValue is not null)
                {
                    next = TransferOperation(block.BranchValue, next, field);
                }
                if (outgoing[block.Ordinal] != next)
                {
                    outgoing[block.Ordinal] = next;
                    changed = true;
                }
            }
        }
        while (changed);

        var exitState = incoming[exit.Ordinal];
        return (exitState & FieldFlowState.Assigned) != 0
            && (exitState & (FieldFlowState.Unassigned | FieldFlowState.Unsafe)) == 0;
    }

    private static FieldFlowState TransferOperations(IEnumerable<IOperation> operations, FieldFlowState state, IFieldSymbol field)
    {
        foreach (var operation in operations)
        {
            state = TransferOperation(operation, state, field);
        }
        return state;
    }

    private static FieldFlowState TransferOperation(IOperation operation, FieldFlowState state, IFieldSymbol field)
    {
        if (operation is IAnonymousFunctionOperation or ILocalFunctionOperation)
        {
            return state;
        }
        if (operation is ISimpleAssignmentOperation simple)
        {
            state = TransferAssignmentTarget(simple.Target, state, field, read: false, write: false);
            state = TransferOperation(simple.Value, state, field);
            return MarkDirectTargetWritten(simple.Target, state, field);
        }
        if (operation is ICompoundAssignmentOperation compound)
        {
            state = TransferAssignmentTarget(compound.Target, state, field, read: true, write: false);
            state = TransferOperation(compound.Value, state, field);
            return MarkDirectTargetWritten(compound.Target, state, field);
        }
        if (operation is IIncrementOrDecrementOperation increment)
        {
            state = TransferAssignmentTarget(increment.Target, state, field, read: true, write: false);
            return MarkDirectTargetWritten(increment.Target, state, field);
        }
        if (operation is IArgumentOperation argument)
        {
            if (argument.Parameter?.RefKind == RefKind.Out)
            {
                return TransferAssignmentTarget(argument.Value, state, field, read: false, write: true);
            }
            state = TransferOperation(argument.Value, state, field);
            if (argument.Parameter?.RefKind == RefKind.Ref)
            {
                state = MarkDirectTargetWritten(argument.Value, state, field);
            }
            return state;
        }
        if (operation is IFieldReferenceOperation fieldReference)
        {
            state = fieldReference.Instance is null ? state : TransferOperation(fieldReference.Instance, state, field);
            return SymbolEqualityComparer.Default.Equals(fieldReference.Field, field)
                ? MarkFieldRead(state)
                : state;
        }
        foreach (var child in operation.ChildOperations)
        {
            state = TransferOperation(child, state, field);
        }
        return state;
    }

    private static FieldFlowState TransferAssignmentTarget(IOperation target, FieldFlowState state, IFieldSymbol field, bool read, bool write)
    {
        if (target is IFieldReferenceOperation fieldReference && SymbolEqualityComparer.Default.Equals(fieldReference.Field, field))
        {
            state = fieldReference.Instance is null ? state : TransferOperation(fieldReference.Instance, state, field);
            if (read) state = MarkFieldRead(state);
            if (write) state = MarkFieldWritten(state);
            return state;
        }
        return TransferOperation(target, state, field);
    }

    private static FieldFlowState MarkDirectTargetWritten(IOperation target, FieldFlowState state, IFieldSymbol field) =>
        target is IFieldReferenceOperation fieldReference && SymbolEqualityComparer.Default.Equals(fieldReference.Field, field)
            ? MarkFieldWritten(state)
            : state;

    private static FieldFlowState MarkFieldRead(FieldFlowState state) =>
        (state & FieldFlowState.Unassigned) != 0
            ? (state & ~FieldFlowState.Unassigned) | FieldFlowState.Unsafe
            : state;

    private static FieldFlowState MarkFieldWritten(FieldFlowState state) =>
        (state & FieldFlowState.Unassigned) != 0
            ? (state & ~FieldFlowState.Unassigned) | FieldFlowState.Assigned
            : state;

    private static bool IsConstructorWrite(Microsoft.CodeAnalysis.IOperation operation, IFieldSymbol field) => operation.Syntax.Ancestors().OfType<ConstructorDeclarationSyntax>().Any();

    private static List<Microsoft.CodeAnalysis.Operations.IAssignmentOperation> FieldWrites(IFieldSymbol field, SemanticModel model, IReadOnlyDictionary<SyntaxTree, SemanticModel> models)
    {
        var writes = new List<Microsoft.CodeAnalysis.Operations.IAssignmentOperation>();
        foreach (var candidateModel in models.Values)
        {
            foreach (var assignment in candidateModel.SyntaxTree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                if (candidateModel.GetOperation(assignment) is Microsoft.CodeAnalysis.Operations.IAssignmentOperation operation && operation.Target is Microsoft.CodeAnalysis.Operations.IFieldReferenceOperation reference && SymbolEqualityComparer.Default.Equals(reference.Field, field)) writes.Add(operation);
            }
        }
        return writes;
    }

    private static bool HasAttributeLists(SyntaxNode node) => node switch
    {
        MethodDeclarationSyntax method => method.AttributeLists.Count != 0,
        OperatorDeclarationSyntax op => op.AttributeLists.Count != 0,
        _ => true,
    };

    private static SyntaxTokenList ModifiersOf(SyntaxNode node) => node switch
    {
        MethodDeclarationSyntax method => method.Modifiers,
        ConstructorDeclarationSyntax constructor => constructor.Modifiers,
        OperatorDeclarationSyntax op => op.Modifiers,
        ConversionOperatorDeclarationSyntax conversion => conversion.Modifiers,
        PropertyDeclarationSyntax property => property.Modifiers,
        IndexerDeclarationSyntax indexer => indexer.Modifiers,
        EventDeclarationSyntax eventDeclaration => eventDeclaration.Modifiers,
        EventFieldDeclarationSyntax eventField => eventField.Modifiers,
        _ => default,
    };

    private static bool HasUnsafeContext(SyntaxNode node) => node.Ancestors().Any(ancestor => ancestor is UnsafeStatementSyntax || ancestor is BaseTypeDeclarationSyntax type && type.Modifiers.Any(SyntaxKind.UnsafeKeyword) || ancestor is MemberDeclarationSyntax member && ModifiersOf(member).Any(SyntaxKind.UnsafeKeyword));

    private static bool ContainsUnsafeConstruct(SyntaxNode node) => node.DescendantNodes().Any(child => child is PointerTypeSyntax or FunctionPointerTypeSyntax or FixedStatementSyntax || child.IsKind(SyntaxKind.AddressOfExpression) || child is SizeOfExpressionSyntax size && size.Type is not PredefinedTypeSyntax);

    private static int AccessibilityRank(SyntaxTokenList modifiers)
    {
        if (modifiers.Any(SyntaxKind.PublicKeyword)) return 4;
        if (modifiers.Any(SyntaxKind.ProtectedKeyword)) return 3;
        if (modifiers.Any(SyntaxKind.InternalKeyword)) return 2;
        if (modifiers.Any(SyntaxKind.PrivateKeyword)) return 1;
        return 0;
    }

    private static bool UsingIsUnused(UsingDirectiveSyntax directive, SyntaxNode root, SemanticModel model)
    {
        if (directive.Name is not { } nameSyntax) return false;
        var imported = model.GetSymbolInfo(nameSyntax).Symbol;
        if (imported is not INamespaceSymbol && imported is not INamedTypeSymbol) return false;
        foreach (var name in root.DescendantNodes().OfType<SimpleNameSyntax>())
        {
            if (name.Ancestors().Contains(directive)) continue;
            var info = model.GetSymbolInfo(name);
            var symbol = info.Symbol ?? info.CandidateSymbols.FirstOrDefault();
            if (symbol is null) return false;
            var namespaceSymbol = symbol.ContainingNamespace;
            if (imported is INamespaceSymbol importedNamespace
                && namespaceSymbol is not null
                && (SymbolEqualityComparer.Default.Equals(namespaceSymbol, importedNamespace)
                    || String.Equals(namespaceSymbol.ToDisplayString(), importedNamespace.ToDisplayString(), StringComparison.Ordinal)))
            {
                return false;
            }
            if (imported is INamedTypeSymbol importedType
                && symbol.ContainingType is not null
                && SymbolEqualityComparer.Default.Equals(symbol.ContainingType, importedType))
            {
                return false;
            }
        }
        return true;
    }

    private static string MinimalAttributeName(INamedTypeSymbol attributeType, SemanticModel model, int position)
    {
        var display = attributeType.ToMinimalDisplayString(model, position);
        return display.EndsWith("Attribute", StringComparison.Ordinal) ? display[..^9] : display;
    }

    private static INamedTypeSymbol? FrameworkType(Compilation compilation, string metadataName)
    {
        var symbol = compilation.GetTypeByMetadataName(metadataName);
        return symbol is not null && !symbol.Locations.Any(location => location.IsInSource) ? symbol : null;
    }

    private static bool IsAttribute(AttributeSyntax syntax, SemanticModel model, INamedTypeSymbol expected)
    {
        var symbol = model.GetSymbolInfo(syntax).Symbol;
        var attributeType = symbol switch
        {
            INamedTypeSymbol named => named,
            IMethodSymbol constructor => constructor.ContainingType,
            _ => model.GetTypeInfo(syntax).Type as INamedTypeSymbol,
        };
        return attributeType is not null && SymbolEqualityComparer.Default.Equals(attributeType, expected);
    }

    private static SyntaxNode? EnclosingType(SyntaxNode node) => node.Ancestors().FirstOrDefault(candidate => candidate is BaseTypeDeclarationSyntax);

    private static bool UsesControllerOnlyApi(ClassDeclarationSyntax declaration, SemanticModel model, INamedTypeSymbol controller)
    {
        foreach (var member in declaration.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            if (model.GetSymbolInfo(member).Symbol is ISymbol symbol && (SymbolEqualityComparer.Default.Equals(symbol.ContainingType, controller) || symbol.ContainingType?.BaseType is not null && SymbolEqualityComparer.Default.Equals(symbol.ContainingType.BaseType, controller))) return true;
        }
        return false;
    }

    private static bool SimpleBranch(StatementSyntax statement) => statement is BlockSyntax block ? block.Statements.Count == 1 : true;

    private static List<StatementSyntax> BranchStatements(IfStatementSyntax statement)
    {
        var result = new List<StatementSyntax>();
        if (statement.Statement is BlockSyntax thenBlock) result.AddRange(thenBlock.Statements); else result.Add(statement.Statement);
        if (statement.Else?.Statement is BlockSyntax elseBlock) result.AddRange(elseBlock.Statements); else if (statement.Else is not null) result.Add(statement.Else.Statement);
        return result;
    }

    private static SyntaxNode? ConditionalReplacement(IfStatementSyntax statement)
    {
        var thenStatement = BranchStatements(statement).First();
        var elseStatement = BranchStatements(statement).Last();
        if (thenStatement is ReturnStatementSyntax { Expression: { } thenExpression }
            && elseStatement is ReturnStatementSyntax { Expression: { } elseExpression }
            && statement.Condition is { } condition)
        {
            return SyntaxFactory.ParseStatement($"return {condition.ToFullString().Trim()} ? {thenExpression.ToFullString().Trim()} : {elseExpression.ToFullString().Trim()};").WithTriviaFrom(statement);
        }
        return null;
    }

    private static bool MatchingAssignment(BinaryExpressionSyntax condition, AssignmentExpressionSyntax assignment, SemanticModel model) =>
        MatchingExpression(condition.Left, assignment.Left, model) && MatchingExpression(condition.Right, assignment.Right, model)
        || MatchingExpression(condition.Left, assignment.Right, model) && MatchingExpression(condition.Right, assignment.Left, model);

    private static bool MatchingExpression(ExpressionSyntax left, ExpressionSyntax right, SemanticModel model)
    {
        left = UnwrapParentheses(left);
        right = UnwrapParentheses(right);
        var leftSymbol = model.GetSymbolInfo(left).Symbol;
        var rightSymbol = model.GetSymbolInfo(right).Symbol;
        if (leftSymbol is not null || rightSymbol is not null)
        {
            return leftSymbol is not null
                && rightSymbol is not null
                && SymbolEqualityComparer.Default.Equals(leftSymbol, rightSymbol);
        }
        var leftConstant = model.GetConstantValue(left);
        var rightConstant = model.GetConstantValue(right);
        return leftConstant.HasValue && rightConstant.HasValue && Equals(leftConstant.Value, rightConstant.Value);
    }

    private static ExpressionSyntax UnwrapParentheses(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax parenthesized)
        {
            expression = parenthesized.Expression;
        }
        return expression;
    }

    private static bool DecimalBitsEqual(decimal actual, decimal expected)
    {
        Span<int> actualBits = stackalloc int[4];
        Span<int> expectedBits = stackalloc int[4];
        decimal.GetBits(actual, actualBits);
        decimal.GetBits(expected, expectedBits);
        for (var index = 0; index < actualBits.Length; index++)
        {
            if (actualBits[index] != expectedBits[index])
            {
                return false;
            }
        }

        return true;
    }

    private static bool DefaultValueMatches(object? actual, object? expected)
    {
        return actual switch
        {
            double actualDouble when expected is double expectedDouble =>
                BitConverter.DoubleToInt64Bits(actualDouble) == BitConverter.DoubleToInt64Bits(expectedDouble),
            float actualFloat when expected is float expectedFloat =>
                BitConverter.SingleToInt32Bits(actualFloat) == BitConverter.SingleToInt32Bits(expectedFloat),
            decimal actualDecimal when expected is decimal expectedDecimal =>
                DecimalBitsEqual(actualDecimal, expectedDecimal),
            _ => Equals(actual, expected),
        };
    }

    private static bool DefaultMatches(ArgumentBinding mapping, SemanticModel model)
    {
        if (mapping.Value is { } value && value.ConstantValue.HasValue)
        {
            return DefaultValueMatches(value.ConstantValue.Value, mapping.Parameter.ExplicitDefaultValue);
        }

        return model.GetConstantValue(mapping.Syntax.Expression) is { HasValue: true } constant
            && DefaultValueMatches(constant.Value, mapping.Parameter.ExplicitDefaultValue);
    }

    private static bool IsInExpressionTree(ArgumentListSyntax argumentList, SemanticModel model)
    {
        foreach (var lambda in argumentList.Ancestors().OfType<LambdaExpressionSyntax>())
        {
            if (model.GetTypeInfo(lambda).ConvertedType is INamedTypeSymbol converted
                && converted.Name == "Expression"
                && converted.ContainingNamespace?.ToDisplayString() == "System.Linq.Expressions")
            {
                return true;
            }
        }
        return false;
    }
    private sealed record ArgumentBinding(
        ArgumentSyntax Syntax,
        IParameterSymbol Parameter,
        ArgumentKind Kind,
        IOperation? Value,
        IArrayTypeSymbol? ParamsArrayType);

    private static ArgumentSyntax? SourceArgument(ArgumentListSyntax argumentList, SyntaxNode syntax)
    {
        if (syntax is ArgumentSyntax argument && argument.Parent == argumentList)
        {
            return argument;
        }

        return argumentList.Arguments.FirstOrDefault(argument => argument.Expression.Span == syntax.Span);
    }

    private static List<ArgumentBinding>? BindArguments(ArgumentListSyntax argumentList, SemanticModel model)
    {
        if (argumentList.Parent is not { } parent)
        {
            return null;
        }

        var argumentOperations = model.GetOperation(parent) switch
        {
            IInvocationOperation invocation => invocation.Arguments,
            IObjectCreationOperation creation => creation.Arguments,
            _ => default(ImmutableArray<IArgumentOperation>),
        };
        if (argumentOperations.IsDefault)
        {
            return null;
        }

        var bindings = new Dictionary<ArgumentSyntax, ArgumentBinding>();
        foreach (var argumentOperation in argumentOperations)
        {
            if (argumentOperation.Parameter is not { } parameter)
            {
                continue;
            }

            if (SourceArgument(argumentList, argumentOperation.Syntax) is { } source)
            {
                if (!bindings.TryAdd(
                    source,
                    new ArgumentBinding(source, parameter, argumentOperation.ArgumentKind, argumentOperation.Value, null)))
                {
                    return null;
                }

                continue;
            }

            if (argumentOperation.ArgumentKind != ArgumentKind.ParamArray
                || argumentOperation.Value is not IArrayCreationOperation arrayCreation
                || arrayCreation.Initializer is not { } initializer)
            {
                continue;
            }

            foreach (var element in initializer.ElementValues)
            {
                if (SourceArgument(argumentList, element.Syntax) is not { } sourceArgument
                    || !bindings.TryAdd(
                        sourceArgument,
                        new ArgumentBinding(
                            sourceArgument,
                            parameter,
                            ArgumentKind.ParamArray,
                            element,
                            arrayCreation.Type as IArrayTypeSymbol)))
                {
                    return null;
                }
            }
        }

        return argumentList.Arguments.All(bindings.ContainsKey)
            ? argumentList.Arguments.Select(argument => bindings[argument]).ToList()
            : null;
    }
    private static string? RemoveArguments(ArgumentListSyntax argumentList, HashSet<ArgumentSyntax> remove)
    {
        var rewritten = argumentList.RemoveNodes(remove, SyntaxRemoveOptions.KeepNoTrivia | SyntaxRemoveOptions.AddElasticMarker);
        return rewritten?.ToFullString();
    }
    private static string FormatArgumentList(ArgumentListSyntax template, IEnumerable<ArgumentSyntax> arguments)
    {
        var separated = SpaceSeparators(SyntaxFactory.SeparatedList(arguments));
        return WithSpacedSeparators(template.WithArguments(separated)).ToFullString();
    }

    private static ArgumentListSyntax WithSpacedSeparators(ArgumentListSyntax list)
    {
        var arguments = list.Arguments;
        for (var index = 0; index < arguments.SeparatorCount; index++)
        {
            var separator = arguments.GetSeparator(index);
            arguments = arguments.ReplaceSeparator(
                separator,
                separator.WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)));
        }
        return list.WithArguments(arguments);
    }

    private static SeparatedSyntaxList<TNode> SpaceSeparators<TNode>(SeparatedSyntaxList<TNode> nodes)
        where TNode : SyntaxNode
    {
        for (var index = 0; index < nodes.SeparatorCount; index++)
        {
            var separator = nodes.GetSeparator(index);
            nodes = nodes.ReplaceSeparator(separator, separator.WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)));
        }
        return nodes;
    }
    private static NameColonSyntax NameColonWithSpace(string name)
    {
        var nameColon = SyntaxFactory.NameColon(SyntaxFactory.IdentifierName(name));
        return nameColon.WithColonToken(
            nameColon.ColonToken.WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)));
    }
    private static ArrayTypeSyntax? ParamsArrayTypeSyntax(
        IArrayTypeSymbol paramsArray,
        SemanticModel model,
        int position)
    {
        var format = SymbolDisplayFormat.FullyQualifiedFormat;
        if ((model.GetNullableContext(position) & NullableContext.AnnotationsEnabled) != 0)
        {
            format = format.WithMiscellaneousOptions(
                format.MiscellaneousOptions | SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier);
        }

        var display = paramsArray.ToDisplayString(format);
        if (paramsArray.NullableAnnotation == NullableAnnotation.Annotated
            && display.EndsWith("?", StringComparison.Ordinal))
        {
            display = display[..^1];
        }

        return SyntaxFactory.ParseTypeName(display) as ArrayTypeSyntax;
    }



    private static string? RemoveArgumentsAndName(
        ArgumentListSyntax argumentList,
        List<ArgumentBinding> mappings,
        HashSet<ArgumentSyntax> remove,
        SemanticModel model)
    {
        var paramsMappings = mappings.Where(mapping => mapping.Parameter.IsParams).ToList();
        ArgumentSyntax? paramsReplacement = null;
        if (paramsMappings.Count > 0)
        {
            var firstMapping = paramsMappings[0];
            var firstArgument = firstMapping.Syntax;
            var paramsParameter = firstMapping.Parameter;
            if (firstArgument.NameColon is not null)
            {
                paramsReplacement = firstArgument;
            }
            else if (paramsMappings.Count == 1
                && firstMapping.Kind != ArgumentKind.ParamArray)
            {
                paramsReplacement = SyntaxFactory.Argument(
                    NameColonWithSpace(paramsParameter.Name),
                    firstArgument.RefOrOutKeyword,
                    firstArgument.Expression);
            }
            else
            {
                var paramsArray = paramsMappings
                    .Select(mapping => mapping.ParamsArrayType)
                    .FirstOrDefault(type => type is not null)
                    ?? paramsParameter.Type as IArrayTypeSymbol;
                if (paramsArray is null)
                {
                    return null;
                }

                var paramsExpressions = paramsMappings
                    .Select(mapping => mapping.Syntax.Expression)
                    .ToList();
                var useImplicitArray = paramsExpressions.All(expression =>
                    model.GetTypeInfo(expression).Type is { } type
                    && SymbolEqualityComparer.Default.Equals(type, paramsArray.ElementType));
                if (!useImplicitArray
                    && paramsExpressions.Any(expression =>
                        !model.ClassifyConversion(expression, paramsArray.ElementType).IsImplicit))
                {
                    return null;
                }

                var initializer = SyntaxFactory.InitializerExpression(
                        SyntaxKind.ArrayInitializerExpression,
                        SpaceSeparators(SyntaxFactory.SeparatedList(paramsExpressions)))
                    .WithOpenBraceToken(
                        SyntaxFactory.Token(SyntaxKind.OpenBraceToken)
                            .WithLeadingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space))
                            .WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)))
                    .WithCloseBraceToken(
                        SyntaxFactory.Token(SyntaxKind.CloseBraceToken)
                            .WithLeadingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)));
                ExpressionSyntax array;
                if (useImplicitArray)
                {
                    array = SyntaxFactory.ImplicitArrayCreationExpression(initializer);
                }
                else
                {
                    var parameterArrayType = ParamsArrayTypeSyntax(paramsArray, model, argumentList.SpanStart);
                    if (parameterArrayType is null)
                    {
                        return null;
                    }

                    array = SyntaxFactory.ArrayCreationExpression(parameterArrayType.WithoutTrivia(), initializer)
                        .WithNewKeyword(
                            SyntaxFactory.Token(SyntaxKind.NewKeyword)
                                .WithTrailingTrivia(SyntaxFactory.TriviaList(SyntaxFactory.Space)));
                }

                paramsReplacement = SyntaxFactory.Argument(
                    NameColonWithSpace(paramsParameter.Name),
                    default,
                    array);
            }
        }

        var outputArguments = new List<ArgumentSyntax>();
        var alreadyRemovedOne = false;
        var emittedParams = false;
        foreach (var mapping in mappings)
        {
            if (mapping.Parameter.IsParams)
            {
                if (!emittedParams)
                {
                    if (paramsReplacement is null)
                    {
                        return null;
                    }

                    outputArguments.Add(paramsReplacement);
                    emittedParams = true;
                }

                continue;
            }

            if (remove.Contains(mapping.Syntax))
            {
                alreadyRemovedOne = true;
                continue;
            }

            outputArguments.Add(alreadyRemovedOne
                ? mapping.Syntax.WithNameColon(NameColonWithSpace(mapping.Parameter.Name))
                : mapping.Syntax);
        }

        return FormatArgumentList(argumentList, outputArguments);
    }
    private static bool IsIdentifierNullComparison(BinaryExpressionSyntax binary, SemanticModel model)
    {
        var value = binary.Left.IsKind(SyntaxKind.NullLiteralExpression) ? binary.Right : binary.Right.IsKind(SyntaxKind.NullLiteralExpression) ? binary.Left : null;
        if (value is not IdentifierNameSyntax identifier || model.GetSymbolInfo(identifier).Symbol is null)
        {
            return false;
        }

        if (model.GetOperation(binary) is not IBinaryOperation operation)
        {
            return false;
        }

        if (operation.OperatorMethod is null)
        {
            return true;
        }

        var expectedOperator = binary.IsKind(SyntaxKind.EqualsExpression) ? "op_Equality" : "op_Inequality";
        return operation.OperatorMethod.Name == expectedOperator
            && operation.OperatorMethod.ContainingType?.SpecialType == SpecialType.System_String;
    }

    private static bool PatternMatches(ExpressionSyntax other, BinaryExpressionSyntax nullCheck, BinaryExpressionSyntax logical, SemanticModel model)
    {
        var nullIdentifier = nullCheck.Left.IsKind(SyntaxKind.NullLiteralExpression) ? nullCheck.Right : nullCheck.Left;
        if (nullIdentifier is not IdentifierNameSyntax nullName || model.GetSymbolInfo(nullName).Symbol is not { } nullSymbol) return false;
        ExpressionSyntax patternExpression = other;
        if (logical.IsKind(SyntaxKind.LogicalOrExpression))
        {
            patternExpression = other switch
            {
                PrefixUnaryExpressionSyntax { Operand: IsPatternExpressionSyntax negated } => negated,
                PrefixUnaryExpressionSyntax { Operand: BinaryExpressionSyntax legacyNegated }
                    when legacyNegated.IsKind(SyntaxKind.IsExpression) => legacyNegated,
                _ => other,
            };
        }

        if (patternExpression is IsPatternExpressionSyntax isPattern
            && isPattern.Expression is IdentifierNameSyntax patternName
            && String.Equals(patternName.Identifier.ValueText, nullName.Identifier.ValueText, StringComparison.Ordinal)
            && model.GetSymbolInfo(patternName).Symbol is { } patternSymbol)
        {
            return SymbolEqualityComparer.Default.Equals(nullSymbol, patternSymbol);
        }

        if (patternExpression is BinaryExpressionSyntax legacyPattern
            && legacyPattern.IsKind(SyntaxKind.IsExpression)
            && legacyPattern.Left is IdentifierNameSyntax legacyName
            && String.Equals(legacyName.Identifier.ValueText, nullName.Identifier.ValueText, StringComparison.Ordinal)
            && model.GetSymbolInfo(legacyName).Symbol is { } legacySymbol
            && model.GetTypeInfo(legacyPattern.Right).Type is not null)
        {
            return SymbolEqualityComparer.Default.Equals(nullSymbol, legacySymbol);
        }

        return false;
    }
    private static TextSpan IncludeFollowingSpace(SyntaxTree tree, TextSpan span)
    {
        var text = SourceText(tree);
        return span.End < text.Length && (text[span.End] == ' ' || text[span.End] == '\t')
            ? new TextSpan(span.Start, span.Length + 1)
            : span;
    }

    private static TextSpan RemoveInitializerTrivia(SyntaxTree tree, VariableDeclaratorSyntax variable, EqualsValueClauseSyntax initializer)
    {
        var text = SourceText(tree);
        var start = initializer.SpanStart;
        while (start > variable.Identifier.Span.End && (text[start - 1] == ' ' || text[start - 1] == '\t')) start--;
        return new TextSpan(start, initializer.Span.End - start);
    }
    private static TextSpan RemoveInlineTrivia(SyntaxTree tree, TextSpan span)
    {
        var text = SourceText(tree);
        if (span.Start > 0 && (text[span.Start - 1] == ' ' || text[span.Start - 1] == '\t'))
        {
            return new TextSpan(span.Start - 1, span.Length + 1);
        }
        if (span.End < text.Length && (text[span.End] == ' ' || text[span.End] == '\t'))
        {
            return new TextSpan(span.Start, span.Length + 1);
        }
        return span;
    }

    private static TextSpan RemoveStatementTrivia(SyntaxTree tree, TextSpan span)
    {
        var text = SourceText(tree);
        var lineStart = text.ToString().LastIndexOf('\n', Math.Max(0, span.Start - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var start = span.Start;
        while (start > lineStart && (text[start - 1] == ' ' || text[start - 1] == '\t')) start--;
        if (start != lineStart) return RemoveInlineTrivia(tree, span);

        var end = span.End;
        while (end < text.Length && (text[end] == ' ' || text[end] == '\t')) end++;
        if (end < text.Length && text[end] == '\r')
        {
            end++;
            if (end < text.Length && text[end] == '\n') end++;
        }
        else if (end < text.Length && text[end] == '\n')
        {
            end++;
        }

        return new TextSpan(start, end - start);
    }

    private static string LineIndent(string source, int position)
    {
        var start = source.LastIndexOf('\n', Math.Max(0, position - 1));
        start = start < 0 ? 0 : start + 1;
        var count = 0;
        while (start + count < source.Length && (source[start + count] == ' ' || source[start + count] == '\t')) count++;
        return source.Substring(start, count);
    }
}

internal sealed class CompilerQuickFixFact
{
    public string SourcePath { get; set; } = "";
    public string RuleKey { get; set; } = "";
    public int StartByte { get; set; }
    public int EndByte { get; set; }
    public List<CompilerQuickFixAction> Actions { get; set; } = new();
}

internal sealed class CompilerRedundantCastFact
{
    public string SourcePath { get; set; } = "";
    public int StartByte { get; set; }
    public int EndByte { get; set; }
    public string Message { get; set; } = "";
}

internal sealed class CompilerQuickFixAction
{
    public string Id { get; set; } = "";
    public string Message { get; set; } = "";
    public List<CompilerQuickFixEdit> Edits { get; set; } = new();
}

internal sealed class CompilerQuickFixEdit
{
    public int StartByte { get; set; }
    public int EndByte { get; set; }
    public string Replacement { get; set; } = "";
}
