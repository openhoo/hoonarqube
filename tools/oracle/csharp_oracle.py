#!/usr/bin/env python3
"""Generate isolated MSBuild projects for the C# oracle fixture corpus."""

from __future__ import annotations

import html
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_NAMESPACE = uuid.UUID("13e0777e-003e-455b-b339-f60c708c020b")
STUBS_SOURCE = Path(__file__).with_name("csharp_oracle_stubs.cs")
TEST_RULE_IDS = {
    "S1607",
    "S2187",
    "S2699",
    "S2701",
    "S2925",
    "S2970",
    "S3415",
    "S3431",
    "S3433",
}

TEST_FRAMEWORK_SOURCE = """namespace NUnit.Framework
{
    [System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method)]
    public sealed class TestAttribute : System.Attribute { }
    [System.AttributeUsage(System.AttributeTargets.Class)]
    public sealed class TestFixtureAttribute : System.Attribute { }
    [System.AttributeUsage(System.AttributeTargets.Method)]
    public sealed class IgnoreAttribute : System.Attribute { }
    [System.AttributeUsage(System.AttributeTargets.Method)]
    public sealed class ExpectedExceptionAttribute : System.Attribute
    {
        public ExpectedExceptionAttribute(System.Type exceptionType) { }
    }
    public static class Assert
    {
        public static void IsTrue(bool value) { }
        public static void IsFalse(bool value) { }
        public static void IsFalse(bool value, string message) { }
        public static void AreEqual<T>(T expected, T actual) { }
        public static void AreNotEqual<T>(T notExpected, T actual) { }
        public static void AreSame<T>(T expected, T actual) { }
        public static void That<T>(T actual) { }
        public static void That<T>(T actual, object constraint) { }
    }
    public static class CollectionAssert
    {
        public static void AreNotEqual<T>(T notExpected, object actual) { }
    }
    public static class Is
    {
        public static object True { get; } = new object();
        public static NotConstraint Not { get; } = new NotConstraint();
        public sealed class NotConstraint
        {
            public object Empty { get; } = new object();
        }
    }
}
"""

NFLUENT_FRAMEWORK_SOURCE = """namespace NFluent
{
    public static class Check
    {
        public static CheckLink That<T>(T actual) => new CheckLink();
    }
    public sealed class CheckLink
    {
        public void IsEqualTo<T>(T expected) { }
    }
}
"""

AZURE_FUNCTIONS_SOURCE = """namespace Microsoft.Azure.WebJobs
{
    [System.AttributeUsage(System.AttributeTargets.Method)]
    public sealed class FunctionNameAttribute : System.Attribute
    {
        public FunctionNameAttribute(string name) { }
    }
}
"""

DURABLE_TASK_SOURCE = """namespace Microsoft.Azure.WebJobs.Extensions.DurableTask
{
    public interface IDurableEntityClient
    {
        void SignalEntityAsync<T>();
    }
}
"""


def is_sonar_rule_id(value: object) -> bool:
    """Return whether `value` is an ASCII Sonar C# rule ID such as S1905."""
    return (
        isinstance(value, str)
        and len(value) > 1
        and value.startswith("S")
        and value[1:].isascii()
        and value[1:].isdigit()
    )


@dataclass(frozen=True)
class FrameworkSpec:
    directory: str
    source_name: str
    project_name: str
    assembly_name: str
    source: str
    rule_ids: frozenset[str]


FRAMEWORKS = (
    FrameworkSpec(
        "test-framework",
        "TestFramework.cs",
        "TestFramework.csproj",
        "nunit.framework",
        TEST_FRAMEWORK_SOURCE,
        frozenset(TEST_RULE_IDS),
    ),
    FrameworkSpec(
        "nfluent-framework",
        "NFluent.cs",
        "NFluent.csproj",
        "NFluent",
        NFLUENT_FRAMEWORK_SOURCE,
        frozenset({"S2970"}),
    ),
    FrameworkSpec(
        "azure-functions-framework",
        "AzureFunctions.cs",
        "AzureFunctions.csproj",
        "Microsoft.Azure.WebJobs.Host",
        AZURE_FUNCTIONS_SOURCE,
        frozenset({"S6419", "S6420", "S6421", "S6422", "S6423"}),
    ),
    FrameworkSpec(
        "durable-task-framework",
        "DurableTask.cs",
        "DurableTask.csproj",
        "Microsoft.Azure.WebJobs.Extensions.DurableTask",
        DURABLE_TASK_SOURCE,
        frozenset({"S6424"}),
    ),
)


def project_guid(source_name: str) -> str:
    return str(uuid.uuid5(PROJECT_NAMESPACE, source_name)).upper()


def source_rule_id(source: Path) -> str:
    return source.stem.split("_", 1)[0].upper()


def validate_options(
    analyzers: Iterable[Path], enabled_rules: Iterable[str], error_log: str | None
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    analyzer_paths = tuple(Path(path).resolve() for path in analyzers)
    missing_analyzers = [path for path in analyzer_paths if not path.is_file()]
    if missing_analyzers:
        raise ValueError(f"C# analyzer does not exist: {missing_analyzers[0]}")
    rule_ids = tuple(sorted(set(enabled_rules)))
    invalid_rules = [rule for rule in rule_ids if not is_sonar_rule_id(rule)]
    if invalid_rules:
        raise ValueError(f"invalid C# analyzer rule ID: {invalid_rules[0]}")
    if error_log is not None and (not error_log or Path(error_log).name != error_log):
        raise ValueError("C# analyzer error log must be a file name")
    return analyzer_paths, rule_ids


def select_sources(source_dir: Path, limit: int | None) -> list[Path]:
    sources = sorted(source_dir.glob("*.cs"), key=lambda path: path.name)
    if limit is not None:
        if limit < 1:
            raise ValueError("C# fixture limit must be positive")
        sources = sources[:limit]
    if not sources:
        raise ValueError(f"no C# fixtures under {source_dir}")
    return sources


def write_framework(projects_dir: Path, framework: FrameworkSpec) -> None:
    framework_dir = projects_dir / framework.directory
    framework_dir.mkdir()
    (framework_dir / framework.source_name).write_text(framework.source)
    (framework_dir / framework.project_name).write_text(
        f"""<Project Sdk=\"Microsoft.NET.Sdk\">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>{framework.assembly_name}</AssemblyName>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include=\"{framework.source_name}\" />
  </ItemGroup>
</Project>
"""
    )


def required_frameworks(sources: Iterable[Path]) -> tuple[FrameworkSpec, ...]:
    rule_ids = {source_rule_id(source) for source in sources}
    return tuple(framework for framework in FRAMEWORKS if framework.rule_ids & rule_ids)


def project_references(source: Path, frameworks: Iterable[FrameworkSpec]) -> str:
    rule_id = source_rule_id(source)
    return "".join(
        f'\n    <ProjectReference Include="../{framework.directory}/{framework.project_name}" />'
        for framework in frameworks
        if rule_id in framework.rule_ids
    )


def write_editor_config(output_dir: Path, rule_ids: tuple[str, ...]) -> None:
    if not rule_ids:
        return
    editor_config = ["root = true", "", "[*.cs]"]
    editor_config.extend(
        f"dotnet_diagnostic.{rule}.severity = warning" for rule in rule_ids
    )
    (output_dir / ".editorconfig").write_text("\n".join(editor_config) + "\n")


def generate_solution(
    source_dir: Path,
    output_dir: Path,
    limit: int | None = None,
    analyzers: Iterable[Path] = (),
    enabled_rules: Iterable[str] = (),
    error_log: str | None = None,
) -> tuple[Path, int]:
    """Create one project per source so unrelated fixture errors cannot collide."""
    analyzer_paths, rule_ids = validate_options(analyzers, enabled_rules, error_log)
    sources = select_sources(source_dir, limit)

    projects_dir = output_dir / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    frameworks = required_frameworks(sources)
    for framework in frameworks:
        write_framework(projects_dir, framework)
    error_log_property = (
        f"\n    <ErrorLog>{html.escape(error_log)}</ErrorLog>" if error_log else ""
    )
    analyzer_items = "".join(
        f'\n    <Analyzer Include="{html.escape(str(path))}" />'
        for path in analyzer_paths
    )
    solution_projects: list[str] = []
    for ordinal, source in enumerate(sources):
        project_name = f"fixture-{ordinal:04}"
        project_dir = projects_dir / project_name
        project_dir.mkdir()
        project_path = project_dir / f"{project_name}.csproj"
        copied_source = project_dir / source.name
        shutil.copyfile(source, copied_source)
        copied_stubs = project_dir / "OracleStubs.g.cs"
        shutil.copyfile(STUBS_SOURCE, copied_stubs)
        references = project_references(source, frameworks)
        project = f"""<Project Sdk=\"Microsoft.NET.Sdk\">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <OutputType>Library</OutputType>
    <ProjectGuid>{{{project_guid(source.name)}}}</ProjectGuid>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <ImplicitUsings>enable</ImplicitUsings>
    <LangVersion>preview</LangVersion>
    <Nullable>enable</Nullable>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>{error_log_property}
  </PropertyGroup>
  <ItemGroup>{analyzer_items}{references}
    <Compile Include=\"{html.escape(copied_source.name)}\" />
    <Compile Include=\"{copied_stubs.name}\" AutoGen=\"true\">
      <SonarQubeExclude>true</SonarQubeExclude>
    </Compile>
    <FrameworkReference Include=\"Microsoft.AspNetCore.App\" />
    <Using Include=\"Microsoft.AspNetCore.Mvc\" />
    <Using Include=\"Microsoft.Extensions.Logging\" />
    <Using Include=\"System.Collections\" />
    <Using Include=\"System.Collections.Concurrent\" />
    <Using Include=\"System.ComponentModel\" />
    <Using Include=\"System.Diagnostics\" />
    <Using Include=\"System.Data.SqlClient\" />
    <Using Include=\"System.IO.Compression\" />
    <Using Include=\"System.Net.Security\" />
    <Using Include=\"System.Reflection\" />
    <Using Include=\"System.Resources\" />
    <Using Include=\"System.Runtime.CompilerServices\" />
    <Using Include=\"System.Runtime.InteropServices\" />
    <Using Include=\"System.Runtime.Serialization\" />
    <Using Include=\"System.Security.Cryptography\" />
    <Using Include=\"System.Text.RegularExpressions\" />
  </ItemGroup>
</Project>
"""
        project_path.write_text(project)
        solution_projects.append(
            f'  <Project Path="projects/{project_name}/{project_path.name}" />'
        )

    write_editor_config(output_dir, rule_ids)

    solution = output_dir / "Oracle.slnx"
    solution.write_text(
        "<Solution>\n" + "\n".join(solution_projects) + "\n</Solution>\n"
    )
    return solution, len(sources)
