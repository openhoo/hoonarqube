import tempfile
import unittest
from pathlib import Path

from csharp_oracle import generate_solution, project_guid


class CSharpOracleProjectTests(unittest.TestCase):
    def test_generates_deterministic_isolated_projects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            output = sources / ".native"
            sources.mkdir()
            (sources / "b.cs").write_text("class B {}\n")
            (sources / "a.cs").write_text("class A {}\n")

            solution, count = generate_solution(sources, output)

            self.assertEqual(count, 2)
            self.assertEqual(
                solution.read_text(),
                '<Solution>\n  <Project Path="projects/fixture-0000/fixture-0000.csproj" />\n'
                '  <Project Path="projects/fixture-0001/fixture-0001.csproj" />\n</Solution>\n',
            )
            first = (output / "projects/fixture-0000/fixture-0000.csproj").read_text()
            second = (output / "projects/fixture-0001/fixture-0001.csproj").read_text()
            self.assertIn('Compile Include="a.cs"', first)
            self.assertIn(
                'FrameworkReference Include="Microsoft.AspNetCore.App"', first
            )
            self.assertIn("<ImplicitUsings>enable</ImplicitUsings>", first)
            self.assertIn('Using Include="Microsoft.AspNetCore.Mvc"', first)
            self.assertIn('Using Include="System.Security.Cryptography"', first)
            self.assertIn('Compile Include="OracleStubs.g.cs" AutoGen="true"', first)
            self.assertIn("<SonarQubeExclude>true</SonarQubeExclude>", first)
            self.assertTrue(
                (output / "projects/fixture-0000/OracleStubs.g.cs").is_file()
            )
            self.assertIn(project_guid("a.cs"), first)
            self.assertIn('Compile Include="b.cs"', second)
            self.assertEqual(
                (output / "projects/fixture-0000/a.cs").read_text(), "class A {}\n"
            )
            self.assertEqual(
                (output / "projects/fixture-0001/b.cs").read_text(), "class B {}\n"
            )

    def test_requires_at_least_one_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "no C# fixtures"):
                generate_solution(root, root / ".native")

    def test_limit_is_deterministic_and_must_be_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.cs").write_text("class B {}\n")
            (root / "a.cs").write_text("class A {}\n")
            solution, count = generate_solution(root, root / "one", limit=1)
            self.assertEqual(count, 1)
            self.assertIn("fixture-0000", solution.read_text())
            self.assertNotIn("fixture-0001", solution.read_text())
            with self.assertRaisesRegex(ValueError, "must be positive"):
                generate_solution(root, root / "zero", limit=0)

    def test_configures_direct_analyzers_and_rule_severities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            (sources / "sample.cs").write_text("class Sample {}\n")
            analyzer = root / "SonarAnalyzer.CSharp.dll"
            analyzer.write_bytes(b"analyzer")

            generate_solution(
                sources,
                root / "native",
                analyzers=[analyzer],
                enabled_rules=["S200", "S100", "S100"],
                error_log="target.sarif",
            )

            project = (
                root / "native/projects/fixture-0000/fixture-0000.csproj"
            ).read_text()
            self.assertIn(f'Analyzer Include="{analyzer.resolve()}"', project)
            self.assertIn("<ErrorLog>target.sarif</ErrorLog>", project)
            self.assertEqual(
                (root / "native/.editorconfig").read_text(),
                "root = true\n\n[*.cs]\n"
                "dotnet_diagnostic.S100.severity = warning\n"
                "dotnet_diagnostic.S200.severity = warning\n",
            )

    def test_test_rule_fixtures_reference_a_test_framework_assembly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            (sources / "s2187_bad.cs").write_text("class Tests {}\n")
            (sources / "s100_bad.cs").write_text("class product {}\n")

            generate_solution(sources, root / "native")

            test_project = (
                root / "native/projects/fixture-0001/fixture-0001.csproj"
            ).read_text()
            product_project = (
                root / "native/projects/fixture-0000/fixture-0000.csproj"
            ).read_text()
            self.assertIn(
                '<ProjectReference Include="../test-framework/TestFramework.csproj" />',
                test_project,
            )
            self.assertNotIn("ProjectReference", product_project)
            marker = root / "native/projects/test-framework/TestFramework.csproj"
            self.assertIn("<AssemblyName>nunit.framework</AssemblyName>", marker.read_text())

    def test_s2970_fixtures_reference_nfluent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            (sources / "s2970_bad.cs").write_text("class Tests {}\n")

            generate_solution(sources, root / "native")

            project = (
                root / "native/projects/fixture-0000/fixture-0000.csproj"
            ).read_text()
            self.assertIn("../nfluent-framework/NFluent.csproj", project)
            marker = root / "native/projects/nfluent-framework/NFluent.csproj"
            self.assertIn("<AssemblyName>NFluent</AssemblyName>", marker.read_text())

    def test_azure_rule_fixtures_reference_framework_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            (sources / "s6419_bad.cs").write_text("class Function {}\n")
            (sources / "s6424_bad.cs").write_text("interface Entity {}\n")

            generate_solution(sources, root / "native")

            first = (root / "native/projects/fixture-0000/fixture-0000.csproj").read_text()
            second = (root / "native/projects/fixture-0001/fixture-0001.csproj").read_text()
            self.assertIn("../azure-functions-framework/AzureFunctions.csproj", first)
            self.assertIn("../durable-task-framework/DurableTask.csproj", second)
            azure = root / "native/projects/azure-functions-framework/AzureFunctions.csproj"
            durable = root / "native/projects/durable-task-framework/DurableTask.csproj"
            self.assertIn("Microsoft.Azure.WebJobs.Host", azure.read_text())
            self.assertIn("Microsoft.Azure.WebJobs.Extensions.DurableTask", durable.read_text())

    def test_rejects_invalid_direct_analyzer_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.cs").write_text("class Sample {}\n")
            with self.assertRaisesRegex(ValueError, "does not exist"):
                generate_solution(root, root / "missing", analyzers=[root / "missing.dll"])
            with self.assertRaisesRegex(ValueError, "rule ID"):
                generate_solution(root, root / "rule", enabled_rules=["CA1000"])
            with self.assertRaisesRegex(ValueError, "file name"):
                generate_solution(root, root / "log", error_log="nested/target.sarif")


if __name__ == "__main__":
    unittest.main()
