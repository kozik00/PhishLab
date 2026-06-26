from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from phishlab_cli.main import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"
EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "emails"


class TestAnalyzeCommand:
    def test_analyze_simple(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(FIXTURES_DIR / "simple.eml")])
        assert result.exit_code == 0
        assert "Email" in result.output
        assert "Analysis Result" in result.output

    def test_analyze_phishing(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(FIXTURES_DIR / "phishing_links.eml")])
        assert result.exit_code == 0
        assert "Findings" in result.output

    def test_analyze_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "-v", str(FIXTURES_DIR / "phishing_links.eml")])
        assert result.exit_code == 0

    def test_analyze_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--json", str(FIXTURES_DIR / "simple.eml")])
        assert result.exit_code == 0
        assert '"risk_score"' in result.output

    def test_analyze_nonexistent(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "nonexistent.eml"])
        assert result.exit_code != 0


class TestReportCommand:
    def test_markdown_report(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", str(FIXTURES_DIR / "phishing_links.eml"), "-f", "markdown"]
        )
        assert result.exit_code == 0
        assert "PhishLab" in result.output

    def test_json_report(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", str(FIXTURES_DIR / "simple.eml"), "-f", "json"]
        )
        assert result.exit_code == 0

    def test_html_report(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", str(FIXTURES_DIR / "phishing_links.eml"), "-f", "html"]
        )
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    def test_user_report(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", str(FIXTURES_DIR / "simple.eml"), "-f", "user"]
        )
        assert result.exit_code == 0

    def test_report_to_file(self, tmp_path):
        out = tmp_path / "report.md"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", str(FIXTURES_DIR / "simple.eml"), "-o", str(out)]
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "PhishLab" in out.read_text(encoding="utf-8")


class TestInspectCommand:
    def test_inspect_simple(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", str(FIXTURES_DIR / "simple.eml")])
        assert result.exit_code == 0
        assert "Email" in result.output
        assert "john.doe@example.com" in result.output

    def test_inspect_with_attachments(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", str(FIXTURES_DIR / "with_attachments.eml")])
        assert result.exit_code == 0
        assert "Attachments" in result.output

    def test_inspect_with_links(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", str(FIXTURES_DIR / "phishing_links.eml")])
        assert result.exit_code == 0
        assert "Links" in result.output


class TestTrainingCommand:
    def test_list_training(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["training"])
        assert result.exit_code == 0
        assert "Training Samples" in result.output
        assert "Microsoft Account" in result.output


class TestScanCommand:
    def test_scan_fixtures(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES_DIR)])
        assert result.exit_code == 0
        assert "Scan Results" in result.output

    def test_scan_examples(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(EXAMPLES_DIR)])
        assert result.exit_code == 0
        assert "7" in result.output or "files" in result.output

    def test_scan_with_threshold(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(EXAMPLES_DIR), "-t", "80"])
        assert result.exit_code == 0

    def test_scan_empty_dir(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No .eml files" in result.output


class TestVersionFlag:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.2.0" in result.output
