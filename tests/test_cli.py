"""
Tests for the CLI interface.

These tests verify the CLI commands work correctly.
Storage integration is tested more thoroughly in test_storage.py.

Note: CLI tests that interact with the database use the user's existing
database (if any). For full isolation, run tests in a clean environment.
"""

import json
import pytest
from click.testing import CliRunner
from syfter.cli import main


@pytest.fixture
def runner():
    """Get a Click test runner."""
    return CliRunner()


class TestCliBasics:
    """Test basic CLI functionality."""
    
    def test_help(self, runner):
        """--help should work."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Syfter" in result.output
    
    def test_version(self, runner):
        """--version should work."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
    
    def test_check_command(self, runner):
        """check command should work (may fail if syft not installed)."""
        result = runner.invoke(main, ["--local", "check"])
        # Either succeeds or fails with helpful message
        assert result.exit_code in [0, 1]
    
    def test_products_command_exists(self, runner):
        """products command should run (even with empty db)."""
        result = runner.invoke(main, ["--local", "products"])
        assert result.exit_code == 0
        # Should have either "No products" or a table header
        assert "Products" in result.output or "No products" in result.output
    
    def test_stats_command_exists(self, runner):
        """stats command should run."""
        result = runner.invoke(main, ["--local", "stats"])
        assert result.exit_code == 0
        assert "Products" in result.output
    
    def test_query_requires_filter(self, runner):
        """query should require a filter."""
        result = runner.invoke(main, ["--local", "query"])
        assert result.exit_code == 0
        assert "specify" in result.output.lower()


class TestQueryCommand:
    """Test the query command structure."""
    
    def test_query_package_option(self, runner):
        """Query with -n option should work."""
        result = runner.invoke(main, ["--local", "query", "-n", "nonexistent-pkg-12345"])
        assert result.exit_code == 0
        # Should complete without error (even if no results)
    
    def test_query_file_option(self, runner):
        """Query with -f option should work."""
        result = runner.invoke(main, ["--local", "query", "-f", "/nonexistent/path/12345"])
        assert result.exit_code == 0
    
    def test_query_json_option(self, runner):
        """Search with --json should output JSON."""
        result = runner.invoke(main, ["--local", "search", "-n", "nonexistent-pkg-12345", "--json"])
        assert result.exit_code == 0
        # Should be valid JSON (even if empty array)
        data = json.loads(result.output)
        assert isinstance(data, list)


class TestListCommand:
    """Test the list command structure."""
    
    def test_list_requires_product(self, runner):
        """list should require product and version."""
        result = runner.invoke(main, ["--local", "list"])
        assert result.exit_code != 0  # Should fail without required options
    
    def test_list_with_nonexistent_product(self, runner):
        """list with nonexistent product should handle gracefully."""
        result = runner.invoke(main, [
            "--local", "list",
            "-p", "nonexistent-product-12345",
            "-v", "1.0.0",
            "-t", "packages"
        ])
        # Should exit cleanly (no packages found is OK)
        assert result.exit_code == 0
    
    def test_list_types(self, runner):
        """list should accept files and packages types."""
        for list_type in ["files", "packages"]:
            result = runner.invoke(main, [
                "--local", "list",
                "-p", "test",
                "-v", "1.0",
                "-t", list_type
            ])
            # Command should be accepted (even if no data)
            assert result.exit_code == 0


class TestExportCommand:
    """Test the export command structure."""
    
    def test_export_requires_options(self, runner):
        """export should require product/version."""
        result = runner.invoke(main, ["--local", "export"])
        assert result.exit_code != 0
    
    def test_export_format_validation(self, runner, tmp_path):
        """export should validate format."""
        result = runner.invoke(main, [
            "--local", "export",
            "-p", "test",
            "-v", "1.0",
            "-f", "invalid-format-xyz",
            "-o", str(tmp_path / "out.json")
        ])
        # Should fail with invalid format
        assert result.exit_code != 0 or "invalid" in result.output.lower() or "not found" in result.output.lower()


class TestScanCommand:
    """Test the scan command structure."""
    
    def test_scan_requires_target(self, runner):
        """scan should require a target."""
        result = runner.invoke(main, ["--local", "scan"])
        assert result.exit_code != 0
    
    def test_scan_requires_product(self, runner):
        """scan should require product and version."""
        result = runner.invoke(main, ["--local", "scan", "/tmp"])
        assert result.exit_code != 0


class TestSystemCommands:
    """Test system-related commands exist."""
    
    def test_systems_command_exists(self, runner):
        """systems command should work."""
        result = runner.invoke(main, ["systems", "--help"])
        assert result.exit_code == 0
        assert "system" in result.output.lower()
    
    def test_system_scan_command_exists(self, runner):
        """system-scan command should have help."""
        result = runner.invoke(main, ["system-scan", "--help"])
        assert result.exit_code == 0
    
    def test_system_query_command_exists(self, runner):
        """system-query command should have help."""
        result = runner.invoke(main, ["system-query", "--help"])
        assert result.exit_code == 0


class TestLayersCommand:
    """Test the layers command structure."""
    
    def test_layers_requires_product(self, runner):
        """layers command should require product/version."""
        result = runner.invoke(main, ["--local", "layers"])
        assert result.exit_code != 0
    
    def test_layers_help(self, runner):
        """layers command should have help."""
        result = runner.invoke(main, ["layers", "--help"])
        assert result.exit_code == 0
        assert "layer" in result.output.lower()
