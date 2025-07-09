# Tests for Pluggable Binary Obfuscation Toolkit

This directory contains tests for the toolkit.

## Running Tests

### CLI Tests

The `test_cli.py` script includes basic integration tests for the command-line interface. It uses `subprocess` to execute the main CLI script (`binary_obfuscation_toolkit/cli/main.py`) with various arguments and checks its behavior.

To run the CLI tests:
```bash
python binary_obfuscation_toolkit/tests/test_cli.py
```
Make sure you are in the root directory of the project when running this, or adjust paths accordingly if `test_cli.py` cannot locate the main CLI script or plugins. The script is designed to be run from the project root or for `PROJECT_ROOT` to be correctly inferred.

**Dependencies for `test_cli.py`:**
- Some tests, like `test_symbol_stripping_via_cli`, may require external tools such as `gcc` (to compile a test binary) and `strip` (used by the `elf_symbol_stripper` plugin). If these are not available, those specific tests might be skipped or fail.
- The required Python packages (e.g., `pyelftools`, `psutil`) should be installed in your environment. You can install them using the main `requirements.txt`:
  ```bash
  pip install -r binary_obfuscation_toolkit/requirements.txt
  ```

### Plugin Self-Tests

Most individual plugins (e.g., `binary_obfuscation_toolkit/plugins/compression/basic_compressor.py`) contain an `if __name__ == '__main__':` block. This block typically includes code to test the plugin's core functionality directly.

To run a plugin's self-test, execute the plugin file directly with Python:
```bash
python binary_obfuscation_toolkit/plugins/compression/basic_compressor.py
python binary_obfuscation_toolkit/plugins/symbol_stripping/elf_symbol_stripper.py
# etc.
```

### Plugin Manager Self-Test

The `PluginManager` also has a self-test:
```bash
python binary_obfuscation_toolkit/core/plugin_manager.py
```
This test creates dummy plugin files and verifies the discovery and loading mechanism. It cleans up these dummy files afterwards.

## Future Improvements

- Implement a more formal testing framework like `unittest` or `pytest`.
- Add more comprehensive unit tests for each module and plugin.
- Create more sophisticated integration tests that verify the binary modifications in detail (e.g., by using `readelf` or other binary analysis tools to inspect the output files).
- Mock external dependencies like the `strip` command for more isolated unit tests of plugins that use them.
