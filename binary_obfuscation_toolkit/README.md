# Pluggable Binary Obfuscation Toolkit

A modular toolkit for applying various obfuscation techniques to binaries (primarily ELF format at this stage). This project is designed to be extensible, allowing new obfuscation methods to be added as plugins.

## Features

*   **Plugin-Based Architecture:** Easily add new obfuscation techniques.
*   **Command-Line Interface (CLI):** User-friendly CLI for applying obfuscations.
*   **Supported Obfuscation Techniques (Plugins):**
    *   **Basic Compression (`basic_compressor`):** Compresses the entire input file using zlib. (Note: Does not create a self-extracting executable like UPX).
    *   **ELF Symbol Stripping (`elf_symbol_stripper`):** Removes symbols from ELF binaries using the system's `strip` utility.
    *   **ELF Section Injection (`elf_section_injector`):** Conceptual plugin to inject a payload into a new section in an ELF binary. (Note: Current implementation is simplified and may not result in a fully functional/valid ELF section without a more advanced ELF manipulation library like LIEF).
    *   **Basic Sandbox Detection (`basic_sandbox_detector`):** Conceptual plugin that simulates anti-sandbox checks on the host environment (does not modify the binary itself to perform these checks at runtime in its current version).

## Project Structure

```
binary_obfuscation_toolkit/
├── AGENTS.md                # Instructions for AI agents working on this codebase
├── cli/
│   ├── __init__.py
│   └── main.py              # Main CLI script
├── core/
│   ├── __init__.py
│   ├── plugin_base.py       # Abstract base class for plugins
│   └── plugin_manager.py    # Discovers and manages plugins
├── docs/                    # (Currently empty, for future detailed documentation)
├── plugins/
│   ├── __init__.py
│   ├── anti_sandbox/
│   │   ├── __init__.py
│   │   └── basic_sandbox_detector.py
│   ├── compression/
│   │   ├── __init__.py
│   │   └── basic_compressor.py
│   ├── section_injection/
│   │   ├── __init__.py
│   │   └── elf_section_injector.py
│   └── symbol_stripping/
│       ├── __init__.py
│       └── elf_symbol_stripper.py
├── README.md                # This file
├── requirements.txt         # Python dependencies
└── tests/
    ├── __init__.py
    ├── README.md            # How to run tests
    └── test_cli.py          # CLI integration tests
```

## Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository-url>
    cd binary-obfuscation-toolkit
    ```

2.  **Install Python dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r binary_obfuscation_toolkit/requirements.txt
    ```

3.  **External Dependencies:**
    *   The `elf_symbol_stripper` plugin relies on the `strip` command-line utility, which is typically part of GNU Binutils on Linux systems.
    *   Some tests (e.g., in `tests/test_cli.py` for symbol stripping) might require `gcc` to compile test binaries.

## Usage

The toolkit is operated via `binary_obfuscation_toolkit/cli/main.py`.

**General Syntax:**
```bash
python binary_obfuscation_toolkit/cli/main.py <input_file> -o <output_file> -p <plugin1> [plugin2...] [--plugin-options <options_string1>...]
```

**1. List Available Plugins:**
```bash
python binary_obfuscation_toolkit/cli/main.py --list-plugins
```

**2. Get Info on a Specific Plugin:**
This shows the plugin's description and any options it accepts.
```bash
python binary_obfuscation_toolkit/cli/main.py --plugin-info basic_compressor
```

**3. Apply a Single Plugin:**
```bash
# Example: Compress a binary
python binary_obfuscation_toolkit/cli/main.py myapp -o myapp.comp -p basic_compressor --plugin-options basic_compressor:level=9
```

**4. Apply Multiple Plugins (Chaining):**
Plugins are applied in the order they are specified. The output of one becomes the input for the next.
```bash
# Example: Compress then strip symbols
python binary_obfuscation_toolkit/cli/main.py myapp -o myapp.obf -p basic_compressor elf_symbol_stripper --plugin-options basic_compressor:level=9
```
(Note: The order might matter. Compressing first then stripping might be different from stripping then compressing, especially regarding symbol table data that could affect compression ratios).

**Plugin Options Format:**
Options are passed using `--plugin-options`. Each option string is formatted as:
*   `plugin_name:key=value` (e.g., `basic_compressor:level=7`)
*   `plugin_name:{"json_key":"json_value", ...}` (for complex options, e.g., `my_plugin:{"config_param":"foo","value":123}`)

## Extending the Toolkit (Adding New Plugins)

1.  Create a new Python file in an appropriate subdirectory under `binary_obfuscation_toolkit/plugins/` (e.g., `plugins/my_new_feature/my_plugin_impl.py`).
2.  In your new file, define a class that inherits from `binary_obfuscation_toolkit.core.plugin_base.ObfuscationPlugin`.
3.  Implement the required abstract methods:
    *   `get_name(self) -> str`: Return a unique name for your plugin (used in the CLI).
    *   `get_description(self) -> str`: Return a short description.
    *   `obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool`: Implement your obfuscation logic. Read from `binary_path`, write to `output_path`. Return `True` on success, `False` on failure.
4.  Optionally, implement `get_options_schema(self) -> dict` to define options your plugin accepts. This schema is used by the CLI to display help information.
5.  The `PluginManager` will automatically discover your new plugin if it's correctly placed and implemented.

Refer to existing plugins for examples.

## Running Tests

See `binary_obfuscation_toolkit/tests/README.md` for instructions on how to run the available tests.

## Disclaimer

This toolkit is for educational and research purposes. Applying these techniques to binaries without proper authorization is unethical and potentially illegal. The effectiveness of these obfuscation techniques can vary and may not deter determined reverse engineers. Some plugins (especially `elf_section_injector`) are conceptual and may produce non-functional binaries.
```
