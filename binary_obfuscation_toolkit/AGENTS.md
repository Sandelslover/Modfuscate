# AGENTS.md - Guidelines for AI Agents

This document provides guidelines for AI agents contributing to the Pluggable Binary Obfuscation Toolkit.

## Project Overview

The toolkit is designed to be a modular system for applying various obfuscation techniques to binaries, primarily ELF files. Key components include:
-   **Core (`core/`):** Contains the plugin management system (`plugin_manager.py`) and the base plugin class (`plugin_base.py`).
-   **Plugins (`plugins/`):** Individual obfuscation techniques are implemented as plugins here, organized into subdirectories by category (e.g., `compression`, `symbol_stripping`).
-   **CLI (`cli/`):** The command-line interface for users to interact with the toolkit.
-   **Tests (`tests/`):** Contains test scripts.

## Development Guidelines

1.  **Plugin Development:**
    *   All new obfuscation techniques should be implemented as plugins.
    *   Plugins must inherit from `binary_obfuscation_toolkit.core.plugin_base.ObfuscationPlugin` and implement all its abstract methods (`get_name`, `get_description`, `obfuscate`).
    *   Plugin names (`get_name()`) should be unique and follow a `snake_case` convention.
    *   If a plugin accepts options, define them in `get_options_schema()`. This helps with CLI integration and user understanding.
    *   Place new plugins in an appropriate subdirectory within `binary_obfuscation_toolkit/plugins/`. Create a new subdirectory if a suitable category doesn't exist.
    *   Ensure each plugin directory and subdirectory containing plugin modules has an `__init__.py` file.
    *   It is highly recommended to include an `if __name__ == '__main__':` block in each plugin file for self-testing its core functionality.

2.  **Binary Format Handling:**
    *   Currently, the toolkit primarily targets ELF files. Be mindful of this when adding features. If PE or Mach-O support is added, it should be clearly delineated.
    *   For reading ELF files, `pyelftools` is the current standard library.
    *   **Important:** `pyelftools` has limited support for *writing or modifying* ELF files. Plugins requiring significant ELF modification (like `elf_section_injector`) are complex.
        *   For robust ELF modification, consider researching and potentially integrating libraries like LIEF (`lief-project.github.io`). This would be a significant enhancement.
        *   If implementing manual ELF modifications, be extremely careful about updating all relevant headers, offsets, and sizes to maintain binary validity. This is error-prone.

3.  **Dependencies:**
    *   Add any new Python package dependencies to `binary_obfuscation_toolkit/requirements.txt`.
    *   If a plugin relies on external command-line tools (like `strip` or `gcc`), ensure the plugin checks for their availability and handles their absence gracefully. Document these external dependencies in the main `README.md` and in the plugin's description/docstrings.

4.  **Testing:**
    *   Add tests for new functionality.
    *   Plugin self-tests (via `if __name__ == '__main__':`) are good for unit testing.
    *   For CLI changes or interactions between plugins, add tests to `binary_obfuscation_toolkit/tests/test_cli.py` or create new test files in the `tests/` directory.
    *   Refer to `binary_obfuscation_toolkit/tests/README.md` for how tests are structured and run.

5.  **Command-Line Interface (`cli/main.py`):**
    *   When adding new global CLI options or significantly changing CLI behavior, update `cli/main.py`.
    *   Plugin-specific options should primarily be handled via the `get_options_schema()` in the plugin and parsed by the existing `--plugin-options` mechanism in the CLI.

6.  **Documentation:**
    *   Update the main `README.md` for any new features, plugins, or significant changes in usage.
    *   Ensure plugin descriptions (`get_description()`) are clear and concise.
    *   Add comments to code where necessary, especially for complex logic.

7.  **Error Handling and User Feedback:**
    *   Plugins should provide clear error messages if they fail.
    *   The CLI should report errors from plugins or its own operations effectively.
    *   Print informative messages about the steps being taken (e.g., "Applying plugin X...").

8.  **Cross-Platform Compatibility:**
    *   While initially focused on ELF (Linux), consider if new features could be cross-platform or how they might affect future cross-platform support. For example, Python's `os`, `shutil`, `subprocess` modules have cross-platform aspects, but binary formats are inherently platform-specific.

9.  **Security/Ethical Considerations:**
    *   Remember that this toolkit deals with binary modification. Emphasize responsible use in documentation.
    *   The `elf_section_injector` and `anti_sandbox` modules, in particular, touch on areas common in malware development. Their implementation should be handled with a focus on understanding the techniques, not for malicious purposes.

## Specific Plugin Notes

*   **`elf_section_injector`:** This plugin is currently conceptual. Enhancing it to correctly and robustly inject sections (especially executable ones) into ELF files is a complex task that would likely require a more powerful ELF manipulation library than `pyelftools` (e.g., LIEF).
*   **`basic_sandbox_detector`:** This plugin is also conceptual, performing checks on the host system. To make it a true anti-sandbox module for binaries, the C code snippets provided as comments would need to be compiled to shellcode and injected into the target binary, with execution flow modified to run them.

By following these guidelines, AI agents can contribute effectively and maintain the quality and structure of the toolkit.
```
