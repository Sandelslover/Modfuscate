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

*   **`elf_section_injector`:**
    *   **Current Capability:** This plugin has been enhanced to correctly add new section headers to the SHT and append section data. It can set section name, type, flags (including `SHF_ALLOC`, `SHF_EXECINSTR`), file offset, size, and calculates a virtual address (`sh_addr`) for the new section. It also correctly updates the `.shstrtab` and relevant ELF header fields (`e_shnum`, `e_shoff`).
    *   **Critical Missing Feature:** The plugin **does NOT yet modify the Program Header Table (PHT)** to add a corresponding `PT_LOAD` segment for newly injected executable sections. This is essential for the OS loader to map the section into memory with execute permissions. Without this, injected code will not run.
    *   **Future Work:** The highest priority for this plugin is implementing robust PHT modification. This could involve finding space for new PHDR entries, potentially shifting file content, or using techniques like converting `PT_NOTE` segments. Investigating the use of a library like LIEF for these modifications is still recommended for long-term robustness.

*   **`basic_sandbox_detector`:**
    *   **Current Workflow:** This plugin now uses `core.compiler_utils.compile_c_to_shellcode` to compile a C snippet into raw shellcode. It then uses `ElfSectionInjectorPlugin` to inject this shellcode into a new executable section and subsequently modifies the ELF's entry point (`e_entry`) to point to the start of this injected shellcode.
    *   **Dependency on Injector:** Its ability to actually execute the injected shellcode is entirely dependent on `ElfSectionInjectorPlugin` creating a correctly mapped executable segment (which, as noted above, is currently limited by PHT handling).
    *   **Shellcode Considerations:** The default test shellcode simply calls `exit(42)`. For true anti-sandbox behavior, the C code would need to perform actual detection logic and then decide whether to terminate, alter behavior, or return control to the original program. Returning control would require careful management of the stack and registers, and a mechanism to jump to the original entry point (which would need to be saved or passed to the shellcode).
    *   **Future Work:** Once section injection (including PHT/`PT_LOAD`) is fully functional, this plugin can be expanded with more sophisticated C-based sandbox detection routines and more advanced control flow hijacking/restoration techniques.

By following these guidelines, AI agents can contribute effectively and maintain the quality and structure of the toolkit.
```
