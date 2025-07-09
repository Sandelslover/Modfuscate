import subprocess
import os
import sys
import shutil

# Determine project root to correctly locate the CLI script and plugins
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_MAIN_PY = os.path.join(PROJECT_ROOT, "binary_obfuscation_toolkit", "cli", "main.py")

# Ensure plugins can be found by the CLI (adjusting PYTHONPATH if necessary for subprocess)
# The CLI script itself tries to adjust sys.path, which works when it's the main script.
# For subprocess, ensuring PYTHONPATH is set or plugins are accessible is key.
# The current CLI structure (main.py in cli/ and plugins in plugins/)
# with sys.path.append(PROJECT_ROOT) in main.py should generally work if
# main.py is invoked with python from the project root or if its location is specified.

def run_cli_command(command_args):
    """Helper function to run the CLI script and return its output."""
    cmd = [sys.executable, CLI_MAIN_PY] + command_args
    print(f"Running command: {' '.join(cmd)}")
    try:
        # Set cwd to PROJECT_ROOT to ensure plugins are discoverable relative to it,
        # as designed in PluginManager and CLI's path adjustments.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=PROJECT_ROOT)
        stdout, stderr = process.communicate(timeout=30)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout + "\nTimeoutExpired", stderr
    except Exception as e:
        return -1, "", str(e)

def create_dummy_binary(filepath="dummy_test_app.bin", content=b"Test binary content"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(content * 100) # Make it a bit larger for compression tests
    return filepath

def setup_test_environment():
    """Creates necessary dummy files or configurations for tests."""
    # The plugin manager test already creates dummy plugins if run directly.
    # For CLI tests, we rely on actual plugins developed.
    # Ensure the plugin directories exist, so plugin discovery doesn't fail early.
    os.makedirs(os.path.join(PROJECT_ROOT, "binary_obfuscation_toolkit", "plugins", "compression"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "binary_obfuscation_toolkit", "plugins", "symbol_stripping"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "binary_obfuscation_toolkit", "plugins", "section_injection"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "binary_obfuscation_toolkit", "plugins", "anti_sandbox"), exist_ok=True)
    # We also need the __init__.py files in these, which should have been created by previous steps.

def cleanup_test_files(*files_or_dirs):
    for item in files_or_dirs:
        if os.path.isdir(item):
            shutil.rmtree(item, ignore_errors=True)
        elif os.path.isfile(item):
            try:
                os.remove(item)
            except OSError:
                pass

def test_list_plugins():
    print("\n--- Testing: List Plugins ---")
    returncode, stdout, stderr = run_cli_command(["--list-plugins"])
    print(f"STDOUT:\n{stdout}")
    print(f"STDERR:\n{stderr}")
    assert returncode == 0, f"CLI --list-plugins failed with stderr: {stderr}"
    assert "Available plugins:" in stdout
    assert "basic_compressor" in stdout
    assert "elf_symbol_stripper" in stdout
    # Add more checks if other plugins are expected by default
    print("List Plugins test PASSED.")

def test_plugin_info():
    print("\n--- Testing: Plugin Info (basic_compressor) ---")
    returncode, stdout, stderr = run_cli_command(["--plugin-info", "basic_compressor"])
    print(f"STDOUT:\n{stdout}")
    print(f"STDERR:\n{stderr}")
    assert returncode == 0, f"CLI --plugin-info failed with stderr: {stderr}"
    assert "Plugin: basic_compressor" in stdout
    assert "Options:" in stdout
    assert "--level" in stdout # Check for a known option
    print("Plugin Info test PASSED.")

def test_basic_compression_via_cli():
    print("\n--- Testing: Basic Compression via CLI ---")
    input_bin = "test_files/input.bin"
    output_bin = "test_files/output.compressed.bin"
    os.makedirs("test_files", exist_ok=True)
    create_dummy_binary(input_bin)

    cmd_args = [
        input_bin,
        "--output_file", output_bin,
        "--plugins", "basic_compressor",
        "--plugin-options", "basic_compressor:level=1"
    ]
    returncode, stdout, stderr = run_cli_command(cmd_args)
    print(f"STDOUT:\n{stdout}")
    print(f"STDERR:\n{stderr}")

    assert returncode == 0, f"CLI compression failed with stderr: {stderr}"
    assert os.path.exists(output_bin), "Output file was not created."
    # A simple check: compressed should be smaller for this dummy binary
    assert os.path.getsize(output_bin) < os.path.getsize(input_bin), \
        f"Compressed file ({os.path.getsize(output_bin)}) is not smaller than original ({os.path.getsize(input_bin)})."
    print("Basic Compression via CLI test PASSED.")
    cleanup_test_files("test_files")


def test_symbol_stripping_via_cli():
    print("\n--- Testing: Symbol Stripping via CLI ---")
    # This test requires a C compiler (gcc) and 'strip' utility to be present.
    # The ElfSymbolStripperPlugin's own test script already handles C file compilation.
    # For this CLI test, we'll rely on that logic or a pre-compiled binary if available.

    # Create a simple C file and compile it with debug symbols
    c_file_content = "#include <stdio.h>\nint main() { printf(\"Hello\\n\"); return 0; }"
    c_file_name = "test_files/temp_strip_test.c"
    executable_name = "test_files/temp_strip_test_orig.elf"
    stripped_executable_name = "test_files/temp_strip_test_stripped.elf"

    os.makedirs("test_files", exist_ok=True)
    with open(c_file_name, "w") as f:
        f.write(c_file_content)

    compile_cmd = ["gcc", "-g", c_file_name, "-o", executable_name]
    compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)

    if compile_proc.returncode != 0 or not shutil.which("strip"):
        print("Skipping Symbol Stripping CLI test: gcc compilation failed or 'strip' command not found.")
        print(f"GCC stdout: {compile_proc.stdout}")
        print(f"GCC stderr: {compile_proc.stderr}")
        cleanup_test_files("test_files")
        return

    original_size = os.path.getsize(executable_name)

    cmd_args = [
        executable_name,
        "--output_file", stripped_executable_name,
        "--plugins", "elf_symbol_stripper",
        # Default options for elf_symbol_stripper should be fine (strip_all=True)
    ]
    returncode, stdout, stderr = run_cli_command(cmd_args)
    print(f"STDOUT:\n{stdout}")
    print(f"STDERR:\n{stderr}")

    assert returncode == 0, f"CLI symbol stripping failed with stderr: {stderr}"
    assert os.path.exists(stripped_executable_name), "Stripped output file was not created."
    stripped_size = os.path.getsize(stripped_executable_name)
    assert stripped_size < original_size, \
        f"Stripped file size ({stripped_size}) is not smaller than original ({original_size}). Might already be stripped or strip failed."

    print("Symbol Stripping via CLI test PASSED.")
    cleanup_test_files("test_files")


if __name__ == "__main__":
    print("Starting CLI tests...")
    setup_test_environment()

    test_list_plugins()
    test_plugin_info()
    test_basic_compression_via_cli()
    test_symbol_stripping_via_cli() # This test has dependencies (gcc, strip)

    # Add calls to other test functions here

    print("\nAll CLI tests completed.")
    # Final cleanup of any persistent test artifacts if necessary, though individual tests try to cleanup.
    cleanup_test_files("test_files") # General cleanup for the test_files dir itself.
