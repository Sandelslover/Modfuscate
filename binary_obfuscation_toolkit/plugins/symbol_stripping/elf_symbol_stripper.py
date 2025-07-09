import os
import shutil
import subprocess
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

class ElfSymbolStripperPlugin(ObfuscationPlugin):
    """
    Strips symbols from an ELF binary using the system's 'strip' utility.
    """

    def get_name(self) -> str:
        return "elf_symbol_stripper"

    def get_description(self) -> str:
        return "Strips symbols from an ELF binary using the 'strip' command."

    def get_options_schema(self) -> dict:
        return {
            "strip_all": {
                "type": "boolean",
                "description": "Equivalent to 'strip --strip-all'. Removes more than just the symbol table.",
                "default": True,
                "required": False
            },
            "strip_debug": {
                "type": "boolean",
                "description": "Equivalent to 'strip --strip-debug'. Removes only debugging symbols.",
                "default": False,
                "required": False
            }
            # Add more options here to mirror `strip` utility's capabilities if needed.
        }

    def _is_strip_available(self) -> bool:
        """Checks if the 'strip' command is available."""
        return shutil.which("strip") is not None

    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        if not self._is_strip_available():
            print("Error: 'strip' command not found in PATH. This plugin cannot operate.")
            return False

        options = options or {}
        strip_all = options.get("strip_all", True)
        strip_debug = options.get("strip_debug", False)

        if not os.path.exists(binary_path):
            print(f"Error: Input binary '{binary_path}' not found.")
            return False

        # It's safer to work on a copy
        try:
            shutil.copy2(binary_path, output_path)
        except Exception as e:
            print(f"Error copying file '{binary_path}' to '{output_path}': {e}")
            return False

        cmd = ["strip"]
        if strip_debug: # --strip-debug often implies not stripping everything else aggressively
            cmd.append("--strip-debug")
        elif strip_all: # Default behavior if strip_debug is false
            cmd.append("--strip-all")
        # If both are false, 'strip' usually defaults to stripping symbol table and relocations not needed for execution.
        # If both are true, let --strip-debug take precedence as it's more specific.
        # Or, we could make them mutually exclusive in option validation.
        # For now, if strip_debug is true, it's the primary mode. Otherwise, strip_all controls.

        cmd.append(output_path)

        try:
            print(f"Executing command: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30) # Timeout to prevent hangs

            if process.returncode == 0:
                print(f"Successfully stripped symbols from '{output_path}'.")
                # Verify by checking size reduction (optional, but good feedback)
                original_size = os.path.getsize(binary_path)
                stripped_size = os.path.getsize(output_path)
                if stripped_size < original_size:
                    print(f"Size reduced from {original_size} to {stripped_size} bytes.")
                elif stripped_size == original_size:
                    print(f"File size did not change. It might have already been stripped or contains no strippable symbols.")
                else:
                    # This should ideally not happen with 'strip' unless it's a very unusual ELF.
                    print(f"Warning: File size increased from {original_size} to {stripped_size} bytes. This is unexpected.")
                return True
            else:
                print(f"Error running 'strip' command (return code {process.returncode}):")
                if stdout:
                    print(f"Stdout: {stdout.decode(errors='ignore')}")
                if stderr:
                    print(f"Stderr: {stderr.decode(errors='ignore')}")
                # If strip failed, the output_path might be corrupted or unchanged.
                # It's safer to remove it if it's different from input_path.
                if binary_path != output_path:
                    try:
                        os.remove(output_path)
                    except OSError:
                        pass
                return False
        except subprocess.TimeoutExpired:
            print(f"Error: 'strip' command timed out for '{output_path}'.")
            if process:
                process.kill()
                process.communicate()
            if binary_path != output_path and os.path.exists(output_path):
                 try:
                    os.remove(output_path)
                 except OSError:
                    pass
            return False
        except Exception as e:
            print(f"An unexpected error occurred while trying to strip '{output_path}': {e}")
            if binary_path != output_path and os.path.exists(output_path):
                 try:
                    os.remove(output_path)
                 except OSError:
                    pass
            return False

if __name__ == '__main__':
    plugin = ElfSymbolStripperPlugin()

    if not plugin._is_strip_available():
        print("Skipping ElfSymbolStripperPlugin direct test: 'strip' command not available.")
    else:
        # Create a dummy ELF file for testing.
        # The best way is to compile a simple C program with debug symbols.
        # gcc -g -o dummy_elf_debuggable tiny.c
        # For this script, we'll try to find a system utility and copy it.
        dummy_elf_file = "dummy_elf_to_strip.bin"
        dummy_output_file_all = "dummy_elf_stripped_all.bin"
        dummy_output_file_debug = "dummy_elf_stripped_debug.bin"

        source_elf_path = None
        # Try to find a suitable ELF file to test stripping on
        # Common system utilities that are not already stripped are good candidates
        # but many are pre-stripped. /usr/bin/cat or /usr/bin/ls are often stripped.
        # A self-compiled simple C program with `gcc -g myprogram.c -o myprogram` is ideal.

        # For automated testing, we'll create a very simple C file and compile it.
        # This makes the test self-contained.
        c_file_content = """
        #include <stdio.h>
        int main() {
            printf("Hello, Stripper!\\n");
            return 0;
        }
        """
        c_file_name = "temp_test_program.c"
        executable_name = "temp_test_program"
        with open(c_file_name, "w") as f:
            f.write(c_file_content)

        compile_cmd = ["gcc", "-g", c_file_name, "-o", executable_name]
        print(f"Compiling test C file: {' '.join(compile_cmd)}")
        compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)

        if compile_proc.returncode == 0:
            print(f"Successfully compiled '{executable_name}'.")
            source_elf_path = executable_name
            shutil.copy2(source_elf_path, dummy_elf_file) # Copy for the test
        else:
            print(f"Failed to compile test C file. Attempting to use /usr/bin/cat as fallback.")
            print(f"Compiler stdout: {compile_proc.stdout}")
            print(f"Compiler stderr: {compile_proc.stderr}")
            if os.path.exists("/usr/bin/cat"): # Fallback
                source_elf_path = "/usr/bin/cat"
                shutil.copy2(source_elf_path, dummy_elf_file)
            else:
                print("Error: Cannot find a suitable ELF file for testing strip. Skipping direct test.")
                # Clean up C file if compilation failed or no fallback
                if os.path.exists(c_file_name): os.remove(c_file_name)
                if os.path.exists(executable_name): os.remove(executable_name)
                exit() # Exit if no test file can be obtained.

        print(f"Testing {plugin.get_name()} with '{dummy_elf_file}':")

        # Test with --strip-all (default)
        options_all = {"strip_all": True}
        success_all = plugin.obfuscate(dummy_elf_file, dummy_output_file_all, options=options_all)
        print(f"Obfuscation with strip_all successful: {success_all}")
        if success_all and os.path.exists(dummy_output_file_all):
            original_size = os.path.getsize(dummy_elf_file)
            stripped_size = os.path.getsize(dummy_output_file_all)
            print(f"Original size: {original_size}, Stripped (all) size: {stripped_size}")
            if compile_proc.returncode == 0: # Only assert if we compiled with -g
                 assert stripped_size < original_size, "Stripping all should reduce size for a debug build."
            # os.remove(dummy_output_file_all) # Keep for inspection

        # Test with --strip-debug
        options_debug = {"strip_debug": True, "strip_all": False} # Explicitly set strip_all to False
        success_debug = plugin.obfuscate(dummy_elf_file, dummy_output_file_debug, options=options_debug)
        print(f"Obfuscation with strip_debug successful: {success_debug}")
        if success_debug and os.path.exists(dummy_output_file_debug):
            original_size = os.path.getsize(dummy_elf_file)
            stripped_size = os.path.getsize(dummy_output_file_debug)
            print(f"Original size: {original_size}, Stripped (debug) size: {stripped_size}")
            if compile_proc.returncode == 0: # Only assert if we compiled with -g
                assert stripped_size < original_size, "Stripping debug should reduce size for a debug build."
            # os.remove(dummy_output_file_debug) # Keep for inspection

        # Test with default options (should be strip_all)
        dummy_output_file_default = "dummy_elf_stripped_default.bin"
        success_default = plugin.obfuscate(dummy_elf_file, dummy_output_file_default)
        print(f"Obfuscation with default options successful: {success_default}")
        if success_default and os.path.exists(dummy_output_file_default):
            original_size = os.path.getsize(dummy_elf_file)
            stripped_size = os.path.getsize(dummy_output_file_default)
            print(f"Original size: {original_size}, Stripped (default) size: {stripped_size}")
            if compile_proc.returncode == 0: # Only assert if we compiled with -g
                 assert stripped_size < original_size, "Stripping with default should reduce size for a debug build."
            # os.remove(dummy_output_file_default)

        # Cleanup
        if os.path.exists(dummy_elf_file): os.remove(dummy_elf_file)
        if os.path.exists(c_file_name): os.remove(c_file_name)
        if os.path.exists(executable_name): os.remove(executable_name)
        # Keep output files for manual inspection if needed, or remove them:
        if os.path.exists(dummy_output_file_all): os.remove(dummy_output_file_all)
        if os.path.exists(dummy_output_file_debug): os.remove(dummy_output_file_debug)
        if os.path.exists(dummy_output_file_default): os.remove(dummy_output_file_default)

        print(f"{plugin.get_name()} test complete.")
