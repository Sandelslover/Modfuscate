import argparse
import os
import sys
import json

# Adjust Python path to import from sibling directories (core, plugins)
# This is a common pattern for simple project structures.
# For more complex projects, packaging and installation (e.g., with setup.py) are better.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from binary_obfuscation_toolkit.core.plugin_manager import PluginManager
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

def main():
    parser = argparse.ArgumentParser(
        description="Pluggable Binary Obfuscation Toolkit.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("input_file", nargs='?', help="Path to the input binary file.")
    parser.add_argument("-o", "--output_file", help="Path to save the obfuscated binary file.")

    parser.add_argument(
        "-p", "--plugins",
        nargs='+',
        help="One or more plugins to apply (e.g., basic_compressor elf_symbol_stripper)."
    )
    parser.add_argument(
        "--plugin-options",
        nargs='+',
        help="JSON strings or key=value pairs for plugin options. "
             "E.g., 'basic_compressor:{\"level\":9}' or 'basic_compressor:level=9'. "
             "Repeat for multiple plugins or options: basic_compressor:level=9 elf_symbol_stripper:strip_debug=true"
    )
    parser.add_argument(
        "-l", "--list-plugins",
        action="store_true",
        help="List available plugins and exit."
    )
    parser.add_argument(
        "--plugin-info",
        metavar="PLUGIN_NAME",
        help="Show detailed information and options for a specific plugin."
    )

    args = parser.parse_args()

    # Initialize PluginManager
    # Assuming plugins are in ../plugins relative to this cli/main.py file's directory's parent
    plugin_dir_path = os.path.join(PROJECT_ROOT, "plugins")
    manager = PluginManager(plugin_dir=plugin_dir_path)
    manager.discover_plugins()
    all_plugins = manager.get_all_plugins()

    if args.list_plugins:
        print("Available plugins:")
        if not all_plugins:
            print("  No plugins found.")
            return
        for name, plugin_instance in all_plugins.items():
            print(f"  - {name}: {plugin_instance.get_description()}")
        return

    if args.plugin_info:
        plugin_name_to_info = args.plugin_info
        if plugin_name_to_info in all_plugins:
            plugin_instance = all_plugins[plugin_name_to_info]
            print(f"Plugin: {plugin_instance.get_name()}")
            print(f"Description: {plugin_instance.get_description()}")
            schema = plugin_instance.get_options_schema()
            if schema:
                print("Options:")
                for opt_name, opt_details in schema.items():
                    desc = opt_details.get('description', 'N/A')
                    dtype = opt_details.get('type', 'N/A')
                    default = opt_details.get('default')
                    required = opt_details.get('required', False)
                    req_str = "(required)" if required else ""
                    default_str = f"(default: {default})" if default is not None else ""
                    print(f"  --{opt_name} : {dtype} {req_str} {default_str}")
                    print(f"      {desc}")
            else:
                print("Options: This plugin does not accept any options.")
        else:
            print(f"Error: Plugin '{plugin_name_to_info}' not found.")
        return

    if not args.input_file:
        parser.error("Input file is required unless listing plugins or getting plugin info.")
        return # Should be handled by parser.error

    if not args.output_file:
        # Default output: input_file.obfuscated.extension
        base, ext = os.path.splitext(args.input_file)
        args.output_file = f"{base}.obfuscated{ext}"
        print(f"Warning: No output file specified. Defaulting to '{args.output_file}'.")

    if not args.plugins:
        print("No plugins specified to apply. The output file will be a copy of the input.")
        # Or, parser.error("At least one plugin must be specified with -p.")
        # For now, allow copying as a valid operation if no plugins.
        try:
            shutil.copy2(args.input_file, args.output_file)
            print(f"Copied '{args.input_file}' to '{args.output_file}' as no plugins were selected.")
            return
        except Exception as e:
            print(f"Error copying file: {e}")
            return


    # Parse plugin options
    parsed_plugin_options = {}
    if args.plugin_options:
        for opt_str in args.plugin_options:
            try:
                plugin_name, option_part = opt_str.split(":", 1)
                if plugin_name not in parsed_plugin_options:
                    parsed_plugin_options[plugin_name] = {}

                if '=' in option_part: # key=value format
                    key, value_str = option_part.split("=", 1)
                    # Attempt to convert value to bool/int/float if possible
                    if value_str.lower() == 'true': value = True
                    elif value_str.lower() == 'false': value = False
                    elif value_str.isdigit(): value = int(value_str)
                    else:
                        try: value = float(value_str)
                        except ValueError: value = value_str # Keep as string
                    parsed_plugin_options[plugin_name][key] = value
                else: # Assume JSON string for more complex options
                    parsed_plugin_options[plugin_name].update(json.loads(option_part))
            except ValueError as e: # Catches split errors or json.loads error
                print(f"Error parsing plugin option string '{opt_str}': {e}. Expected format 'plugin_name:key=value' or 'plugin_name:{{json_string}}'.")
                return
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON for plugin option '{opt_str}': {e}")
                return


    current_input_file = args.input_file
    temp_files = []

    for i, plugin_name in enumerate(args.plugins):
        plugin_instance = manager.get_plugin(plugin_name)
        if not plugin_instance:
            print(f"Error: Plugin '{plugin_name}' not found. Skipping.")
            continue

        print(f"\nApplying plugin: {plugin_name}...")
        plugin_opts = parsed_plugin_options.get(plugin_name, {})

        # Determine output for this plugin step
        if i == len(args.plugins) - 1: # Last plugin
            step_output_file = args.output_file
        else: # Intermediate step
            base, ext = os.path.splitext(args.input_file)
            step_output_file = f"{base}.temp_step_{i}{ext}"
            temp_files.append(step_output_file)

        print(f"  Input: {current_input_file}")
        print(f"  Output: {step_output_file}")
        print(f"  Options: {plugin_opts}")

        success = plugin_instance.obfuscate(current_input_file, step_output_file, options=plugin_opts)
        if success:
            print(f"Plugin '{plugin_name}' applied successfully.")
            current_input_file = step_output_file # Output of this step is input to next
        else:
            print(f"Error: Plugin '{plugin_name}' failed to apply. Aborting chain.")
            # Cleanup temp files created so far
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    try: os.remove(temp_file)
                    except OSError: pass # ignore
            return # Stop processing

    print(f"\nObfuscation chain complete. Final output at: {args.output_file}")

    # Cleanup intermediate temporary files
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                print(f"Cleaned up temporary file: {temp_file}")
            except OSError as e:
                print(f"Warning: Could not clean up temporary file {temp_file}: {e}")


if __name__ == "__main__":
    # This allows running the CLI by executing `python binary_obfuscation_toolkit/cli/main.py ...`
    # For a more user-friendly CLI, consider using setuptools entry_points
    # to make it runnable directly like `binary-obfuscator ...`
    main()
