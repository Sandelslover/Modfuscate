import importlib
import inspect
import os
from typing import Dict, Type
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

class PluginManager:
    """
    Manages the discovery and loading of obfuscation plugins.
    """
    def __init__(self, plugin_dir: str = "binary_obfuscation_toolkit/plugins"):
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, ObfuscationPlugin] = {}
        self._loaded_plugin_classes: Dict[str, Type[ObfuscationPlugin]] = {}

    def discover_plugins(self):
        """
        Discovers plugins in the specified plugin directory.
        A plugin is a Python module containing a class that inherits from ObfuscationPlugin.
        The class name must be the CamelCase version of the plugin module name
        (e.g., `my_plugin.py` should contain `class MyPlugin(ObfuscationPlugin)`).
        """
        if not os.path.isdir(self.plugin_dir):
            # Or raise an error, or log a warning
            print(f"Warning: Plugin directory '{self.plugin_dir}' not found.")
            return

        for package_name in os.listdir(self.plugin_dir):
            package_path = os.path.join(self.plugin_dir, package_name)
            if os.path.isdir(package_path) and not package_name.startswith("__"):
                # This is a plugin package (e.g., compression, symbol_stripping)
                for module_name in os.listdir(package_path):
                    if module_name.endswith(".py") and not module_name.startswith("__"):
                        plugin_module_name = module_name[:-3] # remove .py
                        try:
                            # Construct the full module path for importlib
                            # e.g., binary_obfuscation_toolkit.plugins.compression.upx
                            module_import_path = f"{self.plugin_dir.replace('/', '.')}.{package_name}.{plugin_module_name}"

                            module = importlib.import_module(module_import_path)

                            for name, cls in inspect.getmembers(module, inspect.isclass):
                                if issubclass(cls, ObfuscationPlugin) and cls is not ObfuscationPlugin:
                                    # Instantiate the plugin
                                    plugin_instance = cls()
                                    plugin_id = plugin_instance.get_name()
                                    if plugin_id in self.plugins:
                                        print(f"Warning: Duplicate plugin name '{plugin_id}'. Skipping {name} from {module_import_path}")
                                    else:
                                        self.plugins[plugin_id] = plugin_instance
                                        self._loaded_plugin_classes[plugin_id] = cls
                                        print(f"Discovered plugin: {plugin_id} from {module_import_path}")
                        except ImportError as e:
                            print(f"Error importing plugin module {plugin_module_name} from {package_name}: {e}")
                        except Exception as e:
                            print(f"Error loading plugin from {plugin_module_name} in {package_name}: {e}")

    def get_plugin(self, name: str) -> ObfuscationPlugin | None:
        """
        Retrieves a loaded plugin instance by its name.
        """
        return self.plugins.get(name)

    def get_all_plugins(self) -> Dict[str, ObfuscationPlugin]:
        """
        Returns a dictionary of all loaded plugin instances.
        """
        return self.plugins

    def get_plugin_class(self, name: str) -> Type[ObfuscationPlugin] | None:
        """
        Retrieves a loaded plugin class by its name.
        """
        return self._loaded_plugin_classes.get(name)

if __name__ == '__main__':
    # Example usage (for testing purposes)
    # Create dummy plugin files for this test to work:
    # plugins/demo/hello_plugin.py
    # plugins/another/world_plugin.py

    # Create dummy plugin directories and files
    dummy_plugin_dir = "binary_obfuscation_toolkit/plugins"

    os.makedirs(os.path.join(dummy_plugin_dir, "demo"), exist_ok=True)
    with open(os.path.join(dummy_plugin_dir, "demo", "hello_plugin.py"), "w") as f:
        f.write("""
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

class HelloPlugin(ObfuscationPlugin):
    def get_name(self) -> str:
        return "hello"
    def get_description(self) -> str:
        return "A simple demo plugin."
    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        print(f"HelloPlugin: Pretending to obfuscate {binary_path} to {output_path} with options {options}")
        # In a real plugin, you'd copy the file and modify it or create a new one.
        # For this test, we'll just create an empty output file.
        with open(output_path, 'w') as op:
            op.write("obfuscated_content_by_hello")
        return True
""")

    os.makedirs(os.path.join(dummy_plugin_dir, "another"), exist_ok=True)
    with open(os.path.join(dummy_plugin_dir, "another", "world_plugin.py"), "w") as f:
        f.write("""
from binary_obfuscation_toolkit.core.plugin_base import ObfuscationPlugin

class WorldPlugin(ObfuscationPlugin):
    def get_name(self) -> str:
        return "world"
    def get_description(self) -> str:
        return "Another demo plugin."
    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        print(f"WorldPlugin: Obfuscating {binary_path} to {output_path}")
        with open(output_path, 'w') as op:
            op.write("obfuscated_content_by_world")
        return True
    def get_options_schema(self) -> dict:
        return {
            "strength": {
                "type": "integer",
                "description": "Obfuscation strength.",
                "default": 1,
                "required": False
            }
        }
""")
    # Ensure __init__.py exists in binary_obfuscation_toolkit and plugins
    # These should have been created in the previous step.
    # open("binary_obfuscation_toolkit/__init__.py", "a").close()
    # open(os.path.join(dummy_plugin_dir, "__init__.py"), "a").close()
    # open(os.path.join(dummy_plugin_dir, "demo", "__init__.py"), "a").close()
    # open(os.path.join(dummy_plugin_dir, "another", "__init__.py"), "a").close()


    print(f"Current working directory: {os.getcwd()}")
    print("Attempting to discover plugins...")
    manager = PluginManager(plugin_dir=dummy_plugin_dir)
    manager.discover_plugins()

    print("\\nAvailable plugins:")
    for name, plugin in manager.get_all_plugins().items():
        print(f"  - {name}: {plugin.get_description()}")
        print(f"    Options: {plugin.get_options_schema()}")

    hello_plugin = manager.get_plugin("hello")
    if hello_plugin:
        # Create dummy input and output paths for testing
        dummy_input = "dummy_input.bin"
        dummy_output = "dummy_output.bin"
        with open(dummy_input, "w") as f:
            f.write("original content")

        print(f"\\nTesting plugin '{hello_plugin.get_name()}':")
        success = hello_plugin.obfuscate(dummy_input, dummy_output, {"level": 5})
        print(f"Obfuscation successful: {success}")
        if os.path.exists(dummy_output):
            with open(dummy_output, 'r') as f:
                print(f"Output file content: {f.read()}")
            os.remove(dummy_output)
        if os.path.exists(dummy_input):
            os.remove(dummy_input)

    # Clean up dummy plugins (optional, good for testing)
    # import shutil
    # shutil.rmtree(os.path.join(dummy_plugin_dir, "demo"))
    # shutil.rmtree(os.path.join(dummy_plugin_dir, "another"))
    # If the main plugin_dir was created just for this test, remove it.
    # Be careful if it's the actual project directory.
    print("\\nPlugin manager test complete.")
