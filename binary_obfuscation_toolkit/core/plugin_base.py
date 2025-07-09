import abc

class ObfuscationPlugin(abc.ABC):
    """
    Abstract base class for all obfuscation plugins.
    """
    @abc.abstractmethod
    def get_name(self) -> str:
        """
        Returns the unique name of the plugin.
        This name will be used to identify the plugin in the CLI.
        """
        pass

    @abc.abstractmethod
    def get_description(self) -> str:
        """
        Returns a short description of what the plugin does.
        """
        pass

    @abc.abstractmethod
    def obfuscate(self, binary_path: str, output_path: str, options: dict = None) -> bool:
        """
        Applies the obfuscation technique to the input binary.

        Args:
            binary_path: Path to the input binary file.
            output_path: Path to save the obfuscated binary file.
            options: A dictionary of plugin-specific options.

        Returns:
            True if obfuscation was successful, False otherwise.
        """
        pass

    def get_options_schema(self) -> dict:
        """
        Returns a schema defining the options this plugin accepts.
        This can be used for validation or generating help messages.
        Example:
        {
            "option_name": {
                "type": "integer",
                "description": "Description of the option.",
                "default": 0,
                "required": False
            }
        }
        Returns an empty dict if no options are supported.
        """
        return {}
