# scrubber/config_reader.py

class ConfigReader:
    def __init__(self, default_config_path):
        self.default_config_path = default_config_path

    def read_config(self, config_path=None):
        if config_path is None:
            config_path = self.default_config_path

        config = {}
        try:
            with open(config_path, "r") as config_file:
                for line in config_file:
                    line = line.strip()
                    if not line or line.startswith("#"):  # Skip empty lines and comments
                        continue
                    parts = map(str.strip, line.split("="))
                    parts = list(parts)  # Convert map to list
                    if len(parts) == 2:
                        key, value = parts
                        config[key] = value.lower() == "yes"
        except FileNotFoundError:
            pass  # You may handle the absence of the config file differently if needed
        return config
