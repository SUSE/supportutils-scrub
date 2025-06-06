# config_reader.py

class ConfigReader:
    def __init__(self, default_config_path):
        # Initialize the ConfigReader with a default configuration path.
        self.default_config_path = default_config_path

    def read_config(self, config_path=None):
        # Read and parse the configuration file.
        # Args:
        #     config_path (str): Path to the configuration file. Defaults to the default_config_path.
        # Returns:
        #     dict: Dictionary containing configuration settings.
        if config_path is None:
            config_path = self.default_config_path

        # Default settings
        default_settings = {
            'obfuscate_private_ip': 'no',
            'obfuscate_public_ip': 'yes',
            'obfuscate_domain': 'yes',
            'obfuscate_username': 'yes',
            'obfuscate_hostname': 'yes',
            'obfuscate_mac': 'yes',
            'obfuscate_ipv6': 'yes',
            'verbose': 'true',
            'log_level': 'verbose',
            'use_key_words_file': 'yes',
            'key_words_file': '/var/lib/supportutils-scrub-keywords.txt'
        }


        config = default_settings.copy()

        try:
            with open(config_path, "r") as config_file:
                for line in config_file:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

                    # Handling settings for keyword file
                    if key.strip() == 'use_key_words_file':
                        config['use_key_words_file'] = value.strip().lower() == 'yes'
                    if key.strip() == 'key_words_file':
                        config['key_words_file'] = value.strip()

        except FileNotFoundError:

            print(f"[!] Configuration file not found: {config_path}.")
            print(f"     → Using default settings")
        except Exception as e:
            print(f"[!] Error reading configuration file: {e}")
            print(f"     → Using default settings")
        return config