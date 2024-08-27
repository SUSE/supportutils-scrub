# supportutils_scrub_logger.py
import logging

class SupportutilsScrubLogger:
    def __init__(self, log_level="normal"):
        self.logger = logging.getLogger("supportutils_scrub_logger")
        self.logger.propagate = False  
        self.logger.setLevel(logging.DEBUG)

        # Define a formatter
        formatter = logging.Formatter("%(levelname)s: %(message)s")

        # Create a console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self._get_log_level(log_level))
        console_handler.setFormatter(formatter)

        # Add the console handler to the logger
        self.logger.addHandler(console_handler)

    def _get_log_level(self, log_level):
        if log_level == "quiet":
            return logging.ERROR
        elif log_level == "normal":
            return logging.INFO
        elif log_level == "verbose":
            return logging.DEBUG
        else:
            return logging.INFO  # Default to normal level if an invalid level is provided

    def set_log_level(self, log_level):
        for handler in self.logger.handlers:
            handler.setLevel(self._get_log_level(log_level))

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

    def debug(self, message):
        self.logger.debug(message)

