import logging

class SupportutilsScrubLogger:
    def __init__(self, log_level="normal"):
        self.logger = logging.getLogger("supportutils_scrub_logger")
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter("%(levelname)s: %(message)s")
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self._get_log_level(log_level))
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _get_log_level(self, log_level):
        if log_level == "quiet":
            return logging.ERROR
        elif log_level == "verbose":
            return logging.DEBUG
        return logging.INFO

    def set_log_level(self, log_level):
        for handler in self.logger.handlers:
            handler.setLevel(self._get_log_level(log_level))

    def __getattr__(self, name):
        return getattr(self.logger, name)
