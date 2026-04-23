import logging
import os
import sys


class AuditLogger:
    COLORS = {
        "INFO": "\033[94m",
        "PASS": "\033[92m",
        "WARN": "\033[93m",
        "FAIL": "\033[91m",
        "ERROR": "\033[95m",
        "SKIP": "\033[90m",
        "FIXED": "\033[96m",
    }
    RESET = "\033[0m"

    def __init__(self, quiet: bool = False, silent: bool = False, log_path: str = "/var/log/my_security_audit.log") -> None:
        self.quiet = quiet
        self.silent = silent
        self.use_color = sys.stdout.isatty()
        self.logger = logging.getLogger("zerox")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        self.logger.propagate = False
        self.log_path = self._init_file_handler(log_path)

    def _init_file_handler(self, preferred_path: str) -> str:
        target_path = preferred_path
        try:
            handler = logging.FileHandler(target_path)
        except OSError:
            target_path = os.path.join(os.getcwd(), "zerox_audit.log")
            handler = logging.FileHandler(target_path)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(handler)
        return target_path

    def _emit(self, label: str, message: str, console_allowed: bool) -> None:
        self.logger.info("[%s] %s", label, message)
        if self.silent or not console_allowed:
            return
        if self.use_color and label in self.COLORS:
            print(f"{self.COLORS[label]}[{label}] {message}{self.RESET}")
        else:
            print(f"[{label}] {message}")

    def info(self, message: str) -> None:
        self._emit("INFO", message, not self.quiet)

    def passed(self, message: str) -> None:
        self._emit("PASS", message, not self.quiet)

    def warn(self, message: str) -> None:
        self._emit("WARN", message, True)

    def fail(self, message: str) -> None:
        self._emit("FAIL", message, True)

    def error(self, message: str) -> None:
        self._emit("ERROR", message, True)

    def skip(self, message: str) -> None:
        self._emit("SKIP", message, not self.quiet)

    def fixed(self, message: str) -> None:
        self._emit("FIXED", message, True)
