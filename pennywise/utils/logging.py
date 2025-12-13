"""
Logging configuration for PennyWise.
Provides colored console output and comprehensive file logging.
"""

import logging
import sys
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

import colorama

colorama.init()


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for console."""

    COLORS = {
        'DEBUG': colorama.Fore.CYAN,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Style.BRIGHT,
    }

    RESET = colorama.Style.RESET_ALL

    def __init__(self, fmt: str = None, datefmt: str = None):
        super().__init__(fmt, datefmt)
        self.fmt = fmt or '[@PW %(asctime)s] %(levelname)s: %(message)s'
        self.datefmt = datefmt or '%H:%M:%S'

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')

        # Apply color to the level name
        record.levelname = f"{color}{record.levelname}{self.RESET}"

        # Format the message
        formatted = super().format(record)

        return formatted


@dataclass
class PennywiseLogEntry:
    """Comprehensive log entry for PennyWise."""
    timestamp: str
    event: str
    component: str
    data: Dict[str, Any]
    session_id: Optional[str] = None
    target_url: Optional[str] = None
    ai_involvement: Optional[Dict[str, Any]] = None
    rl_data: Optional[Dict[str, Any]] = None
    payload_info: Optional[Dict[str, Any]] = None
    sandbox_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'event': self.event,
            'component': self.component,
            'data': self.data,
            'session_id': self.session_id,
            'target_url': self.target_url,
            'ai_involvement': self.ai_involvement,
            'rl_data': self.rl_data,
            'payload_info': self.payload_info,
            'sandbox_data': self.sandbox_data
        }


class PennywiseLogger:
    """
    Centralized comprehensive logging configuration for PennyWise.
    """

    BANNER = """
                                      :*.=@=
                                    =@  .@@@@@:
                                   +@     @@@@@@
                                   @  :#@@@@@@@@%
                                  @=    -%@@@@@@@:
                                 :@@@@=:.    .@@@@.
                                %@=             -@@:
                               +@*                @@
                                *@:              @%
                              @@@@@@           %@@@@@@.
                             @@. *#@@         @@.+@@@@@.
                           :@@.      *.      =:    +@ @@
                         .@@=                      :   @@*:
                        %@@                 ..:::---=  -@@@
                       =@@@=  .@%==-:::::::::::::::-@. .  @@@.
                     %@@@*     @-                  :@     @@@*
                    @@@@@@@*=  @=      . :::       :@     *@@@@.
                         :@*: .*=       @@@%       :@-%@@@@@@: *:
                                =      ::%#..      :+      :-
                                =                  :
                                .
                                ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
                                ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣
                                ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
                                AI-Powered Vulnerability Scanner v2.0

    """

    def __init__(self,
                 name: str = "pennywise",
                 log_level: str = "INFO",
                 log_file: Optional[str] = None,
                 pennywise_log_file: str = "pennywise_log.json"):
        """
        Initialize the comprehensive logger.

        Args:
            name: Logger name
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for traditional logging
            pennywise_log_file: File for comprehensive PennyWise logging
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # Clear existing handlers
        self.logger.handlers = []

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            self._add_file_handler(log_file)

        # Comprehensive PennyWise logging
        self.pennywise_log_file = Path(pennywise_log_file)
        self.log_lock = threading.Lock()
        self.current_session_id = None
        self.current_target_url = None

        # Prevent propagation to root logger
        self.logger.propagate = False

    def _add_file_handler(self, log_file: str):
        """Add file handler for logging to file."""
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(file_handler)

    def set_session_context(self, session_id: str, target_url: Optional[str] = None):
        """Set the current session context for logging."""
        self.current_session_id = session_id
        self.current_target_url = target_url

    def log_comprehensive_event(self,
                               event: str,
                               component: str,
                               data: Dict[str, Any],
                               ai_involvement: Optional[Dict[str, Any]] = None,
                               rl_data: Optional[Dict[str, Any]] = None,
                               payload_info: Optional[Dict[str, Any]] = None,
                               sandbox_data: Optional[Dict[str, Any]] = None):
        """Log a comprehensive event with all PennyWise components."""
        log_entry = PennywiseLogEntry(
            timestamp=datetime.now().isoformat(),
            event=event,
            component=component,
            data=data,
            session_id=self.current_session_id,
            target_url=self.current_target_url,
            ai_involvement=ai_involvement,
            rl_data=rl_data,
            payload_info=payload_info,
            sandbox_data=sandbox_data
        )

        # Save to comprehensive log
        self._save_comprehensive_log(log_entry)

        # Also log to console with appropriate level
        log_level = data.get('log_level', 'info')
        message = data.get('message', f"{component}: {event}")

        if log_level == 'debug':
            self.logger.debug(message)
        elif log_level == 'info':
            self.logger.info(message)
        elif log_level == 'warning':
            self.logger.warning(message)
        elif log_level == 'error':
            self.logger.error(message)
        elif log_level == 'critical':
            self.logger.critical(message)

    def _save_comprehensive_log(self, entry: PennywiseLogEntry):
        """Save comprehensive log entry to file."""
        with self.log_lock:
            try:
                # Load existing logs
                logs = []
                if self.pennywise_log_file.exists():
                    with open(self.pennywise_log_file, 'r') as f:
                        logs = json.load(f)

                # Append new entry
                logs.append(entry.to_dict())

                # Save back to file
                with open(self.pennywise_log_file, 'w') as f:
                    json.dump(logs, f, indent=2, default=str)

            except Exception as e:
                self.logger.error(f"Failed to save comprehensive log: {e}")

    def print_banner(self):
        """Print the PennyWise banner."""
        print(colorama.Fore.CYAN + self.BANNER + colorama.Style.RESET_ALL)

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def success(self, msg: str):
        """Log a success message (green)."""
        print(f"{colorama.Fore.GREEN}✓ {msg}{colorama.Style.RESET_ALL}")

    def step(self, step_num: int, msg: str):
        """Log a step in a process."""
        print(f"{colorama.Fore.YELLOW}[Step {step_num}] {msg}{colorama.Style.RESET_ALL}")

    def finding(self, severity: str, title: str):
        """Log a security finding."""
        colors = {
            'critical': colorama.Fore.RED + colorama.Style.BRIGHT,
            'high': colorama.Fore.RED,
            'medium': colorama.Fore.YELLOW,
            'low': colorama.Fore.BLUE,
            'info': colorama.Fore.CYAN
        }
        color = colors.get(severity.lower(), colorama.Fore.WHITE)
        print(f"{color}[{severity.upper()}] {title}{colorama.Style.RESET_ALL}")


def get_logger(name: str = "pennywise") -> logging.Logger:
    """Get or create a logger instance."""
    return logging.getLogger(name)


def setup_logging(log_level: str = "INFO",
                  log_file: Optional[str] = None,
                  pennywise_log_file: str = "pennywise_log.json") -> PennywiseLogger:
    """
    Set up comprehensive logging for PennyWise.

    Args:
        log_level: Logging level
        log_file: Optional file path for traditional logging
        pennywise_log_file: File for comprehensive PennyWise logging

    Returns:
        Configured PennywiseLogger instance
    """
    return PennywiseLogger(log_level=log_level, log_file=log_file, pennywise_log_file=pennywise_log_file)
