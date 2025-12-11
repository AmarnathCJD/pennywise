"""
Logging configuration for PennyWise.
Provides colored console output and file logging.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

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


class PennywiseLogger:
    """
    Centralized logging configuration for PennyWise.
    """
    
    BANNER = """
    ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
    ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
    ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
    AI-Powered Vulnerability Scanner v2.0
    """
    
    def __init__(self, 
                 name: str = "pennywise",
                 log_level: str = "INFO",
                 log_file: Optional[str] = None):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for file logging
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
                  log_file: Optional[str] = None) -> PennywiseLogger:
    """
    Set up logging for PennyWise.
    
    Args:
        log_level: Logging level
        log_file: Optional file path for logging
        
    Returns:
        Configured PennywiseLogger instance
    """
    return PennywiseLogger(log_level=log_level, log_file=log_file)
