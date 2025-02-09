import os
import logging
import logging.handlers
from typing import Any, Dict, Optional

class Logger:
    """Singleton logger class for consistent logging across the application."""
    
    _instance = None
    _initialized = False

    @classmethod
    def setup(cls, config_manager: Any) -> None:
        """Set up logging configuration."""
        if cls._initialized:
            return
            
        # Get logging config
        log_config = config_manager.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = log_config.get('file', 'logs/app.log')
        max_size = log_config.get('max_size', 10 * 1024 * 1024)  # 10MB default
        backup_count = log_config.get('backup_count', 5)
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create JSON formatter for file
        json_formatter = logging.Formatter(
            fmt='{"timestamp": "%(asctime)s" "level": "%(levelname)s" "logger": "%(name)s" "message": "%(message)s"'
            ' "module": "%(module)s" "function": "%(funcName)s" "line": %(lineno)d'
            '%(extra_fields)s}',
            datefmt="%Y-%m-%dT%H:%M:%S.%f"
        )
        
        # Add custom formatter to include extra fields for JSON
        old_format = json_formatter._fmt
        
        def format(record):
            # Collect any extra fields from the record
            extra_fields = {
                key: value
                for key, value in record.__dict__.items()
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename', 'module', 'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName', 'created', 'msecs', 'relativeCreated', 'thread', 'threadName', 'processName', 'process', 'extra_fields']
            }
            
            # Add extra fields to the record
            if extra_fields:
                record.extra_fields = ' ' + ' '.join(
                    f'"{key}": "{value}"' for key, value in extra_fields.items()
                )
            else:
                record.extra_fields = ''
            
            # Use the original format string
            json_formatter._fmt = old_format
            return logging.Formatter.format(json_formatter, record)
            
        json_formatter.format = format
        
        # Create file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(json_formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Remove any existing handlers and add only file handler
        root_logger.handlers = []
        root_logger.addHandler(file_handler)
        
        cls._initialized = True

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Get a logger instance with the given name."""
        if not cls._initialized:
            raise RuntimeError("Logger not initialized. Call setup() first.")
        return logging.getLogger(name)
