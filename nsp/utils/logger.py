"""NEXUS SPECTER PRO — Rich Logger | by OPTIMIUM NEXUS LLC"""
import logging
from rich.logging import RichHandler

def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, markup=True,
                               show_path=False, show_time=True)]
    )
    return logging.getLogger(name)
