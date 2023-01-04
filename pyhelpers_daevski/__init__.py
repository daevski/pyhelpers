import logging
import time
from pathlib import Path
from sys import stdout as sys_stdout
from typing import Any

import yaml


def get_configuration(config_file: Path):
    with config_file.open() as f:
        return yaml.safe_load(f)


def get_logger(
    appconfig: dict[Any, Any],
    logging_level: int = logging.INFO,
    format: str = '[%Y-%m-%d] [%H:%M]',
    configkey_logdir: str = 'LoggingDirectory',
):
    location = (
        '.configy/logs' if appconfig[configkey_logdir] == 'default' else appconfig[configkey_logdir]
    )
    Path(location).mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime('%Y-%m-%d_%H-%M')
    logging_file = Path(f"{location}") / f"{timestamp}.log"
    logging.basicConfig(
        level=logging_level,
        datefmt=format,
        format='%(asctime)s %(levelname)s: %(message)s [PID: %(process)d]',
        handlers=[
            logging.FileHandler(logging_file),
            logging.StreamHandler(sys_stdout),
        ],
    )
    logging.info('APP STARTUP')
    return logging
