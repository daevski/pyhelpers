import logging
import time
from pathlib import Path
from sys import stdout as sys_stdout
from typing import Any

import yaml

from pyhelpers_daevski.LocalPassword import (
    application_password_prompt,
    application_password_prompt_new,
)


def get_configuration(config_file: Path):
    with config_file.open() as f:
        return yaml.safe_load(f)


def set_configuration(configuration: dict, config_file: Path):
    with config_file.open("w") as f:
        f.write(yaml.safe_dump(configuration))


def get_logger(
    appconfig: dict[Any, Any],
    logging_level: int = logging.INFO,
    format: str = "[%Y-%m-%d] [%H:%M]",
    configkey_logdir: str = "LoggingDirectory",
):
    location = (
        ".configy/logs"
        if appconfig[configkey_logdir] == "default"
        else appconfig[configkey_logdir]
    )
    Path(location).mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M")
    logging_file = Path(f"{location}") / f"{timestamp}.log"
    logging.basicConfig(
        level=logging_level,
        datefmt=format,
        format="%(asctime)s %(levelname)s: %(message)s [PID: %(process)d]",
        handlers=[
            logging.FileHandler(logging_file),
            logging.StreamHandler(sys_stdout),
        ],
    )
    logging.info("APP STARTUP")
    return logging


def authenticate_user(password_file: Path) -> bytes:
    return (
        application_password_prompt(password_file)
        if password_file.exists()
        else application_password_prompt_new(password_file)
    )
