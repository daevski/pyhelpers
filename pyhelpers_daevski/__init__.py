import logging
import time
from pathlib import Path
from sys import stdout as sys_stdout
from typing import Any

import yaml

from pyhelpers_daevski.security import (
    application_password_prompt,
    application_password_prompt_new,
    get_local_pw_hash,
    key_from_password,
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


def authenticate_user(pw_hash_file: Path) -> bytes:
    if pw_hash_file.exists():
        pw_hash = get_local_pw_hash(pw_hash_file)
    else:
        pw_hash = application_password_prompt_new(pw_hash_file)

    provided_password: str = application_password_prompt(pw_hash)
    application_key: bytes = key_from_password(provided_password)
    return application_key
