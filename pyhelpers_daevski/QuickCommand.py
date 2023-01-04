from subprocess import PIPE, STDOUT, CompletedProcess, run
from typing import Optional


class QuickCommand:
    def __init__(self, command: list[str]):
        self.result: Optional[CompletedProcess] = None
        self.command = command

    def run(self) -> str:
        prefix = ""
        self.result = run(self.command, shell=True, stdout=PIPE, stderr=STDOUT)
        if self.result and self.result.returncode != 0:
            prefix = "err: "
        return f"{prefix}{self.result.stdout.decode('utf-8')}"

    def return_code(self) -> int:
        if self.result:
            return self.result.returncode
        return 0
