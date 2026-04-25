from dataclasses import dataclass

OK = "OK"
WARN = "WARN"
ERROR = "ERROR"
SKIP = "SKIP"
INFO = "INFO"


@dataclass
class CheckResult:
    category: str
    item: str
    status: str      # OK | WARN | ERROR | SKIP | INFO
    finding: str
    recommendation: str = ""
