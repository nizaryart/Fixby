SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "none": 365}

TRANSITIONS = {
    "reported": {"triaged", "rejected"},
    "triaged": {"patched", "rejected"},
    "patched": {"disclosed"},
    "disclosed": set(),
    "rejected": set(),
}

OPEN_STATUSES = ("reported", "triaged")
