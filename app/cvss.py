import math

ALLOWED = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "HLN",
    "I": "HLN",
    "A": "HLN",
}
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


class CVSSError(ValueError):
    pass


def parse(vector: str) -> dict[str, str]:
    prefix, _, rest = vector.partition("/")
    if prefix != "CVSS:3.1" or not rest:
        raise CVSSError("vector must start with CVSS:3.1/")
    metrics: dict[str, str] = {}
    for part in rest.split("/"):
        key, sep, value = part.partition(":")
        if not sep or key not in ALLOWED or key in metrics or len(value) != 1 or value not in ALLOWED[key]:
            raise CVSSError(f"invalid metric '{part}'")
        metrics[key] = value
    missing = [key for key in ALLOWED if key not in metrics]
    if missing:
        raise CVSSError(f"missing base metrics: {', '.join(missing)}")
    return metrics


def roundup(value: float) -> float:
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def base_score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR[m["S"]][m["PR"]] * UI[m["UI"]]
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return roundup(min(total, 10))


def severity(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"
