import pytest

from app.cvss import CVSSError, base_score, severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", 9.8),
    ],
)
def test_base_score_matches_reference(vector, expected):
    assert base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",
    ],
)
def test_invalid_vectors_are_rejected(vector):
    with pytest.raises(CVSSError):
        base_score(vector)


@pytest.mark.parametrize(
    ("score", "level"),
    [(0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical")],
)
def test_severity_bands(score, level):
    assert severity(score) == level
