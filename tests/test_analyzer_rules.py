"""Reading the risk rules (T08): the format, strict and with clear errors, and the default file."""

import pytest

from vigia.analyzer import RulesError, default_rules, parse_rules
from vigia.analyzer.model import MAX_RULES
from vigia.analyzer.rules import MAX_RULES_BYTES

GOOD = """
[[rule]]
id = "mass-delete"
description = "Ha borrado muchos archivos"
risk = 3
source = "file"
action = "delete"
burst = { count = 100, window = 60 }
"""


def rule(**changes: str | None) -> str:
    """One [[rule]] from a valid base. Values are TOML text as written in the file; None drops
    the key."""
    fields = {"id": '"r1"', "description": '"Algo"', "risk": "2", "source": '"file"'}
    fields.update(changes)
    return "\n".join(["[[rule]]"] + [f"{k} = {v}" for k, v in fields.items() if v is not None])


def test_a_rule_is_read() -> None:
    (parsed,) = parse_rules(GOOD).rules
    assert parsed.id == "mass-delete"
    assert parsed.risk == 3
    assert parsed.sources == {"file"}
    assert parsed.actions == {"delete"}
    assert parsed.burst is not None
    assert (parsed.burst.count, parsed.burst.window, parsed.burst.sum_path) == (100, 60, None)


def test_every_key_in_use() -> None:
    text = """
    [[rule]]
    id = "everything"
    description = "Todo a la vez"
    risk = 1
    source = ["file", "net"]
    action = ["create", "modify"]
    target = ["*.env", ".env"]
    unless = ["*/node_modules/*"]
    where = [
      { field = "nlink", op = "gt", value = 1 },
      { field = "counts.delete", op = "ge", value = 2.5 },
      { field = "type", op = "in", value = ["file", "dir"] },
      { field = "link", op = "glob", value = "/*" },
      { field = "link", op = "exists", value = true },
      { field = "name", op = "ne", value = "x" },
    ]
    burst = { count = 5, window = 10, sum = "counts.delete" }
    """
    (parsed,) = parse_rules(text).rules
    assert parsed.sources == {"file", "net"}
    assert len(parsed.targets) == 2
    assert len(parsed.unless) == 1
    assert [c.op for c in parsed.where] == ["gt", "ge", "in", "glob", "exists", "ne"]
    assert parsed.where[1].path == ("counts", "delete")
    assert len(parsed.where[3].globs) == 1
    assert parsed.burst is not None and parsed.burst.sum_path == ("counts", "delete")


def test_the_default_rules_load_and_make_sense() -> None:
    rules = default_rules()
    ids = [r.id for r in rules.rules]
    assert len(set(ids)) == len(ids) > 10
    assert all(1 <= r.risk <= 3 for r in rules.rules)
    assert all(r.description.isprintable() for r in rules.rules)
    assert rules.origin == "reglas por defecto"


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("", "ninguna regla"),
        ("rule = []", "ninguna regla"),
        ("[[rule]\nid = 1", "TOML"),
        ("extra = 1\n" + GOOD, "extra"),
        (rule(id='"Bad_Id"'), "id"),
        (rule(id="3"), "id"),
        (rule(description='""'), "description"),
        (rule(description='"dos\\nlíneas"'), "description"),
        (rule(description='"' + "x" * 201 + '"'), "description"),
        (rule(risk="0"), "risk"),
        (rule(risk="4"), "risk"),
        (rule(risk='"3"'), "risk"),
        (rule(risk="true"), "risk"),
        (rule(source='"disk"'), "source"),
        (rule(source="[]"), "source"),
        (rule(source="[1]"), "source"),
        (rule(action='"Delete"'), "action"),
        (rule(action='["ok", "NO"]'), "action"),
        (rule(source=None), "al menos"),
        (rule(target="[]"), "target"),
        (rule(target="[1]"), "target"),
        (rule(target='"a[b"'), "target"),
        (rule(unless="[]"), "unless"),
        (rule(unless='"a[b"'), "unless"),
        (rule(target='["' + "*a" * 20 + '"]'), "target"),
        (rule(colour='"red"'), "colour"),
        (rule(where="[]"), "where"),
        (rule(where='[{ field = "a", op = "eq" }]'), "field"),
        (rule(where='[{ field = "a", op = "eq", value = 1, more = 2 }]'), "field"),
        (rule(where='[{ field = "a b", op = "eq", value = 1 }]'), "campo"),
        (rule(where='[{ field = "a.b.c.d.e", op = "eq", value = 1 }]'), "campo"),
        (rule(where='[{ field = "a", op = "regex", value = "x" }]'), "op"),
        (rule(where='[{ field = "a", op = "gt", value = "x" }]'), "número"),
        (rule(where='[{ field = "a", op = "gt", value = true }]'), "número"),
        (rule(where='[{ field = "a", op = "gt", value = inf }]'), "número"),
        (rule(where='[{ field = "a", op = "exists", value = 1 }]'), "true o false"),
        (rule(where='[{ field = "a", op = "in", value = 1 }]'), "lista"),
        (rule(where='[{ field = "a", op = "in", value = [] }]'), "lista"),
        (rule(where='[{ field = "a", op = "eq", value = [1] }]'), "tiene que ser un texto"),
        (rule(where='[{ field = "a", op = "glob", value = "[" }]'), "falta"),
        (rule(where='[{ field = "a", op = "glob", value = [] }]'), "patrón"),
        (rule(where='[{ field = "a", op = "glob", value = 3 }]'), "patrón"),
        (rule(burst="{ count = 1, window = 5 }"), "count"),
        (rule(burst="{ count = 2, window = 0 }"), "window"),
        (rule(burst="{ count = 2, window = 3601 }"), "window"),
        (rule(burst="{ count = 2.5, window = 5 }"), "count"),
        (rule(burst="{ count = 2 }"), "burst"),
        (rule(burst="{ count = 2, window = 5, every = 1 }"), "burst"),
        (rule(burst='{ count = 2, window = 5, sum = "a b" }'), "campo"),
        (GOOD + GOOD, "repetido"),
    ],
)
def test_mistakes_are_refused_and_say_where(text: str, complaint: str) -> None:
    with pytest.raises(RulesError) as error:
        parse_rules(text)
    assert complaint in str(error.value), str(error.value)


def test_an_error_names_the_rule_by_id_or_by_position() -> None:
    with pytest.raises(RulesError, match="«r1»"):
        parse_rules(rule(risk="9"))
    with pytest.raises(RulesError, match=r"n\.º 1"):
        parse_rules(rule(id='"NO"'))


def test_too_many_rules_and_too_big_a_file() -> None:
    many = "\n".join(rule(id=f'"r{i}"') for i in range(MAX_RULES + 1))
    with pytest.raises(RulesError, match="demasiadas"):
        parse_rules(many)
    with pytest.raises(RulesError, match="demasiado grande"):
        parse_rules("# " + "x" * MAX_RULES_BYTES + "\n" + GOOD)


def test_the_limit_of_rules_is_accepted() -> None:
    parse_rules("\n".join(rule(id=f'"r{i}"') for i in range(MAX_RULES)))


def test_an_unknown_key_is_quoted_cut_and_escaped() -> None:
    text = GOOD.replace("risk = 3", 'risk = 3\n"' + "k" * 100 + '\\u001b[2J" = 1')
    with pytest.raises(RulesError) as error:
        parse_rules(text)
    assert "\x1b" not in str(error.value)
    assert len(str(error.value)) < 300
