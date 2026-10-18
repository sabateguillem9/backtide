"""Read the rules: strict, and clear about what is wrong. No file access beyond the default
file that ships with backtide (the service reads the user's file with its own checks).

The format is TOML (the standard library reads it; YAML would need a new dependency)::

    [[rule]]
    id = "mass-delete"                    # lowercase words joined by hyphens, unique
    description = "Ha borrado 100 archivos o más en un minuto"   # Spanish: the alert says it
    risk = 3                              # 1, 2 or 3; what no rule matches is 0
    source = "file"                       # or ["file", "net"]; omitted: any
    action = "delete"                     # or a list; omitted: any
    target = ["*/.ssh/*", ".ssh/*"]       # globs (backtide/analyzer/glob.py); one match is enough
    unless = ["*/node_modules/*"]         # events whose target matches are not this rule's
    where = [{ field = "nlink", op = "gt", value = 1 }]   # ALL must hold
    burst = { count = 100, window = 60 }  # this many in the last `window` seconds (max 3600)

``where`` looks inside the event's details (``field = "counts.delete"`` goes into ``counts``);
``op`` is one of ``eq ne gt ge lt le in glob exists``, and ``glob`` takes a pattern or a list of
them. ``burst`` may carry ``sum = "counts.delete"`` to add up a number in the details instead of
counting events, and with it ``default = 1``: what an event without that number weighs (0 if
omitted), so one rule can add loose events and the ones a summary folded. A rule needs at least
one of ``source``, ``action``, ``target`` or ``where``, any other key is an error, and there is
no regex on purpose (see glob.py).
"""

import math
import re
import tomllib
from collections.abc import Mapping
from importlib import resources
from typing import Any

from backtide.analyzer.glob import Glob
from backtide.analyzer.model import (
    MAX_RULES,
    OPERATORS,
    Burst,
    Condition,
    Rule,
    RulesError,
    RuleSet,
)
from backtide.blackbox.model import Source

DEFAULT_RULES_FILE = "default_rules.toml"
MAX_RULES_BYTES = 64 * 1024

_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,47}", re.ASCII)
_ACTION_RE = re.compile(r"[a-z][a-z0-9_]{0,47}", re.ASCII)
_SEGMENT_RE = re.compile(r"[A-Za-z0-9_]{1,32}", re.ASCII)
_RULE_KEYS = frozenset(
    {"id", "description", "risk", "source", "action", "target", "unless", "where", "burst"}
)
_WHERE_KEYS = frozenset({"field", "op", "value"})
_BURST_KEYS = frozenset({"count", "window", "sum", "default"})
_SOURCES = frozenset(source.value for source in Source)
MAX_LIST = 64
MAX_WHERE = 8
MAX_PATH_SEGMENTS = 4
MAX_DESCRIPTION_CHARS = 200
MAX_BURST_COUNT = 1_000_000
MAX_BURST_WINDOW = 3600


def default_rules() -> RuleSet:
    """The rules that ship with backtide."""
    text = (resources.files("backtide.analyzer") / DEFAULT_RULES_FILE).read_text(encoding="utf-8")
    return parse_rules(text, origin="reglas por defecto")


def parse_rules(text: str, *, origin: str = "reglas") -> RuleSet:
    """The rules in ``text``. RulesError says which rule and which key is wrong."""
    if len(text.encode("utf-8", "replace")) > MAX_RULES_BYTES:
        raise RulesError(f"el archivo de reglas es demasiado grande (máximo {MAX_RULES_BYTES} B)")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise RulesError(f"no es TOML válido: {error}") from None
    unknown = sorted(set(data) - {"rule"})
    if unknown:
        raise RulesError(f"clave desconocida fuera de las reglas: {_names(unknown)}")
    entries = data.get("rule")
    if not isinstance(entries, list) or not entries:
        raise RulesError(
            "no hay ninguna regla: usa [[rule]] (un archivo sin reglas no vigila nada)"
        )
    if len(entries) > MAX_RULES:
        raise RulesError(f"hay demasiadas reglas (máximo {MAX_RULES})")
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        rule = _parse_rule(entry, index)
        if rule.id in seen:
            raise RulesError(f"regla «{rule.id}»: el id está repetido")
        seen.add(rule.id)
        rules.append(rule)
    return RuleSet(tuple(rules), origin)


def _parse_rule(entry: object, index: int) -> Rule:
    if not isinstance(entry, dict):
        raise RulesError(f"regla n.º {index}: tiene que ser una tabla [[rule]]")
    label = f"regla n.º {index}"
    rule_id = entry.get("id")
    if not isinstance(rule_id, str) or not _ID_RE.fullmatch(rule_id):
        raise RulesError(f"{label}: `id` tiene que ser palabras en minúscula unidas por guiones")
    label = f"regla «{rule_id}»"
    unknown = sorted(set(entry) - _RULE_KEYS)
    if unknown:
        raise RulesError(f"{label}: clave desconocida: {_names(unknown)}")
    description = entry.get("description")
    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > MAX_DESCRIPTION_CHARS
        or not description.isprintable()
    ):
        raise RulesError(
            f"{label}: `description` tiene que ser una frase de hasta {MAX_DESCRIPTION_CHARS} "
            "caracteres, sin saltos de línea"
        )
    risk = entry.get("risk")
    if type(risk) is not int or not 1 <= risk <= 3:
        raise RulesError(f"{label}: `risk` tiene que ser 1, 2 o 3 (lo que ninguna regla toca es 0)")
    sources = _text_set(entry, "source", label, lambda text: text in _SOURCES, "un origen conocido")
    actions = _text_set(
        entry, "action", label, lambda t: bool(_ACTION_RE.fullmatch(t)), "una acción"
    )
    targets = tuple(_globs(entry.get("target"), label)) if "target" in entry else ()
    unless = tuple(_globs(entry.get("unless"), label, "unless")) if "unless" in entry else ()
    where = _parse_where(entry.get("where"), label) if "where" in entry else ()
    burst = _parse_burst(entry.get("burst"), label) if "burst" in entry else None
    if not (sources or actions or targets or where):
        raise RulesError(
            f"{label}: necesita al menos `source`, `action`, `target` o `where`; "
            "si no, valdría para todos los eventos"
        )
    return Rule(rule_id, description.strip(), risk, sources, actions, targets, unless, where, burst)


def _text_set(
    entry: Mapping[str, Any], key: str, label: str, accepts: Any, what: str
) -> frozenset[str]:
    if key not in entry:
        return frozenset()
    value = entry[key]
    items = [value] if isinstance(value, str) else value
    if (
        not isinstance(items, list)
        or not items
        or len(items) > MAX_LIST
        or not all(isinstance(item, str) and accepts(item) for item in items)
    ):
        raise RulesError(f"{label}: `{key}` tiene que ser {what}, o una lista de ellos")
    return frozenset(items)


def _globs(value: object, label: str, key: str = "target") -> list[Glob]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items or len(items) > MAX_LIST:
        raise RulesError(f"{label}: `{key}` tiene que ser un patrón, o una lista de ellos")
    compiled = []
    for item in items:
        try:
            compiled.append(Glob.compile(item))
        except ValueError as error:
            raise RulesError(f"{label}: `{key}`: {error}") from None
    return compiled


def _parse_path(value: object, label: str, key: str) -> tuple[str, ...]:
    path = tuple(value.split(".")) if isinstance(value, str) else ()
    if (
        not path
        or len(path) > MAX_PATH_SEGMENTS
        or not all(_SEGMENT_RE.fullmatch(segment) for segment in path)
    ):
        raise RulesError(
            f"{label}: `{key}` tiene que ser el nombre de un campo de details, o varios unidos "
            f"con puntos (como mucho {MAX_PATH_SEGMENTS})"
        )
    return path


def _parse_where(value: object, label: str) -> tuple[Condition, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_WHERE:
        raise RulesError(f"{label}: `where` tiene que ser una lista de 1 a {MAX_WHERE} condiciones")
    return tuple(_parse_condition(item, label) for item in value)


def _parse_condition(item: object, label: str) -> Condition:
    if not isinstance(item, dict) or set(item) != _WHERE_KEYS:
        raise RulesError(f"{label}: cada condición de `where` lleva `field`, `op` y `value`")
    path = _parse_path(item["field"], label, "where.field")
    op = item["op"]
    if op not in OPERATORS:
        raise RulesError(
            f"{label}: `where.op` tiene que ser uno de: {', '.join(sorted(OPERATORS))}"
        )
    value = item["value"]
    where = f"{label}: `where` ({'.'.join(path)} {op})"
    if op == "exists":
        if type(value) is not bool:
            raise RulesError(f"{where}: `value` tiene que ser true o false")
    elif op in ("gt", "ge", "lt", "le"):
        if not _finite_number(value):
            raise RulesError(f"{where}: `value` tiene que ser un número")
    elif op == "in":
        if (
            not isinstance(value, list)
            or not value
            or len(value) > MAX_LIST
            or not all(_scalar(element) for element in value)
        ):
            raise RulesError(f"{where}: `value` tiene que ser una lista de 1 a {MAX_LIST} valores")
    elif op == "glob":
        return Condition(path, op, value, tuple(_globs(value, where, "value")))
    elif not _scalar(value):
        raise RulesError(f"{where}: `value` tiene que ser un texto, un número o true/false")
    return Condition(path, op, value)


def _parse_burst(value: object, label: str) -> Burst:
    if not isinstance(value, dict) or not {"count", "window"} <= set(value) <= _BURST_KEYS:
        raise RulesError(
            f"{label}: `burst` lleva `count`, `window` y quizá `sum` (y `default`), y nada más"
        )
    count, window = value["count"], value["window"]
    if type(count) is not int or not 2 <= count <= MAX_BURST_COUNT:
        raise RulesError(f"{label}: `burst.count` tiene que ser un entero de 2 a {MAX_BURST_COUNT}")
    if type(window) is not int or not 1 <= window <= MAX_BURST_WINDOW:
        raise RulesError(
            f"{label}: `burst.window` tiene que ser un entero de 1 a {MAX_BURST_WINDOW} segundos"
        )
    sum_path = _parse_path(value["sum"], label, "burst.sum") if "sum" in value else None
    default = value.get("default", 0)
    if "default" in value and sum_path is None:
        raise RulesError(f"{label}: `burst.default` solo tiene sentido con `burst.sum`")
    if not _finite_number(default) or not 0 <= default <= MAX_BURST_COUNT:
        raise RulesError(
            f"{label}: `burst.default` tiene que ser un número de 0 a {MAX_BURST_COUNT}"
        )
    return Burst(count, window, sum_path, float(default))


def _scalar(value: object) -> bool:
    if isinstance(value, str):
        return len(value) <= MAX_DESCRIPTION_CHARS
    return type(value) is bool or _finite_number(value)


def _finite_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _names(keys: list[str]) -> str:
    """Keys of the file, escaped and cut: an error message may reach a terminal."""
    return ", ".join(repr(key[:40]) for key in keys[:5])
