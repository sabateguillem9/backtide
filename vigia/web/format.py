"""Times and ages for the pages. Pure."""

from datetime import UTC, datetime, timedelta, tzinfo

from vigia.web.i18n import Translator


def parse_ts(ts: str) -> datetime:
    """A black-box ``ts`` (UTC, microseconds, trailing Z) as an aware datetime."""
    return datetime.fromisoformat(ts).astimezone(UTC)


def clock(moment: datetime, tz: tzinfo) -> str:
    return moment.astimezone(tz).strftime("%H:%M:%S")


def stamp(moment: datetime, tz: tzinfo) -> str:
    return moment.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def local_tz() -> tzinfo:
    local = datetime.now().astimezone().tzinfo
    return local if local is not None else UTC


def age(t: Translator, elapsed: timedelta) -> str:
    seconds = elapsed.total_seconds()
    if seconds < -5:
        return t("age.future")
    if seconds < 60:
        return t("age.now")
    if seconds < 3600:
        return t("age.min", n=int(seconds // 60))
    if seconds < 48 * 3600:
        return t("age.hour", n=int(seconds // 3600))
    return t("age.day", n=int(seconds // 86400))
