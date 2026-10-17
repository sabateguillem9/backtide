"""Sensors: what backtide observes from outside the agent. T04a: the file watcher.

Design and rationale: docs/19-diseno-t04.md, section 1.
"""

from backtide.sensors.files import FileWatcher, WatcherConfig

__all__ = ["FileWatcher", "WatcherConfig"]
