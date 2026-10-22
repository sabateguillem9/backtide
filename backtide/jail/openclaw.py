"""OpenClaw's rules, under the name they had before the agent profile (T17a-2).

They live in backtide/jail/profiles/openclaw.py now; this module only keeps the old imports
working (scripts/demo/probar.py, backtide/service/config.py and the tests). New code imports the
profile.
"""

from backtide.jail.profiles.openclaw import (
    BUILT_IN_PROVIDERS,
    CHANNELS,
    MODEL_ID,
    REWIND_NOTICE_LINES,
    SAFE_DM_POLICIES,
    SAFE_EXEC_MODES,
    SAFE_GATEWAY_AUTH,
    ModelProvider,
    RewindProblem,
    UnrewindableConfig,
    check_rewindable,
    model_settings,
    problems_in,
)

__all__ = [
    "BUILT_IN_PROVIDERS",
    "CHANNELS",
    "MODEL_ID",
    "REWIND_NOTICE_LINES",
    "SAFE_DM_POLICIES",
    "SAFE_EXEC_MODES",
    "SAFE_GATEWAY_AUTH",
    "ModelProvider",
    "RewindProblem",
    "UnrewindableConfig",
    "check_rewindable",
    "model_settings",
    "problems_in",
]
