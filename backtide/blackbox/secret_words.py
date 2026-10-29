"""The names and shapes that mark a secret: one source for every barrier (invariant 5).

redact.py (every recorded text), backtide/sensors/procs.py (the process sensor's second
barrier) and backtide/jail/sensor.py (Tetragon's RE2 rules, the first barrier) build their
patterns from these, so a word added here reaches the three; tests/test_secret_words_parity.py
feeds the same table through all of them, each on its own and chained as in production.

Each one is written in the subset of syntax that Python's ``re`` and RE2 read the same way: no
lookaround, no possessive, no backreference, and no capture group (in a Tetragon rule a capture
group is what gets struck). Each is a whole group, so it can follow ``[\\w.-]*?`` or a flag.

Two sizes of some lists. The rules strike the word after a secret name, whatever it is, and run
in order over what earlier rules struck: a rule that fires on a new name can strike the word
another rule after it starts from (``signing_key: -u alice:pw`` would lose its ``-u``). So the
rules the earlier reviews checked at their place in the order keep the ``*_BASE`` words they
were checked with, and the whole lists go into rules that run after every other one (in
Tetragon, the wrapped-element rule strikes up to the element's closing quote, only when that
quote is followed by whitespace or the end, and the others only strike a plain word: not a
flag, not a quote). A word added here reaches every barrier through those last rules.
"""

# The sensitive names the process-sensor rules were checked with (T07 review).
SENSITIVE_BASE = (
    r"(?:token|secret|passw(?:or)?d|api[-_]?key|private[-_]?key|access[-_]?key"
    r"|authorization|cookie)"
)
# A name is secret when it ENDS with one of these words, so "access_token", "X-Api-Key",
# "client_secret" or "SIGNING_KEY" are secret but "input_tokens", "token_count" or "key_id"
# are not.
SENSITIVE_WORDS = (
    r"(?:token|secret|passw(?:or)?d|pass[-_]?phrase|api[-_]?key|private[-_]?key|access[-_]?key"
    r"|(?:secret|signing|encryption|master)[-_]?key|authorization|cookie)"
)

# The flag words the process-sensor rules were checked with (T07-5).
FLAG_BASE = r"(?:password|passwd|pass|pwd|secret|token|api[-_]?key|apikey|auth|cookie)"
# A flag whose name ends with one of these takes a secret: every sensitive word, and the short
# ones that only a command line gives that meaning (--pass, --pwd, --auth, --apikey). Too common
# in prose for redact, which strikes every text: only the command-line barriers use them.
FLAG_WORDS = rf"(?:{SENSITIVE_WORDS}|pass|pwd|auth|apikey)"

# An environment-style assignment a tool reads its password from (MYSQL_PWD=, SSHPASS=,
# REDISCLI_AUTH=): the short words, which redact leaves out for the same reason.
ENV_WORDS = r"(?:pwd|pass|passwd|auth)"

# ``aws configure set NAME VALUE`` and ``npm config set NAME VALUE``: the value is a secret when
# NAME contains one of these anywhere (aws_secret_access_key, //registry/:_authToken).
CONFIG_BASE = r"(?:secret|token|passw|auth|credential)"
CONFIG_WORDS = rf"(?:{SENSITIVE_WORDS}|secret|token|passw|auth|credential)"

# OpenAI's and Anthropic's keys. The minimum is the lower of the two the barriers had (16 in
# Tetragon's rules, 20 in redact): a short key is struck everywhere, at the cost of a rare
# 16-character "sk-" name ("sk-learn" is far shorter).
SK_KEY = r"sk-[A-Za-z0-9_-]{16,}"
