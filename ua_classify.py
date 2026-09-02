"""
Coarse user-agent classification for the audit log.

The audit log records a browser family and an OS family, never the raw
user-agent string. Order matters when writing an entry: the bot flag has to
be derived from the full string first, because once the log holds
"Chrome / macOS" the detail that told a crawler apart from a person is gone
and no later pass can recover it.

Public API:
    is_bot(ua)          -- True unless the string looks like a real browser
    browser_family(ua)  -- Chrome, Firefox, Safari, Edge, other, bot/tool, unknown
    os_family(ua)       -- Windows, macOS, Linux, iOS, Android, other, unknown
    ua_summary(ua)      -- "<browser family> / <OS family>", the logged value
"""

# A real browser announces a rendering engine. Anything that does not is a
# tool, and anything that names itself a tool is one even if it also claims
# an engine, which crawlers routinely do.
_ENGINE_MARKERS = ("gecko", "webkit", "chrome", "safari", "firefox", "edg")

_TOOL_MARKERS = (
    "bot", "spider", "crawl", "curl", "wget", "python",
    "headless", "monitor", "scanner", "http-client",
)

# Checked in order. iOS before macOS because an iPhone says "like Mac OS X";
# Android before Linux because an Android device says "Linux"; Chrome OS and
# the BSDs before Linux because they arrive under an "X11" prefix.
_OS_RULES = (
    ("iOS", ("iphone", "ipad", "ipod")),
    ("Android", ("android",)),
    ("Windows", ("windows",)),
    ("macOS", ("macintosh", "mac os x", "macos")),
    ("other", ("cros", "freebsd", "openbsd", "netbsd", "sunos", "fuchsia")),
    ("Linux", ("linux", "x11")),
)


def is_bot(ua: str) -> bool:
    """True unless the user agent looks like a browser driven by a person.

    Call this on the full user-agent string. It is the only thing that reads
    the raw value, and it has to run before ua_summary() replaces it.

    A request counts as human only when all three hold: the string starts
    with "Mozilla/", it names a rendering engine, and it names no tool.
    Everything else, an absent user agent included, is a bot.
    """
    if not ua:
        return True
    s = ua.lower()
    if not s.startswith("mozilla/"):
        return True
    if not any(marker in s for marker in _ENGINE_MARKERS):
        return True
    if any(marker in s for marker in _TOOL_MARKERS):
        return True
    return False


def browser_family(ua: str) -> str:
    """Browser family with no version number attached."""
    if not ua:
        return "unknown"
    if is_bot(ua):
        return "bot/tool"
    s = ua.lower()
    if "edg" in s:
        return "Edge"
    if "chrome" in s or "crios" in s:
        return "Chrome"
    if "firefox" in s or "fxios" in s:
        return "Firefox"
    if "safari" in s:
        return "Safari"
    return "other"


def os_family(ua: str) -> str:
    """OS family with no version number attached.

    "unknown" covers both an absent user agent and one that names no OS at
    all, which is the normal case for command-line tools.
    """
    if not ua:
        return "unknown"
    s = ua.lower()
    for family, markers in _OS_RULES:
        if any(marker in s for marker in markers):
            return family
    return "unknown"


def ua_summary(ua: str) -> str:
    """The value written to the audit log's ua field."""
    return "%s / %s" % (browser_family(ua), os_family(ua))
