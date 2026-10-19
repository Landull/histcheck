#!/usr/bin/env python3
"""
histcheck - browser history parser.

Reads history databases from Chrome, Edge, Brave, Opera, Vivaldi, Arc and
other Chromium browsers, Firefox (and its forks), and Safari, and turns them
into one sorted timeline of page visits, downloads and search terms.

Databases are always copied to a temporary folder before they are opened,
so the originals are never touched by SQLite and a running browser's lock
doesn't get in the way. Uncommitted write-ahead log (-wal) data is copied
with them, so the most recent activity is included.

Standard library only. Python 3.8+.

https://github.com/Landull/histcheck
"""

import argparse
import csv
import datetime as dt
import glob
import hashlib
import io
import ipaddress
import json
import os
import plistlib
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from urllib.parse import parse_qs, unquote, urlsplit

__version__ = "1.0.0"

UTC = dt.timezone.utc
EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=UTC)   # Chromium (WebKit) time
EPOCH_1970 = dt.datetime(1970, 1, 1, tzinfo=UTC)   # Firefox (PRTime)
EPOCH_2001 = dt.datetime(2001, 1, 1, tzinfo=UTC)   # Safari (Cocoa / Mac absolute)
SQLITE_MAGIC = b"SQLite format 3\x00"

TYPES = ("visit", "download", "search")

# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------


def _offset(epoch, **delta):
    try:
        return epoch + dt.timedelta(**delta)
    except (OverflowError, ValueError, TypeError):
        return None


def webkit_time(us):
    if not us or us <= 0:
        return None
    return _offset(EPOCH_1601, microseconds=us)


def prtime(us):
    if not us or us <= 0:
        return None
    return _offset(EPOCH_1970, microseconds=us)


def unix_ms(ms):
    if not ms or ms <= 0:
        return None
    return _offset(EPOCH_1970, milliseconds=ms)


def cocoa_time(secs):
    if secs is None:
        return None
    return _offset(EPOCH_2001, seconds=float(secs))


def fmt_time(t, local=False):
    if t is None:
        return ""
    if local:
        return t.astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
    return t.strftime("%Y-%m-%d %H:%M:%SZ")


def parse_when(text, local, end=False):
    """YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS]. A bare --until date covers the whole day."""
    text = text.strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            t = dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d" and end:
            t += dt.timedelta(days=1) - dt.timedelta(microseconds=1)
        if local:
            return t.astimezone().astimezone(UTC)
        return t.replace(tzinfo=UTC)
    raise ValueError(f"can't read date '{text}' (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM')")


def fmt_size(n):
    if n is None or n < 0:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n} B"


def fmt_duration(us):
    if not us or us <= 0:
        return ""
    secs = int(us // 1_000_000)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"


# --------------------------------------------------------------------------
# Code tables
# --------------------------------------------------------------------------

CHROMIUM_CORE = {
    0: "link", 1: "typed", 2: "bookmark", 3: "subframe", 4: "subframe (clicked)",
    5: "omnibox suggestion", 6: "start page", 7: "form submit", 8: "reload",
    9: "keyword search", 10: "keyword search",
}
CHROMIUM_QUALIFIERS = [
    (0x00800000, "back/forward"),
    (0x01000000, "address bar"),
    (0x02000000, "home page"),
    (0x40000000, "client redirect"),
    (0x80000000, "server redirect"),
]
CHROMIUM_DL_STATE = {0: "in progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
CHROMIUM_DANGER = {
    1: "dangerous file", 2: "dangerous URL", 3: "dangerous content",
    4: "possibly dangerous content", 5: "uncommon content",
    6: "kept despite warning", 7: "dangerous host", 8: "potentially unwanted",
    11: "blocked: password protected", 12: "blocked: too large",
    13: "sensitive content warning", 14: "sensitive content blocked",
    17: "deep-scanned: failed", 18: "prompt for deep scan",
}
FIREFOX_VISIT = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "permanent redirect",
    6: "temporary redirect", 7: "download", 8: "framed link", 9: "reload",
}
FIREFOX_DL_STATE = {
    0: "in progress", 1: "complete", 2: "failed", 3: "cancelled", 4: "paused",
    6: "blocked (parental controls)", 8: "blocked (reputation check)",
}

RISKY_EXT = {
    ".exe", ".msi", ".msix", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".dll", ".cpl", ".iso", ".img",
    ".vhd", ".vhdx", ".dmg", ".pkg", ".app", ".command", ".sh", ".apk", ".appx",
    ".docm", ".xlsm", ".pptm", ".one", ".reg", ".url", ".library-ms",
}

# Search engines: (host test, path test, query parameter names)
SEARCH_ENGINES = [
    ("google.", "/search", ("q",)),
    ("bing.com", "/search", ("q",)),
    ("duckduckgo.com", "", ("q",)),
    ("search.yahoo.com", "/search", ("p",)),
    ("yandex.", "/search", ("text",)),
    ("baidu.com", "/s", ("wd", "word")),
    ("ecosia.org", "/search", ("q",)),
    ("search.brave.com", "/search", ("q",)),
    ("startpage.com", "", ("query", "q")),
    ("youtube.com", "/results", ("search_query",)),
    ("amazon.", "/s", ("k",)),
    ("ask.com", "/web", ("q",)),
    ("perplexity.ai", "/search", ("q",)),
    ("github.com", "/search", ("q",)),
    ("reddit.com", "/search", ("q",)),
    ("wikipedia.org", "/w", ("search",)),
]


def chromium_transition(t):
    if t is None:
        return ""
    t &= 0xFFFFFFFF
    parts = [CHROMIUM_CORE.get(t & 0xFF, f"type {t & 0xFF}")]
    parts += [name for bit, name in CHROMIUM_QUALIFIERS if t & bit]
    return ", ".join(parts)


def search_term(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    for host_test, path_test, params in SEARCH_ENGINES:
        if host_test not in host:
            continue
        if path_test and not path.startswith(path_test):
            continue
        qs = parse_qs(parts.query)
        for p in params:
            if qs.get(p) and qs[p][0].strip():
                return qs[p][0].strip()
    return None


def url_host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def file_path_from_uri(uri):
    if uri and uri.startswith("file://"):
        path = unquote(urlsplit(uri).path)
        if len(path) > 2 and path[0] == "/" and path[2] == ":":   # /C:/Users/... on Windows
            path = path[1:].replace("/", "\\")
        return path
    return uri or ""


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


def record(rtype, time, src, url="", title="", detail="", count=None, flags=None, extra=None):
    return {
        "time": time, "type": rtype, "browser": src["browser"], "profile": src["profile"],
        "url": url or "", "title": (title or "").strip(), "detail": detail or "",
        "visit_count": count, "flags": flags or [], "source": src["path"],
        **(extra or {}),
    }


def visit_flags(url):
    flags = []
    low = url.lower()
    if low.startswith("file:"):
        flags.append("local file opened in browser")
    elif low.startswith(("data:", "javascript:")):
        flags.append(f"{low.split(':', 1)[0]}: URL")
    else:
        host = url_host(url)
        if host and is_ip(host):
            flags.append("IP address instead of hostname")
    return flags


def download_flags(path, url, danger=""):
    flags = []
    if danger:
        flags.append(danger)
    ext = os.path.splitext(path.replace("\\", "/").rsplit("/", 1)[-1].lower())[1]
    if ext in RISKY_EXT:
        flags.append(f"executable/script file type ({ext})")
    host = url_host(url)
    if host and is_ip(host):
        flags.append("downloaded from an IP address")
    return flags


# --------------------------------------------------------------------------
# Database access
# --------------------------------------------------------------------------


def columns(conn, table):
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.DatabaseError:
        return set()


def tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def pick(cols, *names, default="NULL"):
    """Column expression that survives schema differences between versions."""
    for n in names:
        if n in cols:
            return n
    return default


def detect_kind(tbls):
    if {"urls", "visits"} <= tbls:
        return "chromium"
    if {"moz_places", "moz_historyvisits"} <= tbls:
        return "firefox"
    if {"history_items", "history_visits"} <= tbls:
        return "safari"
    return None


def parse_chromium(conn, src):
    out = []
    vcols = columns(conn, "visits")
    dur = pick(vcols, "visit_duration", default="0")
    q = (f"SELECT v.visit_time, v.transition, {dur}, u.url, u.title, u.visit_count "
         f"FROM visits v JOIN urls u ON u.id = v.url")
    for vtime, trans, duration, url, title, count in conn.execute(q):
        detail = chromium_transition(trans)
        if duration:
            detail += f", on page {fmt_duration(duration)}"
        out.append(record("visit", webkit_time(vtime), src, url, title, detail, count,
                          visit_flags(url or "")))

    tbls = tables(conn)
    if "downloads" not in tbls:
        return out
    dcols = columns(conn, "downloads")
    chains = {}
    if "downloads_url_chains" in tbls:
        for did, idx, url in conn.execute(
                "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains.setdefault(did, []).append(url)
    q = ("SELECT id, {target}, {cur}, start_time, {end}, {recv}, {total}, {state}, {danger}, "
         "{opened}, {ref}, {tab}, {mime} FROM downloads").format(
        target=pick(dcols, "target_path", "full_path"), cur=pick(dcols, "current_path"),
        end=pick(dcols, "end_time"), recv=pick(dcols, "received_bytes"),
        total=pick(dcols, "total_bytes"), state=pick(dcols, "state"),
        danger=pick(dcols, "danger_type"), opened=pick(dcols, "opened"),
        ref=pick(dcols, "referrer"), tab=pick(dcols, "tab_url"),
        mime=pick(dcols, "mime_type", "original_mime_type"))
    for (did, target, cur, start, end, recv, total, state, danger, opened,
         referrer, tab_url, mime) in conn.execute(q):
        chain = chains.get(did) or []
        url = chain[-1] if chain else (tab_url or "")
        path = target or cur or ""
        bits = [fmt_size(total if total and total > 0 else recv),
                CHROMIUM_DL_STATE.get(state, f"state {state}")]
        if opened:
            bits.append("opened")
        if mime:
            bits.append(mime)
        danger_txt = CHROMIUM_DANGER.get(danger, "")
        flags = download_flags(path, url, danger_txt)
        extra = {
            "path": path, "referrer": referrer or "", "tab_url": tab_url or "",
            "redirect_chain": chain, "end_time": webkit_time(end), "bytes": recv,
        }
        out.append(record("download", webkit_time(start), src, url,
                          os.path.basename(path.replace("\\", "/")),
                          f"{path} ({', '.join(bits)})", None, flags, extra))
    return out


def parse_firefox(conn, src):
    out = []
    q = ("SELECT v.visit_date, v.visit_type, p.url, p.title, p.visit_count "
         "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id")
    for vdate, vtype, url, title, count in conn.execute(q):
        out.append(record("visit", prtime(vdate), src, url, title,
                          FIREFOX_VISIT.get(vtype, f"type {vtype}"), count,
                          visit_flags(url or "")))

    tbls = tables(conn)
    if not {"moz_annos", "moz_anno_attributes"} <= tbls:
        return out
    downloads = {}
    q = ("SELECT a.place_id, n.name, a.content, a.dateAdded, p.url FROM moz_annos a "
         "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
         "JOIN moz_places p ON p.id = a.place_id WHERE n.name LIKE 'downloads/%'")
    for place_id, name, content, added, url in conn.execute(q):
        d = downloads.setdefault(place_id, {"url": url})
        if name == "downloads/destinationFileURI":
            d["path"] = file_path_from_uri(content)
            d["start"] = prtime(added)
        elif name == "downloads/metaData":
            try:
                d["meta"] = json.loads(content)
            except (TypeError, ValueError):
                pass
    for d in downloads.values():
        meta = d.get("meta", {})
        path = d.get("path", "")
        state = meta.get("state")
        bits = [fmt_size(meta.get("fileSize")), FIREFOX_DL_STATE.get(state, f"state {state}")]
        danger = "blocked by reputation check" if state == 8 else ""
        flags = download_flags(path, d["url"], danger)
        extra = {"path": path, "referrer": "", "tab_url": "", "redirect_chain": [],
                 "end_time": unix_ms(meta.get("endTime")), "bytes": meta.get("fileSize")}
        out.append(record("download", d.get("start") or unix_ms(meta.get("endTime")), src,
                          d["url"], os.path.basename(path.replace("\\", "/")),
                          f"{path} ({', '.join(bits)})",
                          None, flags, extra))
    return out


def parse_safari(conn, src):
    out = []
    vcols = columns(conn, "history_visits")
    ok = pick(vcols, "load_successful", default="1")
    q = (f"SELECT v.visit_time, v.title, {ok}, i.url, i.visit_count "
         f"FROM history_visits v JOIN history_items i ON i.id = v.history_item")
    for vtime, title, loaded, url, count in conn.execute(q):
        flags = visit_flags(url or "")
        detail = ""
        if not loaded:
            detail = "page failed to load"
        out.append(record("visit", cocoa_time(vtime), src, url, title, detail, count, flags))
    return out


def parse_safari_downloads(path, src):
    with open(path, "rb") as fh:
        data = plistlib.load(fh)
    out = []
    for e in data.get("DownloadHistory", []) if isinstance(data, dict) else []:
        url = e.get("DownloadEntryURL", "")
        fpath = e.get("DownloadEntryPath", "")
        added = e.get("DownloadEntryDateAddedKey")
        done = e.get("DownloadEntryDateFinishedKey")
        added = added.replace(tzinfo=UTC) if isinstance(added, dt.datetime) else None
        done = done.replace(tzinfo=UTC) if isinstance(done, dt.datetime) else None
        size = e.get("DownloadEntryProgressTotalToLoad")
        got = e.get("DownloadEntryProgressBytesSoFar")
        state = "complete" if done or (size and got == size) else "incomplete"
        extra = {"path": fpath, "referrer": "", "tab_url": "", "redirect_chain": [],
                 "end_time": done, "bytes": got}
        out.append(record("download", added or done, src, url, os.path.basename(fpath),
                          f"{fpath} ({fmt_size(size)}, {state})", None,
                          download_flags(fpath, url), extra))
    return out


# --------------------------------------------------------------------------
# Finding and labelling databases
# --------------------------------------------------------------------------

BROWSER_HINTS = [
    ("microsoft edge", "Edge"), ("microsoft/edge", "Edge"), ("microsoft\\edge", "Edge"),
    ("brave", "Brave"), ("vivaldi", "Vivaldi"), ("opera", "Opera"), ("arc/user data", "Arc"),
    ("yandex", "Yandex"), ("chromium", "Chromium"), ("google-chrome", "Chrome"),
    ("google/chrome", "Chrome"), ("google\\chrome", "Chrome"),
    ("librewolf", "LibreWolf"), ("waterfox", "Waterfox"), ("floorp", "Floorp"),
    ("zen", "Zen"), ("thunderbird", "Thunderbird"), ("firefox", "Firefox"),
    ("safari", "Safari"),
]
DEFAULT_NAME = {"chromium": "Chromium-based", "firefox": "Firefox-based", "safari": "Safari"}


def label(path, kind):
    low = path.replace("\\", "/").lower()
    browser = DEFAULT_NAME.get(kind, kind)
    for hint, name in BROWSER_HINTS:
        if hint.replace("\\", "/") in low:
            browser = name
            break
    parent = os.path.basename(os.path.dirname(os.path.abspath(path)))
    profile = "" if kind == "safari" else parent
    if kind == "firefox" and "." in profile:
        profile = profile.split(".", 1)[1]           # "x1y2z3.default-release" -> "default-release"
    return browser, profile


def live_paths():
    home = os.path.expanduser("~")
    pats = []
    if sys.platform == "darwin":
        sup = os.path.join(home, "Library", "Application Support")
        for d in ("Google/Chrome", "Google/Chrome Beta", "Microsoft Edge",
                  "BraveSoftware/Brave-Browser", "Vivaldi", "Chromium", "Arc/User Data",
                  "Yandex/YandexBrowser"):
            pats.append(os.path.join(sup, d, "*", "History"))
        pats.append(os.path.join(sup, "com.operasoftware.Opera*", "History"))
        for d in ("Firefox", "librewolf", "Waterfox", "Floorp", "zen"):
            pats.append(os.path.join(sup, d, "Profiles", "*", "places.sqlite"))
        pats.append(os.path.join(home, "Library", "Safari", "History.db"))
        pats.append(os.path.join(home, "Library", "Safari", "Downloads.plist"))
    elif os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        roaming = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        for d in (r"Google\Chrome", r"Google\Chrome Beta", r"Microsoft\Edge",
                  r"BraveSoftware\Brave-Browser", "Vivaldi", "Chromium",
                  r"Yandex\YandexBrowser", r"Packages\TheBrowserCompany.Arc*\LocalCache\Local\Arc"):
            pats.append(os.path.join(local, d, "User Data", "*", "History"))
        pats.append(os.path.join(roaming, "Opera Software", "Opera*", "History"))
        pats.append(os.path.join(roaming, "Opera Software", "Opera*", "*", "History"))
        for d in (r"Mozilla\Firefox", "librewolf", r"Waterfox", r"Floorp", "zen"):
            pats.append(os.path.join(roaming, d, "Profiles", "*", "places.sqlite"))
    else:
        cfg = os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config"))
        for d in ("google-chrome", "google-chrome-beta", "chromium", "microsoft-edge",
                  "BraveSoftware/Brave-Browser", "vivaldi", "yandex-browser"):
            pats.append(os.path.join(cfg, d, "*", "History"))
        pats.append(os.path.join(cfg, "opera*", "History"))
        pats.append(os.path.join(home, "snap", "chromium", "common", "chromium", "*", "History"))
        for d in (".mozilla/firefox", ".librewolf", ".waterfox", ".floorp", ".zen",
                  "snap/firefox/common/.mozilla/firefox",
                  ".var/app/org.mozilla.firefox/.mozilla/firefox"):
            pats.append(os.path.join(home, d, "*", "places.sqlite"))
    found = []
    for pat in pats:
        found.extend(sorted(glob.glob(pat)))
    return found


def is_sqlite(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def is_safari_downloads(path):
    return os.path.basename(path).lower() == "downloads.plist"


def iter_candidates(target, recursive=True):
    """Every file under target that could be a browser history store."""
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs.sort()
        for name in sorted(files):
            if name.endswith(("-wal", "-shm", "-journal")):
                continue
            path = os.path.join(root, name)
            if is_safari_downloads(path) or is_sqlite(path):
                yield path
        if not recursive:
            break


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_source(path, tmpdir, warnings, named):
    """Parse one file. Returns (source info, records) or (None, []) if it isn't history."""
    info = {"path": os.path.abspath(path), "browser": "", "profile": "", "kind": "",
            "sha256": "", "wal_bytes": 0, "visits": 0, "downloads": 0, "searches": 0,
            "first": None, "last": None}
    try:
        if is_safari_downloads(path):
            info.update(kind="safari", browser="Safari", sha256=sha256_file(path))
            return info, parse_safari_downloads(path, info)

        if not is_sqlite(path):
            if named:
                warnings.append(f"{path}: not a SQLite database")
            return None, []
        idx = len(os.listdir(tmpdir))
        work = os.path.join(tmpdir, f"{idx}.db")
        shutil.copy2(path, work)
        for suffix in ("-wal", "-journal"):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, work + suffix)
                if suffix == "-wal":
                    info["wal_bytes"] = os.path.getsize(path + suffix)
        conn = sqlite3.connect(work)
        try:
            kind = detect_kind(tables(conn))
            if not kind:
                if named:
                    warnings.append(f"{path}: SQLite database, but not a browser history file")
                return None, []
            info["kind"] = kind
            info["browser"], info["profile"] = label(path, kind)
            info["sha256"] = sha256_file(path)
            parser = {"chromium": parse_chromium, "firefox": parse_firefox,
                      "safari": parse_safari}[kind]
            return info, parser(conn, info)
        finally:
            conn.close()
    except PermissionError:
        hint = ""
        if sys.platform == "darwin" and "/Library/Safari" in path:
            hint = " (give your terminal Full Disk Access in System Settings > Privacy & Security)"
        warnings.append(f"{path}: permission denied{hint}")
    except (OSError, sqlite3.DatabaseError, plistlib.InvalidFileException, ValueError) as exc:
        warnings.append(f"{path}: {exc}")
    return None, []


def add_searches(records):
    """Turn search-engine visits into search records (one per distinct term per minute)."""
    out, seen = [], set()
    for r in records:
        if r["type"] != "visit":
            continue
        term = search_term(r["url"])
        if not term:
            continue
        minute = r["time"].replace(second=0, microsecond=0) if r["time"] else None
        key = (r["source"], term.lower(), minute)
        if key in seen:
            continue
        seen.add(key)
        out.append({**r, "type": "search", "title": term,
                    "detail": url_host(r["url"]), "flags": [], "visit_count": None})
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def who(r):
    return f"{r['browser']}:{r['profile']}" if r["profile"] else r["browser"]


def clip(text, n):
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def render_summary(sources, records, local, top=10):
    lines = ["", "Sources:"]
    for s in sources:
        span = ""
        if s["first"]:
            span = f"  {fmt_time(s['first'], local)} -> {fmt_time(s['last'], local)}"
        counts = ", ".join(f"{s[k]} {k if s[k] != 1 else k[:-2] if k == 'searches' else k[:-1]}"
                           for k in ("visits", "downloads", "searches"))
        lines.append(f"  {who(s)}  [{s['kind']}]  {counts}{span}")
        lines.append(f"    {s['path']}")
        lines.append(f"    sha256 {s['sha256']}")
        if s["wal_bytes"]:
            lines.append(f"    includes {fmt_size(s['wal_bytes'])} of uncommitted -wal data")
    hosts = Counter(url_host(r["url"]) for r in records
                    if r["type"] == "visit" and url_host(r["url"]))
    if hosts:
        lines += ["", f"Top {min(top, len(hosts))} sites by visits:"]
        width = max(len(h) for h, _ in hosts.most_common(top))
        for host, n in hosts.most_common(top):
            lines.append(f"  {host:<{width}}  {n}")
    flagged = sum(1 for r in records if r["flags"])
    if flagged:
        lines += ["", f"{flagged} record(s) flagged with !"]
    return "\n".join(lines) + "\n"


def render_table(records, sources, local, summary_only, full):
    out = []
    if not summary_only:
        if records:
            w = max(len(who(r)) for r in records)
            tz = "local" if local else "UTC"
            out.append(f"{'TIME (' + tz + ')':<24}  {'TYPE':<8}  {'BROWSER':<{w}}  DETAIL")
        for r in records:
            if r["type"] == "search":
                body = f'"{r["title"]}"  ({r["detail"]})'
            elif r["type"] == "download":
                body = f"{r['url']}  -> {r['detail']}"
            else:
                body = r["url"] if full else clip(r["url"], 140)
                if r["title"]:
                    body += f'  "{r["title"] if full else clip(r["title"], 70)}"'
                if r["detail"]:
                    body += f"  [{r['detail']}]"
            mark = "!" if r["flags"] else " "
            out.append(f"{fmt_time(r['time'], local):<24}  {r['type']:<8}  "
                       f"{who(r):<{w}} {mark}{body}")
            for f in r["flags"]:
                out.append(f"{'':<24}  {'':<8}  {'':<{w}} ! {f}")
    return "\n".join(out) + ("\n" if out else "") + render_summary(sources, records, local)


FIELDS = ["time", "type", "browser", "profile", "url", "title", "detail", "visit_count",
          "flags", "path", "referrer", "end_time", "source"]


def render_csv(records, local):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in records:
        row = dict(r)
        row["time"] = fmt_time(r["time"], local)
        row["end_time"] = fmt_time(r.get("end_time"), local)
        row["flags"] = "; ".join(r["flags"])
        w.writerow(row)
    return buf.getvalue()


def render_json(records, sources, warnings, local):
    def clean(obj):
        return {k: (fmt_time(v, local) if isinstance(v, dt.datetime) else v)
                for k, v in obj.items()}
    doc = {
        "tool": "histcheck", "version": __version__,
        "generated": fmt_time(dt.datetime.now(UTC), local),
        "sources": [clean(s) for s in sources],
        "records": [clean(r) for r in records],
        "warnings": warnings,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="histcheck",
        description="Browser history parser: visits, downloads and searches from "
                    "Chromium browsers, Firefox and Safari as one timeline.")
    p.add_argument("targets", nargs="*", metavar="target",
                   help="history database, profile folder, or evidence folder to search")
    p.add_argument("--live", action="store_true",
                   help="find and read every browser profile for the current user")
    p.add_argument("-t", "--type", action="append", choices=TYPES,
                   help="only show this record type (repeatable)")
    p.add_argument("--since", metavar="DATE", help="only records on/after DATE (YYYY-MM-DD[ HH:MM])")
    p.add_argument("--until", metavar="DATE", help="only records on/before DATE")
    p.add_argument("-g", "--grep", metavar="TEXT", action="append",
                   help="only records whose URL, title or detail contain TEXT (repeatable)")
    p.add_argument("-d", "--domain", metavar="DOMAIN", action="append",
                   help="only records for DOMAIN or its subdomains (repeatable)")
    p.add_argument("--flagged", action="store_true", help="only records with findings (!)")
    p.add_argument("--local", action="store_true",
                   help="show and filter times in this computer's time zone instead of UTC")
    p.add_argument("--summary", action="store_true",
                   help="table format: only the per-source summary and top sites")
    p.add_argument("--full", action="store_true", help="table format: don't shorten long URLs/titles")
    p.add_argument("-n", "--no-recurse", action="store_true",
                   help="don't descend into subfolders")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    if not args.targets and not args.live:
        p.error("give a history file or folder, or use --live")
    return args


def keep(r, args, since, until):
    if args.type and r["type"] not in args.type:
        return False
    if since and (r["time"] is None or r["time"] < since):
        return False
    if until and (r["time"] is None or r["time"] > until):
        return False
    if args.flagged and not r["flags"]:
        return False
    if args.domain:
        host = url_host(r["url"])
        if not any(host == d or host.endswith("." + d) for d in
                   (x.lower().lstrip(".") for x in args.domain)):
            return False
    if args.grep:
        hay = f"{r['url']}\n{r['title']}\n{r['detail']}".lower()
        if not any(g.lower() in hay for g in args.grep):
            return False
    return True


def main(argv=None):
    args = parse_args(argv)
    try:
        since = parse_when(args.since, args.local) if args.since else None
        until = parse_when(args.until, args.local, end=True) if args.until else None
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    jobs = []
    for target in args.targets:
        if not os.path.exists(target):
            print(f"[!] Not found: {target}", file=sys.stderr)
            return 2
        named = os.path.isfile(target)
        jobs += [(path, named) for path in iter_candidates(target, not args.no_recurse)]
    if args.live:
        live = live_paths()
        if not live:
            print("[!] No browser profiles found for this user", file=sys.stderr)
        jobs += [(path, True) for path in live]

    sources, records, warnings, seen = [], [], [], set()
    with tempfile.TemporaryDirectory(prefix="histcheck-") as tmpdir:
        for path, named in jobs:
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            info, recs = read_source(path, tmpdir, warnings, named)
            if info is None:
                continue
            recs += add_searches(recs)
            plural = {"visit": "visits", "download": "downloads", "search": "searches"}
            for r in recs:
                info[plural[r["type"]]] += 1
            times = [r["time"] for r in recs if r["time"]]
            if times:
                info["first"], info["last"] = min(times), max(times)
            sources.append(info)
            records += recs

    if not sources:
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
        print("[!] No browser history found", file=sys.stderr)
        return 1

    records = [r for r in records if keep(r, args, since, until)]
    order = {t: i for i, t in enumerate(TYPES)}
    records.sort(key=lambda r: (r["time"] or EPOCH_1601, order[r["type"]], r["url"]))

    if args.format == "csv":
        text = render_csv(records, args.local)
    elif args.format == "json":
        text = render_json(records, sources, warnings, args.local)
    else:
        text = render_table(records, sources, args.local, args.summary, args.full)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"[*] {len(records)} record(s) from {len(sources)} source(s) written to "
              f"{args.output}", file=sys.stderr)
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stderr.close()

    if args.format != "json":
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
