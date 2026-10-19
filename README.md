# histcheck

A browser history parser. Point it at a history database, a browser profile or a whole evidence folder and it turns every Chrome, Edge, Firefox and Safari history it finds into one timeline of page visits, downloads and searches, with the suspicious parts flagged.

No dependencies. Just Python 3.8+ and the standard library. It pairs with [hashcheck](https://github.com/Landull/hashcheck), [metacheck](https://github.com/Landull/metacheck) and [iocheck](https://github.com/Landull/iocheck).

## What it reads

| Browser | File | Records |
|---|---|---|
| Chrome, Edge, Brave, Opera, Vivaldi, Arc, Chromium, Yandex | `History` | visits, downloads (with redirect chain and referrer) |
| Firefox, LibreWolf, Waterfox, Floorp, Zen | `places.sqlite` | visits, downloads |
| Safari | `History.db`, `Downloads.plist` | visits, downloads |

Files are recognized by their database layout, not their name, so renamed or exported copies still work. Searches typed into Google, Bing, DuckDuckGo, Yahoo, YouTube, Brave Search, Ecosia, Yandex, Baidu, Amazon and others are pulled out of the visited URLs as their own records.

Every source also gets its SHA-256 hash, record counts and first/last activity for your case notes.

## What it flags

- **Downloads the user kept after a browser warning**, plus files Chrome rated dangerous or uncommon
- **Executable and script downloads** like `.exe`, `.msi`, `.ps1`, `.js`, `.hta`, `.iso`, `.dmg`, `.pkg` and macro-enabled Office files
- **Downloads and visits that go to a bare IP address** instead of a hostname
- **Local files opened in the browser** (`file://`), such as HTML attachments from a phishing email
- **`data:` and `javascript:` URLs**

It also decodes how each page was reached (typed, link, bookmark, reload, redirect, form submit, back/forward) and, for Chromium browsers, how long the page was open.

## How it handles evidence

- **The originals are never opened by SQLite.** Each database is copied to a temporary folder first and parsed there, so nothing is written next to your evidence and a running browser's lock doesn't block it.
- **Recent activity isn't lost.** A browser keeps its newest history in a `-wal` file until it checkpoints. histcheck copies that along with the database and tells you when it was included.

## Usage

```
python3 histcheck.py History
```

Some real uses:

```
# Every browser profile on this computer
python3 histcheck.py --live

# Every history file inside a mounted image or triage collection
python3 histcheck.py /Volumes/Evidence/Users

# Just the downloads, or just the red flags
python3 histcheck.py /Volumes/Evidence/Users -t download
python3 histcheck.py /Volumes/Evidence/Users --flagged

# What happened in a window, in your own time zone
python3 histcheck.py --live --since "2026-10-18 09:00" --until "2026-10-18 10:00" --local

# Everything touching one domain, or one keyword
python3 histcheck.py --live -d anydesk.com
python3 histcheck.py --live -g invoice

# Spreadsheet for case notes, or JSON for scripts
python3 histcheck.py /Volumes/Evidence/Users -f csv -o history.csv
python3 histcheck.py /Volumes/Evidence/Users -f json -o history.json
```

On Windows, use `python` instead of `python3`. On a Mac, Safari's history is protected, so give your terminal app Full Disk Access (System Settings > Privacy & Security) or histcheck will skip it with a warning.

## Options

| Flag | Description |
|---|---|
| `--live` | find every browser profile for the current user (macOS, Windows, Linux) |
| `-t, --type` | only `visit`, `download` or `search` records (repeatable) |
| `--since DATE` | only records on or after `YYYY-MM-DD` or `YYYY-MM-DD HH:MM` |
| `--until DATE` | only records on or before DATE (a bare date covers that whole day) |
| `-d, --domain DOMAIN` | only records for DOMAIN or its subdomains (repeatable) |
| `-g, --grep TEXT` | only records whose URL, title or detail contain TEXT (repeatable) |
| `--flagged` | only records with findings |
| `--local` | show and filter times in this computer's time zone instead of UTC |
| `--summary` | only the per-source summary and top sites |
| `--full` | don't shorten long URLs and titles in the table |
| `-n, --no-recurse` | don't descend into subfolders |
| `-f, --format` | `table` (default), `csv` or `json` |
| `-o, --output FILE` | write output to a file |

## Example

```
TIME (UTC)                TYPE      BROWSER         DETAIL
2026-10-18 14:01:10Z      visit     Chrome:Default  https://www.google.com/search?q=free+invoice+template  "free invoice template - Google Search"  [keyword search, address bar]
2026-10-18 14:01:10Z      search    Chrome:Default  "free invoice template"  (www.google.com)
2026-10-18 14:01:30Z      visit     Chrome:Default  https://invoice-templates.example.net/download  "Free Invoice Templates"  [link, on page 41s]
2026-10-18 14:02:05Z      visit     Chrome:Default !http://185.220.101.7/files/Invoice_0412.exe  [link, server redirect]
                                                   ! IP address instead of hostname
2026-10-18 14:02:05Z      download  Chrome:Default !http://185.220.101.7/files/Invoice_0412.exe  -> C:\Users\bob\Downloads\Invoice_0412.exe (1.8 MB, complete, opened, application/x-msdownload)
                                                   ! kept despite warning
                                                   ! executable/script file type (.exe)
                                                   ! downloaded from an IP address
2026-10-18 14:06:44Z      visit     Chrome:Default !file:///C:/Users/bob/Downloads/Invoice_0412.html  "Invoice"  [typed]
                                                   ! local file opened in browser
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Browser history found and parsed |
| `1` | No browser history found |
| `2` | Bad input (missing path, bad date) |

## Forensic notes

- **Work on copies.** histcheck never writes to the databases, but copying a file can still update its last-accessed time on some systems. Run it against a forensic image or a write-blocked copy, and record the SHA-256 it reports.
- **Absence isn't proof.** Private/incognito windows aren't recorded, users can clear history, and browsers expire old entries (Chrome after about 90 days). A missing visit doesn't mean it didn't happen.
- **Limits.** Deleted records in free pages aren't recovered, and cache, cookies, session restore files and Chrome's `Archived History` aren't parsed yet. Firefox only keeps downloads it hasn't expired. For deep work, compare against a full tool like Hindsight or KAPE.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s forensics toolkit.
