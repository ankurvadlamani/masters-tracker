# Checks every programme's official pages once a day and records changes in monitor.json.
# Runs on GitHub Actions (see .github/workflows/monitor.yml). Standard library only.
import hashlib, html, json, re, datetime, urllib.request

MONTHS = r'(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
DATE = re.compile(r'\b(?:\d{1,2}(?:st|nd|rd|th)?\.?\s+' + MONTHS + r'\.?,?\s+20\d\d|' + MONTHS + r'\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+20\d\d|20\d\d-\d\d-\d\d|\d{1,2}[./]\d{1,2}[./]20\d\d)\b', re.I)
KEYWORDS = re.compile(r'deadline|application|apply|closing|admission|semester|intake|registration', re.I)


def page_text(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (masters-tracker monitor; +https://ankurvadlamani.github.io/masters-tracker/)'})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode(r.headers.get_content_charset() or 'utf-8', 'replace')
    raw = re.sub(r'(?is)<(script|style|noscript|svg|header|footer|nav)\b.*?</\1>', ' ', raw)
    text = html.unescape(re.sub(r'(?s)<[^>]+>', ' ', raw))
    return re.sub(r'\s+', ' ', text).strip()


def date_snippets(text):
    out = []
    for m in DATE.finditer(text):
        ctx = text[max(0, m.start() - 90): m.end() + 40]
        if KEYWORDS.search(ctx):
            s = ctx.strip()
            if s not in out:
                out.append(s)
    return out[:8]


def main():
    research = json.load(open('research.json', encoding='utf-8'))
    try:
        monitor = json.load(open('monitor.json', encoding='utf-8'))
    except Exception:
        monitor = {'lastRun': None, 'pages': {}}
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    urls = {u: p['id'] for p in research['programs'] for u in p.get('watch', [])}
    pages = monitor.get('pages', {})
    for url, pid in urls.items():
        entry = pages.get(url, {})
        entry['program'] = pid
        entry['lastChecked'] = now
        try:
            text = page_text(url)
            digest = hashlib.sha256(text.encode()).hexdigest()
            dates = date_snippets(text)
            if entry.get('hash') and entry['hash'] != digest:
                entry['lastChanged'] = now
                old = set(entry.get('dates', []))
                entry['newDates'] = [d for d in dates if d not in old]
            elif not entry.get('hash'):
                entry['firstSeen'] = now
            entry['hash'] = digest
            entry['dates'] = dates
            entry['status'] = 'ok'
        except Exception as e:
            entry['status'] = 'error'
            entry['error'] = str(e)[:200]
        pages[url] = entry
    monitor['pages'] = {u: e for u, e in pages.items() if u in urls}
    monitor['lastRun'] = now
    json.dump(monitor, open('monitor.json', 'w', encoding='utf-8'), indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
