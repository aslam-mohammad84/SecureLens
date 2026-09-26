# SecureLens 2.1

This replacement adds a real passive-first website reconnaissance engine and fixes the old `UnboundLocalError: cannot access local variable 'dns'` problem.

## Website mapping

The scanner now:
- parses `robots.txt` Allow/Disallow rules
- reads `Sitemap:` directives
- checks common sitemap locations
- parses normal sitemaps
- recursively parses sitemap indexes
- extracts same-origin sitemap URLs
- extracts same-origin links from HTML
- builds a bounded URL inventory
- labels each URL by source (target, sitemap, HTML)
- classifies each URL as robots Allowed/Disallowed
- reports actual HTTP status separately
- identifies robots-disallowed URLs that are still publicly reachable
- shows the website map directly in the dashboard

`robots.txt` is crawler guidance, not access control.

## Install and run

```powershell
cd C:\Users\Aslam\OneDrive\Desktop\securelens-2.1-site-map
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m py_compile .\app.py
python -m py_compile .\core\analyzer.py
python -m uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

## Crawl limits

Default depth is 2 and default maximum URL count is 200. Configure with `AUDITOR_MAX_CRAWL_DEPTH`, `AUDITOR_MAX_CRAWL_URLS`, and `AUDITOR_CRAWL_CONCURRENCY`.

## Active checks

Keep Authorized Active Checks disabled for normal reconnaissance. When enabled, OPTIONS, TRACE, sensitive-path checks and AXFR may run. Only use active checks on systems you own or are explicitly authorized to assess.
