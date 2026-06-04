# 🔍 Bug Bounty Recon Tracker

A complete recon pipeline tool for bug bounty hunters.

**`recon_merge.py`** merges outputs from multiple recon tools into one unified JSON file.
**`dashboard.html`** provides a visual web dashboard to explore, filter, and export your results — no server required.

---

## 📁 Repository Structure

```
bug-bounty-recon-tracker/
├── recon_merge.py     ← Python merger script
├── dashboard.html     ← Web dashboard (open in any browser)
├── requirements.txt   ← Python dependencies
├── .gitignore         ← Ignores sensitive output files
└── README.md          ← This file
```

---

## ⚙️ How It Works

```
httpx.json  ─┐
waf.json    ─┤──► recon_merge.py ──► unified_recon.json ──► dashboard.html
whatweb.json─┤
ssl.json    ─┘ (optional)
```

---

## 📦 Requirements

- Python 3.8+ (standard library only — no pip install needed)
- Any modern browser (Chrome, Firefox, Edge) for the dashboard

---

## 🛠️ Input Tools

| Flag        | Tool                 | Required |
|-------------|----------------------|----------|
| `--httpx`   | [httpx](https://github.com/projectdiscovery/httpx) | ✅ Yes |
| `--waf`     | wafw00f / custom     | ✅ Yes |
| `--whatweb` | [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | ✅ Yes |
| `--ssl`     | [testssl.sh](https://testssl.sh/) | ❌ Optional |

---

## 🚀 Step 1 — Generate Your Input Files

### httpx
```bash
cat hosts.txt | httpx -json -o httpx.json \
  -title -status-code -tech-detect \
  -tls-grab -content-length -cdn -follow-redirects
```

### WhatWeb
```bash
whatweb --input-file hosts.txt \
  --log-json whatweb.json \
  --aggression 3
```

### WAF Detection (wafw00f)
```bash
wafw00f -i hosts.txt -o waf.json -f json
```

### testssl (optional)
```bash
for host in $(cat hosts.txt); do
  testssl --jsonfile "${host//\//_}_ssl.json" "$host"
done
# Then merge all outputs:
python3 merge_testssl.py --input-dir ./ssl_results/ -o ssl_merged.json
```

---

## 🚀 Step 2 — Run the Merger

### With SSL:
```bash
python3 recon_merge.py \
  --httpx   httpx.json      \
  --waf     waf.json        \
  --whatweb whatweb.json    \
  --ssl     ssl_merged.json \
  -o        unified_recon.json
```

### Without SSL:
```bash
python3 recon_merge.py \
  --httpx   httpx.json   \
  --waf     waf.json     \
  --whatweb whatweb.json \
  -o        unified_recon.json
```

---

## 🚀 Step 3 — Open the Dashboard

1. Open `dashboard.html` in your browser (double-click it)
2. Click **Choose File** and load your `unified_recon.json`
3. Explore, filter, sort, and export your results

### Dashboard Features

- **Summary cards** — total hosts, live hosts, WAF count, CDN count, SSL count, unique tech
- **Search** — filter across host, IP, title, tech, WAF, SSL fields simultaneously
- **Filters** — filter by status code range, WAF detected, CDN detected
- **Sortable columns** — click any column header to sort
- **Detail panel** — click View on any row to see all fields for that host
- **Export** — download filtered results as CSV or JSON

---

## 📊 Output Format

`unified_recon.json` is a list of host objects:

```json
[
  {
    "host": "example.com",
    "url": "https://example.com",
    "ip": "93.184.216.34",
    "status": 200,
    "title": "Example Domain",
    "tech": ["Apache", "PHP", "Bootstrap"],
    "waf": "Cloudflare",
    "waf_manufacturer": "Cloudflare Inc.",
    "ssl": "TLSv1.3",
    "cdn": true,
    "cdn_name": "Cloudflare",
    "content_length": 1256,
    "webserver": "nginx",
    "redirect": null
  }
]
```

---

## ⚠️ Security Notes

- **Never commit real recon `.json` files** — they contain sensitive target data.
  The `.gitignore` excludes all `*.json` files automatically.
- If you want to include example data, name files `example_httpx.json` etc.
  (the `.gitignore` allows `example_*.json`).
- The dashboard runs entirely in your browser — no data is ever uploaded anywhere.

---

## 📝 License

MIT License — free to use, modify, and distribute.
