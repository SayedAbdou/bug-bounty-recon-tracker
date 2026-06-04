# 🔍 Recon Merge

A lightweight Python tool to merge and unify recon outputs from **httpx**, **WhatWeb**, **WAF detection**, and optionally **testssl** into a single structured JSON file — ready for reporting or further analysis.

---

## 📦 Requirements

- Python 3.8+
- Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Tools Expected as Input

| Flag        | Tool              | Required |
|-------------|-------------------|----------|
| `--httpx`   | [httpx](https://github.com/projectdiscovery/httpx) | ✅ Yes |
| `--waf`     | wafw00f / custom  | ✅ Yes |
| `--whatweb` | [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | ✅ Yes |
| `--ssl`     | [testssl.sh](https://testssl.sh/) | ❌ Optional |

---

## 🚀 Usage

### Full command (with SSL):
```bash
python3 recon_merge.py \
  --httpx   httpx.json         \
  --waf     waf.json           \
  --whatweb whatweb.json       \
  --ssl     ssl_merged.json    \
  -o        unified_recon.json
```

### Without SSL (skip testssl):
```bash
python3 recon_merge.py \
  --httpx   httpx.json         \
  --waf     waf.json           \
  --whatweb whatweb.json       \
  -o        unified_recon.json
```

> If `--ssl` is not provided, the SSL column will fall back to whatever httpx detected via its own TLS probe, or `—` if nothing was found.

---

## 📤 How to Generate Each Input File

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

# Then merge all testssl outputs:
python3 merge_testssl.py --input-dir ./ssl_results/ -o ssl_merged.json
```

---

## 📊 Output Format

The output `unified_recon.json` is a list of objects, one per host:

```json
[
  {
    "host": "example.com",
    "ip": "93.184.216.34",
    "status": 200,
    "title": "Example Domain",
    "tech": ["Apache", "PHP"],
    "waf": "Cloudflare",
    "ssl": "TLSv1.3",
    "cdn": true,
    "content_length": 1256,
    "redirect": null
  }
]
```

---

## ⚠️ Notes

- Do **not** commit real `*.json` recon output files — they may contain sensitive target data. The `.gitignore` excludes them by default.
- If you want to include example data, name your files `example_httpx.json`, etc., and they will not be ignored.
- All input files must be in valid JSON or JSON-lines format.

---

## 📁 Recommended Folder Layout for a Recon Project

```
recon-project/
├── recon-merge/          ← this tool
├── output/
│   ├── httpx.json
│   ├── waf.json
│   ├── whatweb.json
│   ├── ssl_merged.json   (optional)
│   └── unified_recon.json
└── hosts.txt
```

---

## 📝 License

MIT License — free to use, modify, and distribute.
