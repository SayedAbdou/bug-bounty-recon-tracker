#!/usr/bin/env python3
"""
recon_merge.py — Merge httpx + wafw00f + whatweb + testssl into one
                 unified JSON for Bug Bounty Recon Tracker v3.
Usage:
  python3 recon_merge.py --httpx recon_AcmeCorp/httpx.json \
                         --waf   recon_AcmeCorp/waf.json \
                         --whatweb recon_AcmeCorp/whatweb.json \
                         --ssl   recon_AcmeCorp/ssl_merged.json \
                         -o AcmeCorp_unified.json
"""

import json, re, argparse, sys
from pathlib import Path

# ── Signature lists ──────────────────────────────────────────────
CMS_LIST = ['WordPress','Drupal','Joomla','Magento','Shopify','Typo3',
            'DotNetNuke','Sitecore','Ghost','HubSpot','Squarespace','Wix',
            'Contentful','Strapi','PrestaShop','OpenCart','Craft CMS']

FRAMEWORK_LIST = ['Ruby-on-Rails','Django','Laravel','Spring','Spring-Boot',
                  'ASP.NET','ASP_NET','Express','Flask','Symfony','CodeIgniter',
                  'CakePHP','Yii','Zend-Framework','Angular','React','Vue.js',
                  'Next.js','Nuxt.js','Gatsby','Svelte','FastAPI','Gin','Echo',
                  'Bootstrap','jQuery-UI']

LANG_LIST = ['PHP','Python','Ruby','Java','Perl','Node.js','ASP','ColdFusion',
             'Go','Rust','Kotlin','Scala','TypeScript','Groovy']

# ── NEW: CDN / Load-Balancer plugins ────────────────────────────
# Keys = whatweb plugin name (lowercase), Value = display label
CDN_PLUGINS = {
    'f5-bigip':   'F5 BIG-IP',
    'bigip':      'F5 BIG-IP',
    'cloudflare': 'Cloudflare',
    'akamai':     'Akamai',
    'fastly':     'Fastly',
    'cloudfront': 'AWS CloudFront',
    'imperva':    'Imperva',
    'sucuri':     'Sucuri',
    'incapsula':  'Incapsula',
    'varnish':    'Varnish',
    'maxcdn':     'MaxCDN',
    'keycdn':     'KeyCDN',
    'stackpath':  'StackPath',
    'edgio':      'Edgio',
}

# ── FIXED: normalized FRAMEWORK lookup (handles ASP_NET → ASP.NET) ─
# Build index with BOTH original and underscore-normalized keys
def _build_fw_index():
    idx = {}
    for f in FRAMEWORK_LIST:
        idx[f.lower()] = f
        # Also map underscore variant → same display label
        # e.g. 'asp_net' → 'ASP.NET', 'ruby_on_rails' → 'Ruby-on-Rails'
        normalized = f.lower().replace('.', '_').replace('-', '_')
        if normalized not in idx:
            idx[normalized] = f
    # Manual aliases whatweb is known to emit
    idx['asp_net']         = 'ASP.NET'
    idx['aspnet']          = 'ASP.NET'
    idx['ruby-on-rails']   = 'Ruby on Rails'
    idx['bootstrap']       = 'Bootstrap'
    idx['jquery']          = 'jQuery'
    idx['jquery-ui']       = 'jQuery UI'
    idx['spring-boot']     = 'Spring Boot'
    idx['zend-framework']  = 'Zend Framework'
    return idx

SENSITIVE_PORTS = {
    '21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','3306':'MySQL',
    '5432':'PostgreSQL','6379':'Redis','27017':'MongoDB',
    '9200':'Elasticsearch','5601':'Kibana','4848':'GlassFish',
    '7001':'WebLogic','8161':'ActiveMQ','1433':'MSSQL','5984':'CouchDB'
}

# ── Domain normalizer ────────────────────────────────────────────
def nd(url):
    if not url: return ''
    url = re.sub(r'^https?://', '', str(url).strip(), flags=re.I)
    return url.split('/')[0].split(':')[0].split('?')[0].lower()

# ── httpx parser ─────────────────────────────────────────────────
def parse_httpx(path):
    results, skipped = {}, 0
    content = Path(path).read_text().strip()
    lines = []
    if content.startswith('['):
        try:   lines = [json.dumps(i) for i in json.loads(content)]
        except: lines = content.splitlines()
    else:
        lines = content.splitlines()

    for line in lines:
        line = line.strip().rstrip(',')
        if not line or line in ['[', ']']: continue
        try:
            j = json.loads(line)
            url    = j.get('url', j.get('host', j.get('input', '')))
            domain = nd(url)
            if not domain: skipped += 1; continue

            tech = j.get('tech', j.get('technologies', j.get('technology', [])))
            if isinstance(tech, str): tech = [t.strip() for t in tech.split(',') if t.strip()]
            if not isinstance(tech, list): tech = []

            code = str(j.get('status-code', j.get('status_code', j.get('status', '—'))))
            if code in ('None', ''): code = '—'

            cdn = j.get('cdn-name', j.get('cdn_name', j.get('cdn', '—')))
            if isinstance(cdn, bool): cdn = 'CDN Detected' if cdn else '—'

            port  = j.get('port', '')
            ports = j.get('ports', port)
            if isinstance(ports, list): ports = ', '.join(str(p) for p in ports)
            else: ports = str(ports) if ports else '—'

            try:   status = 'Active' if 100 <= int(code) < 600 else 'Unknown'
            except: status = 'Unknown'

            ssl = '—'
            tls_data = j.get('tls', {})
            if isinstance(tls_data, dict):
                ver = str(tls_data.get('version', tls_data.get('tls_version', '')))
                for label, key in [('TLS 1.3','1.3'),('TLS 1.2','1.2'),
                                    ('TLS 1.1','1.1'),('TLS 1.0','1.0')]:
                    if key in ver: ssl = label; break

            results[domain] = {
                'domain':       domain,
                'ip':           j.get('ip', j.get('a', '—')) or '—',
                'status':       status,
                'http':         code,
                'server':       j.get('webserver', j.get('server', '—')) or '—',
                'technologies': ', '.join(tech) if tech else '—',
                'cms':          '—',
                'framework':    '—',
                'language':     '—',
                'cdn':          cdn or '—',
                'waf':          '—',
                'ssl':          ssl,
                'ports':        ports,
                'scope':        'In Scope',
                'notes':        ''
            }
        except: skipped += 1

    print(f'    → {len(results)} hosts loaded ({skipped} skipped)')
    return results

# ── wafw00f parser ───────────────────────────────────────────────
def parse_wafw00f(path):
    waf_map = {}
    content = Path(path).read_text().strip()
    if content.startswith('[') or content.startswith('{'):
        try:
            data = json.loads(content)
            if isinstance(data, dict): data = [data]
            for item in data:
                domain = nd(item.get('url', item.get('target', '')))
                if not domain: continue
                detected = item.get('detected', False)
                firewall = item.get('firewall', item.get('waf', ''))
                waf_map[domain] = firewall if (detected and firewall and
                    firewall.lower() not in ['generic','none','unknown']) else 'None detected'
            print(f'    → WAF data for {len(waf_map)} hosts'); return waf_map
        except: pass
    for line in content.splitlines():
        m = re.search(r'https?://([^\s/]+).*?behind\s+([^\.\n]+?)(?:\s+WAF)?(?:\.|$)', line, re.I)
        if m: waf_map[nd(m.group(1))] = m.group(2).strip(); continue
        m2 = re.search(r'No WAF.+?https?://([^\s/]+)', line, re.I)
        if m2: waf_map[nd(m2.group(1))] = 'None detected'
    print(f'    → WAF data for {len(waf_map)} hosts (text format)')
    return waf_map

# ── whatweb parser ───────────────────────────────────────────────
# FIXED: normalized framework index, added CDN extraction,
#        added HTTPServer/cookie-based fallback detection
def parse_whatweb(path):
    tech_map = {}
    cms_idx  = {c.lower(): c for c in CMS_LIST}
    fw_idx   = _build_fw_index()           # ← uses the fixed builder
    lang_idx = {l.lower(): l for l in LANG_LIST}
    content  = Path(path).read_text().strip()

    items = []
    if content.startswith('['):
        try: items = json.loads(content)
        except: pass
    if not items:
        for line in content.splitlines():
            line = line.strip().rstrip(',')
            if not line or line in ['[',']']: continue
            try: items.append(json.loads(line))
            except: pass

    # Group by domain — keep the entry with the most plugins
    # (https follow-up entries are richer than initial http redirects)
    best: dict = {}
    for item in items:
        target = item.get('target', {})
        uri = target.get('uri', '') if isinstance(target, dict) else str(target)
        if not uri: uri = item.get('url', item.get('uri', ''))
        domain = nd(uri)
        if not domain: continue
        n_plugins = len(item.get('plugins', {}))
        prev = best.get(domain)
        if prev is None or n_plugins > len(prev.get('plugins', {})):
            best[domain] = item

    for domain, item in best.items():
        plugins = item.get('plugins', {})
        cms, framework, language, cdn = [], [], [], []

        for pname, pdata in plugins.items():
            pl      = pname.lower()
            # Also try underscore-normalized form for matching
            pl_norm = pl.replace('.', '_').replace('-', '_')

            version = ''
            if isinstance(pdata, dict):
                for k in ('version', 'string', 'detected_version'):
                    v = pdata.get(k, [])
                    if isinstance(v, list) and v:
                        version = f' {v[0]}'; break
                    elif isinstance(v, str) and v:
                        version = f' {v}'; break

            # ── CMS ──────────────────────────────────────────────
            if pl in cms_idx or pl_norm in cms_idx:
                key = pl if pl in cms_idx else pl_norm
                cms.append(cms_idx[key] + version.strip())

            # ── Framework ────────────────────────────────────────
            elif pl in fw_idx or pl_norm in fw_idx:
                key = pl if pl in fw_idx else pl_norm
                framework.append(fw_idx[key])

            # ── Language ─────────────────────────────────────────
            elif pl in lang_idx or pl_norm in lang_idx:
                key = pl if pl in lang_idx else pl_norm
                language.append(lang_idx[key])

            # ── CDN / Load Balancer ───────────────────────────────
            elif pl in CDN_PLUGINS or pl_norm in CDN_PLUGINS:
                key = pl if pl in CDN_PLUGINS else pl_norm
                cdn.append(CDN_PLUGINS[key])

        # ── Fallback: F5 BIG-IP from HTTPServer header string ────
        http_srv = plugins.get('HTTPServer', {})
        if isinstance(http_srv, dict):
            for s in http_srv.get('string', []):
                if 'bigip' in str(s).lower() and 'F5 BIG-IP' not in cdn:
                    cdn.append('F5 BIG-IP')

        # ── Fallback: ASP.NET Core from cookie names ──────────────
        has_aspnet = any(f.startswith('ASP') for f in framework)
        if not has_aspnet:
            for cookie_key in ('Cookies', 'HttpOnly'):
                p = plugins.get(cookie_key, {})
                if isinstance(p, dict):
                    strings = p.get('string', [])
                    if isinstance(strings, list):
                        if any('AspNetCore' in s or '__RequestVerification' in s
                               for s in strings):
                            framework.append('ASP.NET Core')
                            break

        tech_map[domain] = {
            'cms':       ', '.join(dict.fromkeys(cms))       or '—',
            'framework': ', '.join(dict.fromkeys(framework)) or '—',
            'language':  ', '.join(dict.fromkeys(language))  or '—',
            'cdn':       ', '.join(dict.fromkeys(cdn))        or '—',  # ← NEW
        }

    print(f'    → WhatWeb data for {len(tech_map)} hosts')
    return tech_map

# ── testssl.sh parser ────────────────────────────────────────────
def parse_testssl(path):
    ssl_map, RANK = {}, {'TLS 1.3':5,'TLS 1.2':4,'TLS 1.1':3,'TLS 1.0':2,'SSLv3':1,'SSLv2':0}
    try:
        data = json.loads(Path(path).read_text())
        for host_data in data.get('scanResult', [data] if isinstance(data,dict) else data):
            target = nd(host_data.get('targetHost', host_data.get('ip', '')))
            if not target: continue
            best = None
            for f in host_data.get('findings', []):
                fid, res = f.get('id','').lower(), f.get('finding','').lower()
                offered = 'offered' in res and 'not offered' not in res
                tls = None
                if 'tls1_3' in fid and offered: tls = 'TLS 1.3'
                elif 'tls1_2' in fid and offered: tls = 'TLS 1.2'
                elif 'tls1_1' in fid and offered: tls = 'TLS 1.1'
                elif fid in ('tls1','tls1 ') and offered: tls = 'TLS 1.0'
                elif 'ssl3' in fid and offered: tls = 'SSLv3'
                if tls and (best is None or RANK.get(tls,0) > RANK.get(best,0)):
                    best = tls
            if best: ssl_map[target] = best
    except Exception as e:
        print(f'    [!] testssl parse warning: {e}')
    print(f'    → SSL/TLS data for {len(ssl_map)} hosts')
    return ssl_map

# ── Auto-notes generator ─────────────────────────────────────────
def auto_notes(row):
    notes  = []
    domain = row['domain'].lower()
    sub    = domain.split('.')[0]
    http   = row.get('http', '—')
    ssl    = row.get('ssl', '—')
    server = row.get('server', '—').lower()
    ports  = str(row.get('ports', '—'))

    try:
        n = int(http)
        if n == 403: notes.append('⚠️ 403 — check auth bypass')
        if n == 401: notes.append('⚠️ 401 Auth required')
        if n == 500: notes.append('⚠️ 500 Server error exposed')
    except: pass

    if ssl in ('TLS 1.0', 'TLS 1.1', 'SSLv3', 'SSLv2'):
        notes.append(f'⚠️ Weak TLS: {ssl}')

    admin_subs = {'admin','panel','manager','dashboard','backend','cms',
                  'portal','control','manage','phpmyadmin','cpanel','plesk'}
    dev_subs   = {'dev','stage','staging','test','uat','qa','preprod','sandbox'}
    if sub in admin_subs: notes.append('⚠️ Admin/panel endpoint')
    if sub in dev_subs:   notes.append('⚠️ Dev/staging environment')

    if re.search(r'php/[45]\.', server):    notes.append('⚠️ EOL PHP version in Server header')
    if re.search(r'apache/2\.2\.', server): notes.append('⚠️ Outdated Apache 2.2')
    if re.search(r'iis/[67]\.', server):    notes.append('⚠️ Outdated IIS version')
    if re.search(r'openssl/[01]\.', server):notes.append('⚠️ Outdated OpenSSL in Server header')

    port_list = re.findall(r'\d+', ports)
    for p, name in SENSITIVE_PORTS.items():
        if p in port_list: notes.append(f'⚠️ {name}:{p} exposed')

    return ' · '.join(notes)

# ── Main ─────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='Merge recon tools into unified JSON')
    p.add_argument('--httpx',    required=True, help='httpx JSONL file')
    p.add_argument('--waf',      help='wafw00f JSON file')
    p.add_argument('--whatweb',  help='whatweb JSON file')
    p.add_argument('--ssl',      help='testssl.sh merged JSON file')
    p.add_argument('-o','--output', default='unified_recon.json')
    args = p.parse_args()

    print(f'\n{"═"*50}')
    print('  recon_merge.py — Bug Bounty Tracker v3')
    print(f'{"═"*50}\n')

    print(f'[1/5] httpx → {args.httpx}')
    results = parse_httpx(args.httpx)

    for label, flag, parser, fields in [
        ('WAF',     args.waf,     parse_wafw00f, {'waf': None}),
        # ↓ FIXED: added 'cdn' so whatweb CDN merges into the row
        ('WhatWeb', args.whatweb, parse_whatweb, {'cms': None, 'framework': None,
                                                   'language': None, 'cdn': None}),
        ('SSL',     args.ssl,     parse_testssl, {'ssl': None}),
    ]:
        step = {'WAF':'2','WhatWeb':'3','SSL':'4'}[label]
        if flag and Path(flag).exists():
            print(f'[{step}/5] {label} → {flag}')
            data = parser(flag)
            for domain, val in data.items():
                if domain in results:
                    if isinstance(val, dict):
                        for k in fields:
                            new_val = val.get(k, '—')
                            # For CDN: merge httpx CDN + whatweb CDN, don't overwrite
                            if k == 'cdn' and new_val and new_val != '—':
                                existing = results[domain].get('cdn', '—')
                                if existing in ('—', '', 'CDN Detected'):
                                    results[domain]['cdn'] = new_val
                                else:
                                    # Merge and deduplicate
                                    parts = [p.strip() for p in existing.split(',')]
                                    for part in new_val.split(','):
                                        part = part.strip()
                                        if part and part not in parts:
                                            parts.append(part)
                                    results[domain]['cdn'] = ', '.join(parts)
                            else:
                                results[domain][k] = new_val
                    else:
                        key = list(fields.keys())[0]
                        results[domain][key] = val
                else:
                    # Host found by whatweb but not httpx — still add it
                    if isinstance(val, dict) and label == 'WhatWeb':
                        results[domain] = {
                            'domain':       domain,
                            'ip':           '—',
                            'status':       'Unknown',
                            'http':         '—',
                            'server':       '—',
                            'technologies': '—',
                            'cms':          val.get('cms', '—'),
                            'framework':    val.get('framework', '—'),
                            'language':     val.get('language', '—'),
                            'cdn':          val.get('cdn', '—'),
                            'waf':          '—',
                            'ssl':          '—',
                            'ports':        '—',
                            'scope':        'In Scope',
                            'notes':        ''
                        }
        else:
            print(f'[{step}/5] {label} — skipped (file not provided or not found)')

    print('[5/5] Generating auto-notes...')
    flagged = 0
    for row in results.values():
        if not row['notes']:
            row['notes'] = auto_notes(row)
        if row['notes']: flagged += 1
    print(f'    → {flagged} hosts auto-flagged')

    output = list(results.values())
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f'\n{"─"*50}')
    print(f'✅  {len(output)} hosts → {args.output}')
    print(f'⚠️   {flagged} auto-flags generated')
    print(f'\n→  Upload "{args.output}" to Bug Bounty Tracker')
    print(f'   Header → "⬆ Import Unified JSON" → select file')
    print(f'{"─"*50}\n')

if __name__ == '__main__':
    main()