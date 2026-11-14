#!/usr/bin/env python3
"""Fetch public proxy subscription sources, merge, dedupe, and write outputs.

Outputs (in repo root):
  merged.txt         - one proxy link per line
  merged_base64.txt  - base64 subscription (V2RayNG / Shadowrocket / Streisand ...)
  merged_clash.yaml  - Clash / Clash Meta config
  stats.json         - per-source counts
"""
import asyncio
import base64
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse, parse_qsl, urlencode

ROOT = Path(__file__).resolve().parent
SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
           "socks://", "socks5://", "hysteria2://", "hysteria://",
           "tuic://", "wireguard://", "snell://")
HEADERS = {"User-Agent": "Mozilla/5.0 proxy-aggregator"}


def fetch(url: str, timeout: int = 60) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def b64decode_loose(s: str) -> bytes:
    s = re.sub(r"\s+", "", s.strip())
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def extract_links(text: str):
    links = [ln.strip() for ln in text.splitlines()
             if ln.strip().startswith(SCHEMES)]
    if links:
        return links
    try:
        decoded = b64decode_loose(text).decode("utf-8", "replace")
    except Exception:
        return links
    return [ln.strip() for ln in decoded.splitlines()
            if ln.strip().startswith(SCHEMES)]


def dedupe_key(link: str) -> str:
    body = link.split("#", 1)[0].strip()
    if body.startswith("vmess://"):
        try:
            j = json.loads(b64decode_loose(body[8:]).decode("utf-8", "replace"))
            return "vmess|" + str(j.get("add")) + "|" + str(j.get("port")) + "|" + str(j.get("id"))
        except Exception:
            pass
    return body


def clash_to_uri(p: dict):
    t = p.get("type")
    name = quote(str(p.get("name", "node")), safe="")
    server, port = p.get("server"), p.get("port")
    if not server or not port:
        return None
    if t == "ss":
        userinfo = f"{p.get('cipher')}:{p.get('password')}"
        b64 = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
        link = f"ss://{b64}@{server}:{port}"
        plugin = p.get("plugin")
        if plugin == "obfs":
            opts = p.get("plugin-opts", {})
            q = {"plugin": f"simple-obfs;obfs={opts.get('mode')};obfs-host={opts.get('host')}"}
            link += "?" + urlencode(q)
        elif plugin == "v2ray-plugin":
            opts = p.get("plugin-opts", {})
            q = {"plugin": f"v2ray-plugin;tls={opts.get('tls')};host={opts.get('host')};path={opts.get('path')}"}
            link += "?" + urlencode(q)
        return link + "#" + name
    if t == "vmess":
        j = {"v": "2", "ps": p.get("name", ""), "add": server, "port": str(port),
             "id": p.get("uuid"), "aid": str(p.get("alterId", 0)),
             "net": p.get("network", "tcp"), "type": "none",
             "host": "", "path": "", "tls": "tls" if p.get("tls") else ""}
        ws = p.get("ws-opts", {}) or {}
        j["path"] = ws.get("path", "")
        j["host"] = ws.get("headers", {}).get("Host", "")
        if p.get("network") == "ws":
            j["type"] = "ws"
        return "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()
    if t == "vless":
        q = {"encryption": "none", "security": "tls" if p.get("tls") else "none",
             "type": p.get("network", "tcp")}
        if p.get("tls"):
            q["sni"] = p.get("servername", server)
        if p.get("network") == "ws":
            ws = p.get("ws-opts", {}) or {}
            q["path"] = ws.get("path", "")
            q["host"] = ws.get("headers", {}).get("Host", "")
        if p.get("flow"):
            q["flow"] = p["flow"]
        return f"vless://{p.get('uuid')}@{server}:{port}?" + urlencode(q) + "#" + name
    if t == "trojan":
        q = {"security": "tls", "sni": p.get("sni", server), "type": p.get("network", "tcp")}
        return f"trojan://{p.get('password')}@{server}:{port}?" + urlencode(q) + "#" + name
    if t == "socks5":
        auth = ""
        if p.get("username"):
            auth = f"{p.get('username')}:{p.get('password')}@"
        return f"socks5://{auth}{server}:{port}#" + name
    if t == "hysteria2":
        q = {"sni": p.get("sni", server)}
        if p.get("password"):
            return f"hysteria2://{p.get('password')}@{server}:{port}?" + urlencode(q) + "#" + name
        return None
    return None


def uri_to_clash(link: str):
    """Convert a URI link back to a Clash proxy dict. None if unsupported."""
    scheme = link.split("://", 1)[0]
    try:
        if scheme == "ss":
            body = link[5:].split("#", 1)[0]
            name = urllib.parse.unquote(link.split("#", 1)[1]) if "#" in link else "ss"
            if "@" in body:
                b64part, hostport = body.rsplit("@", 1)
                try:
                    method, password = b64decode_loose(b64part).decode().split(":", 1)
                except Exception:
                    method, password = urllib.parse.unquote(b64part).split(":", 1)
                host, port = hostport.rsplit(":", 1)
            else:
                m = re.match(r"(.+?):(.*)@(.+):(\d+)", b64decode_loose(body).decode())
                if not m:
                    return None
                method, password, host, port = m.group(1), m.group(2), m.group(3), m.group(4)
            return {"name": name, "type": "ss", "server": host, "port": int(port),
                    "cipher": method, "password": password}
        if scheme == "vmess":
            j = json.loads(b64decode_loose(link[8:].split("#", 1)[0]).decode())
            p = {"name": j.get("ps", "vmess"), "type": "vmess", "server": j.get("add"),
                 "port": int(j.get("port", 0)), "uuid": j.get("id"),
                 "alterId": int(j.get("aid", 0)), "cipher": j.get("scy", "auto")}
            if j.get("tls") == "tls":
                p["tls"] = True
                if j.get("sni"):
                    p["servername"] = j["sni"]
            net = j.get("net", "tcp")
            p["network"] = net
            if net == "ws":
                p["ws-opts"] = {"path": j.get("path", "/")}
                if j.get("host"):
                    p["ws-opts"]["headers"] = {"Host": j["host"]}
            return p
        if scheme in ("vless", "trojan", "socks5", "socks", "hysteria2"):
            u = urlparse(link)
            name = urllib.parse.unquote(u.fragment) or scheme
            q = dict(parse_qsl(u.query))
            if not u.hostname or not u.port:
                return None
            if scheme == "vless":
                p = {"name": name, "type": "vless", "server": u.hostname, "port": u.port,
                     "uuid": u.username, "encryption": "none"}
                if q.get("security") == "tls":
                    p["tls"] = True
                    if q.get("sni"):
                        p["servername"] = q["sni"]
                if q.get("flow"):
                    p["flow"] = q["flow"]
                if q.get("type") == "ws":
                    p["network"] = "ws"
                    p["ws-opts"] = {"path": q.get("path", "/")}
                    if q.get("host"):
                        p["ws-opts"]["headers"] = {"Host": q["host"]}
                return p
            if scheme == "trojan":
                p = {"name": name, "type": "trojan", "server": u.hostname, "port": u.port,
                     "password": u.username}
                if q.get("sni"):
                    p["sni"] = q["sni"]
                return p
            if scheme in ("socks5", "socks"):
                p = {"name": name, "type": "socks5", "server": u.hostname, "port": u.port}
                if u.username:
                    p["username"] = urllib.parse.unquote(u.username)
                    p["password"] = urllib.parse.unquote(u.password or "")
                return p
            if scheme == "hysteria2":
                p = {"name": name, "type": "hysteria2", "server": u.hostname, "port": u.port,
                     "password": u.username}
                if q.get("sni"):
                    p["sni"] = q["sni"]
                return p
    except Exception:
        return None
    return None


TCP_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
               "socks://", "socks5://")
UDP_SCHEMES = ("hysteria://", "hysteria2://", "tuic://")


def node_host_port(link: str):
    scheme = link.split("://", 1)[0]
    try:
        if scheme == "vmess":
            j = json.loads(b64decode_loose(link[8:].split("#", 1)[0]).decode())
            return j.get("add"), int(j.get("port", 0))
        if scheme == "ss":
            body = link[5:].split("#", 1)[0]
            if "@" in body:
                hostport = body.rsplit("@", 1)[1]
            else:
                m = re.match(r"(.+?):(.*)@(.+):(\d+)", b64decode_loose(body).decode())
                if not m:
                    return None, None
                return m.group(3), int(m.group(4))
            host, port = hostport.rsplit(":", 1)
            return host, int(port)
        u = urlparse(link)
        if not u.hostname or not u.port:
            return None, None
        return u.hostname, u.port
    except Exception:
        return None, None


async def _probe(host, port, timeout, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


def filter_reachable(links, timeout=5.0):
    """Drop TCP-protocol nodes whose server:port refuses a TCP connect
    within `timeout` seconds. UDP-only protocols (hysteria/hysteria2/tuic)
    cannot be probed this way and are kept. Returns (kept, info)."""
    async def run():
        sem = asyncio.Semaphore(100)
        checks = []
        for i, link in enumerate(links):
            scheme = link.split("://", 1)[0] + "://"
            if scheme in UDP_SCHEMES:
                checks.append((i, "udp"))
            elif scheme in TCP_SCHEMES:
                host, port = node_host_port(link)
                if not host or not port:
                    checks.append((i, "unparsable"))
                else:
                    checks.append((i, ("probe", host, port)))
            else:
                checks.append((i, "unparsable"))
        results = {}
        for i, kind in checks:
            if isinstance(kind, tuple):
                _, host, port = kind
                results[i] = await _probe(host, port, timeout, sem)
        return checks, results
    checks, results = asyncio.run(run())
    kept, info = [], {"kept": 0, "dead": 0, "udp_kept": 0, "unparsable": 0}
    for i, kind in checks:
        if kind == "udp":
            kept.append(links[i])
            info["udp_kept"] += 1
        elif kind == "unparsable":
            info["unparsable"] += 1
        elif results.get(i):
            kept.append(links[i])
            info["kept"] += 1
        else:
            info["dead"] += 1
    info["kept"] += info["udp_kept"]
    return kept, info


def main():
    import yaml
    sources = [ln.strip() for ln in (ROOT / "sources.txt").read_text().splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    all_links, stats = [], {}
    for url in sources:
        label = url.split("github.com/")[1].split("/raw/")[0] if "github.com" in url else url
        try:
            text = fetch(url)
        except Exception as e:
            stats[label] = f"fetch failed: {e}"
            continue
        if url.endswith((".yaml", ".yml")):
            try:
                data = yaml.safe_load(text)
                proxies = data.get("proxies", []) if isinstance(data, dict) else []
            except Exception:
                proxies = []
            converted, skipped = [], 0
            for p in proxies:
                uri = clash_to_uri(p)
                if uri:
                    converted.append(uri)
                else:
                    skipped += 1
            stats[label] = len(converted)
            stats[label + " (skipped)"] = skipped
            all_links.extend(converted)
        else:
            links = extract_links(text)
            stats[label] = len(links)
            all_links.extend(links)
    seen, unique = set(), []
    for link in all_links:
        k = dedupe_key(link)
        if k in seen:
            continue
        seen.add(k)
        unique.append(link)
    unique, reach = filter_reachable(unique)
    stats["reachable"] = reach["kept"]
    stats["filtered_unreachable"] = reach["dead"]
    stats["udp_kept_unfiltered"] = reach["udp_kept"]
    stats["unparsable_removed"] = reach["unparsable"]
    plain = "\n".join(unique) + "\n"
    (ROOT / "merged.txt").write_text(plain)
    (ROOT / "merged_base64.txt").write_text(base64.b64encode(plain.encode()).decode())
    proxies, seen_names, skipped = [], {}, 0
    for link in unique:
        p = uri_to_clash(link)
        if not p:
            skipped += 1
            continue
        base = p["name"]
        n = seen_names.get(base, 0)
        seen_names[base] = n + 1
        if n:
            p["name"] = f"{base}-{n}"
        proxies.append(p)
    names = [p["name"] for p in proxies]
    cfg = {"port": 7890, "socks-port": 7891, "allow-lan": False, "mode": "rule",
           "log-level": "info", "external-controller": "127.0.0.1:9090",
           "proxies": proxies,
           "proxy-groups": [
               {"name": "PROXY", "type": "select", "proxies": names},
               {"name": "Auto", "type": "url-test", "proxies": names,
                "url": "http://www.gstatic.com/generate_204", "interval": 300}],
           "rules": ["MATCH,PROXY"]}
    with open(ROOT / "merged_clash.yaml", "w") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    stats["total_raw"] = len(all_links)
    stats["unique"] = len(unique)
    stats["clash_proxies"] = len(proxies)
    stats["clash_skipped"] = skipped
    (ROOT / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2))
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
