# Proxy Subscription Aggregator

Aggregates several public proxy subscription sources into one subscription,
deduplicated. A GitHub Action re-runs the merge every 6 hours, so the links
below always serve the latest nodes.

## Subscribe

Replace `<user>/<repo>` with this repository's path.

- **V2Ray / Shadowrocket / Streisand / V2RayNG** (base64 subscription):

  ```
  https://raw.githubusercontent.com/<user>/<repo>/main/merged_base64.txt
  ```

- **Clash / Clash Meta** (full config):

  ```
  https://raw.githubusercontent.com/<user>/<repo>/main/merged_clash.yaml
  ```

- **Plain link list**: `merged.txt`

## Sources

See [sources.txt](sources.txt). Add or remove a URL there (one per line) and
the next scheduled run picks it up. Plain `vmess://` / `vless://` / `ss://`
lists, base64 subscriptions, and Clash YAML proxy lists are all accepted.

## Notes

- These are public free nodes: unstable, and the operator can see your
  traffic. Don't log in to important accounts through them.
- Last merge stats: see [stats.json](stats.json).
