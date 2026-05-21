# MetaCubeX Wiki Compliance Notes

Last reviewed: 2026-05-21

This project targets Mihomo/Clash Meta configuration generated from the
MetaCubeX wiki:

- https://wiki.metacubex.one/en/
- https://wiki.metacubex.one/en/config/proxies/
- https://wiki.metacubex.one/en/config/proxy-providers/
- https://wiki.metacubex.one/en/config/proxy-groups/
- https://wiki.metacubex.one/en/config/rules/

## Covered

- Core sections: `proxies`, `proxy-groups`, `rules`, `proxy-providers`,
  `rule-providers`, `dns`, `sniffer`, `tun`, `ntp`, `listeners`, `sub-rules`,
  `tunnels`, and `experimental`.
- Common proxy types: `vless`, `vmess`, `trojan`, `ss`, `ssr`, `socks5`,
  `http`, `hysteria`, `hysteria2`, `tuic`, `wireguard`, `ssh`, `direct`, and
  `dns`.
- Manual-only proxy types from the wiki: `snell`, `anytls`, `mieru`, `sudoku`,
  `masque`, `trusttunnel`, `tailscale`, and `openvpn`.
- Transport options for supported VMess/VLESS/Trojan transports:
  `ws`, `http`, `h2`, `grpc`, and VLESS `xhttp`.
- Provider, group, and rule reference validation, including missing references
  and cycle checks.

## Partially Covered

- Some advanced fields are preserved through raw YAML, raw JSON, or extra-field
  passthrough even when no dedicated UI control exists.
- `mihomo:check` validates generated YAML with a local Mihomo binary, but it is
  not part of the default build because CI/hosting environments may not have
  Mihomo installed.

## Follow-Up Audit Targets

- Compare each listener page against the visual editor controls.
- Expand UI controls for advanced per-protocol fields that are currently only
  preserved through passthrough.
- Periodically re-run this checklist because the wiki pages are actively
  updated.
