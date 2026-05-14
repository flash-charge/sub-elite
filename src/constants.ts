export const sampleLinks = [
  'vmess://eyJwcyI6IkNvbnRvaCBWTWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii9wYXRoIn0=',
  'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&host=example.com&path=%2Fpath&sni=example.com#Sample%20VLESS',
  'trojan://password@example.com:443?sni=example.com#Sample%20Trojan',
].join('\n')
export const MAX_IMPORT_FILE_BYTES = 1024 * 1024
export const importFilePattern = /\.(txt|conf|list|log|ya?ml)$/i

export const networkOptions = [
  { value: '', label: 'Default (no network)' },
  { value: 'http', label: 'HTTP' },
  { value: 'h2', label: 'H2' },
  { value: 'grpc', label: 'gRPC' },
  { value: 'ws', label: 'WS' },
  { value: 'xhttp', label: 'XHTTP (VLESS)' },
]

export const networkSupportByType = {
  vmess: ['ws', 'http', 'h2', 'grpc'],
  vless: ['ws', 'http', 'h2', 'grpc', 'xhttp'],
  trojan: ['ws', 'grpc'],
}

export const alpnOptions = ['http/1.1', 'h2', 'h3']

export const clientFingerprintOptions = [
  '',
  'chrome',
  'firefox',
  'safari',
  'iOS',
  'android',
  'edge',
  '360',
  'qq',
  'random',
]

export const vmessCipherOptions = [
  'auto',
  'none',
  'zero',
  'aes-128-gcm',
  'chacha20-poly1305',
]

export const vlessFlowOptions = [
  '',
  'xtls-rprx-vision',
]

export const packetEncodingOptions = [
  '',
  'packetaddr',
  'xudp',
]

export const ipVersionOptions = [
  '',
  'dual',
  'ipv4',
  'ipv6',
  'ipv4-prefer',
  'ipv6-prefer',
]

export const trojanSsMethodOptions = [
  '',
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
]

export const tlsCapabilityByType = {
  vmess: {
    toggle: true,
    fields: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  },
  vless: {
    toggle: true,
    fields: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  },
  trojan: {
    toggle: true,
    fields: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  },
  anytls: {
    toggle: false,
    fields: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify'],
  },
  hysteria: {
    toggle: false,
    fields: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  },
  hysteria2: {
    toggle: false,
    fields: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  },
  tuic: {
    toggle: false,
    fields: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  },
  socks5: {
    toggle: true,
    fields: ['sni', 'skip-cert-verify'],
  },
  http: {
    toggle: true,
    fields: ['sni', 'skip-cert-verify'],
  },
}

export const ssrCipherOptions = [
  'chacha20-ietf',
  'aes-128-cfb',
  'aes-192-cfb',
  'aes-256-cfb',
  'aes-128-ctr',
  'aes-192-ctr',
  'aes-256-ctr',
  'bf-cfb',
  'camellia-128-cfb',
  'camellia-192-cfb',
  'camellia-256-cfb',
  'cast5-cfb',
  'chacha20',
  'rc4-md5',
  'salsa20',
  'seed-cfb',
  'table',
]

export const ssrProtocolOptions = [
  'auth_sha1_v4',
  'origin',
  'verify_sha1',
  'auth_aes128_md5',
  'auth_aes128_sha1',
  'auth_chain_a',
  'auth_chain_b',
]

export const ssrObfsOptions = [
  'tls1.2_ticket_auth',
  'plain',
  'http_simple',
  'http_post',
  'random_head',
  'tls1.2_ticket_fastauth',
]

export const hysteriaProtocolOptions = ['udp', 'wechat-video', 'faketcp']
export const tuicUdpRelayModeOptions = ['', 'native', 'quic']
export const tuicCongestionControllerOptions = ['', 'bbr', 'cubic', 'new_reno']
export const mieruTransportOptions = ['TCP', 'UDP']
export const httpMethodOptions = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']

export const shadowsocksCipherOptions = [
  'aes-128-ctr',
  'aes-192-ctr',
  'aes-256-ctr',
  'aes-128-cfb',
  'aes-192-cfb',
  'aes-256-cfb',
  'aes-128-gcm',
  'aes-192-gcm',
  'aes-256-gcm',
  'aes-128-ccm',
  'aes-192-ccm',
  'aes-256-ccm',
  'aes-128-gcm-siv',
  'aes-256-gcm-siv',
  'chacha20-ietf',
  'chacha20',
  'xchacha20',
  'chacha20-ietf-poly1305',
  'xchacha20-ietf-poly1305',
  'chacha8-ietf-poly1305',
  'xchacha8-ietf-poly1305',
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
  'lea-128-gcm',
  'lea-192-gcm',
  'lea-256-gcm',
  'rabbit128-poly1305',
  'aegis-128l',
  'aegis-256',
  'aez-384',
  'deoxys-ii-256-128',
  'rc4-md5',
  'none',
]

export const shadowsocksPluginOptions = [
  '',
  'obfs',
  'v2ray-plugin',
  'gost-plugin',
  'shadow-tls',
  'restls',
  'kcptun',
]

export const shadowsocksPluginOptExamples = {
  obfs: 'mode=tls\nhost=bing.com',
  'v2ray-plugin': 'mode=websocket\ntls=true\nhost=bing.com\npath=/\nmux=true\nv2ray-http-upgrade=false',
  'gost-plugin': 'mode=websocket\ntls=true\nhost=bing.com\npath=/\nmux=true',
  'shadow-tls': 'host=cloud.tencent.com\npassword=shadow_tls_password\nversion=2',
  restls: 'host=www.microsoft.com\npassword=YOUR_RESTLS_PASSWORD\nversion-hint=tls13\nrestls-script=300?100<1,400~100',
  kcptun: 'key=kcptun-secret\ncrypt=aes\nmode=fast\nconn=1\nautoexpire=0\nscavengettl=600\nmtu=1350\nnocomp=false',
}

export const proxyTypeOptions = [
  'vless',
  'vmess',
  'trojan',
  'ss',
  'ssr',
  'snell',
  'anytls',
  'mieru',
  'sudoku',
  'hysteria',
  'hysteria2',
  'tuic',
  'masque',
  'trusttunnel',
  'socks5',
  'http',
  'wireguard',
  'ssh',
  'direct',
  'dns',
]

export const providerTypes = ['http', 'file', 'inline']

export const proxyTypeLabels = {
  vmess: 'VMess',
  vless: 'VLESS',
  ss: 'Shadowsocks',
  ssr: 'ShadowsocksR',
  anytls: 'AnyTLS',
  hysteria2: 'Hysteria2',
  tuic: 'TUIC',
  socks5: 'SOCKS5',
  http: 'HTTP',
  wireguard: 'WireGuard',
  ssh: 'SSH',
  dns: 'DNS',
  direct: 'DIRECT',
}
