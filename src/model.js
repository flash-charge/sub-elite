import { providerTypes } from './constants.js'
import { compactObject, isPlainObject, normalizeBooleanValue, normalizeClientProxyNode, splitLines, splitLinesOrComma, splitRuleParts } from './utils.js'

export function modelFromYamlObject(raw, { template = '', rulesPreset = '' } = {}) {
  const knownKeys = new Set([
    'port',
    'socks-port',
    'redir-port',
    'tproxy-port',
    'mixed-port',
    'authentication',
    'allow-lan',
    'lan-allowed-ips',
    'lan-disallowed-ips',
    'mode',
    'log-level',
    'ipv6',
    'keep-alive-idle',
    'keep-alive-interval',
    'disable-keep-alive',
    'find-process-mode',
    'bind-address',
    'interface-name',
    'routing-mark',
    'unified-delay',
    'tcp-concurrent',
    'external-controller',
    'external-controller-tls',
    'external-controller-unix',
    'external-controller-pipe',
    'external-controller-cors',
    'external-ui',
    'external-ui-name',
    'external-ui-url',
    'secret',
    'global-client-fingerprint',
    'global-ua',
    'etag-support',
    'skip-auth-prefixes',
    'tls',
    'profile',
    'geodata-mode',
    'geo-auto-update',
    'geo-update-interval',
    'geox-url',
    'dns',
    'sniffer',
    'tun',
    'ntp',
    'experimental',
    'proxies',
    'proxy-groups',
    'proxy-providers',
    'listeners',
    'rule-providers',
    'sub-rules',
    'tunnels',
    'rules',
  ])
  const groups = Array.isArray(raw['proxy-groups']) ? raw['proxy-groups'].filter(isPlainObject).map(yamlGroupToModel) : []
  return {
    template: template,
    rulesPreset: rulesPreset,
    general: yamlGeneralToModel(raw),
    profile: raw.profile || {},
    dns: yamlDnsToModel(raw.dns || {}),
    sniffer: yamlSnifferToModel(raw.sniffer || {}),
    tun: yamlTunToModel(raw.tun || {}),
    ntp: yamlNtpToModel(raw.ntp || {}),
    geo: yamlGeoToModel(raw),
    ruleProviders: yamlNamedMapToList(raw['rule-providers']),
    proxyProviders: yamlNamedMapToList(raw['proxy-providers']),
    listeners: Array.isArray(raw.listeners) ? raw.listeners.filter(isPlainObject) : [],
    subRules: isPlainObject(raw['sub-rules']) ? raw['sub-rules'] : {},
    tunnels: Array.isArray(raw.tunnels) ? raw.tunnels.filter(isPlainObject) : [],
    extraTopLevel: Object.fromEntries(Object.entries(raw).filter(([key]) => !knownKeys.has(key))),
    rawSections: rawSectionsFromYaml(raw),
    proxies: Array.isArray(raw.proxies) ? raw.proxies.filter(isPlainObject).map((proxy) => ({ ...proxy, enabled: true })) : [],
    groups: groups.length ? groups : [{ name: 'PROXY', type: 'select', proxies: ['DIRECT'], use: [] }],
    rules: Array.isArray(raw.rules) ? raw.rules : ['MATCH,PROXY'],
  }
}

export function yamlGeneralToModel(raw) {
  return {
    port: raw.port,
    socksPort: raw['socks-port'],
    redirPort: raw['redir-port'],
    tproxyPort: raw['tproxy-port'],
    mixedPort: raw['mixed-port'],
    allowLan: raw['allow-lan'],
    bindAddress: raw['bind-address'],
    lanAllowedIps: raw['lan-allowed-ips'],
    lanDisallowedIps: raw['lan-disallowed-ips'],
    authentication: raw.authentication,
    skipAuthPrefixes: raw['skip-auth-prefixes'],
    interfaceName: raw['interface-name'],
    routingMark: raw['routing-mark'],
    mode: raw.mode,
    logLevel: raw['log-level'],
    ipv6: raw.ipv6,
    keepAliveIdle: raw['keep-alive-idle'],
    keepAliveInterval: raw['keep-alive-interval'],
    disableKeepAlive: raw['disable-keep-alive'],
    findProcessMode: raw['find-process-mode'],
    unifiedDelay: raw['unified-delay'],
    tcpConcurrent: raw['tcp-concurrent'],
    externalController: raw['external-controller'],
    externalControllerTls: raw['external-controller-tls'],
    externalControllerUnix: raw['external-controller-unix'],
    externalControllerPipe: raw['external-controller-pipe'],
    externalControllerCors: raw['external-controller-cors'],
    externalUi: raw['external-ui'],
    externalUiName: raw['external-ui-name'],
    externalUiUrl: raw['external-ui-url'],
    secret: raw.secret,
    globalClientFingerprint: raw['global-client-fingerprint'],
    globalUa: raw['global-ua'],
    etagSupport: raw['etag-support'],
    tlsCertificate: raw.tls?.certificate,
    tlsPrivateKey: raw.tls?.['private-key'],
    tlsCustom: raw.tls && typeof raw.tls === 'object' ? Object.fromEntries(Object.entries(raw.tls).filter(([key]) => !['certificate', 'private-key'].includes(key))) : {},
  }
}

export function yamlDnsToModel(dns) {
  return {
    ...omitKeys(dns, dnsFieldKeys),
    enable: dns.enable,
    listen: dns.listen,
    ipv6: dns.ipv6,
    cacheAlgorithm: dns['cache-algorithm'],
    preferH3: dns['prefer-h3'],
    useHosts: dns['use-hosts'],
    useSystemHosts: dns['use-system-hosts'],
    respectRules: dns['respect-rules'],
    enhancedMode: dns['enhanced-mode'],
    fakeIpRange: dns['fake-ip-range'],
    fakeIpRange6: dns['fake-ip-range6'],
    fakeIpFilterMode: dns['fake-ip-filter-mode'],
    fakeIpTtl: dns['fake-ip-ttl'],
    fakeIpFilter: dns['fake-ip-filter'],
    defaultNameserver: dns['default-nameserver'],
    nameserver: dns.nameserver,
    fallback: dns.fallback,
    fallbackFilter: dns['fallback-filter'],
    directNameserver: dns['direct-nameserver'],
    directNameserverFollowPolicy: dns['direct-nameserver-follow-policy'],
    proxyServerNameserver: dns['proxy-server-nameserver'],
    proxyServerNameserverPolicy: dns['proxy-server-nameserver-policy'],
    nameserverPolicy: dns['nameserver-policy'],
  }
}

export function yamlSnifferToModel(sniffer) {
  return {
    ...omitKeys(sniffer, snifferFieldKeys),
    enable: sniffer.enable,
    overrideDestination: sniffer['override-destination'],
    parsePureIp: sniffer['parse-pure-ip'],
    forceDnsMapping: sniffer['force-dns-mapping'],
    sniff: normalizeSniffForText(sniffer.sniff),
    forceDomain: sniffer['force-domain'],
    skipDomain: sniffer['skip-domain'],
    skipSrcAddress: sniffer['skip-src-address'],
    skipDstAddress: sniffer['skip-dst-address'],
  }
}

export function yamlTunToModel(tun) {
  return {
    ...omitKeys(tun, tunFieldKeys),
    enable: tun.enable,
    stack: tun.stack,
    device: tun.device,
    autoRoute: tun['auto-route'],
    autoRedirect: tun['auto-redirect'],
    autoDetectInterface: tun['auto-detect-interface'],
    strictRoute: tun['strict-route'],
    dnsHijack: tun['dns-hijack'],
    mtu: tun.mtu,
    gso: tun.gso,
    gsoMaxSize: tun['gso-max-size'],
    udpTimeout: tun['udp-timeout'],
    iproute2TableIndex: tun['iproute2-table-index'],
    iproute2RuleIndex: tun['iproute2-rule-index'],
    endpointIndependentNat: tun['endpoint-independent-nat'],
    routeAddressSet: tun['route-address-set'],
    routeExcludeAddressSet: tun['route-exclude-address-set'],
    routeAddress: tun['route-address'],
    routeExcludeAddress: tun['route-exclude-address'],
    includeInterface: tun['include-interface'],
    excludeInterface: tun['exclude-interface'],
    includeUid: tun['include-uid'],
    includeUidRange: tun['include-uid-range'],
    excludeUid: tun['exclude-uid'],
    excludeUidRange: tun['exclude-uid-range'],
    includeAndroidUser: tun['include-android-user'],
    includePackage: tun['include-package'],
    excludePackage: tun['exclude-package'],
  }
}

export function yamlNtpToModel(ntp) {
  return {
    ...omitKeys(ntp, ntpFieldKeys),
    enable: ntp.enable,
    writeToSystem: ntp['write-to-system'],
    server: ntp.server,
    port: ntp.port,
    interval: ntp.interval,
  }
}

export function rawSectionsFromYaml(raw) {
  return compactObject({
    general: pickGeneralTopLevel(raw),
    dns: isPlainObject(raw.dns) ? raw.dns : undefined,
    sniffer: isPlainObject(raw.sniffer) ? raw.sniffer : undefined,
    tun: isPlainObject(raw.tun) ? raw.tun : undefined,
    ntp: isPlainObject(raw.ntp) ? raw.ntp : undefined,
  })
}

export function pickGeneralTopLevel(raw) {
  const keys = [
    'port',
    'socks-port',
    'redir-port',
    'tproxy-port',
    'mixed-port',
    'authentication',
    'allow-lan',
    'bind-address',
    'lan-allowed-ips',
    'lan-disallowed-ips',
    'mode',
    'log-level',
    'ipv6',
    'keep-alive-idle',
    'keep-alive-interval',
    'disable-keep-alive',
    'find-process-mode',
    'external-controller',
    'external-controller-tls',
    'external-controller-unix',
    'external-controller-pipe',
    'external-controller-cors',
    'external-ui',
    'external-ui-name',
    'external-ui-url',
    'secret',
    'global-client-fingerprint',
    'global-ua',
    'unified-delay',
    'tcp-concurrent',
    'interface-name',
    'routing-mark',
    'etag-support',
    'skip-auth-prefixes',
    'tls',
  ]
  const picked = Object.fromEntries(keys.filter((key) => Object.hasOwn(raw, key)).map((key) => [key, raw[key]]))
  return Object.keys(picked).length ? picked : undefined
}

export function yamlGeoToModel(raw) {
  return {
    ...omitKeys(raw, geoFieldKeys),
    geodataMode: raw['geodata-mode'],
    geoAutoUpdate: raw['geo-auto-update'],
    geoUpdateInterval: raw['geo-update-interval'],
    geoxUrl: raw['geox-url'],
  }
}

export function yamlGroupToModel(group) {
  return {
    ...group,
    includeAll: group['include-all'],
    includeAllProxies: group['include-all-proxies'],
    includeAllProviders: group['include-all-providers'],
    maxFailedTimes: group['max-failed-times'],
    disableUdp: group['disable-udp'],
    interfaceName: group['interface-name'],
    routingMark: group['routing-mark'],
    excludeFilter: group['exclude-filter'],
    excludeType: group['exclude-type'],
    expectedStatus: group['expected-status'],
    proxies: Array.isArray(group.proxies) ? group.proxies : [],
    use: Array.isArray(group.use) ? group.use : [],
  }
}

export function yamlNamedMapToList(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  return Object.entries(value).map(([name, item]) => ({ name, ...(item && typeof item === 'object' ? item : {}) }))
}

export function normalizePortsForText(value) {
  if (Array.isArray(value)) return value.map((item) => String(item))
  if (value === undefined || value === null) return []
  return [String(value)]
}

export function normalizeTextList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return splitLinesOrComma(value)
  return fallback
}

export function normalizeLineList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return splitLines(value)
  return fallback
}

export function normalizeRuleList(value, fallback) {
  return normalizeLineList(value, fallback).map(normalizeRuleLine).filter(Boolean)
}

export function normalizeRuleLine(rule) {
  return splitRuleParts(rule).filter((part) => part !== '').join(',')
}

export function normalizeSubRuleMap(value) {
  if (!isPlainObject(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, rules]) => [String(key).trim(), normalizeRuleList(rules, [])])
      .filter(([key, rules]) => key && rules.length),
  )
}

export function normalizeProxyProviderPayload(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => (isPlainObject(item) ? normalizeClientProxyNode(item) : String(item).trim()))
      .filter((item) => isPlainObject(item) || item)
  }
  if (typeof value === 'string') return splitLines(value)
  return []
}

export function omitKeys(value = {}, keys = []) {
  const omitted = new Set(keys)
  return Object.fromEntries(Object.entries(value || {}).filter(([key]) => !omitted.has(key)))
}

export function normalizeClientRuleProvider(provider) {
  const providerType = String(provider.type || '').trim()
  const behavior = String(provider.behavior || 'classical').trim().toLowerCase()
  const normalizedBehavior = ['classical', 'domain', 'ipcidr'].includes(behavior) ? behavior : 'classical'
  const format = String(provider.format || '').trim().toLowerCase()
  const rest = { ...provider }
  delete rest['size-limit']
  return {
    ...rest,
    name: String(provider.name || '').trim(),
    type: providerTypes.includes(providerType) ? providerType : 'http',
    behavior: normalizedBehavior,
    path: String(provider.path || '').trim(),
    url: String(provider.url || '').trim(),
    target: String(provider.target || 'PROXY').trim(),
    interval: Number(provider.interval) || 86400,
    proxy: String(provider.proxy || '').trim(),
    format: ['yaml', 'text', 'mrs'].includes(format) ? format : '',
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: isPlainObject(provider.header) ? provider.header : {},
    payload: normalizeRuleProviderPayload(provider.payload, normalizedBehavior),
  }
}

export function normalizeRuleProviderPayload(payload, behavior = 'classical') {
  return behavior === 'classical'
    ? normalizeRuleList(payload, [])
    : normalizeLineList(payload, [])
}

export function normalizeClientProxyProvider(provider) {
  const providerType = String(provider.type || '').trim()
  const healthCheck = isPlainObject(provider.healthCheck) ? provider.healthCheck : {}
  const rawHealthCheck = isPlainObject(provider['health-check']) ? provider['health-check'] : {}
  const rest = { ...provider }
  delete rest['health-check']
  delete rest['size-limit']
  delete rest['exclude-filter']
  delete rest['exclude-type']
  return {
    ...rest,
    name: String(provider.name || '').trim(),
    type: providerTypes.includes(providerType) ? providerType : 'http',
    url: String(provider.url || '').trim(),
    path: String(provider.path || '').trim(),
    interval: Number(provider.interval) || 3600,
    proxy: String(provider.proxy || '').trim(),
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: isPlainObject(provider.header) ? provider.header : {},
    healthCheck: {
      enable: normalizeBooleanValue(healthCheck.enable ?? rawHealthCheck.enable),
      url: String(healthCheck.url || rawHealthCheck.url || 'https://www.gstatic.com/generate_204').trim(),
      interval: Number(healthCheck.interval || rawHealthCheck.interval) || 300,
      timeout: Number(healthCheck.timeout || rawHealthCheck.timeout) || 5000,
      lazy: normalizeBooleanValue(healthCheck.lazy ?? rawHealthCheck.lazy, true),
      expectedStatus: String(healthCheck.expectedStatus || rawHealthCheck['expected-status'] || '').trim(),
    },
    override: isPlainObject(provider.override) ? provider.override : {},
    filter: String(provider.filter || '').trim(),
    excludeFilter: String(provider.excludeFilter || provider['exclude-filter'] || '').trim(),
    excludeType: String(provider.excludeType || provider['exclude-type'] || '').trim(),
    payload: normalizeProxyProviderPayload(provider.payload),
  }
}

export function normalizeClientGroup(group) {
  const groupType = String(group.type || '').trim().toLowerCase()
  const rest = { ...group }
  delete rest['include-all']
  delete rest['include-all-proxies']
  delete rest['include-all-providers']
  delete rest['max-failed-times']
  delete rest['disable-udp']
  delete rest['interface-name']
  delete rest['routing-mark']
  delete rest['exclude-filter']
  delete rest['exclude-type']
  delete rest['expected-status']
  return {
    ...rest,
    name: String(group.name || 'PROXY').trim(),
    type: ['select', 'url-test', 'fallback', 'load-balance', 'relay'].includes(groupType) ? groupType : 'select',
    proxies: normalizeTextList(group.proxies, []),
    use: normalizeTextList(group.use, []),
    includeAll: normalizeBooleanValue(group.includeAll ?? group['include-all']),
    includeAllProxies: normalizeBooleanValue(group.includeAllProxies ?? group['include-all-proxies']),
    includeAllProviders: normalizeBooleanValue(group.includeAllProviders ?? group['include-all-providers']),
    maxFailedTimes: Number(group.maxFailedTimes ?? group['max-failed-times']) || 0,
    disableUdp: normalizeBooleanValue(group.disableUdp ?? group['disable-udp']),
    interfaceName: String(group.interfaceName ?? group['interface-name'] ?? '').trim(),
    routingMark: Number(group.routingMark ?? group['routing-mark']) || 0,
    excludeFilter: String(group.excludeFilter ?? group['exclude-filter'] ?? '').trim(),
    excludeType: String(group.excludeType ?? group['exclude-type'] ?? '').trim(),
    expectedStatus: String(group.expectedStatus ?? group['expected-status'] ?? '').trim(),
  }
}

export function normalizeClientGeo(geo = {}) {
  const geoxUrl = isPlainObject(geo.geoxUrl) ? geo.geoxUrl : isPlainObject(geo['geox-url']) ? geo['geox-url'] : {}
  const extra = omitKeys(geo, geoFieldKeys)
  return {
    ...extra,
    geodataMode: normalizeBooleanValue(geo.geodataMode ?? geo['geodata-mode']),
    geoAutoUpdate: normalizeBooleanValue(geo.geoAutoUpdate ?? geo['geo-auto-update']),
    geoUpdateInterval: geo.geoUpdateInterval ?? geo['geo-update-interval'] ?? 24,
    geoxUrl: {
      geoip: geoxUrl.geoip || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
      geosite: geoxUrl.geosite || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
      mmdb: geoxUrl.mmdb || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb',
      asn: geoxUrl.asn || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    },
  }
}

export const geoFieldKeys = [
  'geodataMode',
  'geodata-mode',
  'geoAutoUpdate',
  'geo-auto-update',
  'geoUpdateInterval',
  'geo-update-interval',
  'geoxUrl',
  'geox-url',
]

export function normalizeClientGeneral(general = {}) {
  const tls = isPlainObject(general.tls) ? general.tls : {}
  const tlsCustom = isPlainObject(general.tlsCustom)
    ? general.tlsCustom
    : Object.fromEntries(Object.entries(tls).filter(([key]) => !['certificate', 'private-key'].includes(key)))
  const extra = omitKeys(general, generalFieldKeys)
  return {
    ...extra,
    port: general.port || 0,
    socksPort: general.socksPort ?? general['socks-port'] ?? 0,
    redirPort: general.redirPort ?? general['redir-port'] ?? 0,
    tproxyPort: general.tproxyPort ?? general['tproxy-port'] ?? 0,
    mixedPort: general.mixedPort ?? general['mixed-port'] ?? 7890,
    allowLan: normalizeBooleanValue(general.allowLan ?? general['allow-lan']),
    bindAddress: general.bindAddress ?? general['bind-address'] ?? '*',
    lanAllowedIps: normalizeTextList(general.lanAllowedIps ?? general['lan-allowed-ips'], []),
    lanDisallowedIps: normalizeTextList(general.lanDisallowedIps ?? general['lan-disallowed-ips'], []),
    authentication: normalizeTextList(general.authentication, []),
    skipAuthPrefixes: normalizeTextList(general.skipAuthPrefixes ?? general['skip-auth-prefixes'], []),
    interfaceName: general.interfaceName ?? general['interface-name'] ?? '',
    routingMark: general.routingMark ?? general['routing-mark'] ?? 0,
    mode: general.mode || 'rule',
    logLevel: general.logLevel ?? general['log-level'] ?? 'info',
    ipv6: normalizeBooleanValue(general.ipv6),
    keepAliveIdle: general.keepAliveIdle ?? general['keep-alive-idle'] ?? 0,
    keepAliveInterval: general.keepAliveInterval ?? general['keep-alive-interval'] ?? 0,
    disableKeepAlive: normalizeBooleanValue(general.disableKeepAlive ?? general['disable-keep-alive']),
    findProcessMode: general.findProcessMode ?? general['find-process-mode'] ?? '',
    unifiedDelay: normalizeBooleanValue(general.unifiedDelay ?? general['unified-delay']),
    tcpConcurrent: normalizeBooleanValue(general.tcpConcurrent ?? general['tcp-concurrent']),
    externalController: general.externalController ?? general['external-controller'] ?? '',
    externalControllerTls: general.externalControllerTls ?? general['external-controller-tls'] ?? '',
    externalControllerUnix: general.externalControllerUnix ?? general['external-controller-unix'] ?? '',
    externalControllerPipe: general.externalControllerPipe ?? general['external-controller-pipe'] ?? '',
    externalControllerCors: general.externalControllerCors ?? general['external-controller-cors'] ?? '',
    externalUi: general.externalUi ?? general['external-ui'] ?? '',
    externalUiName: general.externalUiName ?? general['external-ui-name'] ?? '',
    externalUiUrl: general.externalUiUrl ?? general['external-ui-url'] ?? '',
    secret: general.secret || '',
    globalClientFingerprint: general.globalClientFingerprint ?? general['global-client-fingerprint'] ?? '',
    globalUa: general.globalUa ?? general['global-ua'] ?? '',
    etagSupport: normalizeBooleanValue(general.etagSupport ?? general['etag-support']),
    tlsCertificate: general.tlsCertificate ?? tls.certificate ?? '',
    tlsPrivateKey: general.tlsPrivateKey ?? tls['private-key'] ?? '',
    tlsCustom,
  }
}

export const generalFieldKeys = [
  'port',
  'socksPort',
  'socks-port',
  'redirPort',
  'redir-port',
  'tproxyPort',
  'tproxy-port',
  'mixedPort',
  'mixed-port',
  'allowLan',
  'allow-lan',
  'bindAddress',
  'bind-address',
  'lanAllowedIps',
  'lan-allowed-ips',
  'lanDisallowedIps',
  'lan-disallowed-ips',
  'authentication',
  'skipAuthPrefixes',
  'skip-auth-prefixes',
  'interfaceName',
  'interface-name',
  'routingMark',
  'routing-mark',
  'mode',
  'logLevel',
  'log-level',
  'ipv6',
  'keepAliveIdle',
  'keep-alive-idle',
  'keepAliveInterval',
  'keep-alive-interval',
  'disableKeepAlive',
  'disable-keep-alive',
  'findProcessMode',
  'find-process-mode',
  'unifiedDelay',
  'unified-delay',
  'tcpConcurrent',
  'tcp-concurrent',
  'externalController',
  'external-controller',
  'externalControllerTls',
  'external-controller-tls',
  'externalControllerUnix',
  'external-controller-unix',
  'externalControllerPipe',
  'external-controller-pipe',
  'externalControllerCors',
  'external-controller-cors',
  'externalUi',
  'external-ui',
  'externalUiName',
  'external-ui-name',
  'externalUiUrl',
  'external-ui-url',
  'secret',
  'globalClientFingerprint',
  'global-client-fingerprint',
  'globalUa',
  'global-ua',
  'etagSupport',
  'etag-support',
  'tlsCertificate',
  'tlsPrivateKey',
  'tlsCustom',
  'tls',
]

export function normalizeClientDns(dns = {}) {
  const extra = omitKeys(dns, dnsFieldKeys)
  return {
    ...extra,
    enable: normalizeBooleanValue(dns.enable, true),
    listen: dns.listen || '0.0.0.0:1053',
    ipv6: normalizeBooleanValue(dns.ipv6),
    cacheAlgorithm: dns.cacheAlgorithm ?? dns['cache-algorithm'] ?? '',
    preferH3: normalizeBooleanValue(dns.preferH3 ?? dns['prefer-h3']),
    useHosts: normalizeBooleanValue(dns.useHosts ?? dns['use-hosts']),
    useSystemHosts: normalizeBooleanValue(dns.useSystemHosts ?? dns['use-system-hosts']),
    respectRules: normalizeBooleanValue(dns.respectRules ?? dns['respect-rules']),
    enhancedMode: dns.enhancedMode ?? dns['enhanced-mode'] ?? 'redir-host',
    fakeIpRange: dns.fakeIpRange ?? dns['fake-ip-range'] ?? '198.18.0.1/16',
    fakeIpRange6: dns.fakeIpRange6 ?? dns['fake-ip-range6'] ?? '',
    fakeIpFilterMode: dns.fakeIpFilterMode ?? dns['fake-ip-filter-mode'] ?? '',
    fakeIpTtl: dns.fakeIpTtl ?? dns['fake-ip-ttl'] ?? 0,
    fakeIpFilter: normalizeTextList(dns.fakeIpFilter ?? dns['fake-ip-filter'], ['*.lan', '*.local']),
    defaultNameserver: normalizeTextList(dns.defaultNameserver ?? dns['default-nameserver'], ['1.1.1.1', '8.8.8.8']),
    nameserver: normalizeTextList(dns.nameserver, ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query']),
    fallback: normalizeTextList(dns.fallback, []),
    fallbackFilter: isPlainObject(dns.fallbackFilter) ? dns.fallbackFilter : isPlainObject(dns['fallback-filter']) ? dns['fallback-filter'] : {},
    directNameserver: normalizeTextList(dns.directNameserver ?? dns['direct-nameserver'], []),
    directNameserverFollowPolicy: normalizeBooleanValue(dns.directNameserverFollowPolicy ?? dns['direct-nameserver-follow-policy']),
    proxyServerNameserver: normalizeTextList(dns.proxyServerNameserver ?? dns['proxy-server-nameserver'], []),
    proxyServerNameserverPolicy: isPlainObject(dns.proxyServerNameserverPolicy) ? dns.proxyServerNameserverPolicy : isPlainObject(dns['proxy-server-nameserver-policy']) ? dns['proxy-server-nameserver-policy'] : {},
    nameserverPolicy: isPlainObject(dns.nameserverPolicy) ? dns.nameserverPolicy : isPlainObject(dns['nameserver-policy']) ? dns['nameserver-policy'] : {},
  }
}

export const dnsFieldKeys = [
  'enable',
  'listen',
  'ipv6',
  'cacheAlgorithm',
  'cache-algorithm',
  'preferH3',
  'prefer-h3',
  'useHosts',
  'use-hosts',
  'useSystemHosts',
  'use-system-hosts',
  'respectRules',
  'respect-rules',
  'enhancedMode',
  'enhanced-mode',
  'fakeIpRange',
  'fake-ip-range',
  'fakeIpRange6',
  'fake-ip-range6',
  'fakeIpFilterMode',
  'fake-ip-filter-mode',
  'fakeIpTtl',
  'fake-ip-ttl',
  'fakeIpFilter',
  'fake-ip-filter',
  'defaultNameserver',
  'default-nameserver',
  'nameserver',
  'fallback',
  'fallbackFilter',
  'fallback-filter',
  'directNameserver',
  'direct-nameserver',
  'directNameserverFollowPolicy',
  'direct-nameserver-follow-policy',
  'proxyServerNameserver',
  'proxy-server-nameserver',
  'proxyServerNameserverPolicy',
  'proxy-server-nameserver-policy',
  'nameserverPolicy',
  'nameserver-policy',
]

export function normalizeClientSniffer(sniffer = {}) {
  const extra = omitKeys(sniffer, snifferFieldKeys)
  return {
    ...extra,
    enable: normalizeBooleanValue(sniffer.enable),
    overrideDestination: sniffer.overrideDestination ?? sniffer['override-destination'] ?? true,
    parsePureIp: normalizeBooleanValue(sniffer.parsePureIp ?? sniffer['parse-pure-ip']),
    forceDnsMapping: normalizeBooleanValue(sniffer.forceDnsMapping ?? sniffer['force-dns-mapping']),
    sniff: normalizeSniffForText(sniffer.sniff, ['TLS:443,8443', 'HTTP:80,8080-8880', 'QUIC:443,8443']),
    forceDomain: normalizeTextList(sniffer.forceDomain ?? sniffer['force-domain'], ['+.netflix.com', '+.youtube.com']),
    skipDomain: normalizeTextList(sniffer.skipDomain ?? sniffer['skip-domain'], ['+.apple.com']),
    skipSrcAddress: normalizeTextList(sniffer.skipSrcAddress ?? sniffer['skip-src-address'], []),
    skipDstAddress: normalizeTextList(sniffer.skipDstAddress ?? sniffer['skip-dst-address'], []),
  }
}

export const snifferFieldKeys = [
  'enable',
  'overrideDestination',
  'override-destination',
  'parsePureIp',
  'parse-pure-ip',
  'forceDnsMapping',
  'force-dns-mapping',
  'sniff',
  'forceDomain',
  'force-domain',
  'skipDomain',
  'skip-domain',
  'skipSrcAddress',
  'skip-src-address',
  'skipDstAddress',
  'skip-dst-address',
]

export function normalizeClientTun(tun = {}) {
  const extra = omitKeys(tun, tunFieldKeys)
  return {
    ...extra,
    enable: normalizeBooleanValue(tun.enable),
    stack: tun.stack || 'mixed',
    device: tun.device || '',
    autoRoute: tun.autoRoute ?? tun['auto-route'] ?? true,
    autoRedirect: normalizeBooleanValue(tun.autoRedirect ?? tun['auto-redirect']),
    autoDetectInterface: tun.autoDetectInterface ?? tun['auto-detect-interface'] ?? true,
    strictRoute: normalizeBooleanValue(tun.strictRoute ?? tun['strict-route']),
    dnsHijack: normalizeTextList(tun.dnsHijack ?? tun['dns-hijack'], ['any:53']),
    mtu: tun.mtu || 0,
    gso: normalizeBooleanValue(tun.gso),
    gsoMaxSize: tun.gsoMaxSize ?? tun['gso-max-size'] ?? 0,
    udpTimeout: tun.udpTimeout ?? tun['udp-timeout'] ?? 0,
    iproute2TableIndex: tun.iproute2TableIndex ?? tun['iproute2-table-index'] ?? 0,
    iproute2RuleIndex: tun.iproute2RuleIndex ?? tun['iproute2-rule-index'] ?? 0,
    endpointIndependentNat: normalizeBooleanValue(tun.endpointIndependentNat ?? tun['endpoint-independent-nat']),
    routeAddressSet: normalizeTextList(tun.routeAddressSet ?? tun['route-address-set'], []),
    routeExcludeAddressSet: normalizeTextList(tun.routeExcludeAddressSet ?? tun['route-exclude-address-set'], []),
    routeAddress: normalizeTextList(tun.routeAddress ?? tun['route-address'], []),
    routeExcludeAddress: normalizeTextList(tun.routeExcludeAddress ?? tun['route-exclude-address'], []),
    includeInterface: normalizeTextList(tun.includeInterface ?? tun['include-interface'], []),
    excludeInterface: normalizeTextList(tun.excludeInterface ?? tun['exclude-interface'], []),
    includeUid: normalizeTextList(tun.includeUid ?? tun['include-uid'], []),
    includeUidRange: normalizeTextList(tun.includeUidRange ?? tun['include-uid-range'], []),
    excludeUid: normalizeTextList(tun.excludeUid ?? tun['exclude-uid'], []),
    excludeUidRange: normalizeTextList(tun.excludeUidRange ?? tun['exclude-uid-range'], []),
    includeAndroidUser: normalizeTextList(tun.includeAndroidUser ?? tun['include-android-user'], []),
    includePackage: normalizeTextList(tun.includePackage ?? tun['include-package'], []),
    excludePackage: normalizeTextList(tun.excludePackage ?? tun['exclude-package'], []),
  }
}

export const tunFieldKeys = [
  'enable',
  'stack',
  'device',
  'autoRoute',
  'auto-route',
  'autoRedirect',
  'auto-redirect',
  'autoDetectInterface',
  'auto-detect-interface',
  'strictRoute',
  'strict-route',
  'dnsHijack',
  'dns-hijack',
  'mtu',
  'gso',
  'gsoMaxSize',
  'gso-max-size',
  'udpTimeout',
  'udp-timeout',
  'iproute2TableIndex',
  'iproute2-table-index',
  'iproute2RuleIndex',
  'iproute2-rule-index',
  'endpointIndependentNat',
  'endpoint-independent-nat',
  'routeAddressSet',
  'route-address-set',
  'routeExcludeAddressSet',
  'route-exclude-address-set',
  'routeAddress',
  'route-address',
  'routeExcludeAddress',
  'route-exclude-address',
  'includeInterface',
  'include-interface',
  'excludeInterface',
  'exclude-interface',
  'includeUid',
  'include-uid',
  'includeUidRange',
  'include-uid-range',
  'excludeUid',
  'exclude-uid',
  'excludeUidRange',
  'exclude-uid-range',
  'includeAndroidUser',
  'include-android-user',
  'includePackage',
  'include-package',
  'excludePackage',
  'exclude-package',
]

export function normalizeClientNtp(ntp = {}) {
  const extra = omitKeys(ntp, ntpFieldKeys)
  return {
    ...extra,
    enable: normalizeBooleanValue(ntp.enable),
    writeToSystem: normalizeBooleanValue(ntp.writeToSystem ?? ntp['write-to-system']),
    server: ntp.server || 'time.apple.com',
    port: ntp.port || 123,
    interval: ntp.interval || 30,
  }
}

const ntpFieldKeys = [
  'enable',
  'writeToSystem',
  'write-to-system',
  'server',
  'port',
  'interval',
]

export function normalizeSniffForText(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return splitLines(value)
  if (!isPlainObject(value)) return fallback

  const items = Object.entries(value)
    .map(([protocol, options]) => {
      const ports = normalizePortsForText(isPlainObject(options) ? options.ports : options).join(',')
      const name = String(protocol).trim()
      return name ? `${name}${ports ? `:${ports}` : ''}` : ''
    })
    .filter(Boolean)

  return items.length ? items : fallback
}

export function normalizeClientModel(model) {
  return {
    template: model?.template || 'full',
    rulesPreset: model?.rulesPreset || 'proxy',
    general: normalizeClientGeneral(model?.general),
    profile: {
      ...omitKeys(model?.profile, profileFieldKeys),
      storeSelected: normalizeBooleanValue(model?.profile?.storeSelected ?? model?.profile?.['store-selected']),
      storeFakeIp: normalizeBooleanValue(model?.profile?.storeFakeIp ?? model?.profile?.['store-fake-ip']),
    },
    dns: normalizeClientDns(model?.dns),
    sniffer: normalizeClientSniffer(model?.sniffer),
    tun: normalizeClientTun(model?.tun),
    ntp: normalizeClientNtp(model?.ntp),
    geo: normalizeClientGeo(model?.geo),
    ruleProviders: Array.isArray(model?.ruleProviders)
      ? model.ruleProviders
        .filter(isPlainObject)
        .map(normalizeClientRuleProvider)
      : [],
    proxyProviders: Array.isArray(model?.proxyProviders)
      ? model.proxyProviders
        .filter(isPlainObject)
        .map(normalizeClientProxyProvider)
      : [],
    listeners: Array.isArray(model?.listeners) ? model.listeners.filter((listener) => isPlainObject(listener)) : [],
    subRules: normalizeSubRuleMap(model?.subRules),
    tunnels: Array.isArray(model?.tunnels) ? model.tunnels.filter(isPlainObject) : [],
    extraTopLevel: model?.extraTopLevel && typeof model.extraTopLevel === 'object' && !Array.isArray(model.extraTopLevel) ? model.extraTopLevel : {},
    rawSections: isPlainObject(model?.rawSections)
      ? Object.fromEntries(Object.entries(model.rawSections).filter(([, value]) => isPlainObject(value)))
      : {},
    proxies: Array.isArray(model?.proxies)
      ? model.proxies.filter(isPlainObject).map(normalizeClientProxyNode)
      : [],
    groups: Array.isArray(model?.groups)
      ? model.groups
        .filter(isPlainObject)
        .map(normalizeClientGroup)
      : [],
    rules: normalizeRuleList(model?.rules, ['MATCH,PROXY']),
  }
}

export const profileFieldKeys = [
  'storeSelected',
  'store-selected',
  'storeFakeIp',
  'store-fake-ip',
]

