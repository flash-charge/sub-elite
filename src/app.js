import { autoFixConfigModel, buildYamlFromModel, createConfigModel, validateConfigModel } from '../lib/converter.ts'
import { parseDocument, stringify } from 'yaml'

const sampleLinks = [
  'vmess://eyJwcyI6IkNvbnRvaCBWTWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii9wYXRoIn0=',
  'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&host=example.com&path=%2Fpath&sni=example.com#Sample%20VLESS',
  'trojan://password@example.com:443?sni=example.com#Sample%20Trojan',
].join('\n')
const MAX_IMPORT_FILE_BYTES = 1024 * 1024
const importFilePattern = /\.(txt|conf|list|log|ya?ml)$/i

const networkOptions = [
  { value: '', label: 'Default (no network)' },
  { value: 'http', label: 'HTTP' },
  { value: 'h2', label: 'H2' },
  { value: 'grpc', label: 'gRPC' },
  { value: 'ws', label: 'WS' },
  { value: 'xhttp', label: 'XHTTP (VLESS)' },
]

const networkSupportByType = {
  vmess: ['ws', 'http', 'h2', 'grpc'],
  vless: ['ws', 'http', 'h2', 'grpc', 'xhttp'],
  trojan: ['ws', 'grpc'],
}

const alpnOptions = ['http/1.1', 'h2', 'h3']

const clientFingerprintOptions = [
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

const vmessCipherOptions = [
  'auto',
  'none',
  'zero',
  'aes-128-gcm',
  'chacha20-poly1305',
]

const vlessFlowOptions = [
  '',
  'xtls-rprx-vision',
]

const packetEncodingOptions = [
  '',
  'packetaddr',
  'xudp',
]

const ipVersionOptions = [
  '',
  'dual',
  'ipv4',
  'ipv6',
  'ipv4-prefer',
  'ipv6-prefer',
]

const trojanSsMethodOptions = [
  '',
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
]

const tlsCapabilityByType = {
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

const ssrCipherOptions = [
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

const ssrProtocolOptions = [
  'auth_sha1_v4',
  'origin',
  'verify_sha1',
  'auth_aes128_md5',
  'auth_aes128_sha1',
  'auth_chain_a',
  'auth_chain_b',
]

const ssrObfsOptions = [
  'tls1.2_ticket_auth',
  'plain',
  'http_simple',
  'http_post',
  'random_head',
  'tls1.2_ticket_fastauth',
]

const hysteriaProtocolOptions = ['udp', 'wechat-video', 'faketcp']
const tuicUdpRelayModeOptions = ['', 'native', 'quic']
const tuicCongestionControllerOptions = ['', 'bbr', 'cubic', 'new_reno']
const mieruTransportOptions = ['TCP', 'UDP']
const httpMethodOptions = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']

const shadowsocksCipherOptions = [
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

const shadowsocksPluginOptions = [
  '',
  'obfs',
  'v2ray-plugin',
  'gost-plugin',
  'shadow-tls',
  'restls',
  'kcptun',
]

const shadowsocksPluginOptExamples = {
  obfs: 'mode=tls\nhost=bing.com',
  'v2ray-plugin': 'mode=websocket\ntls=true\nhost=bing.com\npath=/\nmux=true\nv2ray-http-upgrade=false',
  'gost-plugin': 'mode=websocket\ntls=true\nhost=bing.com\npath=/\nmux=true',
  'shadow-tls': 'host=cloud.tencent.com\npassword=shadow_tls_password\nversion=2',
  restls: 'host=www.microsoft.com\npassword=YOUR_RESTLS_PASSWORD\nversion-hint=tls13\nrestls-script=300?100<1,400~100',
  kcptun: 'key=kcptun-secret\ncrypt=aes\nmode=fast\nconn=1\nautoexpire=0\nscavengettl=600\nmtu=1350\nnocomp=false',
}

const proxyTypeOptions = [
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

const proxyTypeLabels = {
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

const state = {
  yaml: '',
  originalYaml: '',
  model: null,
  originalModel: null,
  draggedNode: -1,
  expandedNodeKeys: new Set(),
  yamlManualEdit: false,
  subscriptionUrl: '',
  subscriptionApiAvailable: false,
  toastTimer: null,
}

const invalidEditorInput = Symbol('invalid-editor-input')
const nodeUiKeys = new WeakMap()
const apiBaseUrl = readApiBaseUrl()

const linkProtocolPattern = /(?:^|\s)(vmess|vless|trojan|ss|ssr|socks|socks5|hysteria|hysteria2|hy2|tuic|wireguard):\/\//i

const input = document.querySelector('#converter-input')
const fileInput = document.querySelector('#file-input')
const templateSelect = document.querySelector('#template-select')
const rulesSelect = document.querySelector('#rules-select')
const namePatternInput = document.querySelector('#name-pattern-input')
const filenameInput = document.querySelector('#filename-input')
const convertButton = document.querySelector('#convert-button')
const blankConfigButton = document.querySelector('#blank-config-button')
const sampleButton = document.querySelector('#sample-button')
const copyButton = document.querySelector('#copy-button')
const downloadButton = document.querySelector('#download-button')
const exportFormatSelect = document.querySelector('#export-format-select')
const formatYamlButton = document.querySelector('#format-yaml-button')
const validateYamlButton = document.querySelector('#validate-yaml-button')
const autoFixButton = document.querySelector('#auto-fix-button')
const toggleDiffButton = document.querySelector('#toggle-diff-button')
const resetYamlButton = document.querySelector('#reset-yaml-button')
const createSubscriptionButton = document.querySelector('#create-subscription-button')
const copySubscriptionButton = document.querySelector('#copy-subscription-button')
const openSubscriptionLink = document.querySelector('#open-subscription-link')
const subscriptionExpirySelect = document.querySelector('#subscription-expiry-select')
const subscriptionUrlInput = document.querySelector('#subscription-url-input')
const subscriptionStatus = document.querySelector('#subscription-status')
const errorBanner = document.querySelector('#error-banner')
const yamlEditor = document.querySelector('#yaml-editor')
const diffPanel = document.querySelector('#diff-panel')
const diffSummary = document.querySelector('#diff-summary')
const diffViewer = document.querySelector('#diff-viewer')
const validationBanner = document.querySelector('#validation-banner')
const validationDetails = document.querySelector('#validation-details')
const validationIssuesList = document.querySelector('#validation-issues-list')
const yamlSectionSelect = document.querySelector('#yaml-section-select')
const yamlSectionPreview = document.querySelector('#yaml-section-preview')
const warnings = document.querySelector('#warnings')
const warningsList = document.querySelector('#warnings-list')
const statTotal = document.querySelector('#stat-total')
const statConverted = document.querySelector('#stat-converted')
const statSkipped = document.querySelector('#stat-skipped')
const nodeList = document.querySelector('#node-list')
const groupList = document.querySelector('#group-list')
const groupNameInput = document.querySelector('#group-name-input')
const groupTypeInput = document.querySelector('#group-type-input')
const addGroupButton = document.querySelector('#add-group-button')
const rulesEditor = document.querySelector('#rules-editor')
const dnsEnable = document.querySelector('#dns-enable')
const dnsListen = document.querySelector('#dns-listen')
const dnsCacheAlgorithm = document.querySelector('#dns-cache-algorithm')
const dnsPreferH3 = document.querySelector('#dns-prefer-h3')
const dnsUseHosts = document.querySelector('#dns-use-hosts')
const dnsUseSystemHosts = document.querySelector('#dns-use-system-hosts')
const dnsRespectRules = document.querySelector('#dns-respect-rules')
const dnsDefault = document.querySelector('#dns-default')
const dnsNameservers = document.querySelector('#dns-nameservers')
const generalPort = document.querySelector('#general-port')
const generalSocksPort = document.querySelector('#general-socks-port')
const generalRedirPort = document.querySelector('#general-redir-port')
const generalTproxyPort = document.querySelector('#general-tproxy-port')
const generalMixedPort = document.querySelector('#general-mixed-port')
const generalMode = document.querySelector('#general-mode')
const generalLogLevel = document.querySelector('#general-log-level')
const generalBindAddress = document.querySelector('#general-bind-address')
const generalLanAllowedIps = document.querySelector('#general-lan-allowed-ips')
const generalLanDisallowedIps = document.querySelector('#general-lan-disallowed-ips')
const generalAuthentication = document.querySelector('#general-authentication')
const generalSkipAuthPrefixes = document.querySelector('#general-skip-auth-prefixes')
const generalInterfaceName = document.querySelector('#general-interface-name')
const generalRoutingMark = document.querySelector('#general-routing-mark')
const generalKeepAliveIdle = document.querySelector('#general-keep-alive-idle')
const generalKeepAliveInterval = document.querySelector('#general-keep-alive-interval')
const generalFindProcessMode = document.querySelector('#general-find-process-mode')
const generalController = document.querySelector('#general-controller')
const generalControllerTls = document.querySelector('#general-controller-tls')
const generalControllerUnix = document.querySelector('#general-controller-unix')
const generalControllerPipe = document.querySelector('#general-controller-pipe')
const generalControllerCors = document.querySelector('#general-controller-cors')
const generalUi = document.querySelector('#general-ui')
const generalUiName = document.querySelector('#general-ui-name')
const generalUiUrl = document.querySelector('#general-ui-url')
const generalSecret = document.querySelector('#general-secret')
const generalClientFingerprint = document.querySelector('#general-client-fingerprint')
const generalUa = document.querySelector('#general-ua')
const generalTlsCertificate = document.querySelector('#general-tls-certificate')
const generalTlsPrivateKey = document.querySelector('#general-tls-private-key')
const generalAllowLan = document.querySelector('#general-allow-lan')
const generalIpv6 = document.querySelector('#general-ipv6')
const generalDisableKeepAlive = document.querySelector('#general-disable-keep-alive')
const generalUnifiedDelay = document.querySelector('#general-unified-delay')
const generalTcpConcurrent = document.querySelector('#general-tcp-concurrent')
const generalEtagSupport = document.querySelector('#general-etag-support')
const profileStoreSelected = document.querySelector('#profile-store-selected')
const profileStoreFakeIp = document.querySelector('#profile-store-fake-ip')
const dnsEnhancedMode = document.querySelector('#dns-enhanced-mode')
const dnsFakeIpRange = document.querySelector('#dns-fake-ip-range')
const dnsFakeIpRange6 = document.querySelector('#dns-fake-ip-range6')
const dnsFakeIpFilterMode = document.querySelector('#dns-fake-ip-filter-mode')
const dnsFakeIpTtl = document.querySelector('#dns-fake-ip-ttl')
const dnsFakeIpFilter = document.querySelector('#dns-fake-ip-filter')
const dnsFallback = document.querySelector('#dns-fallback')
const dnsFallbackFilter = document.querySelector('#dns-fallback-filter')
const dnsDirectNameserver = document.querySelector('#dns-direct-nameserver')
const dnsDirectFollowPolicy = document.querySelector('#dns-direct-follow-policy')
const dnsProxyServer = document.querySelector('#dns-proxy-server')
const dnsProxyPolicy = document.querySelector('#dns-proxy-policy')
const dnsPolicy = document.querySelector('#dns-policy')
const snifferEnable = document.querySelector('#sniffer-enable')
const snifferOverride = document.querySelector('#sniffer-override')
const snifferParseIp = document.querySelector('#sniffer-parse-ip')
const snifferForceDnsMapping = document.querySelector('#sniffer-force-dns-mapping')
const snifferSniff = document.querySelector('#sniffer-sniff')
const snifferForce = document.querySelector('#sniffer-force')
const snifferSkip = document.querySelector('#sniffer-skip')
const snifferSkipSrc = document.querySelector('#sniffer-skip-src')
const snifferSkipDst = document.querySelector('#sniffer-skip-dst')
const tunEnable = document.querySelector('#tun-enable')
const tunStack = document.querySelector('#tun-stack')
const tunDevice = document.querySelector('#tun-device')
const tunAutoRoute = document.querySelector('#tun-auto-route')
const tunAutoRedirect = document.querySelector('#tun-auto-redirect')
const tunAutoDetect = document.querySelector('#tun-auto-detect')
const tunStrictRoute = document.querySelector('#tun-strict-route')
const tunDnsHijack = document.querySelector('#tun-dns-hijack')
const tunMtu = document.querySelector('#tun-mtu')
const tunGso = document.querySelector('#tun-gso')
const tunGsoMaxSize = document.querySelector('#tun-gso-max-size')
const tunUdpTimeout = document.querySelector('#tun-udp-timeout')
const tunIproute2TableIndex = document.querySelector('#tun-iproute2-table-index')
const tunIproute2RuleIndex = document.querySelector('#tun-iproute2-rule-index')
const tunEndpointIndependentNat = document.querySelector('#tun-endpoint-independent-nat')
const tunRouteAddressSet = document.querySelector('#tun-route-address-set')
const tunRouteExcludeAddressSet = document.querySelector('#tun-route-exclude-address-set')
const tunRouteAddress = document.querySelector('#tun-route-address')
const tunRouteExcludeAddress = document.querySelector('#tun-route-exclude-address')
const tunIncludeInterface = document.querySelector('#tun-include-interface')
const tunExcludeInterface = document.querySelector('#tun-exclude-interface')
const tunIncludeUid = document.querySelector('#tun-include-uid')
const tunIncludeUidRange = document.querySelector('#tun-include-uid-range')
const tunExcludeUid = document.querySelector('#tun-exclude-uid')
const tunExcludeUidRange = document.querySelector('#tun-exclude-uid-range')
const tunIncludeAndroidUser = document.querySelector('#tun-include-android-user')
const tunIncludePackage = document.querySelector('#tun-include-package')
const tunExcludePackage = document.querySelector('#tun-exclude-package')
const geoGeodataMode = document.querySelector('#geo-geodata-mode')
const geoAutoUpdate = document.querySelector('#geo-auto-update')
const geoUpdateInterval = document.querySelector('#geo-update-interval')
const geoUrlGeoip = document.querySelector('#geo-url-geoip')
const geoUrlGeosite = document.querySelector('#geo-url-geosite')
const geoUrlMmdb = document.querySelector('#geo-url-mmdb')
const geoUrlAsn = document.querySelector('#geo-url-asn')
const ruleProviderName = document.querySelector('#rule-provider-name')
const ruleProviderUrl = document.querySelector('#rule-provider-url')
const ruleProviderBehavior = document.querySelector('#rule-provider-behavior')
const ruleProviderTarget = document.querySelector('#rule-provider-target')
const ruleProviderFormat = document.querySelector('#rule-provider-format')
const addRuleProviderButton = document.querySelector('#add-rule-provider-button')
const addAdsProviderButton = document.querySelector('#add-ads-provider-button')
const applyLanRulesButton = document.querySelector('#apply-lan-rules-button')
const ruleProviderList = document.querySelector('#rule-provider-list')
const ruleBuilderType = document.querySelector('#rule-builder-type')
const ruleBuilderValue = document.querySelector('#rule-builder-value')
const ruleBuilderTarget = document.querySelector('#rule-builder-target')
const addRuleButton = document.querySelector('#add-rule-button')
const proxyProviderName = document.querySelector('#proxy-provider-name')
const proxyProviderUrl = document.querySelector('#proxy-provider-url')
const proxyProviderType = document.querySelector('#proxy-provider-type')
const addProxyProviderButton = document.querySelector('#add-proxy-provider-button')
const proxyProviderList = document.querySelector('#proxy-provider-list')
const manualNodeName = document.querySelector('#manual-node-name')
const manualNodeType = document.querySelector('#manual-node-type')
const manualNodeFields = document.querySelector('#manual-node-fields')
const addManualNodeButton = document.querySelector('#add-manual-node-button')
const nodeFilterQuery = document.querySelector('#node-filter-query')
const nodeFilterType = document.querySelector('#node-filter-type')
const nodeFilterStatus = document.querySelector('#node-filter-status')
const openNodeToolsButton = document.querySelector('#open-node-tools-button')
const nodeToolsSheet = document.querySelector('#node-tools-sheet')
const closeNodeToolsButton = document.querySelector('#close-node-tools-button')
const bulkRenamePattern = document.querySelector('#bulk-rename-pattern')
const applyBulkRenameButton = document.querySelector('#apply-bulk-rename-button')
const nodeSortField = document.querySelector('#node-sort-field')
const sortNodesButton = document.querySelector('#sort-nodes-button')
const deleteDuplicateNodesButton = document.querySelector('#delete-duplicate-nodes-button')
const nodeKeywordInput = document.querySelector('#node-keyword-input')
const enableKeywordNodesButton = document.querySelector('#enable-keyword-nodes-button')
const disableKeywordNodesButton = document.querySelector('#disable-keyword-nodes-button')
const fabCopy = document.querySelector('#fab-copy')
const fabDownload = document.querySelector('#fab-download')
const toast = document.querySelector('#toast')
const viewTabs = document.querySelectorAll('[data-view-target]')
const viewPanels = document.querySelectorAll('.view-panel')
const editTabs = document.querySelectorAll('[data-edit-target]')
const editPanels = document.querySelectorAll('[data-edit-panel]')
const editorSectionSelect = document.querySelector('#editor-section-select')

viewTabs.forEach((tab) => tab.addEventListener('click', () => setActiveView(tab.dataset.viewTarget)))
editTabs.forEach((tab) => tab.addEventListener('click', () => setActiveEdit(tab.dataset.editTarget)))
editorSectionSelect.addEventListener('change', () => setActiveEdit(editorSectionSelect.value))
populateNodeFilterTypes()
checkSubscriptionApiAvailability()
setupNetworkStatus()
sampleButton.addEventListener('click', useSample)
convertButton.addEventListener('click', processInput)
blankConfigButton.addEventListener('click', createBlankConfig)
copyButton.addEventListener('click', copyYaml)
downloadButton.addEventListener('click', downloadYaml)
fabCopy.addEventListener('click', copyYaml)
fabDownload.addEventListener('click', downloadYaml)
exportFormatSelect.addEventListener('change', renderSectionPreview)
yamlSectionSelect.addEventListener('change', renderSectionPreview)
formatYamlButton.addEventListener('click', formatCurrentYaml)
validateYamlButton.addEventListener('click', validateCurrentYaml)
autoFixButton.addEventListener('click', autoFixCurrentModel)
toggleDiffButton.addEventListener('click', toggleDiffPanel)
resetYamlButton.addEventListener('click', resetModel)
createSubscriptionButton.addEventListener('click', createSubscriptionUrl)
copySubscriptionButton.addEventListener('click', copySubscriptionUrl)
input.addEventListener('input', updateSubmitState)
fileInput.addEventListener('change', importFile)
templateSelect.addEventListener('change', updateTemplateFromControl)
rulesSelect.addEventListener('change', updateRulesPresetFromControl)
addGroupButton.addEventListener('click', addGroup)
addRuleButton.addEventListener('click', addRuleFromBuilder)
ruleBuilderType.addEventListener('change', updateRuleBuilderState)
addRuleProviderButton.addEventListener('click', addRuleProvider)
addProxyProviderButton.addEventListener('click', addProxyProvider)
addManualNodeButton.addEventListener('click', addManualNode)
nodeFilterQuery.addEventListener('input', renderNodes)
nodeFilterType.addEventListener('change', renderNodes)
nodeFilterStatus.addEventListener('change', renderNodes)
manualNodeType.addEventListener('change', () => renderManualNodeFields())
manualNodeFields.addEventListener('change', (event) => {
  if (event.target.dataset.manualField === 'network') renderManualNodeFields(readManualNodeValues())
  if (event.target.dataset.manualField === 'tls') toggleManualTlsFields(event.target.checked)
  if (event.target.dataset.manualField === 'plugin') updateShadowsocksPluginOptsPlaceholder(manualNodeFields, event.target.value)
})
addAdsProviderButton.addEventListener('click', addAdsProviderPreset)
applyLanRulesButton.addEventListener('click', applyLanDirectRules)
openNodeToolsButton.addEventListener('click', openNodeTools)
closeNodeToolsButton.addEventListener('click', closeNodeTools)
nodeToolsSheet.addEventListener('click', (event) => {
  if (event.target.dataset.sheetClose !== undefined) closeNodeTools()
})
applyBulkRenameButton.addEventListener('click', applyBulkRename)
sortNodesButton.addEventListener('click', sortNodes)
deleteDuplicateNodesButton.addEventListener('click', deleteDuplicateNodes)
enableKeywordNodesButton.addEventListener('click', () => setNodesByKeyword(true))
disableKeywordNodesButton.addEventListener('click', () => setNodesByKeyword(false))
document.querySelectorAll('[data-token-target]').forEach((row) => {
  row.addEventListener('click', handleTokenClick)
})
rulesEditor.addEventListener('input', updateRulesFromEditor)
dnsEnable.addEventListener('change', updateDnsFromEditor)
dnsListen.addEventListener('input', updateDnsFromEditor)
dnsCacheAlgorithm.addEventListener('change', updateDnsFromEditor)
dnsPreferH3.addEventListener('change', updateDnsFromEditor)
dnsUseHosts.addEventListener('change', updateDnsFromEditor)
dnsUseSystemHosts.addEventListener('change', updateDnsFromEditor)
dnsRespectRules.addEventListener('change', updateDnsFromEditor)
dnsDefault.addEventListener('input', updateDnsFromEditor)
dnsNameservers.addEventListener('input', updateDnsFromEditor)
;[
  generalPort,
  generalSocksPort,
  generalRedirPort,
  generalTproxyPort,
  generalMixedPort,
  generalMode,
  generalLogLevel,
  generalBindAddress,
  generalLanAllowedIps,
  generalLanDisallowedIps,
  generalAuthentication,
  generalSkipAuthPrefixes,
  generalInterfaceName,
  generalRoutingMark,
  generalKeepAliveIdle,
  generalKeepAliveInterval,
  generalFindProcessMode,
  generalController,
  generalControllerTls,
  generalControllerUnix,
  generalControllerPipe,
  generalControllerCors,
  generalUi,
  generalUiName,
  generalUiUrl,
  generalSecret,
  generalClientFingerprint,
  generalUa,
  generalTlsCertificate,
  generalTlsPrivateKey,
  generalAllowLan,
  generalIpv6,
  generalDisableKeepAlive,
  generalUnifiedDelay,
  generalTcpConcurrent,
  generalEtagSupport,
  profileStoreSelected,
  profileStoreFakeIp,
].forEach((field) => field.addEventListener(field.type === 'checkbox' ? 'change' : 'input', updateGeneralFromEditor))
;[
  dnsEnhancedMode,
  dnsFakeIpRange,
  dnsFakeIpRange6,
  dnsFakeIpFilterMode,
  dnsFakeIpTtl,
  dnsFakeIpFilter,
  dnsFallback,
  dnsFallbackFilter,
  dnsDirectNameserver,
  dnsDirectFollowPolicy,
  dnsProxyServer,
  dnsProxyPolicy,
  dnsPolicy,
].forEach((field) => field.addEventListener(field.tagName === 'SELECT' ? 'change' : 'input', updateDnsFromEditor))
;[
  snifferEnable,
  snifferOverride,
  snifferParseIp,
  snifferForceDnsMapping,
  snifferSniff,
  snifferForce,
  snifferSkip,
  snifferSkipSrc,
  snifferSkipDst,
].forEach((field) => field.addEventListener(field.type === 'checkbox' ? 'change' : 'input', updateSnifferFromEditor))
;[
  tunEnable,
  tunStack,
  tunDevice,
  tunAutoRoute,
  tunAutoRedirect,
  tunAutoDetect,
  tunStrictRoute,
  tunDnsHijack,
  tunMtu,
  tunGso,
  tunGsoMaxSize,
  tunUdpTimeout,
  tunIproute2TableIndex,
  tunIproute2RuleIndex,
  tunEndpointIndependentNat,
  tunRouteAddressSet,
  tunRouteExcludeAddressSet,
  tunRouteAddress,
  tunRouteExcludeAddress,
  tunIncludeInterface,
  tunExcludeInterface,
  tunIncludeUid,
  tunIncludeUidRange,
  tunExcludeUid,
  tunExcludeUidRange,
  tunIncludeAndroidUser,
  tunIncludePackage,
  tunExcludePackage,
].forEach((field) => field.addEventListener(field.type === 'checkbox' || field.tagName === 'SELECT' ? 'change' : 'input', updateTunFromEditor))
;[
  geoGeodataMode,
  geoAutoUpdate,
  geoUpdateInterval,
  geoUrlGeoip,
  geoUrlGeosite,
  geoUrlMmdb,
  geoUrlAsn,
].forEach((field) => field.addEventListener(field.type === 'checkbox' ? 'change' : 'input', updateGeoFromEditor))
yamlEditor.addEventListener('input', () => {
  state.yaml = yamlEditor.value
  state.yamlManualEdit = true
  resetSubscriptionUrl()
  validateCurrentYaml(false)
  renderDiff()
  renderSectionPreview()
})

async function processInput() {
  const kind = detectInputType(input.value)
  if (kind === 'http-url') {
    showError('Paste config links directly, not http/https subscription URLs.')
    return
  }
  if (kind === 'yaml') {
    try {
      importYamlText(input.value)
    } catch (error) {
      showError(error instanceof Error ? error.message : 'YAML import failed.')
    }
    return
  }
  if (kind === 'links') {
    await convertLinks()
    return
  }

  showError('Input not recognized. Paste config links directly or Mihomo YAML.')
}

async function convertLinks() {
  convertButton.disabled = true
  convertButton.querySelector('span').textContent = 'Converting...'
  copyButton.querySelector('span').textContent = 'Copy'
  clearError()

  try {
    const payload = await convertLinksViaApi()

    state.model = normalizeClientModel(payload.model)
    state.yamlManualEdit = false
    normalizeEditorModel()
    state.originalModel = clone(state.model)
    renderModel()
    state.yaml = buildYamlFromModel(state.model)
    state.originalYaml = state.yaml
    resetSubscriptionUrl()
    syncYamlEditor()
    statTotal.textContent = payload.stats.total
    statConverted.textContent = payload.stats.converted
    statSkipped.textContent = payload.stats.skipped
    setOutputEnabled(true)
    renderWarnings(payload.warnings)
    validateCurrentYaml(false)
    renderDiff()
    renderSectionPreview()
    setActiveView('yaml')
  } catch (error) {
    clearConvertedState()
    showError(error instanceof Error ? error.message : 'Conversion failed.')
  } finally {
    convertButton.querySelector('span').textContent = 'Convert'
    updateSubmitState()
  }
}

async function convertLinksViaApi() {
  const response = await fetch(apiUrl('/api/convert'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      input: input.value,
      ...readConvertOptions(),
    }),
  })
  const payload = await readJsonResponse(response, 'Conversion failed.')
  if (!response.ok) throw new Error(payload.error || 'Conversion failed.')
  return payload
}

async function readJsonResponse(response, fallbackMessage) {
  const text = await response.text()
  if (!text.trim()) {
    throw new Error(response.ok ? fallbackMessage : `${fallbackMessage} API returned an empty response.`)
  }

  try {
    return JSON.parse(text)
  } catch {
    throw new Error(response.ok ? fallbackMessage : `${fallbackMessage} API returned a non-JSON response.`)
  }
}

function createBlankConfig() {
  input.value = ''
  clearError()
  const model = normalizeClientModel(createConfigModel([], {
    template: templateSelect.value,
    rulesPreset: rulesSelect.value,
  }))
  loadModel(model, {
    originalYaml: buildYamlFromModel(model),
    stats: { total: 0, converted: 0, skipped: 0 },
    warnings: [],
    view: 'edit',
  })
  updateSubmitState()
  showToast('Blank config created. Add nodes or edit sections as needed.')
}

function importYamlText(text) {
  clearError()
  const source = String(text || '').trim()
  if (!source) {
    showError('Paste Mihomo YAML first.')
    return
  }

  const doc = parseDocument(source)
  if (doc.errors.length) {
    showError(doc.errors.map((error) => error.message).join(' '))
    return
  }

  const raw = doc.toJS()
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    showError('YAML must be a Mihomo config object.')
    return
  }

  const model = normalizeClientModel(modelFromYamlObject(raw))
  loadModel(model, {
    originalYaml: source,
    stats: { total: Array.isArray(raw.proxies) ? raw.proxies.length : 0, converted: Array.isArray(raw.proxies) ? raw.proxies.length : 0, skipped: 0 },
    warnings: [],
    view: 'edit',
  })
  showToast('YAML imported into the editor.')
}

function loadModel(model, options = {}) {
  state.model = normalizeClientModel(model)
  state.yamlManualEdit = false
  normalizeEditorModel()
  state.originalModel = clone(state.model)
  renderModel()
  state.yaml = buildYamlFromModel(state.model)
  state.originalYaml = options.originalYaml || state.yaml
  resetSubscriptionUrl()
  syncYamlEditor()
  statTotal.textContent = options.stats?.total ?? state.model.proxies.length
  statConverted.textContent = options.stats?.converted ?? state.model.proxies.length
  statSkipped.textContent = options.stats?.skipped ?? 0
  setOutputEnabled(true)
  renderWarnings(options.warnings || [])
  validateCurrentYaml(false)
  renderDiff()
  renderSectionPreview()
  setActiveView(options.view || 'yaml')
}

async function copyYaml() {
  if (!state.yaml) return
  try {
    await navigator.clipboard.writeText(state.yaml)
    showToast('YAML copied.')
  } catch {
    showToast('Copy failed.', 'error')
  }
}

async function createSubscriptionUrl() {
  if (!state.yaml) return
  if (!state.subscriptionApiAvailable) {
    showToast('Subscription API is not available on this deployment.', 'error')
    return
  }
  createSubscriptionButton.disabled = true
  createSubscriptionButton.textContent = 'Creating...'

  try {
    const response = await fetch(apiUrl('/api/subscriptions'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        yaml: state.yaml,
        expiresIn: subscriptionExpirySelect.value,
      }),
    })
    const payload = await readJsonResponse(response, 'Subscription URL failed.')
    if (!response.ok) throw new Error(payload.error || 'Subscription URL failed.')

    state.subscriptionUrl = payload.url
    renderSubscriptionUrl()
    showToast('Subscription URL created.')
  } catch (error) {
    showToast(error instanceof Error ? error.message : 'Subscription URL failed.', 'error')
  } finally {
    createSubscriptionButton.textContent = 'Create URL'
    createSubscriptionButton.disabled = !state.yaml || !state.subscriptionApiAvailable
  }
}

async function copySubscriptionUrl() {
  if (!state.subscriptionUrl) return
  try {
    await navigator.clipboard.writeText(state.subscriptionUrl)
    showToast('Subscription URL copied.')
  } catch {
    showToast('Copy URL failed.', 'error')
  }
}

function showToast(message, type = 'ok') {
  toast.textContent = message
  toast.className = `toast ${type}`
  toast.classList.remove('hidden')
  
  window.clearTimeout(state.toastTimer)
  state.toastTimer = window.setTimeout(() => {
    toast.classList.add('hidden')
  }, 2400)
}

function downloadYaml() {
  if (!state.yaml) return
  const exportKind = exportFormatSelect.value
  const text = buildExportYaml(exportKind)
  const filename = exportKind === 'full'
    ? normalizeFilename(filenameInput.value)
    : normalizeFilename(`${exportKind}.yaml`)
  downloadText(filename, text, 'application/yaml;charset=utf-8')
}

function useSample() {
  input.value = sampleLinks
  clearConvertedState()
  clearError()
  updateSubmitState()
  showToast('Sample loaded. Review it, then tap Convert.')
}

async function importFile() {
  const file = fileInput.files?.[0]
  if (!file) return

  if (file.size > MAX_IMPORT_FILE_BYTES) {
    showError('File is too large. Maximum import size is 1 MB.')
    fileInput.value = ''
    return
  }

  if (!isSupportedImportFile(file)) {
    showError('File must be text or YAML: .txt, .conf, .list, .log, .yaml, or .yml.')
    fileInput.value = ''
    return
  }

  try {
    input.value = await file.text()
    clearConvertedState()
    clearError()
    updateSubmitState()
    showToast('File imported. Review it, then tap Convert.')
  } catch {
    showError('File read failed.')
  } finally {
    fileInput.value = ''
  }
}

function isSupportedImportFile(file) {
  const name = String(file?.name || '')
  const type = String(file?.type || '').toLowerCase()
  return importFilePattern.test(name)
    || type.startsWith('text/')
    || type === 'application/yaml'
    || type === 'application/x-yaml'
}

function renderModel() {
  if (!state.model) return
  normalizeEditorModel()
  templateSelect.value = state.model.template || 'full'
  rulesSelect.value = state.model.rulesPreset || 'proxy'
  updateRulesState()
  renderRuleTargetOptions()
  renderGeneral()
  renderNodes()
  renderGroups()
  renderRules()
  renderDns()
  renderSniffer()
  renderTun()
  renderGeo()
  renderRuleProviders()
  renderProxyProviders()
  applyPlaceholders()
}

function setActiveView(view) {
  viewTabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.viewTarget === view))
  viewPanels.forEach((panel) => panel.classList.toggle('active', panel.dataset.view === view))
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function setActiveEdit(target) {
  let activeTab = null
  editTabs.forEach((tab) => {
    const active = tab.dataset.editTarget === target
    tab.classList.toggle('active', active)
    if (active) activeTab = tab
  })
  editPanels.forEach((panel) => {
    const active = panel.dataset.editPanel === target
    panel.classList.toggle('active', active)
    panel.hidden = !active
  })
  if (editorSectionSelect.value !== target) editorSectionSelect.value = target
  activeTab?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' })
}

function populateNodeFilterTypes() {
  const current = nodeFilterType.value
  nodeFilterType.innerHTML = `
    <option value="">All Protocols</option>
    ${proxyTypeOptions.map((type) => `<option value="${escapeAttr(type)}">${escapeHtml(proxyTypeLabel(type))}</option>`).join('')}
  `
  nodeFilterType.value = proxyTypeOptions.includes(current) ? current : ''
}

function proxyTypeLabel(type) {
  return proxyTypeLabels[type] || type
}

function renderNodes() {
  nodeList.replaceChildren()
  if (!state.model?.proxies.length) {
    nodeList.textContent = 'No nodes yet. Convert config links first.'
    return
  }

  const entries = filteredNodeEntries()
  if (!entries.length) {
    nodeList.textContent = 'No nodes match the current filter.'
    return
  }

  entries.forEach(({ proxy, index }) => {
    const nodeKey = nodeExpansionKey(proxy)
    const expanded = state.expandedNodeKeys.has(nodeKey)
    const bodyId = `node-body-${index}`
    const row = document.createElement('article')
    row.className = `node-row ${expanded ? 'expanded' : 'collapsed'}`
    row.draggable = true
    row.dataset.index = String(index)
    row.innerHTML = `
      <div class="node-row-head">
        <div class="node-summary">
          <div class="node-title-line">
            <strong>${escapeHtml(proxy.type || 'proxy')}</strong>
            <span>${escapeHtml(proxy.name || 'Unnamed node')}</span>
          </div>
          <div class="node-meta">
            ${nodeSummaryParts(proxy).map((part) => `<span>${escapeHtml(part)}</span>`).join('')}
          </div>
        </div>
        <button type="button" class="ghost-button node-toggle" data-action="toggle-node" aria-expanded="${expanded ? 'true' : 'false'}" aria-controls="${escapeAttr(bodyId)}" aria-label="${expanded ? 'Collapse node' : 'Expand node'}" title="${expanded ? 'Collapse' : 'Expand'}">
          <svg class="icon-small node-toggle-icon" aria-hidden="true"><use href="/icons.svg#icon-chevron-${expanded ? 'up' : 'down'}"></use></svg>
          <span class="node-action-label">${expanded ? 'Collapse' : 'Expand'}</span>
        </button>
        <div class="row-actions node-toolbar">
          <label class="checkbox-row"><input type="checkbox" data-field="enabled" ${proxy.enabled !== false ? 'checked' : ''}> Enabled</label>
          <button type="button" class="ghost-button node-action-button" data-action="up" aria-label="Move node up" title="Up">
            <svg class="icon-small" aria-hidden="true"><use href="/icons.svg#icon-chevron-up"></use></svg>
            <span class="node-action-label">Up</span>
          </button>
          <button type="button" class="ghost-button node-action-button" data-action="down" aria-label="Move node down" title="Down">
            <svg class="icon-small" aria-hidden="true"><use href="/icons.svg#icon-chevron-down"></use></svg>
            <span class="node-action-label">Down</span>
          </button>
          <button type="button" class="ghost-button node-action-button danger-action" data-action="delete" aria-label="Delete node" title="Delete">
            <svg class="icon-small" aria-hidden="true"><use href="/icons.svg#icon-trash"></use></svg>
            <span class="node-action-label">Delete</span>
          </button>
        </div>
      </div>
      <div id="${escapeAttr(bodyId)}" class="node-body" ${expanded ? '' : 'hidden'}>
        <div class="node-fields">
          <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(proxy.name || '')}"></label>
          <label><span>Type</span><select data-field="type">${renderSelectOptions(proxyTypeOptions, normalizeProxyType(proxy.type || ''))}</select></label>
          ${needsEndpoint(proxy) ? `<label><span>Server</span><input type="text" data-field="server" value="${escapeAttr(proxy.server || '')}"></label>` : ''}
          ${needsEndpoint(proxy) ? `<label><span>Port</span><input type="text" data-field="port" value="${escapeAttr(proxy.port || '')}"></label>` : ''}
          ${renderProtocolFields(proxy)}
          ${supportedNetworksForProxy(proxy).length ? `<label><span>Network</span><select data-field="network">${renderNetworkOptions(proxy)}</select></label>` : ''}
          ${renderTransportFields(proxy)}
          ${renderTlsFields(proxy)}
          ${renderCommonProxyFields(proxy)}
        </div>
        <details>
          <summary>Raw JSON</summary>
          <textarea class="compact-editor raw-json" data-field="rawJson" spellcheck="false">${escapeHtml(JSON.stringify(stripEnabled(proxy), null, 2))}</textarea>
        </details>
      </div>
    `

    row.addEventListener('dragstart', () => {
      state.draggedNode = index
    })
    row.addEventListener('dragover', (event) => event.preventDefault())
    row.addEventListener('drop', (event) => {
      event.preventDefault()
      moveNode(state.draggedNode, index)
    })
    row.addEventListener('click', (event) => handleNodeClick(event, index))
    row.addEventListener('input', (event) => handleNodeInput(event, index))
    row.addEventListener('change', (event) => handleNodeInput(event, index))
    nodeList.append(row)
  })
  applyPlaceholders(nodeList)
  nodeList.querySelectorAll('.node-row').forEach((row) => updateShadowsocksPluginOptsPlaceholder(row))
}

function nodeExpansionKey(proxy) {
  if (proxy.id) return `id:${proxy.id}`
  if (!nodeUiKeys.has(proxy)) {
    const randomPart = Math.random().toString(36).slice(2, 9)
    nodeUiKeys.set(proxy, `ui:${randomPart}`)
  }
  return nodeUiKeys.get(proxy)
}

function nodeSummaryParts(proxy) {
  const parts = []
  if (needsEndpoint(proxy)) parts.push(`${proxy.server || 'server'}:${proxy.port || 'port'}`)
  if (proxy.network) parts.push(`network ${proxy.network}`)
  if (proxy.tls) parts.push('TLS')
  if (proxy.enabled === false) parts.push('disabled')
  return parts.length ? parts : ['local node']
}

function filteredNodeEntries() {
  const query = nodeFilterQuery.value.trim().toLowerCase()
  const type = nodeFilterType.value
  const status = nodeFilterStatus.value
  return (state.model?.proxies || [])
    .map((proxy, index) => ({ proxy, index }))
    .filter(({ proxy }) => {
      const proxyType = normalizeProxyType(proxy.type)
      if (type && proxyType !== type) return false
      if (status === 'enabled' && proxy.enabled === false) return false
      if (status === 'disabled' && proxy.enabled !== false) return false
      if (!query) return true
      return [proxy.name, proxy.server, proxyType, proxy.network]
        .map((value) => String(value || '').toLowerCase())
        .some((value) => value.includes(query))
    })
}

function renderGroups() {
  groupList.replaceChildren()
  if (!state.model) return
  if (!state.model.groups.length) {
    groupList.classList.add('empty-state')
    groupList.textContent = 'No proxy groups yet.'
    return
  }

  groupList.classList.remove('empty-state')
  state.model.groups.forEach((group, index) => {
    const row = document.createElement('details')
    row.className = 'editor-field-section group-editor-row'
    row.open = index === 0
    const healthFields = groupSupportsHealth(group)
    row.innerHTML = `
      <summary>
        <span class="group-summary">
          <strong>${escapeHtml(group.name || 'Unnamed group')}</strong>
          <em>${escapeHtml(group.type || 'select')}</em>
        </span>
        <small>${escapeHtml(groupSummaryText(group))}</small>
      </summary>
      <div class="form-grid section-grid group-edit-grid">
        <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(group.name)}"></label>
        <label><span>Type</span><select data-field="type">
          ${['select', 'url-test', 'fallback', 'load-balance', 'relay'].map((type) => `<option value="${type}" ${type === group.type ? 'selected' : ''}>${type}</option>`).join('')}
        </select></label>
      </div>
      <div class="form-grid section-grid group-edit-grid group-members-section">
        ${renderGroupProxyPicker(group)}
        ${renderGroupProviderPicker(group)}
        <label class="checkbox-row"><input type="checkbox" data-field="includeAll" ${group.includeAll ? 'checked' : ''}> Include All</label>
        <label class="checkbox-row"><input type="checkbox" data-field="includeAllProxies" ${group.includeAllProxies ? 'checked' : ''}> Include All Proxies</label>
        <label class="checkbox-row"><input type="checkbox" data-field="includeAllProviders" ${group.includeAllProviders ? 'checked' : ''}> Include All Providers</label>
      </div>
      ${healthFields ? `
        <div class="form-grid section-grid group-edit-grid group-subsection">
          <label class="wide-field"><span>URL</span><input type="text" data-field="url" value="${escapeAttr(group.url || '')}"></label>
          <label><span>Interval</span><input type="text" data-field="interval" value="${escapeAttr(group.interval || 300)}"></label>
          <label><span>Timeout</span><input type="text" data-field="timeout" value="${escapeAttr(group.timeout || '')}"></label>
          <label><span>Max Failed Times</span><input type="text" data-field="maxFailedTimes" value="${escapeAttr(group.maxFailedTimes || '')}"></label>
          <label><span>Expected Status</span><input type="text" data-field="expectedStatus" value="${escapeAttr(group.expectedStatus || '')}"></label>
          <label class="checkbox-row"><input type="checkbox" data-field="lazy" ${group.lazy ? 'checked' : ''}> Lazy</label>
        </div>
      ` : ''}
      <div class="form-grid section-grid group-edit-grid group-subsection">
        <label><span>Filter</span><input type="text" data-field="filter" value="${escapeAttr(group.filter || '')}"></label>
        <label><span>Exclude Filter</span><input type="text" data-field="excludeFilter" value="${escapeAttr(group.excludeFilter || '')}"></label>
        <label><span>Exclude Type</span><input type="text" data-field="excludeType" value="${escapeAttr(group.excludeType || '')}"></label>
      </div>
      <div class="form-grid section-grid group-edit-grid group-subsection">
        <label><span>Interface</span><input type="text" data-field="interfaceName" value="${escapeAttr(group.interfaceName || '')}"></label>
        <label><span>Routing Mark</span><input type="text" data-field="routingMark" value="${escapeAttr(group.routingMark || '')}"></label>
        <label><span>Icon</span><input type="text" data-field="icon" value="${escapeAttr(group.icon || '')}"></label>
        <label class="checkbox-row"><input type="checkbox" data-field="disableUdp" ${group.disableUdp ? 'checked' : ''}> Disable UDP</label>
        <label class="checkbox-row"><input type="checkbox" data-field="hidden" ${group.hidden ? 'checked' : ''}> Hidden</label>
        <button type="button" class="ghost-button group-delete-button" data-action="delete">Delete Group</button>
      </div>
    `
    row.addEventListener('input', (event) => handleGroupInput(event, index))
    row.addEventListener('change', (event) => handleGroupInput(event, index))
    row.addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]')?.dataset.action
      if (action === 'select-all-group-proxies') {
        group.proxies = groupProxyOptions(group).map((option) => option.value)
        updateYamlFromModel()
        return
      }
      if (action === 'clear-group-proxies') {
        group.proxies = ['DIRECT']
        updateYamlFromModel()
        return
      }
      if (action === 'select-all-group-providers') {
        group.use = groupProviderOptions().map((option) => option.value)
        updateYamlFromModel()
        return
      }
      if (action === 'clear-group-providers') {
        group.use = []
        updateYamlFromModel()
        return
      }
      if (action === 'delete') {
        const previousName = group.name
        state.model.groups.splice(index, 1)
        if (previousName) {
          removeGroupProxyName(previousName)
          replacePolicyTargetName(previousName, fallbackPolicyTarget())
        }
        updateYamlFromModel()
      }
    })
    groupList.append(row)
  })
  applyPlaceholders(groupList)
}

function groupSupportsHealth(group) {
  return ['url-test', 'fallback', 'load-balance'].includes(group.type)
}

function groupSummaryText(group) {
  const proxyCount = Array.isArray(group.proxies) ? group.proxies.length : 0
  const providerCount = Array.isArray(group.use) ? group.use.length : 0
  const parts = [`${proxyCount} ${proxyCount === 1 ? 'proxy' : 'proxies'}`]
  if (providerCount || group.includeAllProviders) parts.push(`${providerCount} ${providerCount === 1 ? 'provider' : 'providers'}`)
  if (group.includeAll || group.includeAllProxies || group.includeAllProviders) parts.push('include all')
  return parts.join(' · ')
}

function groupProxyOptions(group) {
  const proxyNames = (state.model?.proxies || [])
    .filter((proxy) => proxy.enabled !== false)
    .map((proxy) => proxy.name)
    .filter(Boolean)
  const groupNames = (state.model?.groups || [])
    .map((item) => item.name)
    .filter((name) => name && name !== group.name && !groupReferenceCreatesCycle(group.name, name))
  const selectable = new Set(['DIRECT', 'REJECT', ...proxyNames, ...groupNames])
  const selected = (Array.isArray(group.proxies) ? group.proxies : []).filter((name) => selectable.has(name))

  return uniqueList(['DIRECT', 'REJECT', ...proxyNames, ...groupNames, ...selected])
    .map((value) => ({ value }))
}

function uniqueList(items) {
  return [...new Set(items.map((item) => String(item || '').trim()).filter(Boolean))]
}

function hasDuplicateName(items, name) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item) => String(item?.name || '').trim() === normalizedName)
}

function hasDuplicateNameExcept(items, name, index) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item, itemIndex) => itemIndex !== index && String(item?.name || '').trim() === normalizedName)
}

function hasNameInCollection(items, name) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item) => String(item?.name || '').trim() === normalizedName)
}

function rejectEmptyNameInput(target, previousName, label) {
  if (String(target.value || '').trim()) return false
  target.value = previousName || ''
  showValidation(`${label} name cannot be empty.`, 'error')
  return true
}

function nameHasRuleSeparator(value) {
  return String(value || '').includes(',')
}

function rejectRuleSeparatorNameInput(target, previousName, label) {
  if (!nameHasRuleSeparator(target.value)) return false
  target.value = previousName || ''
  showValidation(`${label} name cannot contain commas.`, 'error')
  return true
}

function validEditableName(name, label) {
  if (!String(name || '').trim()) return `${label} name cannot be empty.`
  if (nameHasRuleSeparator(name)) return `${label} name cannot contain commas.`
  return ''
}

function generatedProviderPath(basePath, name) {
  return `${basePath}/${name}.yaml`
}

function syncGeneratedProviderPath(provider, previousName, nextName, basePath) {
  if (!provider || !previousName || !nextName || previousName === nextName) return
  const previousPath = generatedProviderPath(basePath, previousName)
  if (!provider.path || provider.path === previousPath) provider.path = generatedProviderPath(basePath, nextName)
}

function cleanupEmptyNestedSection(proxy, section, parents) {
  pruneEmptyTransportParents(proxy[section], parents)
  if (isEmptyTransportValue(proxy[section])) delete proxy[section]
}

function renderGroupProxyPicker(group) {
  const selected = new Set(Array.isArray(group.proxies) ? group.proxies : [])
  const options = groupProxyOptions(group)
  return `
    <div class="group-proxy-picker wide-field">
      <span>Proxies</span>
      <div class="picker-toolbar">
        <button type="button" class="ghost-button" data-action="select-all-group-proxies">Select All</button>
        <button type="button" class="ghost-button" data-action="clear-group-proxies">Clear</button>
      </div>
      <div class="checkbox-list dependent-multi-select" role="group" aria-label="Proxies">
        ${options.map((option) => `
          <label class="checkbox-chip">
            <input type="checkbox" data-field="group-proxy-option" value="${escapeAttr(option.value)}" ${selected.has(option.value) ? 'checked' : ''}>
            <span>${escapeHtml(option.value)}</span>
          </label>
        `).join('')}
      </div>
    </div>
  `
}

function groupProviderOptions() {
  const providerNames = (state.model?.proxyProviders || [])
    .map((provider) => provider.name)
    .filter(Boolean)
  return uniqueList(providerNames)
    .map((value) => ({ value }))
}

function renderGroupProviderPicker(group) {
  const selected = new Set(Array.isArray(group.use) ? group.use : [])
  const options = groupProviderOptions()
  return `
    <div class="group-provider-picker wide-field">
      <span>Use Provider</span>
      <div class="picker-toolbar">
        <button type="button" class="ghost-button" data-action="select-all-group-providers" ${options.length ? '' : 'disabled'}>Select All</button>
        <button type="button" class="ghost-button" data-action="clear-group-providers" ${selected.size ? '' : 'disabled'}>Clear</button>
      </div>
      <div class="checkbox-list dependent-multi-select" role="group" aria-label="Use Provider">
        ${options.length ? options.map((option) => `
          <label class="checkbox-chip">
            <input type="checkbox" data-field="group-provider-option" value="${escapeAttr(option.value)}" ${selected.has(option.value) ? 'checked' : ''}>
            <span>${escapeHtml(option.value)}</span>
          </label>
        `).join('') : '<small>No proxy providers yet.</small>'}
      </div>
    </div>
  `
}

function renderRules() {
  rulesEditor.value = state.model?.rules.join('\n') || ''
}

function renderDns() {
  if (!state.model) return
  dnsEnable.checked = state.model.dns.enable !== false
  dnsListen.value = state.model.dns.listen || ''
  dnsCacheAlgorithm.value = state.model.dns.cacheAlgorithm || ''
  dnsPreferH3.checked = Boolean(state.model.dns.preferH3)
  dnsUseHosts.checked = Boolean(state.model.dns.useHosts)
  dnsUseSystemHosts.checked = Boolean(state.model.dns.useSystemHosts)
  dnsRespectRules.checked = Boolean(state.model.dns.respectRules)
  dnsDefault.value = state.model.dns.defaultNameserver.join('\n')
  dnsNameservers.value = state.model.dns.nameserver.join('\n')
  dnsEnhancedMode.value = state.model.dns.enhancedMode || 'redir-host'
  dnsFakeIpRange.value = state.model.dns.fakeIpRange || '198.18.0.1/16'
  dnsFakeIpRange6.value = state.model.dns.fakeIpRange6 || ''
  dnsFakeIpFilterMode.value = state.model.dns.fakeIpFilterMode || ''
  dnsFakeIpTtl.value = state.model.dns.fakeIpTtl || ''
  dnsFakeIpFilter.value = (state.model.dns.fakeIpFilter || []).join('\n')
  dnsFallback.value = (state.model.dns.fallback || []).join('\n')
  dnsFallbackFilter.value = policyToText(state.model.dns.fallbackFilter)
  dnsDirectNameserver.value = (state.model.dns.directNameserver || []).join('\n')
  dnsDirectFollowPolicy.checked = Boolean(state.model.dns.directNameserverFollowPolicy)
  dnsProxyServer.value = (state.model.dns.proxyServerNameserver || []).join('\n')
  dnsProxyPolicy.value = policyToText(state.model.dns.proxyServerNameserverPolicy)
  dnsPolicy.value = policyToText(state.model.dns.nameserverPolicy)
}

function renderGeneral() {
  if (!state.model) return
  generalPort.value = state.model.general.port || ''
  generalSocksPort.value = state.model.general.socksPort || ''
  generalRedirPort.value = state.model.general.redirPort || ''
  generalTproxyPort.value = state.model.general.tproxyPort || ''
  generalMixedPort.value = state.model.general.mixedPort
  generalMode.value = state.model.general.mode
  generalLogLevel.value = state.model.general.logLevel
  generalBindAddress.value = state.model.general.bindAddress
  generalLanAllowedIps.value = (state.model.general.lanAllowedIps || []).join('\n')
  generalLanDisallowedIps.value = (state.model.general.lanDisallowedIps || []).join('\n')
  generalAuthentication.value = (state.model.general.authentication || []).join('\n')
  generalSkipAuthPrefixes.value = (state.model.general.skipAuthPrefixes || []).join('\n')
  generalInterfaceName.value = state.model.general.interfaceName || ''
  generalRoutingMark.value = state.model.general.routingMark || ''
  generalKeepAliveIdle.value = state.model.general.keepAliveIdle || ''
  generalKeepAliveInterval.value = state.model.general.keepAliveInterval || ''
  generalFindProcessMode.value = state.model.general.findProcessMode || ''
  generalController.value = state.model.general.externalController
  generalControllerTls.value = state.model.general.externalControllerTls || ''
  generalControllerUnix.value = state.model.general.externalControllerUnix || ''
  generalControllerPipe.value = state.model.general.externalControllerPipe || ''
  generalControllerCors.value = state.model.general.externalControllerCors || ''
  generalUi.value = state.model.general.externalUi
  generalUiName.value = state.model.general.externalUiName || ''
  generalUiUrl.value = state.model.general.externalUiUrl || ''
  generalSecret.value = state.model.general.secret
  generalClientFingerprint.value = state.model.general.globalClientFingerprint || ''
  generalUa.value = state.model.general.globalUa || ''
  generalTlsCertificate.value = state.model.general.tlsCertificate || ''
  generalTlsPrivateKey.value = state.model.general.tlsPrivateKey || ''
  generalAllowLan.checked = state.model.general.allowLan
  generalIpv6.checked = state.model.general.ipv6
  generalDisableKeepAlive.checked = Boolean(state.model.general.disableKeepAlive)
  generalUnifiedDelay.checked = state.model.general.unifiedDelay
  generalTcpConcurrent.checked = state.model.general.tcpConcurrent
  generalEtagSupport.checked = Boolean(state.model.general.etagSupport)
  profileStoreSelected.checked = state.model.profile.storeSelected
  profileStoreFakeIp.checked = state.model.profile.storeFakeIp
}

function renderSniffer() {
  if (!state.model) return
  snifferEnable.checked = state.model.sniffer.enable
  snifferOverride.checked = state.model.sniffer.overrideDestination
  snifferParseIp.checked = state.model.sniffer.parsePureIp
  snifferForceDnsMapping.checked = Boolean(state.model.sniffer.forceDnsMapping)
  snifferSniff.value = state.model.sniffer.sniff.join('\n')
  snifferForce.value = state.model.sniffer.forceDomain.join('\n')
  snifferSkip.value = state.model.sniffer.skipDomain.join('\n')
  snifferSkipSrc.value = (state.model.sniffer.skipSrcAddress || []).join('\n')
  snifferSkipDst.value = (state.model.sniffer.skipDstAddress || []).join('\n')
}

function renderTun() {
  if (!state.model) return
  tunEnable.checked = state.model.tun.enable
  tunStack.value = state.model.tun.stack
  tunDevice.value = state.model.tun.device || ''
  tunAutoRoute.checked = state.model.tun.autoRoute
  tunAutoRedirect.checked = Boolean(state.model.tun.autoRedirect)
  tunAutoDetect.checked = state.model.tun.autoDetectInterface
  tunStrictRoute.checked = state.model.tun.strictRoute
  tunDnsHijack.value = state.model.tun.dnsHijack.join('\n')
  tunMtu.value = state.model.tun.mtu || ''
  tunGso.checked = Boolean(state.model.tun.gso)
  tunGsoMaxSize.value = state.model.tun.gsoMaxSize || ''
  tunUdpTimeout.value = state.model.tun.udpTimeout || ''
  tunIproute2TableIndex.value = state.model.tun.iproute2TableIndex || ''
  tunIproute2RuleIndex.value = state.model.tun.iproute2RuleIndex || ''
  tunEndpointIndependentNat.checked = Boolean(state.model.tun.endpointIndependentNat)
  tunRouteAddressSet.value = (state.model.tun.routeAddressSet || []).join('\n')
  tunRouteExcludeAddressSet.value = (state.model.tun.routeExcludeAddressSet || []).join('\n')
  tunRouteAddress.value = (state.model.tun.routeAddress || []).join('\n')
  tunRouteExcludeAddress.value = (state.model.tun.routeExcludeAddress || []).join('\n')
  tunIncludeInterface.value = (state.model.tun.includeInterface || []).join('\n')
  tunExcludeInterface.value = (state.model.tun.excludeInterface || []).join('\n')
  tunIncludeUid.value = (state.model.tun.includeUid || []).join('\n')
  tunIncludeUidRange.value = (state.model.tun.includeUidRange || []).join('\n')
  tunExcludeUid.value = (state.model.tun.excludeUid || []).join('\n')
  tunExcludeUidRange.value = (state.model.tun.excludeUidRange || []).join('\n')
  tunIncludeAndroidUser.value = (state.model.tun.includeAndroidUser || []).join('\n')
  tunIncludePackage.value = (state.model.tun.includePackage || []).join('\n')
  tunExcludePackage.value = (state.model.tun.excludePackage || []).join('\n')
}

function renderGeo() {
  if (!state.model) return
  geoGeodataMode.checked = state.model.geo.geodataMode
  geoAutoUpdate.checked = state.model.geo.geoAutoUpdate
  geoUpdateInterval.value = state.model.geo.geoUpdateInterval
  geoUrlGeoip.value = state.model.geo.geoxUrl.geoip
  geoUrlGeosite.value = state.model.geo.geoxUrl.geosite
  geoUrlMmdb.value = state.model.geo.geoxUrl.mmdb
  geoUrlAsn.value = state.model.geo.geoxUrl.asn
}

function renderRuleProviders() {
  ruleProviderList.replaceChildren()
  if (!state.model?.ruleProviders.length) {
    ruleProviderList.classList.add('empty-state')
    ruleProviderList.textContent = 'No custom rule providers yet.'
    return
  }

  ruleProviderList.classList.remove('empty-state')
  state.model.ruleProviders.forEach((provider, index) => {
    const target = validPolicyTarget(provider.target || 'PROXY')
    const row = document.createElement('details')
    row.className = 'editor-field-section provider-row'
    row.open = index === 0
    row.innerHTML = `
      <summary>
        <span class="provider-summary">
          <strong>${escapeHtml(provider.name || 'Unnamed provider')}</strong>
          <em>${escapeHtml(provider.behavior || 'classical')}</em>
          <em>${escapeHtml(provider.target || 'PROXY')}</em>
        </span>
        <small>${escapeHtml(provider.url || provider.path || 'No source configured')}</small>
      </summary>
      <div class="form-grid section-grid provider-edit-grid">
        <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(valueOrEmpty(provider.name))}"></label>
        <label><span>Behavior</span><select data-field="behavior">
          ${['classical', 'domain', 'ipcidr'].map((type) => `<option value="${type}" ${type === provider.behavior ? 'selected' : ''}>${type}</option>`).join('')}
        </select></label>
        <label><span>Target</span><select data-field="target">
          ${renderSelectOptions(policyTargetOptions(), target)}
        </select></label>
        <label><span>Format</span><select data-field="format">
          ${['', 'yaml', 'text', 'mrs'].map((format) => `<option value="${format}" ${format === (provider.format || '') ? 'selected' : ''}>${format || 'default'}</option>`).join('')}
        </select></label>
        <label class="wide-field"><span>URL</span><input type="text" data-field="url" value="${escapeAttr(valueOrEmpty(provider.url))}"></label>
        <label><span>Path</span><input type="text" data-field="path" value="${escapeAttr(valueOrEmpty(provider.path))}"></label>
        <label><span>Interval</span><input type="text" data-field="interval" value="${escapeAttr(valueOrEmpty(provider.interval))}"></label>
        <label><span>Proxy</span><input type="text" data-field="proxy" value="${escapeAttr(provider.proxy || '')}"></label>
      </div>
      <div class="form-grid section-grid provider-edit-grid provider-subsection">
        <label><span>Size Limit</span><input type="text" data-field="sizeLimit" value="${escapeAttr(provider.sizeLimit || '')}"></label>
        <label><span>Header</span><textarea class="mini-editor" data-field="header">${escapeHtml(policyToText(provider.header))}</textarea></label>
        <label class="wide-field"><span>Payload</span><textarea class="mini-editor" data-field="payload">${escapeHtml((provider.payload || []).join('\n'))}</textarea></label>
        <button type="button" class="ghost-button provider-delete-button" data-action="delete">Delete Rule Provider</button>
      </div>
    `
    row.addEventListener('input', (event) => handleRuleProviderInput(event, index))
    row.addEventListener('change', (event) => handleRuleProviderInput(event, index))
    row.addEventListener('click', (event) => {
      if (event.target.closest('[data-action]')?.dataset.action === 'delete') {
        const previousName = state.model.ruleProviders[index]?.name
        state.model.ruleProviders.splice(index, 1)
        if (previousName) removeRuleProviderRules(previousName)
        updateYamlFromModel()
      }
    })
    ruleProviderList.append(row)
  })
  applyPlaceholders(ruleProviderList)
}

function renderProxyProviders() {
  proxyProviderList.replaceChildren()
  if (!state.model?.proxyProviders.length) {
    proxyProviderList.classList.add('empty-state')
    proxyProviderList.textContent = 'No proxy providers yet.'
    return
  }

  proxyProviderList.classList.remove('empty-state')
  state.model.proxyProviders.forEach((provider, index) => {
    const row = document.createElement('details')
    row.className = 'editor-field-section provider-row'
    row.open = index === 0
    row.innerHTML = `
      <summary>
        <span class="provider-summary">
          <strong>${escapeHtml(provider.name || 'Unnamed provider')}</strong>
          <em>${escapeHtml(provider.type || 'http')}</em>
        </span>
        <small>${escapeHtml(provider.url || provider.path || 'No source configured')}</small>
      </summary>
      <div class="form-grid section-grid provider-edit-grid">
        <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(valueOrEmpty(provider.name))}"></label>
        <label><span>Type</span><select data-field="type">
          ${['http', 'file', 'inline'].map((type) => `<option value="${type}" ${type === provider.type ? 'selected' : ''}>${type}</option>`).join('')}
        </select></label>
        <label class="wide-field"><span>URL</span><input type="text" data-field="url" value="${escapeAttr(valueOrEmpty(provider.url))}"></label>
        <label><span>Path</span><input type="text" data-field="path" value="${escapeAttr(valueOrEmpty(provider.path))}"></label>
        <label><span>Interval</span><input type="text" data-field="interval" value="${escapeAttr(valueOrEmpty(provider.interval))}"></label>
        <label><span>Proxy</span><input type="text" data-field="proxy" value="${escapeAttr(provider.proxy || '')}"></label>
        <label><span>Size Limit</span><input type="text" data-field="sizeLimit" value="${escapeAttr(provider.sizeLimit || '')}"></label>
      </div>
      <div class="form-grid section-grid provider-edit-grid provider-subsection">
        <label><span>Filter</span><input type="text" data-field="filter" value="${escapeAttr(provider.filter || '')}"></label>
        <label><span>Exclude Filter</span><input type="text" data-field="excludeFilter" value="${escapeAttr(provider.excludeFilter || '')}"></label>
        <label><span>Exclude Type</span><input type="text" data-field="excludeType" value="${escapeAttr(provider.excludeType || '')}"></label>
      </div>
      <div class="form-grid section-grid provider-edit-grid provider-subsection">
        <label class="checkbox-row"><input type="checkbox" data-field="healthCheckEnable" ${provider.healthCheck?.enable ? 'checked' : ''}> Health Check</label>
        <label class="checkbox-row"><input type="checkbox" data-field="healthCheckLazy" ${provider.healthCheck?.lazy !== false ? 'checked' : ''}> Lazy Health Check</label>
        <label class="wide-field"><span>Health URL</span><input type="text" data-field="healthCheckUrl" value="${escapeAttr(provider.healthCheck?.url || 'https://www.gstatic.com/generate_204')}"></label>
        <label><span>Health Interval</span><input type="text" data-field="healthCheckInterval" value="${escapeAttr(provider.healthCheck?.interval || 300)}"></label>
        <label><span>Health Timeout</span><input type="text" data-field="healthCheckTimeout" value="${escapeAttr(provider.healthCheck?.timeout || 5000)}"></label>
        <label><span>Expected Status</span><input type="text" data-field="healthCheckExpectedStatus" value="${escapeAttr(provider.healthCheck?.expectedStatus || '')}"></label>
      </div>
      <div class="form-grid section-grid provider-edit-grid provider-subsection">
        <label><span>Header</span><textarea class="mini-editor" data-field="header">${escapeHtml(policyToText(provider.header))}</textarea></label>
        <label><span>Override</span><textarea class="mini-editor" data-field="override">${escapeHtml(policyToText(provider.override))}</textarea></label>
        <label class="wide-field"><span>Inline Payload</span><textarea class="mini-editor" data-field="payload">${escapeHtml(JSON.stringify(provider.payload || [], null, 2))}</textarea></label>
        <button type="button" class="ghost-button provider-delete-button" data-action="delete">Delete Provider</button>
      </div>
    `
    row.addEventListener('input', (event) => handleProxyProviderInput(event, index))
    row.addEventListener('change', (event) => handleProxyProviderInput(event, index))
    row.addEventListener('click', (event) => {
      if (event.target.closest('[data-action]')?.dataset.action === 'delete') {
        const previousName = state.model.proxyProviders[index]?.name
        state.model.proxyProviders.splice(index, 1)
        if (previousName) removeGroupProviderName(previousName)
        updateYamlFromModel()
      }
    })
    proxyProviderList.append(row)
  })
  applyPlaceholders(proxyProviderList)
}

function handleNodeClick(event, index) {
  const actionTarget = event.target.closest('[data-action]')
  const action = actionTarget?.dataset.action
  if (!action) return
  const proxy = state.model?.proxies[index]
  if (action === 'toggle-node' && proxy) {
    const key = nodeExpansionKey(proxy)
    if (state.expandedNodeKeys.has(key)) state.expandedNodeKeys.delete(key)
    else state.expandedNodeKeys.add(key)
    renderNodes()
    return
  }
  if (action === 'up') moveNodeByVisibleOffset(index, -1)
  if (action === 'down') moveNodeByVisibleOffset(index, 1)
  if (action === 'delete') {
    const previousName = proxy?.name
    if (proxy) state.expandedNodeKeys.delete(nodeExpansionKey(proxy))
    state.model.proxies.splice(index, 1)
    if (previousName) {
      pruneGroupProxyRefs(new Set(state.model.proxies.filter((item) => item.enabled !== false).map((item) => item.name)))
      replacePolicyTargetName(previousName, fallbackPolicyTarget())
    }
    updateYamlFromModel()
  }
}

function handleNodeInput(event, index) {
  const field = event.target.dataset.field
  if (!field || !state.model?.proxies[index]) return
  const proxy = state.model.proxies[index]
  const previousName = proxy.name

  if (field === 'rawJson') {
    try {
      const parsed = JSON.parse(event.target.value)
      if (!isPlainObject(parsed)) throw new Error('Node Raw JSON must be an object.')
      if (!String(parsed.name || '').trim()) {
        showValidation('Node Raw JSON must include a non-empty name.', 'error')
        return
      }
      if (nameHasRuleSeparator(parsed.name)) {
        showValidation('Node Raw JSON name cannot contain commas.', 'error')
        return
      }
      if (hasDuplicateNameExcept(state.model.proxies, parsed.name, index)) {
        showValidation(`Node "${String(parsed.name || '').trim()}" already exists.`, 'error')
        return
      }
      if (hasNameInCollection(state.model.groups, parsed.name)) {
        showValidation(`Node name "${String(parsed.name || '').trim()}" conflicts with a group name.`, 'error')
        return
      }
      state.model.proxies[index] = { ...parsed, enabled: proxy.enabled !== false }
      const nextName = state.model.proxies[index].name
      if (nextName) replaceGroupProxyName(previousName, nextName)
      else removeGroupProxyName(previousName)
      replacePolicyTargetName(previousName, nextName || fallbackPolicyTarget())
      clearValidation()
      renderGroups()
      renderRuleTargetOptions()
      updateYamlFromModel(false)
    } catch {
      showValidation('Node Raw JSON is invalid.', 'error')
    }
    return
  }

  if (field === 'name' && rejectEmptyNameInput(event.target, previousName, 'Node')) return
  if (field === 'name' && rejectRuleSeparatorNameInput(event.target, previousName, 'Node')) return
  if (field === 'name' && hasDuplicateNameExcept(state.model.proxies, event.target.value, index)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Node "${attemptedName}" already exists.`, 'error')
    return
  }
  if (field === 'name' && hasNameInCollection(state.model.groups, event.target.value)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Node name "${attemptedName}" conflicts with a group name.`, 'error')
    return
  }

  if (field === 'alpn-option') {
    updateAlpnSelection(proxy, event.target.value, event.target.checked)
    updateYamlFromModel()
    return
  }

  if (field.startsWith('nested:')) {
    if (updateNestedProxyField(proxy, field, event.target) === false) return
  } else if (field.startsWith('transport:')) {
    if (updateTransportField(proxy, field, event.target) === false) return
  } else if (event.target.type === 'checkbox') {
    proxy[field] = event.target.checked
    if (field === 'enabled') {
      if (!event.target.checked && proxy.name) {
        const keptNames = new Set(state.model.proxies.filter((item) => item.enabled !== false).map((item) => item.name))
        pruneGroupProxyRefs(keptNames)
        replacePolicyTargetName(proxy.name, fallbackPolicyTarget())
      }
      renderGroups()
      renderRuleTargetOptions()
      refreshRenderedRuleProviderTargets()
    }
    if (field === 'tls') {
      if (!event.target.checked) cleanupDisabledTlsFields(proxy)
      toggleNodeTlsFields(event.target.closest('.tls-fields'), event.target.checked)
    }
  } else if (field === 'port') {
    proxy.port = Number(event.target.value) || event.target.value
  } else if (field.endsWith(':number')) {
    const key = field.replace(/:number$/, '')
    const value = Number(event.target.value)
    if (Number.isFinite(value) && event.target.value.trim() !== '') proxy[key] = value
    else delete proxy[key]
  } else if (field.endsWith(':policy')) {
    const key = field.replace(/:policy$/, '')
    const value = textToPolicy(event.target.value)
    if (Object.keys(value).length) proxy[key] = value
    else delete proxy[key]
  } else if (field.endsWith(':json')) {
    const key = field.replace(/:json$/, '')
    const value = parseJsonObjectInput(event.target.value, key)
    if (value === invalidEditorInput) return
    if (Object.keys(value).length) proxy[key] = value
    else delete proxy[key]
  } else if (field === 'sni') {
    proxy.sni = event.target.value
    proxy.servername = event.target.value
  } else if (field === 'type') {
    proxy.type = normalizeProxyType(event.target.value)
    cleanupProtocolSpecificFields(proxy)
    applyProtocolDefaults(proxy)
    cleanupUnsupportedTlsFields(proxy)
    if (!needsEndpoint(proxy)) {
      delete proxy.server
      delete proxy.port
    }
    if (!isNetworkSupported(proxy, proxy.network)) {
      delete proxy.network
      cleanupTransportOptions(proxy)
    }
    updateYamlFromModel()
    return
  } else if (field === 'network') {
    setProxyNetwork(proxy, event.target.value)
    updateYamlFromModel()
    return
  } else if (['flow', 'udp-relay-mode', 'congestion-controller'].includes(field) && !event.target.value) {
    delete proxy[field]
  } else if (['certificate', 'private-key', 'fingerprint', 'client-fingerprint'].includes(field)) {
    if (event.target.value) proxy[field] = event.target.value
    else delete proxy[field]
  } else if (field.endsWith(':list')) {
    const key = field.replace(/:list$/, '')
    const value = splitLinesOrComma(event.target.value)
    if (value.length) proxy[key] = value
    else delete proxy[key]
  } else {
    proxy[field] = event.target.value
  }

  if (field === 'name') {
    if (proxy.name) replaceGroupProxyName(previousName, proxy.name)
    else removeGroupProxyName(previousName)
    replacePolicyTargetName(previousName, proxy.name || fallbackPolicyTarget())
    renderGroups()
    renderRuleTargetOptions()
  }
  syncWireGuardPeerField(proxy, field)
  if (field === 'plugin') updateShadowsocksPluginOptsPlaceholder(event.target.closest('.node-row'), proxy.plugin)
  updateYamlFromModel(false)
}

function handleGroupInput(event, index) {
  const field = event.target.dataset.field
  if (!field || !state.model?.groups[index]) return
  const group = state.model.groups[index]
  const previousName = group.name
  if (field === 'name' && rejectEmptyNameInput(event.target, previousName, 'Group')) return
  if (field === 'name' && rejectRuleSeparatorNameInput(event.target, previousName, 'Group')) return
  if (field === 'name' && hasDuplicateNameExcept(state.model.groups, event.target.value, index)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Group "${attemptedName}" already exists.`, 'error')
    return
  }
  if (field === 'name' && hasNameInCollection(state.model.proxies, event.target.value)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Group name "${attemptedName}" conflicts with a node name.`, 'error')
    return
  }
  if (field === 'group-proxy-option') group.proxies = readGroupProxySelection(event.currentTarget)
  else if (field === 'group-provider-option') group.use = readGroupProviderSelection(event.currentTarget)
  else if (field === 'proxies') group.proxies = splitLinesOrComma(event.target.value)
  else if (field === 'use') group.use = splitLinesOrComma(event.target.value)
  else if (field === 'interval') group.interval = Number(event.target.value) || 300
  else if (field === 'timeout') group.timeout = Number(event.target.value) || 0
  else if (field === 'maxFailedTimes') group.maxFailedTimes = Number(event.target.value) || 0
  else if (field === 'routingMark') group.routingMark = Number(event.target.value) || 0
  else if (event.target.type === 'checkbox') group[field] = event.target.checked
  else group[field] = event.target.value
  if (field === 'name') {
    if (group.name) replaceGroupProxyName(previousName, group.name)
    else removeGroupProxyName(previousName)
    replacePolicyTargetName(previousName, group.name || fallbackPolicyTarget())
    renderRuleTargetOptions()
  }
  if (field === 'type') {
    updateYamlFromModel()
    return
  }
  updateYamlFromModel(false)
}

function readGroupProxySelection(row) {
  return [...row.querySelectorAll('[data-field="group-proxy-option"]:checked')]
    .map((input) => input.value)
    .filter(Boolean)
}

function readGroupProviderSelection(row) {
  return [...row.querySelectorAll('[data-field="group-provider-option"]:checked')]
    .map((input) => input.value)
    .filter(Boolean)
}

function handleRuleProviderInput(event, index) {
  const field = event.target.dataset.field
  if (!field || !state.model?.ruleProviders[index]) return
  const provider = state.model.ruleProviders[index]
  const previousName = provider.name
  if (field === 'name' && rejectEmptyNameInput(event.target, previousName, 'Rule provider')) return
  if (field === 'name' && rejectRuleSeparatorNameInput(event.target, previousName, 'Rule provider')) return
  if (field === 'name' && hasDuplicateNameExcept(state.model.ruleProviders, event.target.value, index)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Rule provider "${attemptedName}" already exists.`, 'error')
    return
  }
  if (field === 'interval') provider.interval = Number(event.target.value) || 86400
  else if (field === 'sizeLimit') provider.sizeLimit = Number(event.target.value) || 0
  else if (field === 'header') provider.header = textToPolicy(event.target.value)
  else if (field === 'payload') provider.payload = splitLines(event.target.value)
  else if (field === 'target') {
    provider.target = validPolicyTarget(event.target.value)
    event.target.value = provider.target
  }
  else provider[field] = event.target.value
  if (field === 'name') {
    if (provider.name) {
      syncGeneratedProviderPath(provider, previousName, provider.name, './rules')
      replaceProviderRuleName(previousName, provider.name)
    }
    else removeRuleProviderRules(previousName)
  }
  if (field === 'target') syncProviderRule(provider.name, provider.target)
  updateYamlFromModel(false)
}

function handleProxyProviderInput(event, index) {
  const field = event.target.dataset.field
  if (!field || !state.model?.proxyProviders[index]) return
  const provider = state.model.proxyProviders[index]
  const previousName = provider.name
  if (field === 'name' && rejectEmptyNameInput(event.target, previousName, 'Proxy provider')) return
  if (field === 'name' && rejectRuleSeparatorNameInput(event.target, previousName, 'Proxy provider')) return
  if (field === 'name' && hasDuplicateNameExcept(state.model.proxyProviders, event.target.value, index)) {
    const attemptedName = String(event.target.value || '').trim()
    event.target.value = previousName || ''
    showValidation(`Proxy provider "${attemptedName}" already exists.`, 'error')
    return
  }
  provider.healthCheck = provider.healthCheck || {}
  if (field === 'interval') provider.interval = Number(event.target.value) || 3600
  else if (field === 'sizeLimit') provider.sizeLimit = Number(event.target.value) || 0
  else if (field === 'header') provider.header = textToPolicy(event.target.value)
  else if (field === 'override') provider.override = textToPolicy(event.target.value, { typedValues: true })
  else if (field === 'payload') provider.payload = parseJsonOrLines(event.target.value)
  else if (field === 'healthCheckEnable') provider.healthCheck.enable = event.target.checked
  else if (field === 'healthCheckUrl') provider.healthCheck.url = event.target.value
  else if (field === 'healthCheckInterval') provider.healthCheck.interval = Number(event.target.value) || 300
  else if (field === 'healthCheckTimeout') provider.healthCheck.timeout = Number(event.target.value) || 5000
  else if (field === 'healthCheckExpectedStatus') provider.healthCheck.expectedStatus = event.target.value
  else if (field === 'healthCheckLazy') provider.healthCheck.lazy = event.target.checked
  else provider[field] = event.target.value
  if (field === 'name') {
    if (provider.name) {
      syncGeneratedProviderPath(provider, previousName, provider.name, './proxy_providers')
      replaceGroupProviderName(previousName, provider.name)
    }
    else removeGroupProviderName(previousName)
    renderGroups()
  }
  updateYamlFromModel(false)
}

function upsertRuleProvider(provider) {
  const existing = state.model.ruleProviders.find((item) => item.name === provider.name)
  if (existing) Object.assign(existing, provider)
  else state.model.ruleProviders.push(provider)
}

function ensureRule(rule, beforeMatch = false) {
  if (!state.model.rules.includes(rule)) {
    if (beforeMatch) {
      const matchIndex = state.model.rules.findIndex((item) => item.startsWith('MATCH,'))
      if (matchIndex >= 0) state.model.rules.splice(matchIndex, 0, rule)
      else state.model.rules.push(rule)
      return
    }
    state.model.rules.push(rule)
  }
}

function ensureMatchRule() {
  if (!state.model.rules.some((rule) => rule.startsWith('MATCH,'))) state.model.rules.push('MATCH,PROXY')
}

function policyTargetOptions() {
  const groupNames = (state.model?.groups || [])
    .map((group) => group.name)
    .filter((name) => name && !nameHasRuleSeparator(name))
  const proxyNames = (state.model?.proxies || [])
    .filter((proxy) => proxy.enabled !== false)
    .map((proxy) => proxy.name)
    .filter((name) => name && !nameHasRuleSeparator(name))
  return uniqueList(['PROXY', 'DIRECT', 'REJECT', 'GLOBAL', ...groupNames, ...proxyNames])
}

function renderRuleTargetOptions() {
  const options = policyTargetOptions()
  const ruleTarget = validPolicyTarget(ruleBuilderTarget.value, options)
  const providerTarget = validPolicyTarget(ruleProviderTarget.value, options)
  ruleBuilderTarget.innerHTML = renderSelectOptions(options, ruleTarget)
  ruleProviderTarget.innerHTML = renderSelectOptions(options, providerTarget)
  updateRuleBuilderState()
}

function validPolicyTarget(value, options = policyTargetOptions()) {
  return options.includes(value) ? value : fallbackPolicyTarget()
}

function addRuleFromBuilder() {
  if (!state.model) return
  const type = ruleBuilderType.value
  const value = ruleBuilderValue.value.trim()
  const target = validPolicyTarget(ruleBuilderTarget.value)
  if (type !== 'MATCH' && !value) {
    showValidation('Rule value is required.', 'error')
    return
  }
  if (type === 'RULE-SET' && nameHasRuleSeparator(value)) {
    showValidation('RULE-SET provider name cannot contain commas.', 'error')
    return
  }
  if (type !== 'MATCH' && /[\r\n]/.test(value)) {
    showValidation('Rule value must be a single line.', 'error')
    return
  }
  const rule = type === 'MATCH' ? `MATCH,${target}` : `${type},${value},${target}`
  ensureRule(rule, type !== 'MATCH')
  ruleBuilderValue.value = ''
  updateYamlFromModel()
  showToast('Rule added.')
}

function updateRuleBuilderState() {
  const matchRule = ruleBuilderType.value === 'MATCH'
  ruleBuilderValue.disabled = matchRule
  ruleBuilderValue.placeholder = matchRule ? 'MATCH has no value' : rulePlaceholderForType(ruleBuilderType.value)
}

function rulePlaceholderForType(type) {
  if (type === 'IP-CIDR') return '1.1.1.0/24'
  if (type === 'GEOIP') return 'ID'
  if (type === 'GEOSITE') return 'category-ads-all'
  if (type === 'RULE-SET') return 'provider-name'
  return 'example.com'
}

function syncProviderRule(name, target) {
  if (!name) return
  const ruleMatchesProvider = (rule) => {
    const [type, providerName] = splitRuleParts(rule)
    return type === 'RULE-SET' && providerName === name
  }
  const ruleTarget = validPolicyTarget(target)
  const index = state.model.rules.findIndex(ruleMatchesProvider)
  if (index >= 0) state.model.rules[index] = `RULE-SET,${name},${ruleTarget}`
  else ensureRule(`RULE-SET,${name},${ruleTarget}`, true)
  renderRules()
}

function replaceProviderRuleName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName) return
  state.model.rules = state.model.rules.map((rule) => {
    const parts = splitRuleParts(rule)
    if (parts[0] === 'RULE-SET' && parts[1] === previousName) {
      parts[1] = nextName
      return parts.join(',')
    }
    return rule
  })
  mapSubRuleRules((rule) => {
    const parts = splitRuleParts(rule)
    if (parts[0] === 'RULE-SET' && parts[1] === previousName) {
      parts[1] = nextName
      return parts.join(',')
    }
    return rule
  })
  renderRules()
}

function removeRuleProviderRules(name) {
  if (!name || !state.model) return
  state.model.rules = state.model.rules.filter((rule) => {
    const parts = splitRuleParts(rule)
    return !(parts[0] === 'RULE-SET' && parts[1] === name)
  })
  mapSubRuleRules((rule) => {
    const parts = splitRuleParts(rule)
    return parts[0] === 'RULE-SET' && parts[1] === name ? '' : rule
  })
  renderRules()
}

function replacePolicyTargetName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  state.model.rules = state.model.rules.map((rule) => replaceRuleTargetName(rule, previousName, nextName))
  mapSubRuleRules((rule) => replaceRuleTargetName(rule, previousName, nextName))
  state.model.ruleProviders.forEach((provider) => {
    if (provider.target === previousName) provider.target = nextName
    if (provider.proxy === previousName) provider.proxy = nextName
  })
  state.model.proxyProviders.forEach((provider) => {
    if (provider.proxy === previousName) provider.proxy = nextName
  })
  state.model.tunnels.forEach((tunnel) => {
    if (tunnel.proxy === previousName) tunnel.proxy = nextName
  })
  renderRules()
  renderRuleTargetOptions()
  refreshRenderedRuleProviderTargets()
}

function replacePolicyTargetNames(renameMap) {
  if (!state.model || !renameMap.size) return
  state.model.rules = state.model.rules.map((rule) => {
    let nextRule = rule
    for (const [previousName, nextName] of renameMap) {
      nextRule = replaceRuleTargetName(nextRule, previousName, nextName)
    }
    return nextRule
  })
  mapSubRuleRules((rule) => {
    let nextRule = rule
    for (const [previousName, nextName] of renameMap) {
      nextRule = replaceRuleTargetName(nextRule, previousName, nextName)
    }
    return nextRule
  })
  state.model.ruleProviders.forEach((provider) => {
    if (renameMap.has(provider.target)) provider.target = renameMap.get(provider.target)
    if (renameMap.has(provider.proxy)) provider.proxy = renameMap.get(provider.proxy)
  })
  state.model.proxyProviders.forEach((provider) => {
    if (renameMap.has(provider.proxy)) provider.proxy = renameMap.get(provider.proxy)
  })
  state.model.tunnels.forEach((tunnel) => {
    if (renameMap.has(tunnel.proxy)) tunnel.proxy = renameMap.get(tunnel.proxy)
  })
  renderRules()
  renderRuleTargetOptions()
  refreshRenderedRuleProviderTargets()
}

function replaceRemovedPolicyTargets(removedNames, nextName) {
  if (!state.model || !removedNames.size || !nextName) return
  state.model.rules = state.model.rules.map((rule) => {
    let nextRule = rule
    for (const previousName of removedNames) {
      nextRule = replaceRuleTargetName(nextRule, previousName, nextName)
    }
    return nextRule
  })
  mapSubRuleRules((rule) => {
    let nextRule = rule
    for (const previousName of removedNames) {
      nextRule = replaceRuleTargetName(nextRule, previousName, nextName)
    }
    return nextRule
  })
  state.model.ruleProviders.forEach((provider) => {
    if (removedNames.has(provider.target)) provider.target = nextName
    if (removedNames.has(provider.proxy)) provider.proxy = nextName
  })
  state.model.proxyProviders.forEach((provider) => {
    if (removedNames.has(provider.proxy)) provider.proxy = nextName
  })
  state.model.tunnels.forEach((tunnel) => {
    if (removedNames.has(tunnel.proxy)) tunnel.proxy = nextName
  })
  renderRules()
  renderRuleTargetOptions()
  refreshRenderedRuleProviderTargets()
}

function mapSubRuleRules(mapper) {
  if (!state.model?.subRules) return
  for (const [name, rules] of Object.entries(state.model.subRules)) {
    if (!Array.isArray(rules)) continue
    state.model.subRules[name] = rules.map(mapper).map((rule) => String(rule).trim()).filter(Boolean)
  }
}

function replaceRuleTargetName(rule, previousName, nextName) {
  const parts = splitRuleParts(rule)
  if (parts[0] === 'SUB-RULE') return rule
  const targetIndex = parts[0] === 'MATCH' ? 1 : 2
  if (parts[targetIndex] === previousName) parts[targetIndex] = nextName
  return parts.join(',')
}

function splitRuleParts(rule) {
  const parts = []
  let current = ''
  let depth = 0
  for (const char of String(rule)) {
    if (char === '(') depth += 1
    else if (char === ')' && depth > 0) depth -= 1

    if (char === ',' && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else {
      current += char
    }
  }
  parts.push(current.trim())
  return parts
}

function fallbackPolicyTarget() {
  if (!state.model) return 'DIRECT'
  return state.model.groups.find((group) => group.name && !nameHasRuleSeparator(group.name))?.name || 'DIRECT'
}

function refreshRenderedRuleProviderTargets() {
  if (!state.model) return
  const options = policyTargetOptions()
  ruleProviderList.querySelectorAll('select[data-field="target"]').forEach((select, index) => {
    const provider = state.model.ruleProviders[index]
    if (!provider) return
    const target = provider.target || 'PROXY'
    const validTarget = validPolicyTarget(target, options)
    provider.target = validTarget
    select.innerHTML = renderSelectOptions(options, validTarget)
  })
}

function normalizeEditorModel() {
  if (!state.model) return
  const options = policyTargetOptions()
  state.model.ruleProviders.forEach((provider) => {
    provider.target = validPolicyTarget(provider.target || 'PROXY', options)
    if (provider.proxy && !options.includes(provider.proxy)) provider.proxy = ''
  })
  state.model.proxyProviders.forEach((provider) => {
    if (provider.proxy && !options.includes(provider.proxy)) provider.proxy = ''
  })
  state.model.tunnels.forEach((tunnel) => {
    if (tunnel.proxy && !options.includes(tunnel.proxy)) tunnel.proxy = ''
  })
  const enabledProxyNames = new Set(state.model.proxies.filter((proxy) => proxy.enabled !== false).map((proxy) => proxy.name).filter(Boolean))
  pruneGroupProxyRefs(enabledProxyNames)
  const proxyProviderNames = new Set(state.model.proxyProviders.map((provider) => provider.name).filter(Boolean))
  state.model.groups.forEach((group) => {
    group.use = (Array.isArray(group.use) ? group.use : []).filter((name) => proxyProviderNames.has(name))
  })
}

function syncWireGuardPeerField(proxy, field) {
  if (normalizeProxyType(proxy?.type) !== 'wireguard') return
  if (!['server', 'port', 'public-key', 'presharedKey', 'allowedIPs'].includes(field)) return
  proxy.peers = Array.isArray(proxy.peers) && proxy.peers.length ? proxy.peers : [{}]
  const peer = proxy.peers[0]
  if (field === 'server') peer.server = proxy.server
  else if (field === 'port') peer.port = proxy.port
  else if (field === 'public-key') peer['public-key'] = proxy['public-key']
  else if (field === 'presharedKey') {
    if (proxy.presharedKey) peer.presharedKey = proxy.presharedKey
    else delete peer.presharedKey
  } else if (field === 'allowedIPs') {
    if (Array.isArray(proxy.allowedIPs) && proxy.allowedIPs.length) peer.allowedIPs = proxy.allowedIPs
    else delete peer.allowedIPs
  }
  proxy.peers[0] = compactManualObject(peer)
}

function moveNode(from, to) {
  if (!state.model || from < 0 || to < 0 || from >= state.model.proxies.length || to >= state.model.proxies.length) return
  const [item] = state.model.proxies.splice(from, 1)
  state.model.proxies.splice(to, 0, item)
  updateYamlFromModel()
}

function moveNodeByVisibleOffset(index, offset) {
  const visibleIndexes = filteredNodeEntries().map((entry) => entry.index)
  const visibleIndex = visibleIndexes.indexOf(index)
  const targetIndex = visibleIndexes[visibleIndex + offset]
  if (targetIndex === undefined) return
  moveNode(index, targetIndex)
}

function openNodeTools() {
  if (!state.model) return
  nodeToolsSheet.hidden = false
}

function closeNodeTools() {
  nodeToolsSheet.hidden = true
}

function applyBulkRename() {
  if (!state.model) return
  const pattern = bulkRenamePattern.value.trim() || '{name}'
  const previousNames = state.model.proxies.map((proxy) => proxy.name)
  const renameMap = new Map()
  state.model.proxies.forEach((proxy, index) => {
    proxy.name = formatNodeName(proxy, index, pattern)
  })
  makeLocalUniqueNames(state.model.proxies)
  state.model.proxies.forEach((proxy, index) => {
    if (previousNames[index] && proxy.name) renameMap.set(previousNames[index], proxy.name)
  })
  replaceGroupProxyNames(renameMap)
  replacePolicyTargetNames(renameMap)
  updateYamlFromModel()
  showToast('Bulk rename applied.')
}

function handleTokenClick(event) {
  const token = event.target.dataset.token
  if (!token) return
  const target = document.querySelector(`#${event.currentTarget.dataset.tokenTarget}`)
  if (!target) return
  insertAtCursor(target, token)
  target.dispatchEvent(new Event('input', { bubbles: true }))
  target.focus()
}

function insertAtCursor(inputElement, text) {
  const start = inputElement.selectionStart ?? inputElement.value.length
  const end = inputElement.selectionEnd ?? inputElement.value.length
  const before = inputElement.value.slice(0, start)
  const after = inputElement.value.slice(end)
  const prefix = before && !before.endsWith(' ') ? ' ' : ''
  const suffix = after && !after.startsWith(' ') ? ' ' : ''
  const inserted = `${prefix}${text}${suffix}`
  inputElement.value = `${before}${inserted}${after}`
  const cursor = before.length + inserted.length
  inputElement.setSelectionRange(cursor, cursor)
}

function sortNodes() {
  if (!state.model) return
  const field = nodeSortField.value
  state.model.proxies.sort((left, right) => String(left[field] || '').localeCompare(String(right[field] || '')))
  updateYamlFromModel()
  showToast('Nodes sorted.')
}

function deleteDuplicateNodes() {
  if (!state.model) return
  const seen = new Set()
  const keptNames = new Set()
  const removedNames = new Set()
  const before = state.model.proxies.length
  state.model.proxies = state.model.proxies.filter((proxy) => {
    const key = proxySignature(proxy)
    if (seen.has(key)) {
      if (proxy.name) removedNames.add(proxy.name)
      return false
    }
    seen.add(key)
    if (proxy.enabled !== false) keptNames.add(proxy.name)
    return true
  })
  pruneGroupProxyRefs(keptNames)
  replaceRemovedPolicyTargets(removedNames, fallbackPolicyTarget())
  updateYamlFromModel()
  showToast(`${before - state.model.proxies.length} duplicate nodes removed.`)
}

function setNodesByKeyword(enabled) {
  if (!state.model) return
  const keyword = nodeKeywordInput.value.trim().toLowerCase()
  if (!keyword) {
    showValidation('Node keyword is required.', 'warning')
    return
  }
  let changed = 0
  const disabledNames = new Set()
  for (const proxy of state.model.proxies) {
    const haystack = [proxy.name, proxy.type, proxy.server].join(' ').toLowerCase()
    if (haystack.includes(keyword)) {
      if (!enabled && proxy.enabled !== false && proxy.name) disabledNames.add(proxy.name)
      proxy.enabled = enabled
      changed += 1
    }
  }
  if (disabledNames.size) {
    const keptNames = new Set(state.model.proxies.filter((proxy) => proxy.enabled !== false).map((proxy) => proxy.name))
    pruneGroupProxyRefs(keptNames)
    replaceRemovedPolicyTargets(disabledNames, fallbackPolicyTarget())
  }
  renderRuleTargetOptions()
  refreshRenderedRuleProviderTargets()
  updateYamlFromModel()
  showToast(`${changed} nodes updated.`)
}

function addGroup() {
  if (!state.model) return
  const name = groupNameInput.value.trim() || `GROUP ${state.model.groups.length + 1}`
  const nameIssue = validEditableName(name, 'Group')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.groups, name)) {
    showValidation(`Group "${name}" already exists.`, 'error')
    return
  }
  if (hasNameInCollection(state.model.proxies, name)) {
    showValidation(`Group name "${name}" conflicts with a node name.`, 'error')
    return
  }
  const enabledNames = state.model.proxies.filter((proxy) => proxy.enabled !== false).map((proxy) => proxy.name)
  state.model.groups.push({
    name,
    type: groupTypeInput.value,
    proxies: enabledNames,
    url: 'http://www.gstatic.com/generate_204',
    interval: 300,
  })
  groupNameInput.value = ''
  updateYamlFromModel()
}

function addRuleProvider() {
  if (!state.model) return
  const name = ruleProviderName.value.trim()
  const url = ruleProviderUrl.value.trim()
  if (!name || !url) {
    showValidation('Rule provider requires name and URL.', 'error')
    return
  }
  const nameIssue = validEditableName(name, 'Rule provider')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.ruleProviders, name)) {
    showValidation(`Rule provider "${name}" already exists.`, 'error')
    return
  }
  const target = validPolicyTarget(ruleProviderTarget.value)
  state.model.ruleProviders.push({
    name,
    type: 'http',
    behavior: ruleProviderBehavior.value,
    path: generatedProviderPath('./rules', name),
    url,
    target,
    format: ruleProviderFormat.value,
    interval: 86400,
  })
  ensureRule(`RULE-SET,${name},${target}`)
  ruleProviderName.value = ''
  ruleProviderUrl.value = ''
  updateYamlFromModel()
}

function addProxyProvider() {
  if (!state.model) return
  const name = proxyProviderName.value.trim()
  const nameIssue = validEditableName(name, 'Proxy provider')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.proxyProviders, name)) {
    showValidation(`Proxy provider "${name}" already exists.`, 'error')
    return
  }
  state.model.proxyProviders.push({
    name,
    type: proxyProviderType.value,
    url: proxyProviderUrl.value.trim(),
    path: generatedProviderPath('./proxy_providers', name),
    interval: 3600,
    healthCheck: {
      enable: true,
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      timeout: 5000,
      lazy: true,
      expectedStatus: '204',
    },
  })
  proxyProviderName.value = ''
  proxyProviderUrl.value = ''
  updateYamlFromModel()
}

function renderManualNodeFields(values = {}) {
  manualNodeFields.replaceChildren()
  for (const field of manualNodeFieldDefinitions(manualNodeType.value, values)) {
    manualNodeFields.insertAdjacentHTML('beforeend', renderManualNodeField(field, values))
  }
  applyPlaceholders(manualNodeFields)
}

function manualNodeFieldDefinitions(type, values = {}) {
  const fields = []
  if (needsManualEndpoint(type)) {
    fields.push(
      { key: 'server', label: 'Server', required: true },
      { key: 'port', label: 'Port', required: true },
    )
  }

  const byType = {
    vless: [
      { key: 'uuid', label: 'UUID', required: true },
      { key: 'flow', label: 'Flow', type: 'select', options: vlessFlowOptions, defaultValue: '' },
      { key: 'packet-encoding', label: 'Packet Encoding', type: 'select', options: packetEncodingOptions, defaultValue: '' },
      { key: 'encryption', label: 'Encryption', placeholder: 'none or advanced VLESS encryption string' },
      ...manualTransportFields(type, values),
      ...manualTlsFields(),
      ...manualCommonProxyFields(type),
    ],
    vmess: [
      { key: 'uuid', label: 'UUID', required: true },
      { key: 'cipher', label: 'Cipher', type: 'select', options: vmessCipherOptions, defaultValue: 'auto' },
      { key: 'alterId', label: 'Alter ID', defaultValue: '0' },
      { key: 'packet-encoding', label: 'Packet Encoding', type: 'select', options: packetEncodingOptions, defaultValue: '' },
      { key: 'global-padding', label: 'Global Padding', type: 'checkbox' },
      { key: 'authenticated-length', label: 'Authenticated Length', type: 'checkbox' },
      ...manualTransportFields(type, values),
      ...manualTlsFields(),
      ...manualCommonProxyFields(type),
    ],
    trojan: [
      { key: 'password', label: 'Password', required: true },
      { key: 'ss.enabled', label: 'ss-opts.enabled', type: 'checkbox' },
      { key: 'ss.method', label: 'ss-opts.method', type: 'select', options: trojanSsMethodOptions, defaultValue: '' },
      { key: 'ss.password', label: 'ss-opts.password' },
      ...manualTransportFields(type, values),
      ...manualTlsFields(),
      ...manualCommonProxyFields(type),
    ],
    ss: [
      { key: 'cipher', label: 'Cipher', type: 'select', options: shadowsocksCipherOptions, defaultValue: 'aes-128-gcm', required: true },
      { key: 'password', label: 'Password', required: true },
      { key: 'udp-over-tcp', label: 'UDP over TCP', type: 'checkbox' },
      { key: 'udp-over-tcp-version', label: 'UDP over TCP Version', type: 'select', options: ['', '1', '2'], defaultValue: '' },
      { key: 'plugin', label: 'Plugin', type: 'select', options: shadowsocksPluginOptions, defaultValue: '' },
      { key: 'plugin-opts', label: 'Plugin opts', type: 'textarea', wide: true, placeholder: shadowsocksPluginOptExample(values.plugin) },
      ...manualCommonProxyFields(type),
    ],
    ssr: [
      { key: 'cipher', label: 'Cipher', type: 'select', options: ssrCipherOptions, defaultValue: 'chacha20-ietf', required: true },
      { key: 'password', label: 'Password', required: true },
      { key: 'protocol', label: 'Protocol', type: 'select', options: ssrProtocolOptions, defaultValue: 'auth_sha1_v4', required: true },
      { key: 'obfs', label: 'Obfs', type: 'select', options: ssrObfsOptions, defaultValue: 'tls1.2_ticket_auth', required: true },
      { key: 'protocol-param', label: 'Protocol Param' },
      { key: 'obfs-param', label: 'Obfs Param' },
      ...manualCommonProxyFields(type),
    ],
    snell: [
      { key: 'psk', label: 'PSK', required: true },
      { key: 'version', label: 'Version', defaultValue: '3' },
      ...manualCommonProxyFields(type),
    ],
    anytls: [
      { key: 'password', label: 'Password', required: true },
      { key: 'idle-session-check-interval', label: 'idle-session-check-interval', type: 'number', defaultValue: '30' },
      { key: 'idle-session-timeout', label: 'idle-session-timeout', type: 'number', defaultValue: '30' },
      { key: 'min-idle-session', label: 'min-idle-session', type: 'number', defaultValue: '0' },
      ...manualTlsFields(),
      { key: 'udp', label: 'UDP', type: 'checkbox', checked: true },
      ...manualCommonProxyFields(type, { includeUdp: false }),
    ],
    mieru: [
      { key: 'username', label: 'Username', required: true },
      { key: 'password', label: 'Password', required: true },
      { key: 'transport', label: 'Transport', type: 'select', options: mieruTransportOptions, defaultValue: 'TCP' },
      ...manualCommonProxyFields(type),
    ],
    sudoku: [
      { key: 'key', label: 'Key', required: true },
      { key: 'aead-method', label: 'AEAD Method', defaultValue: 'chacha20-poly1305' },
      ...manualCommonProxyFields(type),
    ],
    hysteria: [
      { key: 'auth-str', label: 'Auth String', required: true },
      { key: 'protocol', label: 'Protocol', type: 'select', options: hysteriaProtocolOptions, defaultValue: 'udp' },
      { key: 'up', label: 'Up' },
      { key: 'down', label: 'Down' },
      ...manualTlsFields(),
      ...manualCommonProxyFields(type, { includeUdp: false, includeTcp: false }),
    ],
    hysteria2: [
      { key: 'password', label: 'Password', required: true },
      { key: 'up', label: 'Up' },
      { key: 'down', label: 'Down' },
      { key: 'obfs', label: 'Obfs' },
      { key: 'obfs-password', label: 'Obfs Password' },
      ...manualTlsFields(['h3']),
      ...manualCommonProxyFields(type, { includeUdp: false, includeTcp: false }),
    ],
    tuic: [
      { key: 'uuid', label: 'UUID', required: true },
      { key: 'password', label: 'Password', required: true },
      { key: 'udp-relay-mode', label: 'UDP Relay Mode', type: 'select', options: tuicUdpRelayModeOptions, defaultValue: 'native' },
      { key: 'congestion-controller', label: 'Congestion Controller', type: 'select', options: tuicCongestionControllerOptions, defaultValue: '' },
      ...manualTlsFields(['h3']),
      ...manualCommonProxyFields(type, { includeUdp: false, includeTcp: false }),
    ],
    masque: [
      { key: 'public-key', label: 'Public Key', required: true },
      { key: 'private-key', label: 'Private Key', required: true },
      { key: 'ip', label: 'IP', defaultValue: '172.16.0.2/32' },
      { key: 'mtu', label: 'MTU', defaultValue: '1280' },
      ...manualCommonProxyFields(type, { includeUdp: false, includeTcp: false }),
    ],
    trusttunnel: [
      { key: 'username', label: 'Username', required: true },
      { key: 'password', label: 'Password', required: true },
      ...manualCommonProxyFields(type),
    ],
    socks5: [
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password' },
      { key: 'udp', label: 'UDP', type: 'checkbox' },
      ...manualTlsFields(),
      ...manualCommonProxyFields(type, { includeUdp: false }),
    ],
    http: [
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password' },
      ...manualTlsFields(),
      ...manualCommonProxyFields(type),
    ],
    wireguard: [
      { key: 'ip', label: 'IP' },
      { key: 'private-key', label: 'Private Key', required: true },
      { key: 'public-key', label: 'Public Key', required: true },
      { key: 'presharedKey', label: 'Preshared Key' },
      { key: 'allowedIPs', label: 'Allowed IPs', type: 'textarea', wide: true },
      { key: 'mtu', label: 'MTU' },
      ...manualCommonProxyFields(type, { includeUdp: false, includeTcp: false }),
    ],
    ssh: [
      { key: 'username', label: 'Username', required: true },
      { key: 'password', label: 'Password' },
      ...manualCommonProxyFields(type),
    ],
  }

  return [...fields, ...(byType[type] || [])]
}

function manualTlsFields(defaultAlpn = []) {
  const type = manualNodeType?.value || ''
  const capability = tlsCapabilityByType[type]
  if (!capability) return []
  const fields = new Set(capability.fields)
  const basicFields = [
    ...(fields.has('sni') ? [{ key: 'sni', label: 'SNI / servername' }] : []),
    ...(fields.has('alpn') ? [{ key: 'alpn', label: 'ALPN', type: 'alpn', selected: defaultAlpn }] : []),
    ...(fields.has('skip-cert-verify') ? [{ key: 'skip-cert-verify', label: 'Skip Cert Verify', type: 'checkbox' }] : []),
  ]
  const advancedFields = [
    ...(fields.has('client-fingerprint') ? [{ key: 'client-fingerprint', label: 'Client Fingerprint', type: 'select', options: clientFingerprintOptions, defaultValue: '' }] : []),
    ...(fields.has('fingerprint') ? [{ key: 'fingerprint', label: 'Fingerprint' }] : []),
    ...(fields.has('certificate') ? [{ key: 'certificate', label: 'Certificate', type: 'textarea', wide: true }] : []),
    ...(fields.has('private-key') ? [{ key: 'private-key', label: 'Private Key', type: 'textarea', wide: true }] : []),
    ...(fields.has('reality') ? [
      { key: 'reality.public-key', label: 'reality-opts.public-key' },
      { key: 'reality.short-id', label: 'reality-opts.short-id' },
      { key: 'reality.support-x25519mlkem768', label: 'reality-opts.support-x25519mlkem768', type: 'select', options: ['', 'false', 'true'], defaultValue: '' },
    ] : []),
    ...(fields.has('ech') ? [
      { key: 'ech.enable', label: 'ech-opts.enable', type: 'select', options: ['', 'false', 'true'], defaultValue: '' },
      { key: 'ech.config', label: 'ech-opts.config', type: 'textarea', wide: true },
      { key: 'ech.query-server-name', label: 'ech-opts.query-server-name' },
    ] : []),
  ]
  return [{
    key: 'tls-options',
    type: 'tls-section',
    title: 'TLS',
    toggle: capability.toggle,
    checked: false,
    basicFields,
    advancedFields,
  }]
}

function manualCommonProxyFields(type, options = {}) {
  if (!needsManualEndpoint(type)) return []
  const includeUdp = options.includeUdp !== false
  const includeTcp = options.includeTcp !== false
  return [
    ...(includeUdp ? [{ key: 'udp', label: 'UDP', type: 'checkbox' }] : []),
    { key: 'ip-version', label: 'IP Version', type: 'select', options: ipVersionOptions, defaultValue: '' },
    { key: 'interface-name', label: 'Interface Name' },
    { key: 'routing-mark', label: 'Routing Mark', type: 'number' },
    ...(includeTcp ? [
      { key: 'tfo', label: 'TFO', type: 'checkbox' },
      { key: 'mptcp', label: 'MPTCP', type: 'checkbox' },
    ] : []),
    { key: 'dialer-proxy', label: 'Dialer Proxy' },
  ]
}

function manualTransportFields(type, values = {}) {
  const supported = supportedNetworksForType(type)
  const network = supported.includes(values.network) ? values.network : ''
  const fields = [
    { key: 'network', label: 'Network', type: 'select', options: supported, defaultValue: '' },
  ]
  if (!network) return fields
  if (network === 'http') {
    return fields.concat(manualFieldGroup('Transport', [
      { key: 'http.method', label: 'http-opts.method', type: 'select', options: httpMethodOptions, defaultValue: '' },
      { key: 'http.path', label: 'http-opts.path', type: 'list' },
      { key: 'http.headers', label: 'http-opts.headers', type: 'policy', wide: true },
    ]))
  }
  if (network === 'h2') {
    return fields.concat(manualFieldGroup('Transport', [
      { key: 'h2.host', label: 'h2-opts.host', type: 'list' },
      { key: 'h2.path', label: 'h2-opts.path', defaultValue: '/' },
    ]))
  }
  if (network === 'grpc') {
    return fields.concat(manualFieldGroup('Transport', [
      { key: 'grpc.grpc-service-name', label: 'grpc-opts.grpc-service-name' },
      { key: 'grpc.grpc-user-agent', label: 'grpc-opts.grpc-user-agent' },
    ], [
      { key: 'grpc.ping-interval', label: 'grpc-opts.ping-interval', type: 'number' },
      { key: 'grpc.max-connections', label: 'grpc-opts.max-connections', type: 'number' },
      { key: 'grpc.min-streams', label: 'grpc-opts.min-streams', type: 'number' },
      { key: 'grpc.max-streams', label: 'grpc-opts.max-streams', type: 'number' },
    ]))
  }
  if (network === 'ws') {
    return fields.concat(manualFieldGroup('Transport', [
      { key: 'ws.path', label: 'ws-opts.path', defaultValue: '/' },
      { key: 'ws.headers', label: 'ws-opts.headers', type: 'policy', wide: true },
    ], [
      { key: 'ws.max-early-data', label: 'ws-opts.max-early-data', type: 'number' },
      { key: 'ws.early-data-header-name', label: 'ws-opts.early-data-header-name' },
      { key: 'ws.v2ray-http-upgrade', label: 'ws-opts.v2ray-http-upgrade', type: 'boolean-select', defaultValue: 'false' },
      { key: 'ws.v2ray-http-upgrade-fast-open', label: 'ws-opts.v2ray-http-upgrade-fast-open', type: 'boolean-select', defaultValue: 'false' },
    ]))
  }
  if (network === 'xhttp') {
    return fields.concat(manualFieldGroup('Transport', [
      { key: 'xhttp.path', label: 'xhttp-opts.path', defaultValue: '/' },
      { key: 'xhttp.host', label: 'xhttp-opts.host' },
      { key: 'xhttp.mode', label: 'xhttp-opts.mode', type: 'select', options: ['', 'auto', 'stream-one', 'stream-up', 'packet-up'], defaultValue: '' },
      { key: 'xhttp.headers', label: 'xhttp-opts.headers', type: 'policy', wide: true },
    ], [
      { key: 'xhttp.no-grpc-header', label: 'xhttp-opts.no-grpc-header', type: 'boolean-select', defaultValue: 'false' },
      { key: 'xhttp.x-padding-bytes', label: 'xhttp-opts.x-padding-bytes' },
      { key: 'xhttp.x-padding-obfs-mode', label: 'xhttp-opts.x-padding-obfs-mode', type: 'boolean-select', defaultValue: 'false' },
      { key: 'xhttp.x-padding-key', label: 'xhttp-opts.x-padding-key' },
      { key: 'xhttp.x-padding-header', label: 'xhttp-opts.x-padding-header' },
      { key: 'xhttp.x-padding-placement', label: 'xhttp-opts.x-padding-placement', type: 'select', options: ['', 'queryInHeader', 'cookie', 'header', 'query'], defaultValue: '' },
      { key: 'xhttp.x-padding-method', label: 'xhttp-opts.x-padding-method', type: 'select', options: ['', 'repeat-x', 'tokenish'], defaultValue: '' },
      { key: 'xhttp.uplink-http-method', label: 'xhttp-opts.uplink-http-method', type: 'select', options: ['', 'POST', 'PUT', 'PATCH', 'DELETE'], defaultValue: '' },
      { key: 'xhttp.session-placement', label: 'xhttp-opts.session-placement', type: 'select', options: ['', 'path', 'query', 'cookie', 'header'], defaultValue: '' },
      { key: 'xhttp.session-key', label: 'xhttp-opts.session-key' },
      { key: 'xhttp.seq-placement', label: 'xhttp-opts.seq-placement', type: 'select', options: ['', 'path', 'query', 'cookie', 'header'], defaultValue: '' },
      { key: 'xhttp.seq-key', label: 'xhttp-opts.seq-key' },
      { key: 'xhttp.uplink-data-placement', label: 'xhttp-opts.uplink-data-placement', type: 'select', options: ['', 'body', 'cookie', 'header'], defaultValue: '' },
      { key: 'xhttp.uplink-data-key', label: 'xhttp-opts.uplink-data-key' },
      { key: 'xhttp.uplink-chunk-size', label: 'xhttp-opts.uplink-chunk-size', type: 'number' },
      { key: 'xhttp.sc-max-each-post-bytes', label: 'xhttp-opts.sc-max-each-post-bytes', type: 'number' },
      { key: 'xhttp.sc-min-posts-interval-ms', label: 'xhttp-opts.sc-min-posts-interval-ms', type: 'number' },
      { key: 'xhttp.reuse-settings.max-concurrency', label: 'xhttp-opts.reuse-settings.max-concurrency' },
      { key: 'xhttp.reuse-settings.max-connections', label: 'xhttp-opts.reuse-settings.max-connections' },
      { key: 'xhttp.reuse-settings.c-max-reuse-times', label: 'xhttp-opts.reuse-settings.c-max-reuse-times' },
      { key: 'xhttp.reuse-settings.h-max-request-times', label: 'xhttp-opts.reuse-settings.h-max-request-times' },
      { key: 'xhttp.reuse-settings.h-max-reusable-secs', label: 'xhttp-opts.reuse-settings.h-max-reusable-secs' },
      { key: 'xhttp.reuse-settings.h-keep-alive-period', label: 'xhttp-opts.reuse-settings.h-keep-alive-period', type: 'number' },
      { key: 'xhttp.download-settings', label: 'xhttp-opts.download-settings', type: 'json', wide: true, defaultValue: '{}' },
    ]))
  }
  return fields
}

function manualFieldGroup(title, basicFields, advancedFields = []) {
  return [{ key: `${title.toLowerCase()}-options`, type: 'field-group', title, basicFields, advancedFields }]
}

function renderManualNodeField(field, values = {}) {
  if (field.type === 'field-group') {
    return renderManualOptionDetails(field.title, field.basicFields, field.advancedFields, values)
  }
  if (field.type === 'tls-section') {
    const tlsEnabled = field.toggle
      ? (Object.hasOwn(values, 'tls') ? Boolean(values.tls) : Boolean(field.checked))
      : true
    return `
      <div class="wide-field tls-fields">
        ${field.toggle ? `<label class="check-row tls-toggle"><input type="checkbox" data-manual-field="tls" ${tlsEnabled ? 'checked' : ''}> TLS</label>` : ''}
        <div class="nested-node-fields tls-config-panel" data-manual-tls-field ${tlsEnabled ? '' : 'hidden'}>
          ${renderManualOptionDetails(field.title, field.basicFields, field.advancedFields, values)}
        </div>
      </div>
    `
  }
  const value = Object.hasOwn(values, field.key) ? values[field.key] : (field.defaultValue ?? '')
  const label = `${escapeHtml(field.label)}${field.required ? ' *' : ''}`
  const className = field.wide || ['textarea', 'policy', 'json', 'alpn'].includes(field.type) ? ' class="wide-field"' : ''
  const placeholder = field.placeholder ? ` placeholder="${escapeAttr(field.placeholder)}"` : ''
  const tlsEnabled = Object.hasOwn(values, 'tls')
    ? Boolean(values.tls)
    : Boolean(manualNodeFieldDefinitions(manualNodeType.value, values).find((item) => item.key === 'tls')?.checked)
  const hidden = field.tlsOnly && !tlsEnabled ? ' hidden' : ''
  const tlsOnly = field.tlsOnly ? ' data-manual-tls-field' : ''
  if (field.type === 'checkbox') {
    const checked = Object.hasOwn(values, field.key) ? Boolean(values[field.key]) : Boolean(field.checked)
    return `<label class="check-row"${tlsOnly}${hidden}><input type="checkbox" data-manual-field="${escapeAttr(field.key)}" ${checked ? 'checked' : ''}> ${label}</label>`
  }
  if (field.type === 'select' || field.type === 'boolean-select') {
    const options = field.type === 'boolean-select' ? ['false', 'true'] : (field.options || [])
    const optionHtml = field.key === 'network'
      ? renderManualNetworkOptions(options, String(value))
      : renderSelectOptions(options, String(value))
    return `<label${className}${tlsOnly}${hidden}><span>${label}</span><select data-manual-field="${escapeAttr(field.key)}">${optionHtml}</select></label>`
  }
  if (['textarea', 'policy', 'json'].includes(field.type)) {
    return `<label${className}${tlsOnly}${hidden}><span>${label}</span><textarea class="mini-editor" data-manual-field="${escapeAttr(field.key)}"${placeholder}>${escapeHtml(String(value))}</textarea></label>`
  }
  if (field.type === 'alpn') {
    const selected = new Set(Array.isArray(values.alpn) ? values.alpn : (field.selected || []))
    return `
      ${renderAlpnCheckboxGroup({
        label,
        selected,
        inputAttribute: 'data-manual-alpn',
        extraAttributes: `${tlsOnly}${hidden}`,
      })}
    `
  }
  return `<label${className}${tlsOnly}${hidden}><span>${label}</span><input type="text" data-manual-field="${escapeAttr(field.key)}" value="${escapeAttr(value)}"${placeholder}></label>`
}

function renderManualOptionDetails(title, basicFields, advancedFields = [], values = {}) {
  const basic = basicFields.map((field) => renderManualNodeField(field, values)).filter(Boolean).join('')
  const advanced = advancedFields.map((field) => renderManualNodeField(field, values)).filter(Boolean).join('')
  if (!basic && !advanced) return ''
  return `
    <div class="node-option-block wide-field manual-option-block">
      ${basic ? `<details class="node-option-section" open><summary>${escapeHtml(title)} Basic</summary><div class="nested-node-fields">${basic}</div></details>` : ''}
      ${advanced ? `<details class="node-option-section"><summary>${escapeHtml(title)} Advanced</summary><div class="nested-node-fields">${advanced}</div></details>` : ''}
    </div>
  `
}

function renderManualNetworkOptions(options, value) {
  const allowed = new Set(options)
  return networkOptions
    .filter((option) => allowed.has(option.value))
    .map((option) => `<option value="${escapeAttr(option.value)}" ${option.value === value ? 'selected' : ''}>${escapeHtml(option.label)}</option>`)
    .join('')
}

function readManualNodeValues() {
  const values = {}
  manualNodeFields.querySelectorAll('[data-manual-field]').forEach((field) => {
    if (field.closest('[data-manual-tls-field][hidden]')) return
    values[field.dataset.manualField] = field.type === 'checkbox' ? field.checked : field.value.trim()
  })
  const alpn = [...manualNodeFields.querySelectorAll('[data-manual-alpn]:checked')]
    .filter((field) => !field.closest('[data-manual-tls-field][hidden]'))
    .map((field) => field.value)
  if (alpn.length) values.alpn = alpn
  return values
}

function validateManualNodeValues(type, values) {
  for (const field of manualNodeFieldDefinitions(type).filter((item) => item.required)) {
    if (!values[field.key]) return `${field.label} is required for ${type}.`
  }
  if (needsManualEndpoint(type) && (!values.server || !values.port)) return `Server and Port are required for ${type}.`
  if (needsManualEndpoint(type) && !isValidPortValue(values.port)) return `Port must be a number between 1 and 65535 for ${type}.`
  if (values.network === 'xhttp' && parseJsonObjectInput(values['xhttp.download-settings'], 'xhttp-opts.download-settings') === invalidEditorInput) {
    return 'xhttp-opts.download-settings must be a valid JSON object.'
  }
  return ''
}

function needsManualEndpoint(type) {
  return !['direct', 'dns'].includes(type)
}

function supportedNetworksForType(type) {
  return ['', ...(networkSupportByType[type] || [])]
}

function parseManualNumber(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  const number = Number(text)
  return Number.isFinite(number) ? number : ''
}

function isValidPortValue(value) {
  const port = Number(String(value || '').trim())
  return Number.isInteger(port) && port >= 1 && port <= 65535
}

function parseBooleanSelect(value) {
  if (value === 'true') return true
  if (value === 'false') return false
  return ''
}

function applyManualCommonOptions(proxy, values) {
  const capability = tlsCapabilityByType[normalizeProxyType(proxy.type)]
  const tlsFields = new Set(capability?.fields || [])
  if (Array.isArray(values.alpn) && values.alpn.length) proxy.alpn = values.alpn
  if (values.udp !== undefined) proxy.udp = values.udp
  if (values['ip-version']) proxy['ip-version'] = values['ip-version']
  if (values['interface-name']) proxy['interface-name'] = values['interface-name']
  if (values['routing-mark'] !== undefined && values['routing-mark'] !== '') proxy['routing-mark'] = parseManualNumber(values['routing-mark'])
  if (values.tfo !== undefined) proxy.tfo = values.tfo
  if (values.mptcp !== undefined) proxy.mptcp = values.mptcp
  if (values['dialer-proxy']) proxy['dialer-proxy'] = values['dialer-proxy']
  if (tlsFields.has('fingerprint') && values.fingerprint) proxy.fingerprint = values.fingerprint
  if (tlsFields.has('client-fingerprint') && values['client-fingerprint']) proxy['client-fingerprint'] = values['client-fingerprint']
  if (tlsFields.has('skip-cert-verify') && values['skip-cert-verify'] !== undefined) proxy['skip-cert-verify'] = values['skip-cert-verify']
  if (tlsFields.has('certificate') && values.certificate) proxy.certificate = values.certificate
  if (tlsFields.has('private-key') && values['private-key']) proxy['private-key'] = values['private-key']
  if (tlsFields.has('reality')) {
    proxy['reality-opts'] = compactManualObject({
      'public-key': values['reality.public-key'],
      'short-id': values['reality.short-id'],
      'support-x25519mlkem768': parseBooleanSelect(values['reality.support-x25519mlkem768']),
    })
  }
  if (tlsFields.has('ech')) {
    proxy['ech-opts'] = compactManualObject({
      enable: parseBooleanSelect(values['ech.enable']),
      config: values['ech.config'],
      'query-server-name': values['ech.query-server-name'],
    })
  }
  if (tlsFields.has('sni') && values.sni) {
    proxy.sni = values.sni
    proxy.servername = values.sni
  }
  if (!values.network) return

  setProxyNetwork(proxy, values.network)
  if (values.network === 'ws') {
    proxy['ws-opts'] = compactManualObject({
      path: values['ws.path'] || '/',
      headers: textToPolicy(values['ws.headers']),
      'max-early-data': parseManualNumber(values['ws.max-early-data']),
      'early-data-header-name': values['ws.early-data-header-name'],
      'v2ray-http-upgrade': values['ws.v2ray-http-upgrade'] === 'true',
      'v2ray-http-upgrade-fast-open': values['ws.v2ray-http-upgrade-fast-open'] === 'true',
    })
  } else if (values.network === 'grpc') {
    proxy['grpc-opts'] = compactManualObject({
      'grpc-service-name': values['grpc.grpc-service-name'],
      'grpc-user-agent': values['grpc.grpc-user-agent'],
      'ping-interval': parseManualNumber(values['grpc.ping-interval']),
      'max-connections': parseManualNumber(values['grpc.max-connections']),
      'min-streams': parseManualNumber(values['grpc.min-streams']),
      'max-streams': parseManualNumber(values['grpc.max-streams']),
    })
  } else if (values.network === 'h2') {
    proxy['h2-opts'] = compactManualObject({
      host: splitLinesOrComma(values['h2.host']),
      path: values['h2.path'] || '/',
    })
  } else if (values.network === 'http') {
    proxy['http-opts'] = compactManualObject({
      method: values['http.method'],
      path: splitLinesOrComma(values['http.path']),
      headers: textToPolicy(values['http.headers']),
    })
  } else if (values.network === 'xhttp') {
    const reuseSettings = compactManualObject({
      'max-concurrency': values['xhttp.reuse-settings.max-concurrency'],
      'max-connections': values['xhttp.reuse-settings.max-connections'],
      'c-max-reuse-times': values['xhttp.reuse-settings.c-max-reuse-times'],
      'h-max-request-times': values['xhttp.reuse-settings.h-max-request-times'],
      'h-max-reusable-secs': values['xhttp.reuse-settings.h-max-reusable-secs'],
      'h-keep-alive-period': parseManualNumber(values['xhttp.reuse-settings.h-keep-alive-period']),
    })
    proxy['xhttp-opts'] = compactManualObject({
      ...(proxy['xhttp-opts'] || {}),
      path: values['xhttp.path'] || '/',
      host: values['xhttp.host'] || values.sni,
      mode: values['xhttp.mode'],
      headers: textToPolicy(values['xhttp.headers']),
      'no-grpc-header': values['xhttp.no-grpc-header'] === 'true',
      'x-padding-bytes': values['xhttp.x-padding-bytes'],
      'x-padding-obfs-mode': values['xhttp.x-padding-obfs-mode'] === 'true',
      'x-padding-key': values['xhttp.x-padding-key'],
      'x-padding-header': values['xhttp.x-padding-header'],
      'x-padding-placement': values['xhttp.x-padding-placement'],
      'x-padding-method': values['xhttp.x-padding-method'],
      'uplink-http-method': values['xhttp.uplink-http-method'],
      'session-placement': values['xhttp.session-placement'],
      'session-key': values['xhttp.session-key'],
      'seq-placement': values['xhttp.seq-placement'],
      'seq-key': values['xhttp.seq-key'],
      'uplink-data-placement': values['xhttp.uplink-data-placement'],
      'uplink-data-key': values['xhttp.uplink-data-key'],
      'uplink-chunk-size': parseManualNumber(values['xhttp.uplink-chunk-size']),
      'sc-max-each-post-bytes': parseManualNumber(values['xhttp.sc-max-each-post-bytes']),
      'sc-min-posts-interval-ms': parseManualNumber(values['xhttp.sc-min-posts-interval-ms']),
      'reuse-settings': reuseSettings,
      'download-settings': parseJsonObjectInput(values['xhttp.download-settings'], 'xhttp-opts.download-settings'),
    })
  }
}

function cleanupManualProxy(proxy) {
  for (const [key, value] of Object.entries(proxy)) {
    if (value === '' || value === undefined || value === null) delete proxy[key]
    else if (Array.isArray(value) && !value.length) delete proxy[key]
    else if (isPlainObject(value) && !Object.keys(value).length) delete proxy[key]
  }
  if (Array.isArray(proxy.peers)) {
    proxy.peers = proxy.peers.map((peer) => compactManualObject(peer))
  }
}

function compactManualObject(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => {
      if (value === '' || value === undefined || value === null) return false
      if (Array.isArray(value) && !value.length) return false
      if (isPlainObject(value) && !Object.keys(value).length) return false
      return true
    }),
  )
}

function addManualNode() {
  if (!state.model) return
  const name = manualNodeName.value.trim()
  const type = manualNodeType.value
  const values = readManualNodeValues()
  const nameIssue = validEditableName(name, 'Node')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.proxies, name)) {
    showValidation(`Node "${name}" already exists.`, 'error')
    return
  }
  if (hasNameInCollection(state.model.groups, name)) {
    showValidation(`Node name "${name}" conflicts with a group name.`, 'error')
    return
  }
  const issue = validateManualNodeValues(type, values)
  if (issue) {
    showValidation(issue, 'error')
    return
  }
  const proxy = compactObject({
    name,
    type,
    server: values.server,
    port: parseManualNumber(values.port) || values.port,
    enabled: true,
  })
  if (type === 'wireguard') {
    proxy['private-key'] = values['private-key']
    proxy['public-key'] = values['public-key']
    proxy.presharedKey = values.presharedKey
    proxy.ip = values.ip
    proxy.mtu = parseManualNumber(values.mtu)
    proxy.peers = [{
      server: values.server,
      port: parseManualNumber(values.port) || values.port,
      'public-key': values['public-key'],
      presharedKey: values.presharedKey || undefined,
      allowedIPs: splitLinesOrComma(values.allowedIPs),
    }]
  } else if (type === 'vless') {
    proxy.uuid = values.uuid
    proxy.flow = values.flow
    proxy.tls = values.tls
    proxy.servername = values.sni
    proxy.encryption = values.encryption
    proxy['packet-encoding'] = values['packet-encoding']
  } else if (type === 'vmess') {
    proxy.uuid = values.uuid
    proxy.alterId = parseManualNumber(values.alterId) || 0
    proxy.cipher = values.cipher || 'auto'
    proxy['packet-encoding'] = values['packet-encoding']
    proxy['global-padding'] = values['global-padding']
    proxy['authenticated-length'] = values['authenticated-length']
    proxy.tls = values.tls
    proxy.servername = values.sni
  } else if (type === 'trojan') {
    proxy.password = values.password
    proxy.tls = values.tls
    proxy.sni = values.sni
    proxy['ss-opts'] = compactManualObject({
      enabled: values['ss.enabled'],
      method: values['ss.method'],
      password: values['ss.password'],
    })
  } else if (type === 'anytls') {
    proxy.password = values.password
    proxy.udp = true
    proxy['idle-session-check-interval'] = parseManualNumber(values['idle-session-check-interval'])
    proxy['idle-session-timeout'] = parseManualNumber(values['idle-session-timeout'])
    proxy['min-idle-session'] = parseManualNumber(values['min-idle-session'])
  } else if (type === 'hysteria2') {
    proxy.password = values.password
    proxy.tls = values.tls
    proxy.sni = values.sni
    proxy.up = values.up
    proxy.down = values.down
    proxy.obfs = values.obfs
    proxy['obfs-password'] = values['obfs-password']
  } else if (type === 'hysteria') {
    proxy['auth-str'] = values['auth-str']
    proxy.protocol = values.protocol || 'udp'
    proxy.up = values.up
    proxy.down = values.down
    proxy.sni = values.sni
  } else if (type === 'ss') {
    proxy.cipher = values.cipher || 'aes-128-gcm'
    proxy.password = values.password
    proxy['udp-over-tcp'] = values['udp-over-tcp']
    proxy['udp-over-tcp-version'] = parseManualNumber(values['udp-over-tcp-version'])
    proxy.plugin = values.plugin
    proxy['plugin-opts'] = textToPolicy(values['plugin-opts'])
    proxy.udp = true
  } else if (type === 'ssr') {
    proxy.cipher = values.cipher || 'chacha20-ietf'
    proxy.password = values.password
    proxy.obfs = values.obfs || 'tls1.2_ticket_auth'
    proxy.protocol = values.protocol || 'auth_sha1_v4'
    proxy['protocol-param'] = values['protocol-param']
    proxy['obfs-param'] = values['obfs-param']
  } else if (type === 'tuic') {
    proxy.uuid = values.uuid
    proxy.password = values.password
    proxy.sni = values.sni
    proxy['udp-relay-mode'] = values['udp-relay-mode'] || 'native'
    proxy['congestion-controller'] = values['congestion-controller']
    proxy.udp = true
  } else if (type === 'snell') {
    proxy.psk = values.psk
    proxy.version = parseManualNumber(values.version) || 3
  } else if (type === 'mieru') {
    proxy.username = values.username
    proxy.password = values.password
    proxy.transport = values.transport || 'TCP'
  } else if (type === 'sudoku') {
    proxy.key = values.key
    proxy['aead-method'] = values['aead-method'] || 'chacha20-poly1305'
  } else if (type === 'masque') {
    proxy['public-key'] = values['public-key']
    proxy['private-key'] = values['private-key']
    proxy.ip = values.ip || '172.16.0.2/32'
    proxy.mtu = parseManualNumber(values.mtu) || 1280
    proxy.udp = true
  } else if (type === 'trusttunnel') {
    proxy.username = values.username
    proxy.password = values.password
    proxy.udp = true
  } else if (type === 'ssh') {
    proxy.username = values.username
    proxy.password = values.password
  } else {
    proxy.username = values.username
    proxy.password = values.password
  }
  applyManualCommonOptions(proxy, values)
  cleanupManualProxy(proxy)
  state.model.proxies.push(proxy)
  state.expandedNodeKeys.add(nodeExpansionKey(proxy))
  for (const group of state.model.groups) {
    if (group.name === 'PROXY' && !group.proxies.includes(name)) group.proxies.push(name)
  }
  manualNodeName.value = ''
  renderManualNodeFields()
  updateYamlFromModel()
}

function addAdsProviderPreset() {
  if (!state.model) return
  upsertRuleProvider({
    name: 'ads',
    type: 'http',
    behavior: 'domain',
    path: './rules/ads.yaml',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.yaml',
    target: 'REJECT',
    interval: 86400,
  })
  syncProviderRule('ads', 'REJECT')
  updateYamlFromModel()
  showToast('Ad block rule provider added.')
}

function applyLanDirectRules() {
  if (!state.model) return
  for (const rule of presetRules('lan-direct').filter((item) => item !== 'MATCH,PROXY')) {
    ensureRule(rule, true)
  }
  ensureMatchRule()
  updateYamlFromModel()
  showToast('LAN DIRECT rules added.')
}

function updateRulesFromEditor() {
  if (!state.model) return
  state.model.rules = rulesEditor.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  updateYamlFromModel(false)
}

function updateDnsFromEditor() {
  if (!state.model) return
  clearRawSection('dns')
  const extra = omitKeys(state.model.dns, dnsFieldKeys)
  state.model.dns = {
    ...extra,
    enable: dnsEnable.checked,
    listen: dnsListen.value.trim(),
    ipv6: Boolean(state.model.dns.ipv6),
    cacheAlgorithm: dnsCacheAlgorithm.value,
    preferH3: dnsPreferH3.checked,
    useHosts: dnsUseHosts.checked,
    useSystemHosts: dnsUseSystemHosts.checked,
    respectRules: dnsRespectRules.checked,
    enhancedMode: dnsEnhancedMode.value,
    fakeIpRange: dnsFakeIpRange.value.trim(),
    fakeIpRange6: dnsFakeIpRange6.value.trim(),
    fakeIpFilterMode: dnsFakeIpFilterMode.value,
    fakeIpTtl: Number(dnsFakeIpTtl.value) || 0,
    fakeIpFilter: splitLinesOrComma(dnsFakeIpFilter.value),
    defaultNameserver: splitLinesOrComma(dnsDefault.value),
    nameserver: splitLinesOrComma(dnsNameservers.value),
    fallback: splitLinesOrComma(dnsFallback.value),
    fallbackFilter: textToPolicy(dnsFallbackFilter.value, { typedValues: true }),
    directNameserver: splitLinesOrComma(dnsDirectNameserver.value),
    directNameserverFollowPolicy: dnsDirectFollowPolicy.checked,
    proxyServerNameserver: splitLinesOrComma(dnsProxyServer.value),
    proxyServerNameserverPolicy: textToPolicy(dnsProxyPolicy.value),
    nameserverPolicy: textToPolicy(dnsPolicy.value),
  }
  updateYamlFromModel(false)
}

function updateGeneralFromEditor() {
  if (!state.model) return
  clearRawSection('general')
  const extra = omitKeys(state.model.general, generalFieldKeys)
  state.model.general = {
    ...extra,
    port: Number(generalPort.value) || 0,
    socksPort: Number(generalSocksPort.value) || 0,
    redirPort: Number(generalRedirPort.value) || 0,
    tproxyPort: Number(generalTproxyPort.value) || 0,
    mixedPort: Number(generalMixedPort.value) || 7890,
    mode: generalMode.value,
    logLevel: generalLogLevel.value,
    bindAddress: generalBindAddress.value.trim() || '*',
    lanAllowedIps: splitLinesOrComma(generalLanAllowedIps.value),
    lanDisallowedIps: splitLinesOrComma(generalLanDisallowedIps.value),
    authentication: splitLinesOrComma(generalAuthentication.value),
    skipAuthPrefixes: splitLinesOrComma(generalSkipAuthPrefixes.value),
    interfaceName: generalInterfaceName.value.trim(),
    routingMark: Number(generalRoutingMark.value) || 0,
    keepAliveIdle: Number(generalKeepAliveIdle.value) || 0,
    keepAliveInterval: Number(generalKeepAliveInterval.value) || 0,
    findProcessMode: generalFindProcessMode.value,
    externalController: generalController.value.trim(),
    externalControllerTls: generalControllerTls.value.trim(),
    externalControllerUnix: generalControllerUnix.value.trim(),
    externalControllerPipe: generalControllerPipe.value.trim(),
    externalControllerCors: generalControllerCors.value.trim(),
    externalUi: generalUi.value.trim(),
    externalUiName: generalUiName.value.trim(),
    externalUiUrl: generalUiUrl.value.trim(),
    secret: generalSecret.value.trim(),
    globalClientFingerprint: generalClientFingerprint.value.trim(),
    globalUa: generalUa.value.trim(),
    tlsCertificate: generalTlsCertificate.value.trim(),
    tlsPrivateKey: generalTlsPrivateKey.value.trim(),
    tlsCustom: isPlainObject(state.model.general.tlsCustom) ? state.model.general.tlsCustom : {},
    allowLan: generalAllowLan.checked,
    ipv6: generalIpv6.checked,
    disableKeepAlive: generalDisableKeepAlive.checked,
    unifiedDelay: generalUnifiedDelay.checked,
    tcpConcurrent: generalTcpConcurrent.checked,
    etagSupport: generalEtagSupport.checked,
  }
  const profileExtra = omitKeys(state.model.profile, profileFieldKeys)
  state.model.profile = {
    ...profileExtra,
    storeSelected: profileStoreSelected.checked,
    storeFakeIp: profileStoreFakeIp.checked,
  }
  updateYamlFromModel(false)
}

function updateSnifferFromEditor() {
  if (!state.model) return
  clearRawSection('sniffer')
  const extra = omitKeys(state.model.sniffer, snifferFieldKeys)
  state.model.sniffer = {
    ...extra,
    enable: snifferEnable.checked,
    overrideDestination: snifferOverride.checked,
    parsePureIp: snifferParseIp.checked,
    forceDnsMapping: snifferForceDnsMapping.checked,
    sniff: splitLines(snifferSniff.value),
    forceDomain: splitLinesOrComma(snifferForce.value),
    skipDomain: splitLinesOrComma(snifferSkip.value),
    skipSrcAddress: splitLinesOrComma(snifferSkipSrc.value),
    skipDstAddress: splitLinesOrComma(snifferSkipDst.value),
  }
  updateYamlFromModel(false)
}

function updateTunFromEditor() {
  if (!state.model) return
  clearRawSection('tun')
  const extra = omitKeys(state.model.tun, tunFieldKeys)
  state.model.tun = {
    ...extra,
    enable: tunEnable.checked,
    stack: tunStack.value,
    device: tunDevice.value.trim(),
    autoRoute: tunAutoRoute.checked,
    autoRedirect: tunAutoRedirect.checked,
    autoDetectInterface: tunAutoDetect.checked,
    strictRoute: tunStrictRoute.checked,
    dnsHijack: splitLinesOrComma(tunDnsHijack.value),
    mtu: Number(tunMtu.value) || 0,
    gso: tunGso.checked,
    gsoMaxSize: Number(tunGsoMaxSize.value) || 0,
    udpTimeout: Number(tunUdpTimeout.value) || 0,
    iproute2TableIndex: Number(tunIproute2TableIndex.value) || 0,
    iproute2RuleIndex: Number(tunIproute2RuleIndex.value) || 0,
    endpointIndependentNat: tunEndpointIndependentNat.checked,
    routeAddressSet: splitLinesOrComma(tunRouteAddressSet.value),
    routeExcludeAddressSet: splitLinesOrComma(tunRouteExcludeAddressSet.value),
    routeAddress: splitLinesOrComma(tunRouteAddress.value),
    routeExcludeAddress: splitLinesOrComma(tunRouteExcludeAddress.value),
    includeInterface: splitLinesOrComma(tunIncludeInterface.value),
    excludeInterface: splitLinesOrComma(tunExcludeInterface.value),
    includeUid: splitLinesOrComma(tunIncludeUid.value),
    includeUidRange: splitLinesOrComma(tunIncludeUidRange.value),
    excludeUid: splitLinesOrComma(tunExcludeUid.value),
    excludeUidRange: splitLinesOrComma(tunExcludeUidRange.value),
    includeAndroidUser: splitLinesOrComma(tunIncludeAndroidUser.value),
    includePackage: splitLinesOrComma(tunIncludePackage.value),
    excludePackage: splitLinesOrComma(tunExcludePackage.value),
  }
  updateYamlFromModel(false)
}

function clearRawSection(section) {
  if (!state.model?.rawSections) return
  delete state.model.rawSections[section]
}

function updateGeoFromEditor() {
  if (!state.model) return
  const extra = omitKeys(state.model.geo, geoFieldKeys)
  state.model.geo = {
    ...extra,
    geodataMode: geoGeodataMode.checked,
    geoAutoUpdate: geoAutoUpdate.checked,
    geoUpdateInterval: Number(geoUpdateInterval.value) || 24,
    geoxUrl: {
      geoip: geoUrlGeoip.value.trim(),
      geosite: geoUrlGeosite.value.trim(),
      mmdb: geoUrlMmdb.value.trim(),
      asn: geoUrlAsn.value.trim(),
    },
  }
  updateYamlFromModel(false)
}

function updateYamlFromModel(rerender = true) {
  if (!state.model) return
  state.yamlManualEdit = false
  normalizeEditorModel()
  state.yaml = buildYamlFromModel(state.model)
  resetSubscriptionUrl()
  syncYamlEditor()
  validateCurrentYaml(false)
  renderDiff()
  renderSectionPreview()
  if (rerender) renderModel()
}

function formatCurrentYaml() {
  if (!state.yaml) return

  if (!state.yamlManualEdit) {
    updateYamlFromModel()
    return
  }

  const syntaxIssues = validateYamlText(state.yaml)
  if (syntaxIssues.length) {
    showValidation(syntaxIssues.join(' '), 'error')
    return
  }

  const doc = parseDocument(state.yaml)
  state.yaml = doc.toString()
  syncYamlEditor()
  validateCurrentYaml(true)
  renderDiff()
  renderSectionPreview()
}

function resetModel() {
  if (!state.originalModel) return
  state.model = clone(state.originalModel)
  updateYamlFromModel()
}

function autoFixCurrentModel() {
  if (!state.model) return
  const result = autoFixConfigModel(state.model)
  state.model = normalizeClientModel(result.model)
  updateYamlFromModel()
  showToast(result.fixes.length ? `${result.fixes.length} issues fixed.` : 'No safe fixes required.')
}

function toggleDiffPanel() {
  if (!state.yaml) return
  diffPanel.hidden = !diffPanel.hidden
  if (!diffPanel.hidden) renderDiff()
}

function renderDiff() {
  if (!state.originalYaml || !state.yaml) {
    diffSummary.textContent = 'No changes yet.'
    diffViewer.textContent = ''
    return
  }

  const originalLines = state.originalYaml.split(/\r?\n/)
  const currentLines = state.yaml.split(/\r?\n/)
  const max = Math.max(originalLines.length, currentLines.length)
  const output = []
  let added = 0
  let removed = 0
  let changed = 0

  for (let index = 0; index < max; index += 1) {
    const originalLine = originalLines[index]
    const currentLine = currentLines[index]
    if (originalLine === currentLine) {
      output.push(`  ${originalLine || ''}`)
    } else {
      if (originalLine !== undefined) {
        output.push(`- ${originalLine}`)
        removed += 1
      }
      if (currentLine !== undefined) {
        output.push(`+ ${currentLine}`)
        added += 1
      }
      changed += 1
    }
  }

  diffSummary.textContent = changed ? `${added} added, ${removed} removed, ${changed} lines changed.` : 'No changes yet.'
  diffViewer.innerHTML = output.map((line) => {
    const className = line.startsWith('+ ') ? 'diff-added' : line.startsWith('- ') ? 'diff-removed' : ''
    return `<span class="${className}">${escapeHtml(line)}</span>`
  }).join('\n')
}

function renderSectionPreview() {
  if (!state.yaml) {
    yamlSectionPreview.textContent = 'No YAML yet.'
    return
  }

  try {
    yamlSectionPreview.textContent = buildSectionPreview(yamlSectionSelect.value)
  } catch (error) {
    yamlSectionPreview.textContent = error instanceof Error ? error.message : 'Section preview failed.'
  }
}

function buildSectionPreview(section) {
  const raw = parseYamlObject(state.yaml)
  if (section === 'full') return state.yaml
  if (section === 'providers') {
    return yamlFromObject(compactObject({
      'proxy-providers': raw['proxy-providers'],
      'rule-providers': raw['rule-providers'],
    }))
  }
  return yamlFromObject({ [section]: raw[section] ?? emptySectionValue(section) })
}

function buildExportYaml(kind) {
  if (!state.yaml) return ''
  if (kind === 'full') return state.yaml

  const raw = parseYamlObject(state.yaml)
  if (kind === 'groups-rules') {
    return yamlFromObject(compactObject({
      'proxy-groups': raw['proxy-groups'],
      rules: raw.rules,
    }))
  }
  if (kind === 'provider') {
    const proxies = raw.proxies || []
    return yamlFromObject({
      'proxy-providers': {
        converted: {
          type: 'inline',
          payload: proxies,
        },
      },
    })
  }
  return yamlFromObject({ [kind]: raw[kind] ?? emptySectionValue(kind) })
}

function parseYamlObject(value) {
  const doc = parseDocument(value)
  if (doc.errors.length) throw new Error(doc.errors.map((error) => error.message).join(' '))
  const raw = doc.toJS()
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('YAML must be an object.')
  return raw
}

function yamlFromObject(value) {
  return stringify(value).trimEnd() + '\n'
}

function emptySectionValue(section) {
  return ['proxies', 'proxy-groups', 'rules'].includes(section) ? [] : {}
}

function validateCurrentYaml(showOk = true) {
  if (!state.yaml) {
    clearValidation()
    return
  }

  const syntaxIssues = validateYamlText(state.yaml)
  if (syntaxIssues.length) {
    renderValidationIssues([])
    showValidation(syntaxIssues.join(' '), 'error')
    return
  }

  if (state.yamlManualEdit) {
    renderValidationIssues([])
    if (showOk) showValidation('YAML syntax is valid. Manual edits are not synced into editor panels.', 'ok')
    else clearValidation()
    return
  }

  const modelValidation = state.model ? validateConfigModel(state.model) : { valid: true, errors: [], warnings: [] }
  renderValidationIssues(modelValidation.issues || [])

  if (modelValidation.errors.length) showValidation(modelValidation.errors.join(' '), 'warning')
  else if (modelValidation.warnings.length) showValidation(modelValidation.warnings.join(' '), 'warning')
  else if (showOk) showValidation('YAML is valid for the generated model structure.', 'ok')
  else clearValidation()
}

function validateYamlText(value) {
  const issues = []
  if (value.includes('\t')) issues.push('YAML must not use tabs for indentation.')
  if (!value.trim()) issues.push('YAML is empty.')
  if (issues.length) return issues

  try {
    const doc = parseDocument(value)
    if (doc.errors.length) issues.push(...doc.errors.map((error) => error.message))
  } catch (error) {
    issues.push(error.message || 'YAML syntax is invalid.')
  }

  return issues
}

function renderWarnings(items) {
  warningsList.replaceChildren()

  if (!items.length) {
    warnings.hidden = true
    return
  }

  for (const warning of items.slice(0, 8)) {
    const item = document.createElement('li')
    const detail = warning.snippet ? ` Input: ${warning.snippet}` : ''
    item.textContent = `${warning.message}${detail}`
    warningsList.append(item)
  }
  warnings.hidden = false
}

function renderValidationIssues(items) {
  validationIssuesList.replaceChildren()
  if (!items.length) {
    validationDetails.hidden = true
    return
  }

  for (const issue of items.slice(0, 12)) {
    const item = document.createElement('li')
    item.dataset.severity = issue.severity
    item.textContent = `${issue.location}: ${issue.message}`
    validationIssuesList.append(item)
  }
  validationDetails.hidden = false
}

function clearConvertedState() {
  state.yaml = ''
  state.originalYaml = ''
  state.model = null
  state.originalModel = null
  state.draggedNode = -1
  state.yamlManualEdit = false
  state.subscriptionUrl = ''

  yamlEditor.value = 'Converted YAML will appear here.'
  resetSubscriptionUrl()
  statTotal.textContent = '0'
  statConverted.textContent = '0'
  statSkipped.textContent = '0'

  nodeList.textContent = 'No nodes yet. Convert config links first.'
  groupList.classList.add('empty-state')
  groupList.textContent = 'No proxy groups yet. Convert config links first.'
  rulesEditor.value = ''
  ruleProviderList.textContent = 'No custom rule providers yet.'
  proxyProviderList.classList.add('empty-state')
  proxyProviderList.textContent = 'No proxy providers yet.'
  diffPanel.hidden = true
  diffSummary.textContent = 'No changes yet.'
  diffViewer.textContent = ''
  yamlSectionPreview.textContent = 'No YAML yet.'
  groupNameInput.value = ''
  ruleProviderName.value = ''
  ruleProviderUrl.value = ''

  resetAdvancedControls()
  renderWarnings([])
  clearValidation()
  setOutputEnabled(false)
  updateRulesState()
}

function resetAdvancedControls() {
  generalMixedPort.value = '7890'
  generalMode.value = 'rule'
  generalLogLevel.value = 'info'
  generalBindAddress.value = '*'
  generalInterfaceName.value = ''
  generalRoutingMark.value = ''
  generalController.value = ''
  generalControllerCors.value = ''
  generalUi.value = ''
  generalUiName.value = ''
  generalUiUrl.value = ''
  generalSecret.value = ''
  generalAllowLan.checked = false
  generalIpv6.checked = false
  generalUnifiedDelay.checked = false
  generalTcpConcurrent.checked = false
  profileStoreSelected.checked = false
  profileStoreFakeIp.checked = false

  dnsEnable.checked = true
  dnsListen.value = '0.0.0.0:1053'
  dnsCacheAlgorithm.value = ''
  dnsPreferH3.checked = false
  dnsUseHosts.checked = false
  dnsUseSystemHosts.checked = false
  dnsRespectRules.checked = false
  dnsDefault.value = '1.1.1.1\n8.8.8.8'
  dnsNameservers.value = 'https://dns.google/dns-query\nhttps://cloudflare-dns.com/dns-query'
  dnsEnhancedMode.value = 'redir-host'
  dnsFakeIpRange.value = '198.18.0.1/16'
  dnsFakeIpRange6.value = ''
  dnsFakeIpFilterMode.value = ''
  dnsFakeIpTtl.value = ''
  dnsFakeIpFilter.value = '*.lan\n*.local'
  dnsFallback.value = ''
  dnsFallbackFilter.value = ''
  dnsDirectNameserver.value = ''
  dnsDirectFollowPolicy.checked = false
  dnsProxyServer.value = ''
  dnsProxyPolicy.value = ''
  dnsPolicy.value = ''

  snifferEnable.checked = false
  snifferOverride.checked = true
  snifferParseIp.checked = false
  snifferForceDnsMapping.checked = false
  snifferSniff.value = 'TLS:443,8443\nHTTP:80,8080-8880\nQUIC:443,8443'
  snifferForce.value = '+.netflix.com\n+.youtube.com'
  snifferSkip.value = '+.apple.com'
  snifferSkipSrc.value = ''
  snifferSkipDst.value = ''

  tunEnable.checked = false
  tunStack.value = 'mixed'
  tunAutoRoute.checked = true
  tunAutoDetect.checked = true
  tunStrictRoute.checked = false
  tunDnsHijack.value = 'any:53'

  geoGeodataMode.checked = false
  geoAutoUpdate.checked = false
  geoUpdateInterval.value = '24'
  geoUrlGeoip.value = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat'
  geoUrlGeosite.value = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat'
  geoUrlMmdb.value = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb'
  geoUrlAsn.value = 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb'
}

function setOutputEnabled(enabled) {
  copyButton.disabled = !enabled
  downloadButton.disabled = !enabled
  formatYamlButton.disabled = !enabled
  validateYamlButton.disabled = !enabled
  autoFixButton.disabled = !enabled
  toggleDiffButton.disabled = !enabled
  resetYamlButton.disabled = !enabled
  yamlEditor.disabled = !enabled
  createSubscriptionButton.disabled = !enabled || !state.subscriptionApiAvailable
  if (!enabled) resetSubscriptionUrl()
}

function updateSubmitState() {
  const hasInput = input.value.trim().length > 0
  convertButton.disabled = !hasInput || convertButton.textContent === 'Converting...'
}

function hasHttpUrl(value) {
  return String(value || '')
    .split(/\s+/)
    .some((item) => /^https?:\/\//i.test(item.trim()))
}

function detectInputType(value) {
  const text = String(value || '').trim()
  if (!text) return 'unknown'
  if (looksLikeYamlConfig(text)) return 'yaml'
  if (hasHttpUrl(text)) return 'http-url'
  if (linkProtocolPattern.test(text)) return 'links'
  return 'unknown'
}

function looksLikeYamlConfig(text) {
  if (!/^[\s\S]*:\s*/.test(text)) return false
  try {
    const doc = parseDocument(text)
    if (doc.errors.length) return false
    const raw = doc.toJS()
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false
    return ['proxies', 'proxy-groups', 'rules', 'dns', 'sniffer', 'tun', 'ntp', 'mixed-port', 'proxy-providers', 'rule-providers'].some((key) => Object.hasOwn(raw, key))
  } catch {
    return false
  }
}

function updateRulesState() {
  rulesSelect.disabled = templateSelect.value !== 'full'
}

function updateTemplateFromControl() {
  if (state.model) {
    state.model.template = templateSelect.value
    updateYamlFromModel(false)
  }
  updateRulesState()
}

function updateRulesPresetFromControl() {
  if (!state.model) return
  state.model.rulesPreset = rulesSelect.value
  state.model.rules = presetRules(rulesSelect.value)
  renderRules()
  updateYamlFromModel(false)
}

function readConvertOptions() {
  return {
    template: templateSelect.value,
    rulesPreset: rulesSelect.value,
    namePattern: namePatternInput.value,
  }
}

function modelFromYamlObject(raw) {
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
    template: templateSelect.value,
    rulesPreset: rulesSelect.value,
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

function yamlGeneralToModel(raw) {
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

function yamlDnsToModel(dns) {
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

function yamlSnifferToModel(sniffer) {
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

function yamlTunToModel(tun) {
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

function yamlNtpToModel(ntp) {
  return {
    ...omitKeys(ntp, ntpFieldKeys),
    enable: ntp.enable,
    writeToSystem: ntp['write-to-system'],
    server: ntp.server,
    port: ntp.port,
    interval: ntp.interval,
  }
}

function rawSectionsFromYaml(raw) {
  return compactObject({
    general: pickGeneralTopLevel(raw),
    dns: isPlainObject(raw.dns) ? raw.dns : undefined,
    sniffer: isPlainObject(raw.sniffer) ? raw.sniffer : undefined,
    tun: isPlainObject(raw.tun) ? raw.tun : undefined,
    ntp: isPlainObject(raw.ntp) ? raw.ntp : undefined,
  })
}

function pickGeneralTopLevel(raw) {
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

function yamlGeoToModel(raw) {
  return {
    ...omitKeys(raw, geoFieldKeys),
    geodataMode: raw['geodata-mode'],
    geoAutoUpdate: raw['geo-auto-update'],
    geoUpdateInterval: raw['geo-update-interval'],
    geoxUrl: raw['geox-url'],
  }
}

function yamlGroupToModel(group) {
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

function yamlNamedMapToList(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  return Object.entries(value).map(([name, item]) => ({ name, ...(item && typeof item === 'object' ? item : {}) }))
}

function normalizePortsForText(value) {
  if (Array.isArray(value)) return value.map((item) => String(item))
  if (value === undefined || value === null) return []
  return [String(value)]
}

function normalizeTextList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return splitLinesOrComma(value)
  return fallback
}

function normalizeLineList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return splitLines(value)
  return fallback
}

function normalizeSubRuleMap(value) {
  if (!isPlainObject(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, rules]) => [String(key).trim(), normalizeLineList(rules, [])])
      .filter(([key, rules]) => key && rules.length),
  )
}

function normalizeProxyProviderPayload(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => (isPlainObject(item) ? { ...item } : String(item).trim()))
      .filter((item) => isPlainObject(item) || item)
  }
  if (typeof value === 'string') return splitLines(value)
  return []
}

function omitKeys(value = {}, keys = []) {
  const omitted = new Set(keys)
  return Object.fromEntries(Object.entries(value || {}).filter(([key]) => !omitted.has(key)))
}

function normalizeClientRuleProvider(provider) {
  const rest = { ...provider }
  delete rest['size-limit']
  return {
    ...rest,
    name: String(provider.name || '').trim(),
    type: String(provider.type || 'http').trim(),
    behavior: String(provider.behavior || 'classical').trim(),
    path: String(provider.path || '').trim(),
    url: String(provider.url || '').trim(),
    target: String(provider.target || 'PROXY').trim(),
    interval: Number(provider.interval) || 86400,
    proxy: String(provider.proxy || '').trim(),
    format: ['yaml', 'text', 'mrs'].includes(provider.format) ? provider.format : '',
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: isPlainObject(provider.header) ? provider.header : {},
    payload: normalizeLineList(provider.payload, []),
  }
}

function normalizeClientProxyProvider(provider) {
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
    type: ['http', 'file', 'inline'].includes(provider.type) ? provider.type : 'http',
    url: String(provider.url || '').trim(),
    path: String(provider.path || '').trim(),
    interval: Number(provider.interval) || 3600,
    proxy: String(provider.proxy || '').trim(),
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: isPlainObject(provider.header) ? provider.header : {},
    healthCheck: {
      enable: Boolean(healthCheck.enable ?? rawHealthCheck.enable),
      url: String(healthCheck.url || rawHealthCheck.url || 'https://www.gstatic.com/generate_204').trim(),
      interval: Number(healthCheck.interval || rawHealthCheck.interval) || 300,
      timeout: Number(healthCheck.timeout || rawHealthCheck.timeout) || 5000,
      lazy: healthCheck.lazy ?? rawHealthCheck.lazy ?? true,
      expectedStatus: String(healthCheck.expectedStatus || rawHealthCheck['expected-status'] || '').trim(),
    },
    override: isPlainObject(provider.override) ? provider.override : {},
    filter: String(provider.filter || '').trim(),
    excludeFilter: String(provider.excludeFilter || provider['exclude-filter'] || '').trim(),
    excludeType: String(provider.excludeType || provider['exclude-type'] || '').trim(),
    payload: normalizeProxyProviderPayload(provider.payload),
  }
}

function normalizeClientGroup(group) {
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
    proxies: normalizeTextList(group.proxies, []),
    use: normalizeTextList(group.use, []),
    includeAll: Boolean(group.includeAll ?? group['include-all']),
    includeAllProxies: Boolean(group.includeAllProxies ?? group['include-all-proxies']),
    includeAllProviders: Boolean(group.includeAllProviders ?? group['include-all-providers']),
    maxFailedTimes: Number(group.maxFailedTimes ?? group['max-failed-times']) || 0,
    disableUdp: Boolean(group.disableUdp ?? group['disable-udp']),
    interfaceName: String(group.interfaceName ?? group['interface-name'] ?? '').trim(),
    routingMark: Number(group.routingMark ?? group['routing-mark']) || 0,
    excludeFilter: String(group.excludeFilter ?? group['exclude-filter'] ?? '').trim(),
    excludeType: String(group.excludeType ?? group['exclude-type'] ?? '').trim(),
    expectedStatus: String(group.expectedStatus ?? group['expected-status'] ?? '').trim(),
  }
}

function normalizeClientGeo(geo = {}) {
  const geoxUrl = isPlainObject(geo.geoxUrl) ? geo.geoxUrl : isPlainObject(geo['geox-url']) ? geo['geox-url'] : {}
  const extra = omitKeys(geo, geoFieldKeys)
  return {
    ...extra,
    geodataMode: Boolean(geo.geodataMode ?? geo['geodata-mode']),
    geoAutoUpdate: Boolean(geo.geoAutoUpdate ?? geo['geo-auto-update']),
    geoUpdateInterval: geo.geoUpdateInterval ?? geo['geo-update-interval'] ?? 24,
    geoxUrl: {
      geoip: geoxUrl.geoip || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
      geosite: geoxUrl.geosite || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
      mmdb: geoxUrl.mmdb || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb',
      asn: geoxUrl.asn || 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    },
  }
}

const geoFieldKeys = [
  'geodataMode',
  'geodata-mode',
  'geoAutoUpdate',
  'geo-auto-update',
  'geoUpdateInterval',
  'geo-update-interval',
  'geoxUrl',
  'geox-url',
]

function normalizeClientGeneral(general = {}) {
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
    allowLan: Boolean(general.allowLan ?? general['allow-lan']),
    bindAddress: general.bindAddress ?? general['bind-address'] ?? '*',
    lanAllowedIps: normalizeTextList(general.lanAllowedIps ?? general['lan-allowed-ips'], []),
    lanDisallowedIps: normalizeTextList(general.lanDisallowedIps ?? general['lan-disallowed-ips'], []),
    authentication: normalizeTextList(general.authentication, []),
    skipAuthPrefixes: normalizeTextList(general.skipAuthPrefixes ?? general['skip-auth-prefixes'], []),
    interfaceName: general.interfaceName ?? general['interface-name'] ?? '',
    routingMark: general.routingMark ?? general['routing-mark'] ?? 0,
    mode: general.mode || 'rule',
    logLevel: general.logLevel ?? general['log-level'] ?? 'info',
    ipv6: Boolean(general.ipv6),
    keepAliveIdle: general.keepAliveIdle ?? general['keep-alive-idle'] ?? 0,
    keepAliveInterval: general.keepAliveInterval ?? general['keep-alive-interval'] ?? 0,
    disableKeepAlive: Boolean(general.disableKeepAlive ?? general['disable-keep-alive']),
    findProcessMode: general.findProcessMode ?? general['find-process-mode'] ?? '',
    unifiedDelay: Boolean(general.unifiedDelay ?? general['unified-delay']),
    tcpConcurrent: Boolean(general.tcpConcurrent ?? general['tcp-concurrent']),
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
    etagSupport: Boolean(general.etagSupport ?? general['etag-support']),
    tlsCertificate: general.tlsCertificate ?? tls.certificate ?? '',
    tlsPrivateKey: general.tlsPrivateKey ?? tls['private-key'] ?? '',
    tlsCustom,
  }
}

const generalFieldKeys = [
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

function normalizeClientDns(dns = {}) {
  const extra = omitKeys(dns, dnsFieldKeys)
  return {
    ...extra,
    enable: dns.enable !== false,
    listen: dns.listen || '0.0.0.0:1053',
    ipv6: Boolean(dns.ipv6),
    cacheAlgorithm: dns.cacheAlgorithm ?? dns['cache-algorithm'] ?? '',
    preferH3: Boolean(dns.preferH3 ?? dns['prefer-h3']),
    useHosts: Boolean(dns.useHosts ?? dns['use-hosts']),
    useSystemHosts: Boolean(dns.useSystemHosts ?? dns['use-system-hosts']),
    respectRules: Boolean(dns.respectRules ?? dns['respect-rules']),
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
    directNameserverFollowPolicy: Boolean(dns.directNameserverFollowPolicy ?? dns['direct-nameserver-follow-policy']),
    proxyServerNameserver: normalizeTextList(dns.proxyServerNameserver ?? dns['proxy-server-nameserver'], []),
    proxyServerNameserverPolicy: isPlainObject(dns.proxyServerNameserverPolicy) ? dns.proxyServerNameserverPolicy : isPlainObject(dns['proxy-server-nameserver-policy']) ? dns['proxy-server-nameserver-policy'] : {},
    nameserverPolicy: isPlainObject(dns.nameserverPolicy) ? dns.nameserverPolicy : isPlainObject(dns['nameserver-policy']) ? dns['nameserver-policy'] : {},
  }
}

const dnsFieldKeys = [
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

function normalizeClientSniffer(sniffer = {}) {
  const extra = omitKeys(sniffer, snifferFieldKeys)
  return {
    ...extra,
    enable: Boolean(sniffer.enable),
    overrideDestination: sniffer.overrideDestination ?? sniffer['override-destination'] ?? true,
    parsePureIp: Boolean(sniffer.parsePureIp ?? sniffer['parse-pure-ip']),
    forceDnsMapping: Boolean(sniffer.forceDnsMapping ?? sniffer['force-dns-mapping']),
    sniff: normalizeSniffForText(sniffer.sniff, ['TLS:443,8443', 'HTTP:80,8080-8880', 'QUIC:443,8443']),
    forceDomain: normalizeTextList(sniffer.forceDomain ?? sniffer['force-domain'], ['+.netflix.com', '+.youtube.com']),
    skipDomain: normalizeTextList(sniffer.skipDomain ?? sniffer['skip-domain'], ['+.apple.com']),
    skipSrcAddress: normalizeTextList(sniffer.skipSrcAddress ?? sniffer['skip-src-address'], []),
    skipDstAddress: normalizeTextList(sniffer.skipDstAddress ?? sniffer['skip-dst-address'], []),
  }
}

const snifferFieldKeys = [
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

function normalizeClientTun(tun = {}) {
  const extra = omitKeys(tun, tunFieldKeys)
  return {
    ...extra,
    enable: Boolean(tun.enable),
    stack: tun.stack || 'mixed',
    device: tun.device || '',
    autoRoute: tun.autoRoute ?? tun['auto-route'] ?? true,
    autoRedirect: Boolean(tun.autoRedirect ?? tun['auto-redirect']),
    autoDetectInterface: tun.autoDetectInterface ?? tun['auto-detect-interface'] ?? true,
    strictRoute: Boolean(tun.strictRoute ?? tun['strict-route']),
    dnsHijack: normalizeTextList(tun.dnsHijack ?? tun['dns-hijack'], ['any:53']),
    mtu: tun.mtu || 0,
    gso: Boolean(tun.gso),
    gsoMaxSize: tun.gsoMaxSize ?? tun['gso-max-size'] ?? 0,
    udpTimeout: tun.udpTimeout ?? tun['udp-timeout'] ?? 0,
    iproute2TableIndex: tun.iproute2TableIndex ?? tun['iproute2-table-index'] ?? 0,
    iproute2RuleIndex: tun.iproute2RuleIndex ?? tun['iproute2-rule-index'] ?? 0,
    endpointIndependentNat: Boolean(tun.endpointIndependentNat ?? tun['endpoint-independent-nat']),
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

const tunFieldKeys = [
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

function normalizeClientNtp(ntp = {}) {
  const extra = omitKeys(ntp, ntpFieldKeys)
  return {
    ...extra,
    enable: Boolean(ntp.enable),
    writeToSystem: Boolean(ntp.writeToSystem ?? ntp['write-to-system']),
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

function normalizeSniffForText(value, fallback) {
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

function normalizeClientModel(model) {
  return {
    template: model?.template || 'full',
    rulesPreset: model?.rulesPreset || 'proxy',
    general: normalizeClientGeneral(model?.general),
    profile: {
      ...omitKeys(model?.profile, profileFieldKeys),
      storeSelected: Boolean(model?.profile?.storeSelected ?? model?.profile?.['store-selected']),
      storeFakeIp: Boolean(model?.profile?.storeFakeIp ?? model?.profile?.['store-fake-ip']),
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
    proxies: Array.isArray(model?.proxies) ? model.proxies.filter(isPlainObject).map((proxy) => ({ ...proxy, enabled: proxy.enabled !== false })) : [],
    groups: Array.isArray(model?.groups)
      ? model.groups
        .filter(isPlainObject)
        .map(normalizeClientGroup)
      : [],
    rules: normalizeLineList(model?.rules, ['MATCH,PROXY']),
  }
}

const profileFieldKeys = [
  'storeSelected',
  'store-selected',
  'storeFakeIp',
  'store-fake-ip',
]

function normalizeFilename(value) {
  const cleaned = String(value || '').trim().replace(/[\\/:*?"<>|]+/g, '-')
  const fallback = cleaned || 'config.yaml'
  return /\.(ya?ml)$/i.test(fallback) ? fallback : `${fallback}.yaml`
}

function syncYamlEditor() {
  yamlEditor.value = state.yaml
}

function resetSubscriptionUrl() {
  state.subscriptionUrl = ''
  renderSubscriptionUrl()
}

function renderSubscriptionUrl() {
  subscriptionUrlInput.value = state.subscriptionUrl
  copySubscriptionButton.disabled = !state.subscriptionUrl
  openSubscriptionLink.href = state.subscriptionUrl || '#'
  openSubscriptionLink.classList.toggle('disabled', !state.subscriptionUrl)
  openSubscriptionLink.setAttribute('aria-disabled', state.subscriptionUrl ? 'false' : 'true')
}

async function checkSubscriptionApiAvailability() {
  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    state.subscriptionApiAvailable = false
    updateSubscriptionStatus()
    return
  }

  try {
    const response = await fetch(apiUrl('/healthz'), {
      headers: { accept: 'application/json' },
      cache: 'no-store',
    })
    const contentType = response.headers.get('content-type') || ''
    if (!response.ok || !contentType.includes('application/json')) throw new Error('Subscription API unavailable.')
    const payload = await response.json()
    state.subscriptionApiAvailable = payload?.ok === true
  } catch {
    state.subscriptionApiAvailable = false
  }
  updateSubscriptionStatus()
}

function setupNetworkStatus() {
  window.addEventListener('online', () => {
    checkSubscriptionApiAvailability()
  })
  window.addEventListener('offline', () => {
    state.subscriptionApiAvailable = false
    updateSubscriptionStatus()
  })
}

function apiUrl(path) {
  return apiBaseUrl ? `${apiBaseUrl}${path}` : path
}

function readApiBaseUrl() {
  const runtimeValue = typeof window !== 'undefined' ? window.SUB_ELITE_API_BASE_URL || '' : ''
  const metaValue = document.querySelector('meta[name="sub-elite-api-base-url"]')?.content || ''
  const value = String(runtimeValue || metaValue || '').trim().replace(/\/+$/u, '')
  if (value && !value.includes('%SUB_ELITE_API_BASE_URL%')) return value
  return ''
}

function updateSubscriptionStatus() {
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false
  createSubscriptionButton.disabled = !state.yaml || !state.subscriptionApiAvailable || offline
  subscriptionStatus.classList.toggle('status-ok', state.subscriptionApiAvailable && !offline)
  subscriptionStatus.classList.toggle('status-warn', !state.subscriptionApiAvailable || offline)
  subscriptionStatus.textContent = offline
    ? 'Offline mode: the app shell is cached, but subscription API requires internet.'
    : state.subscriptionApiAvailable
      ? 'Backend API connected. Treat subscription URLs like secrets.'
      : 'Backend API is not available. Copy and Download still work.'
}

function showError(message) {
  errorBanner.textContent = message
  errorBanner.hidden = false
}

function clearError() {
  errorBanner.textContent = ''
  errorBanner.hidden = true
}

function showValidation(message, type) {
  validationBanner.textContent = message
  validationBanner.className = `validation-banner ${type}`
  validationBanner.hidden = false
}

function clearValidation() {
  validationBanner.textContent = ''
  validationBanner.hidden = true
  renderValidationIssues([])
}

function splitLinesOrComma(value) {
  return String(value || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

function splitLines(value) {
  return String(value || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

function compactObject(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => value !== '' && value !== undefined && value !== null),
  )
}

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function valueOrEmpty(value) {
  return value ?? ''
}

function normalizeProxyType(type) {
  return String(type || '').trim().toLowerCase()
}

function supportedNetworksForProxy(proxy) {
  return networkSupportByType[normalizeProxyType(proxy.type)] || []
}

function needsEndpoint(proxy) {
  return !['direct', 'dns'].includes(normalizeProxyType(proxy.type))
}

function isNetworkSupported(proxy, network) {
  if (!network) return true
  const supportedNetworks = supportedNetworksForProxy(proxy)
  return supportedNetworks.includes(network)
}

function normalizeAlpnValues(value) {
  if (!Array.isArray(value)) return []
  const selected = new Set(value.map((item) => String(item).trim()).filter(Boolean))
  return alpnOptions.filter((option) => selected.has(option))
}

function renderAlpnCheckboxGroup({ label = 'ALPN', selected = new Set(), inputAttribute, extraAttributes = '' }) {
  return `
    <div class="alpn-field conditional-checkbox-group wide-field" data-conditional-checkbox-group="alpn"${extraAttributes}>
      <span>${label}</span>
      <div class="alpn-options" role="group" aria-label="${escapeAttr(label)}">
        ${alpnOptions.map((option) => `
          <label class="alpn-chip">
            <input type="checkbox" ${inputAttribute} value="${escapeAttr(option)}" ${selected.has(option) ? 'checked' : ''}>
            <span>${escapeHtml(option)}</span>
          </label>
        `).join('')}
      </div>
    </div>
  `
}

function renderAlpnSelector(proxy) {
  return renderAlpnCheckboxGroup({
    selected: new Set(normalizeAlpnValues(proxy.alpn)),
    inputAttribute: 'data-field="alpn-option"',
  })
}

function updateAlpnSelection(proxy, value, checked) {
  const selected = new Set(normalizeAlpnValues(proxy.alpn))
  if (checked) selected.add(value)
  else selected.delete(value)

  const ordered = alpnOptions.filter((option) => selected.has(option))
  if (ordered.length) proxy.alpn = ordered
  else if (proxy.network === 'xhttp') proxy.alpn = ['h2']
  else delete proxy.alpn
}

function renderTlsFields(proxy) {
  const type = normalizeProxyType(proxy.type)
  const capability = tlsCapabilityByType[type]
  if (!capability) return ''
  const fields = new Set(capability.fields)
  const canToggleTls = capability.toggle
  const tlsEnabled = Boolean(proxy.tls)
  const panelHidden = canToggleTls && !tlsEnabled
  const basicFields = [
    fields.has('sni') ? `<label><span>SNI / servername</span><input type="text" data-field="sni" value="${escapeAttr(proxy.sni || proxy.servername || '')}"></label>` : '',
    fields.has('alpn') ? renderAlpnSelector(proxy) : '',
    fields.has('skip-cert-verify') ? `<label class="checkbox-row"><input type="checkbox" data-field="skip-cert-verify" ${proxy['skip-cert-verify'] ? 'checked' : ''}> Skip Cert Verify</label>` : '',
  ]
  const advancedFields = [
    fields.has('client-fingerprint') ? `<label><span>Client Fingerprint</span><select data-field="client-fingerprint">${renderSelectOptions(selectOptionsWithCurrent(clientFingerprintOptions, proxy['client-fingerprint'] || ''), proxy['client-fingerprint'] || '')}</select></label>` : '',
    fields.has('fingerprint') ? `<label><span>Fingerprint</span><input type="text" data-field="fingerprint" value="${escapeAttr(proxy.fingerprint || '')}"></label>` : '',
    fields.has('certificate') ? `<label class="wide-field"><span>Certificate</span><textarea class="mini-editor" data-field="certificate">${escapeHtml(proxy.certificate || '')}</textarea></label>` : '',
    fields.has('private-key') ? `<label class="wide-field"><span>Private Key</span><textarea class="mini-editor" data-field="private-key">${escapeHtml(proxy['private-key'] || '')}</textarea></label>` : '',
    fields.has('reality') ? `
      <label><span>reality-opts.public-key</span><input type="text" data-field="nested:reality-opts.public-key" value="${escapeAttr(proxy['reality-opts']?.['public-key'] || '')}"></label>
      <label><span>reality-opts.short-id</span><input type="text" data-field="nested:reality-opts.short-id" value="${escapeAttr(proxy['reality-opts']?.['short-id'] || '')}"></label>
      <label><span>reality-opts.support-x25519mlkem768</span><select data-field="nested:reality-opts.support-x25519mlkem768:boolean-string">${renderSelectOptions(['', 'false', 'true'], booleanOptionValue(proxy['reality-opts']?.['support-x25519mlkem768']))}</select></label>
    ` : '',
    fields.has('ech') ? `
      <label><span>ech-opts.enable</span><select data-field="nested:ech-opts.enable:boolean-string">${renderSelectOptions(['', 'false', 'true'], booleanOptionValue(proxy['ech-opts']?.enable))}</select></label>
      <label class="wide-field"><span>ech-opts.config</span><textarea class="mini-editor" data-field="nested:ech-opts.config">${escapeHtml(proxy['ech-opts']?.config || '')}</textarea></label>
      <label><span>ech-opts.query-server-name</span><input type="text" data-field="nested:ech-opts.query-server-name" value="${escapeAttr(proxy['ech-opts']?.['query-server-name'] || '')}"></label>
    ` : '',
  ]
  return `
    <div class="wide-field tls-fields">
      ${canToggleTls ? `<label class="checkbox-row tls-toggle"><input type="checkbox" data-field="tls" ${tlsEnabled ? 'checked' : ''}> TLS</label>` : ''}
      <div class="nested-node-fields tls-config-panel" ${panelHidden ? 'hidden' : ''}>
        ${renderOptionDetails('TLS', basicFields, advancedFields)}
      </div>
    </div>
  `
}

function toggleNodeTlsFields(container, enabled) {
  container?.querySelector('.tls-config-panel')?.toggleAttribute('hidden', !enabled)
}

function toggleManualTlsFields(enabled) {
  manualNodeFields.querySelectorAll('[data-manual-tls-field]').forEach((field) => {
    field.toggleAttribute('hidden', !enabled)
  })
}

function renderProtocolFields(proxy) {
  const type = normalizeProxyType(proxy.type)
  if (type === 'vless') {
    return `
      <label><span>UUID</span><input type="text" data-field="uuid" value="${escapeAttr(proxy.uuid || '')}"></label>
      <label><span>Flow</span><select data-field="flow">${renderSelectOptions(selectOptionsWithCurrent(vlessFlowOptions, proxy.flow || ''), proxy.flow || '')}</select></label>
      <label><span>Packet Encoding</span><select data-field="packet-encoding">${renderSelectOptions(selectOptionsWithCurrent(packetEncodingOptions, proxy['packet-encoding'] || ''), proxy['packet-encoding'] || '')}</select></label>
      <label><span>Encryption</span><input type="text" data-field="encryption" value="${escapeAttr(valueOrEmpty(proxy.encryption))}" placeholder="none or advanced VLESS encryption string"></label>
    `
  }
  if (type === 'vmess') {
    return `
      <label><span>UUID</span><input type="text" data-field="uuid" value="${escapeAttr(proxy.uuid || '')}"></label>
      <label><span>Cipher</span><select data-field="cipher">${renderSelectOptions(selectOptionsWithCurrent(vmessCipherOptions, proxy.cipher || 'auto'), proxy.cipher || 'auto')}</select></label>
      <label><span>Alter ID</span><input type="text" data-field="alterId:number" value="${escapeAttr(proxy.alterId ?? 0)}"></label>
      <label><span>Packet Encoding</span><select data-field="packet-encoding">${renderSelectOptions(selectOptionsWithCurrent(packetEncodingOptions, proxy['packet-encoding'] || ''), proxy['packet-encoding'] || '')}</select></label>
      <label class="checkbox-row"><input type="checkbox" data-field="global-padding" ${proxy['global-padding'] ? 'checked' : ''}> Global Padding</label>
      <label class="checkbox-row"><input type="checkbox" data-field="authenticated-length" ${proxy['authenticated-length'] ? 'checked' : ''}> Authenticated Length</label>
    `
  }
  if (type === 'trojan') {
    return `
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label class="checkbox-row"><input type="checkbox" data-field="nested:ss-opts.enabled:boolean" ${proxy['ss-opts']?.enabled ? 'checked' : ''}> ss-opts.enabled</label>
      <label><span>ss-opts.method</span><select data-field="nested:ss-opts.method">${renderSelectOptions(selectOptionsWithCurrent(trojanSsMethodOptions, proxy['ss-opts']?.method || ''), proxy['ss-opts']?.method || '')}</select></label>
      <label><span>ss-opts.password</span><input type="text" data-field="nested:ss-opts.password" value="${escapeAttr(proxy['ss-opts']?.password || '')}"></label>
    `
  }
  if (type === 'anytls') {
    return `
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label><span>idle-session-check-interval</span><input type="text" data-field="idle-session-check-interval:number" value="${escapeAttr(proxy['idle-session-check-interval'] ?? '')}"></label>
      <label><span>idle-session-timeout</span><input type="text" data-field="idle-session-timeout:number" value="${escapeAttr(proxy['idle-session-timeout'] ?? '')}"></label>
      <label><span>min-idle-session</span><input type="text" data-field="min-idle-session:number" value="${escapeAttr(proxy['min-idle-session'] ?? '')}"></label>
    `
  }
  if (type === 'hysteria2') {
    return `
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label><span>Up</span><input type="text" data-field="up" value="${escapeAttr(proxy.up || '')}"></label>
      <label><span>Down</span><input type="text" data-field="down" value="${escapeAttr(proxy.down || '')}"></label>
      <label><span>Obfs</span><input type="text" data-field="obfs" value="${escapeAttr(proxy.obfs || '')}"></label>
      <label><span>Obfs Password</span><input type="text" data-field="obfs-password" value="${escapeAttr(proxy['obfs-password'] || '')}"></label>
    `
  }
  if (type === 'ss') {
    return `
      <label><span>Cipher</span><select data-field="cipher">${renderSelectOptions(selectOptionsWithCurrent(shadowsocksCipherOptions, proxy.cipher || 'aes-128-gcm'), proxy.cipher || 'aes-128-gcm')}</select></label>
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label class="checkbox-row"><input type="checkbox" data-field="udp-over-tcp" ${proxy['udp-over-tcp'] ? 'checked' : ''}> UDP over TCP</label>
      <label><span>UDP over TCP Version</span><select data-field="udp-over-tcp-version:number">${renderSelectOptions(['', '1', '2'], String(proxy['udp-over-tcp-version'] || ''))}</select></label>
      <label><span>Plugin</span><select data-field="plugin">${renderSelectOptions(selectOptionsWithCurrent(shadowsocksPluginOptions, proxy.plugin || ''), proxy.plugin || '')}</select></label>
      <label class="wide-field"><span>Plugin opts</span><textarea class="mini-editor" data-field="plugin-opts:policy" placeholder="${escapeAttr(shadowsocksPluginOptExample(proxy.plugin))}">${escapeHtml(policyToText(proxy['plugin-opts']))}</textarea></label>
    `
  }
  if (type === 'ssr') {
    return `
      <label><span>Cipher</span><select data-field="cipher">${renderSelectOptions(selectOptionsWithCurrent(ssrCipherOptions, proxy.cipher || 'chacha20-ietf'), proxy.cipher || 'chacha20-ietf')}</select></label>
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label><span>Protocol</span><select data-field="protocol">${renderSelectOptions(selectOptionsWithCurrent(ssrProtocolOptions, proxy.protocol || 'auth_sha1_v4'), proxy.protocol || 'auth_sha1_v4')}</select></label>
      <label><span>Obfs</span><select data-field="obfs">${renderSelectOptions(selectOptionsWithCurrent(ssrObfsOptions, proxy.obfs || 'tls1.2_ticket_auth'), proxy.obfs || 'tls1.2_ticket_auth')}</select></label>
    `
  }
  if (type === 'hysteria') {
    return `
      <label><span>Auth String</span><input type="text" data-field="auth-str" value="${escapeAttr(proxy['auth-str'] || '')}"></label>
      <label><span>Protocol</span><select data-field="protocol">${renderSelectOptions(selectOptionsWithCurrent(hysteriaProtocolOptions, proxy.protocol || 'udp'), proxy.protocol || 'udp')}</select></label>
      <label><span>Up</span><input type="text" data-field="up" value="${escapeAttr(proxy.up || '')}"></label>
      <label><span>Down</span><input type="text" data-field="down" value="${escapeAttr(proxy.down || '')}"></label>
    `
  }
  if (type === 'tuic') {
    return `
      <label><span>UUID</span><input type="text" data-field="uuid" value="${escapeAttr(proxy.uuid || '')}"></label>
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label><span>UDP Relay Mode</span><select data-field="udp-relay-mode">${renderSelectOptions(selectOptionsWithCurrent(tuicUdpRelayModeOptions, proxy['udp-relay-mode'] || ''), proxy['udp-relay-mode'] || '')}</select></label>
      <label><span>Congestion Controller</span><select data-field="congestion-controller">${renderSelectOptions(selectOptionsWithCurrent(tuicCongestionControllerOptions, proxy['congestion-controller'] || ''), proxy['congestion-controller'] || '')}</select></label>
    `
  }
  if (type === 'mieru') {
    return `
      <label><span>Username</span><input type="text" data-field="username" value="${escapeAttr(proxy.username || '')}"></label>
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
      <label><span>Transport</span><select data-field="transport">${renderSelectOptions(selectOptionsWithCurrent(mieruTransportOptions, proxy.transport || 'TCP'), proxy.transport || 'TCP')}</select></label>
    `
  }
  if (['socks5', 'http', 'ssh', 'trusttunnel'].includes(type)) {
    return `
      <label><span>Username</span><input type="text" data-field="username" value="${escapeAttr(proxy.username || '')}"></label>
      <label><span>Password</span><input type="text" data-field="password" value="${escapeAttr(proxy.password || '')}"></label>
    `
  }
  if (type === 'wireguard') {
    return `
      <label><span>IP</span><input type="text" data-field="ip" value="${escapeAttr(proxy.ip || '')}"></label>
      <label><span>Private Key</span><input type="text" data-field="private-key" value="${escapeAttr(proxy['private-key'] || '')}"></label>
      <label><span>Public Key</span><input type="text" data-field="public-key" value="${escapeAttr(proxy['public-key'] || '')}"></label>
      <label><span>Preshared Key</span><input type="text" data-field="presharedKey" value="${escapeAttr(proxy.presharedKey || '')}"></label>
      <label class="wide-field"><span>Allowed IPs</span><textarea class="mini-editor" data-field="allowedIPs:list">${escapeHtml(listForInput(proxy.allowedIPs || proxy.peers?.[0]?.allowedIPs))}</textarea></label>
      <label><span>MTU</span><input type="text" data-field="mtu:number" value="${escapeAttr(proxy.mtu || '')}"></label>
    `
  }
  if (type === 'snell') {
    return `
      <label><span>PSK</span><input type="text" data-field="psk" value="${escapeAttr(proxy.psk || '')}"></label>
      <label><span>Version</span><input type="text" data-field="version:number" value="${escapeAttr(proxy.version || '')}"></label>
    `
  }
  if (type === 'sudoku') {
    return `
      <label><span>Key</span><input type="text" data-field="key" value="${escapeAttr(proxy.key || '')}"></label>
      <label><span>AEAD Method</span><input type="text" data-field="aead-method" value="${escapeAttr(proxy['aead-method'] || '')}"></label>
    `
  }
  if (type === 'masque') {
    return `
      <label><span>Public Key</span><input type="text" data-field="public-key" value="${escapeAttr(proxy['public-key'] || '')}"></label>
      <label><span>Private Key</span><input type="text" data-field="private-key" value="${escapeAttr(proxy['private-key'] || '')}"></label>
      <label><span>IP</span><input type="text" data-field="ip" value="${escapeAttr(proxy.ip || '')}"></label>
      <label><span>MTU</span><input type="text" data-field="mtu:number" value="${escapeAttr(proxy.mtu || '')}"></label>
    `
  }
  return ''
}

function renderCommonProxyFields(proxy) {
  if (!needsEndpoint(proxy)) return ''
  const type = normalizeProxyType(proxy.type)
  const includeUdp = !['hysteria', 'hysteria2', 'tuic', 'wireguard', 'masque'].includes(type)
  const includeTcp = !['hysteria', 'hysteria2', 'tuic', 'wireguard', 'masque'].includes(type)
  return `
    ${includeUdp ? `<label class="checkbox-row"><input type="checkbox" data-field="udp" ${proxy.udp ? 'checked' : ''}> UDP</label>` : ''}
    <label><span>IP Version</span><select data-field="ip-version">${renderSelectOptions(ipVersionOptions, proxy['ip-version'] || '')}</select></label>
    <label><span>Interface Name</span><input type="text" data-field="interface-name" value="${escapeAttr(proxy['interface-name'] || '')}"></label>
    <label><span>Routing Mark</span><input type="text" data-field="routing-mark:number" value="${escapeAttr(proxy['routing-mark'] || '')}"></label>
    ${includeTcp ? `<label class="checkbox-row"><input type="checkbox" data-field="tfo" ${proxy.tfo ? 'checked' : ''}> TFO</label>` : ''}
    ${includeTcp ? `<label class="checkbox-row"><input type="checkbox" data-field="mptcp" ${proxy.mptcp ? 'checked' : ''}> MPTCP</label>` : ''}
    <label><span>Dialer Proxy</span><input type="text" data-field="dialer-proxy" value="${escapeAttr(proxy['dialer-proxy'] || '')}"></label>
  `
}

function booleanSelectValue(value) {
  return String(value === true || String(value).toLowerCase() === 'true')
}

function renderNetworkOptions(proxy) {
  const current = isNetworkSupported(proxy, proxy.network) ? proxy.network : ''
  return networkOptions
    .map((option) => {
      const disabled = option.value && !isNetworkSupported(proxy, option.value)
      return `<option value="${escapeAttr(option.value)}" ${option.value === current ? 'selected' : ''} ${disabled ? 'disabled' : ''}>${escapeHtml(option.label)}</option>`
    })
    .join('')
}

function renderOptionDetails(title, basicFields, advancedFields = []) {
  const basic = basicFields.filter(Boolean).join('')
  const advanced = advancedFields.filter(Boolean).join('')
  if (!basic && !advanced) return ''
  return `
    <div class="node-option-block wide-field">
      ${basic ? `<details class="node-option-section" open><summary>${escapeHtml(title)} Basic</summary><div class="nested-node-fields">${basic}</div></details>` : ''}
      ${advanced ? `<details class="node-option-section"><summary>${escapeHtml(title)} Advanced</summary><div class="nested-node-fields">${advanced}</div></details>` : ''}
    </div>
  `
}

function renderTransportFields(proxy) {
  if (proxy.network && !isNetworkSupported(proxy, proxy.network)) return ''

  if (proxy.network === 'http') {
    return renderOptionDetails('Transport', [
      `<label><span>http-opts.method</span><select data-field="transport:http-opts.method">${renderSelectOptions(selectOptionsWithCurrent(httpMethodOptions, proxy['http-opts']?.method || ''), proxy['http-opts']?.method || '')}</select></label>`,
      `<label><span>http-opts.path</span><input type="text" data-field="transport:http-opts.path:list" value="${escapeAttr(listForInput(proxy['http-opts']?.path))}"></label>`,
      `<label class="wide-field"><span>http-opts.headers</span><textarea class="mini-editor" data-field="transport:http-opts.headers:policy">${escapeHtml(policyToText(proxy['http-opts']?.headers))}</textarea></label>`,
    ])
  }

  if (proxy.network === 'h2') {
    return renderOptionDetails('Transport', [
      `<label><span>h2-opts.host</span><input type="text" data-field="transport:h2-opts.host:list" value="${escapeAttr(listForInput(proxy['h2-opts']?.host))}"></label>`,
      `<label><span>h2-opts.path</span><input type="text" data-field="transport:h2-opts.path" value="${escapeAttr(proxy['h2-opts']?.path || '')}"></label>`,
    ])
  }

  if (proxy.network === 'grpc') {
    return renderOptionDetails('Transport', [
      `<label><span>grpc-opts.grpc-service-name</span><input type="text" data-field="transport:grpc-opts.grpc-service-name" value="${escapeAttr(proxy['grpc-opts']?.['grpc-service-name'] || '')}"></label>`,
      `<label><span>grpc-opts.grpc-user-agent</span><input type="text" data-field="transport:grpc-opts.grpc-user-agent" value="${escapeAttr(proxy['grpc-opts']?.['grpc-user-agent'] || '')}"></label>`,
    ], [
      `<label><span>grpc-opts.ping-interval</span><input type="text" data-field="transport:grpc-opts.ping-interval:number" value="${escapeAttr(proxy['grpc-opts']?.['ping-interval'] || '')}"></label>`,
      `<label><span>grpc-opts.max-connections</span><input type="text" data-field="transport:grpc-opts.max-connections:number" value="${escapeAttr(proxy['grpc-opts']?.['max-connections'] || '')}"></label>`,
      `<label><span>grpc-opts.min-streams</span><input type="text" data-field="transport:grpc-opts.min-streams:number" value="${escapeAttr(proxy['grpc-opts']?.['min-streams'] || '')}"></label>`,
      `<label><span>grpc-opts.max-streams</span><input type="text" data-field="transport:grpc-opts.max-streams:number" value="${escapeAttr(proxy['grpc-opts']?.['max-streams'] || '')}"></label>`,
    ])
  }

  if (proxy.network === 'ws') {
    return renderOptionDetails('Transport', [
      `<label><span>ws-opts.path</span><input type="text" data-field="transport:ws-opts.path" value="${escapeAttr(proxy['ws-opts']?.path || '')}"></label>`,
      `<label class="wide-field"><span>ws-opts.headers</span><textarea class="mini-editor" data-field="transport:ws-opts.headers:policy">${escapeHtml(policyToText(proxy['ws-opts']?.headers))}</textarea></label>`,
    ], [
      `<label><span>ws-opts.max-early-data</span><input type="text" data-field="transport:ws-opts.max-early-data:number" value="${escapeAttr(proxy['ws-opts']?.['max-early-data'] || '')}"></label>`,
      `<label><span>ws-opts.early-data-header-name</span><input type="text" data-field="transport:ws-opts.early-data-header-name" value="${escapeAttr(proxy['ws-opts']?.['early-data-header-name'] || '')}"></label>`,
      `<label><span>ws-opts.v2ray-http-upgrade</span><select data-field="transport:ws-opts.v2ray-http-upgrade:boolean-string">${renderSelectOptions(['false', 'true'], String(Boolean(proxy['ws-opts']?.['v2ray-http-upgrade'])))}</select></label>`,
      `<label><span>ws-opts.v2ray-http-upgrade-fast-open</span><select data-field="transport:ws-opts.v2ray-http-upgrade-fast-open:boolean-string">${renderSelectOptions(['false', 'true'], String(Boolean(proxy['ws-opts']?.['v2ray-http-upgrade-fast-open'])))}</select></label>`,
    ])
  }

  if (proxy.network === 'xhttp') {
    return renderOptionDetails('Transport', [
      `<label><span>xhttp-opts.path</span><input type="text" data-field="transport:xhttp-opts.path" value="${escapeAttr(proxy['xhttp-opts']?.path || '')}"></label>`,
      `<label><span>xhttp-opts.host</span><input type="text" data-field="transport:xhttp-opts.host" value="${escapeAttr(proxy['xhttp-opts']?.host || '')}"></label>`,
      `<label><span>xhttp-opts.mode</span><select data-field="transport:xhttp-opts.mode">${renderSelectOptions(['', 'auto', 'stream-one', 'stream-up', 'packet-up'], proxy['xhttp-opts']?.mode || '')}</select></label>`,
      `<label class="wide-field"><span>xhttp-opts.headers</span><textarea class="mini-editor" data-field="transport:xhttp-opts.headers:policy">${escapeHtml(policyToText(proxy['xhttp-opts']?.headers))}</textarea></label>`,
    ], [
      `<label><span>xhttp-opts.no-grpc-header</span><select data-field="transport:xhttp-opts.no-grpc-header:boolean-string">${renderSelectOptions(['false', 'true'], booleanSelectValue(proxy['xhttp-opts']?.['no-grpc-header']))}</select></label>`,
      `<label><span>xhttp-opts.x-padding-bytes</span><input type="text" data-field="transport:xhttp-opts.x-padding-bytes" value="${escapeAttr(proxy['xhttp-opts']?.['x-padding-bytes'] || '')}"></label>`,
      `<label><span>xhttp-opts.x-padding-obfs-mode</span><select data-field="transport:xhttp-opts.x-padding-obfs-mode:boolean-string">${renderSelectOptions(['false', 'true'], booleanSelectValue(proxy['xhttp-opts']?.['x-padding-obfs-mode']))}</select></label>`,
      `<label><span>xhttp-opts.x-padding-key</span><input type="text" data-field="transport:xhttp-opts.x-padding-key" value="${escapeAttr(proxy['xhttp-opts']?.['x-padding-key'] || '')}"></label>`,
      `<label><span>xhttp-opts.x-padding-header</span><input type="text" data-field="transport:xhttp-opts.x-padding-header" value="${escapeAttr(proxy['xhttp-opts']?.['x-padding-header'] || '')}"></label>`,
      `<label><span>xhttp-opts.x-padding-placement</span><select data-field="transport:xhttp-opts.x-padding-placement">${renderSelectOptions(['', 'queryInHeader', 'cookie', 'header', 'query'], proxy['xhttp-opts']?.['x-padding-placement'] || '')}</select></label>`,
      `<label><span>xhttp-opts.x-padding-method</span><select data-field="transport:xhttp-opts.x-padding-method">${renderSelectOptions(['', 'repeat-x', 'tokenish'], proxy['xhttp-opts']?.['x-padding-method'] || '')}</select></label>`,
      `<label><span>xhttp-opts.uplink-http-method</span><select data-field="transport:xhttp-opts.uplink-http-method">${renderSelectOptions(['', 'POST', 'PUT', 'PATCH', 'DELETE'], proxy['xhttp-opts']?.['uplink-http-method'] || '')}</select></label>`,
      `<label><span>xhttp-opts.session-placement</span><select data-field="transport:xhttp-opts.session-placement">${renderSelectOptions(['', 'path', 'query', 'cookie', 'header'], proxy['xhttp-opts']?.['session-placement'] || '')}</select></label>`,
      `<label><span>xhttp-opts.session-key</span><input type="text" data-field="transport:xhttp-opts.session-key" value="${escapeAttr(proxy['xhttp-opts']?.['session-key'] || '')}"></label>`,
      `<label><span>xhttp-opts.seq-placement</span><select data-field="transport:xhttp-opts.seq-placement">${renderSelectOptions(['', 'path', 'query', 'cookie', 'header'], proxy['xhttp-opts']?.['seq-placement'] || '')}</select></label>`,
      `<label><span>xhttp-opts.seq-key</span><input type="text" data-field="transport:xhttp-opts.seq-key" value="${escapeAttr(proxy['xhttp-opts']?.['seq-key'] || '')}"></label>`,
      `<label><span>xhttp-opts.uplink-data-placement</span><select data-field="transport:xhttp-opts.uplink-data-placement">${renderSelectOptions(['', 'body', 'cookie', 'header'], proxy['xhttp-opts']?.['uplink-data-placement'] || '')}</select></label>`,
      `<label><span>xhttp-opts.uplink-data-key</span><input type="text" data-field="transport:xhttp-opts.uplink-data-key" value="${escapeAttr(proxy['xhttp-opts']?.['uplink-data-key'] || '')}"></label>`,
      `<label><span>xhttp-opts.uplink-chunk-size</span><input type="text" data-field="transport:xhttp-opts.uplink-chunk-size:number" value="${escapeAttr(proxy['xhttp-opts']?.['uplink-chunk-size'] || '')}"></label>`,
      `<label><span>xhttp-opts.sc-max-each-post-bytes</span><input type="text" data-field="transport:xhttp-opts.sc-max-each-post-bytes:number" value="${escapeAttr(proxy['xhttp-opts']?.['sc-max-each-post-bytes'] || '')}"></label>`,
      `<label><span>xhttp-opts.sc-min-posts-interval-ms</span><input type="text" data-field="transport:xhttp-opts.sc-min-posts-interval-ms:number" value="${escapeAttr(proxy['xhttp-opts']?.['sc-min-posts-interval-ms'] || '')}"></label>`,
      `<label><span>reuse-settings.max-concurrency</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.max-concurrency" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['max-concurrency'] || '')}"></label>`,
      `<label><span>reuse-settings.max-connections</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.max-connections" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['max-connections'] || '')}"></label>`,
      `<label><span>reuse-settings.c-max-reuse-times</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.c-max-reuse-times" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['c-max-reuse-times'] || '')}"></label>`,
      `<label><span>reuse-settings.h-max-request-times</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.h-max-request-times" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['h-max-request-times'] || '')}"></label>`,
      `<label><span>reuse-settings.h-max-reusable-secs</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.h-max-reusable-secs" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['h-max-reusable-secs'] || '')}"></label>`,
      `<label><span>reuse-settings.h-keep-alive-period</span><input type="text" data-field="transport:xhttp-opts.reuse-settings.h-keep-alive-period:number" value="${escapeAttr(proxy['xhttp-opts']?.['reuse-settings']?.['h-keep-alive-period'] ?? '')}"></label>`,
      `<label class="wide-field"><span>xhttp-opts.download-settings</span><textarea class="mini-editor" data-field="transport:xhttp-opts.download-settings:json">${escapeHtml(JSON.stringify(proxy['xhttp-opts']?.['download-settings'] || {}, null, 2))}</textarea></label>`,
    ])
  }

  return ''
}

function renderSelectOptions(options, value) {
  return options
    .map((option) => `<option value="${escapeAttr(option)}" ${option === value ? 'selected' : ''}>${escapeHtml(option || 'default')}</option>`)
    .join('')
}

function booleanOptionValue(value) {
  if (value === true) return 'true'
  if (value === false) return 'false'
  return ''
}

function selectOptionsWithCurrent(options, value) {
  return value && !options.includes(value) ? [value, ...options] : options
}

function shadowsocksPluginOptExample(plugin) {
  return shadowsocksPluginOptExamples[plugin] || 'mode=websocket\nhost=example.com\npath=/'
}

function updateShadowsocksPluginOptsPlaceholder(root, plugin) {
  if (!root) return
  const pluginSelect = root.querySelector('[data-field="plugin"], [data-manual-field="plugin"]')
  const pluginOpts = root.querySelector('[data-field="plugin-opts:policy"], [data-manual-field="plugin-opts"]')
  if (!pluginOpts) return
  pluginOpts.placeholder = shadowsocksPluginOptExample(plugin ?? pluginSelect?.value)
}

function cleanupProtocolSpecificFields(proxy) {
  const keys = [
    'uuid',
    'cipher',
    'alterId',
    'flow',
    'encryption',
    'packet-encoding',
    'global-padding',
    'authenticated-length',
    'password',
    'ss-opts',
    'plugin',
    'plugin-opts',
    'udp-over-tcp',
    'udp-over-tcp-version',
    'protocol',
    'obfs',
    'protocol-param',
    'obfs-param',
    'psk',
    'version',
    'username',
    'auth-str',
    'up',
    'down',
    'obfs-password',
    'udp-relay-mode',
    'congestion-controller',
    'transport',
    'key',
    'aead-method',
    'public-key',
    'private-key',
    'presharedKey',
    'allowedIPs',
    'peers',
    'ip',
    'mtu',
    'idle-session-check-interval',
    'idle-session-timeout',
    'min-idle-session',
    'tls',
    'sni',
    'servername',
    'alpn',
    'client-fingerprint',
    'fingerprint',
    'skip-cert-verify',
    'certificate',
    'reality-opts',
    'ech-opts',
  ]
  for (const key of keys) delete proxy[key]
}

function applyProtocolDefaults(proxy) {
  const type = normalizeProxyType(proxy.type)
  if (type === 'vmess') {
    proxy.cipher = 'auto'
    proxy.alterId = 0
  } else if (type === 'ss') {
    proxy.cipher = 'aes-128-gcm'
  } else if (type === 'ssr') {
    proxy.cipher = 'chacha20-ietf'
    proxy.protocol = 'auth_sha1_v4'
    proxy.obfs = 'tls1.2_ticket_auth'
  } else if (type === 'snell') {
    proxy.version = 3
  } else if (type === 'anytls') {
    proxy.udp = true
  } else if (type === 'tuic') {
    proxy['udp-relay-mode'] = 'native'
    proxy.udp = true
  } else if (type === 'masque') {
    proxy.ip = '172.16.0.2/32'
    proxy.mtu = 1280
    proxy.udp = true
  } else if (['hysteria2', 'trusttunnel'].includes(type)) {
    proxy.udp = true
  }
}

function cleanupUnsupportedTlsFields(proxy) {
  const fields = new Set(tlsCapabilityByType[normalizeProxyType(proxy.type)]?.fields || [])
  if (!fields.has('sni')) {
    delete proxy.sni
    delete proxy.servername
  }
  if (!fields.has('alpn') && proxy.network !== 'xhttp') delete proxy.alpn
  if (!fields.has('client-fingerprint')) delete proxy['client-fingerprint']
  if (!fields.has('fingerprint')) delete proxy.fingerprint
  if (!fields.has('skip-cert-verify')) delete proxy['skip-cert-verify']
  if (!fields.has('certificate')) delete proxy.certificate
  if (!fields.has('private-key')) delete proxy['private-key']
  if (!fields.has('reality')) delete proxy['reality-opts']
  if (!fields.has('ech')) delete proxy['ech-opts']
}

function cleanupDisabledTlsFields(proxy) {
  delete proxy.sni
  delete proxy.servername
  if (proxy.network !== 'xhttp') delete proxy.alpn
  delete proxy['client-fingerprint']
  delete proxy.fingerprint
  delete proxy['skip-cert-verify']
  delete proxy.certificate
  delete proxy['private-key']
  delete proxy['reality-opts']
  delete proxy['ech-opts']
}

function setProxyNetwork(proxy, value) {
  cleanupTransportOptions(proxy)
  if (!value) {
    delete proxy.network
    return
  }

  if (!isNetworkSupported(proxy, value)) {
    delete proxy.network
    showValidation('Network is not compatible with this node type according to Mihomo.', 'error')
    return
  }

  proxy.network = value
  if (value === 'xhttp') {
    if (!Array.isArray(proxy.alpn) || !proxy.alpn.length) proxy.alpn = ['h2']
    if (proxy.encryption === undefined) proxy.encryption = ''
    proxy['xhttp-opts'] = {
      path: '/',
      'no-grpc-header': false,
      'x-padding-obfs-mode': false,
      ...(proxy.servername || proxy.sni ? { host: proxy.servername || proxy.sni } : {}),
    }
  }
}

function updateNestedProxyField(proxy, field, target) {
  const [, optionKey, valueType = 'string'] = field.split(':')
  const [section, ...keyParts] = optionKey.split('.')
  const key = keyParts.at(-1)
  const parents = keyParts.slice(0, -1)
  proxy[section] = proxy[section] || {}
  let container = proxy[section]
  for (const parent of parents) {
    container[parent] = container[parent] || {}
    container = container[parent]
  }

  let value
  if (valueType === 'boolean') value = target.checked
  else if (valueType === 'boolean-string') value = target.value === 'true' ? true : target.value === 'false' ? false : ''
  else if (valueType === 'number') value = parseNumberInput(target.value)
  else if (valueType === 'list') value = splitLinesOrComma(target.value)
  else if (valueType === 'policy') value = textToPolicy(target.value)
  else if (valueType === 'json') {
    value = parseJsonObjectInput(target.value, key)
    if (value === invalidEditorInput) {
      cleanupEmptyNestedSection(proxy, section, parents)
      return false
    }
  }
  else value = target.value

  if (isEmptyTransportValue(value)) delete container[key]
  else container[key] = value
  cleanupEmptyNestedSection(proxy, section, parents)
  return true
}

function updateTransportField(proxy, field, target) {
  const [, optionKey, valueType = 'string'] = field.split(':')
  const [section, ...keyParts] = optionKey.split('.')
  const key = keyParts.at(-1)
  const parents = keyParts.slice(0, -1)
  proxy[section] = proxy[section] || {}
  let container = proxy[section]
  for (const parent of parents) {
    container[parent] = container[parent] || {}
    container = container[parent]
  }

  let value
  if (valueType === 'boolean') value = target.checked
  else if (valueType === 'boolean-string') value = target.value === 'true'
  else if (valueType === 'number') value = parseNumberInput(target.value)
  else if (valueType === 'list') value = splitLinesOrComma(target.value)
  else if (valueType === 'policy') value = textToPolicy(target.value)
  else if (valueType === 'json') {
    value = parseJsonObjectInput(target.value, key)
    if (value === invalidEditorInput) {
      cleanupEmptyNestedSection(proxy, section, parents)
      return false
    }
  }
  else value = target.value

  if (isEmptyTransportValue(value)) delete container[key]
  else container[key] = value
  cleanupEmptyNestedSection(proxy, section, parents)
  return true
}

function cleanupTransportOptions(proxy) {
  delete proxy['ws-opts']
  delete proxy['grpc-opts']
  delete proxy['h2-opts']
  delete proxy['http-opts']
  delete proxy['httpupgrade-opts']
  delete proxy['xhttp-opts']
}

function listForInput(value) {
  if (Array.isArray(value)) return value.join(', ')
  return String(value || '')
}

function isEmptyTransportValue(value) {
  if (value === '' || value === undefined || value === null) return true
  if (Array.isArray(value) && value.length === 0) return true
  if (typeof value === 'object' && Object.keys(value).length === 0) return true
  return false
}

function parseNumberInput(value) {
  const text = String(value || '').trim()
  if (text === '') return ''
  const number = Number(text)
  return Number.isFinite(number) ? number : ''
}

function pruneEmptyTransportParents(root, parents) {
  for (let depth = parents.length; depth > 0; depth -= 1) {
    const path = parents.slice(0, depth)
    const parentPath = parents.slice(0, depth - 1)
    const key = path.at(-1)
    const parent = parentPath.reduce((object, part) => object?.[part], root)
    if (parent?.[key] && typeof parent[key] === 'object' && Object.keys(parent[key]).length === 0) delete parent[key]
  }
}

function textToPolicy(value, { typedValues = false } = {}) {
  return Object.fromEntries(
    String(value || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [key, ...rest] = line.split('=')
        return rest.length ? [key.trim(), parsePolicyValue(rest.join('='), typedValues)] : ['', '']
      })
      .filter(([key]) => key),
  )
}

function policyToText(value = {}) {
  if (!isPlainObject(value)) return ''
  return Object.entries(value)
    .map(([key, resolvers]) => `${key}=${Array.isArray(resolvers) ? resolvers.join(',') : resolvers}`)
    .join('\n')
}

function parsePolicyValue(value, typedValues = false) {
  const text = String(value || '').trim()
  if (typedValues) {
    if (text === 'true') return true
    if (text === 'false') return false
    const number = Number(text)
    if (text && Number.isFinite(number)) return number
  }
  const values = splitLinesOrComma(text)
  return values.length > 1 ? values : text
}

function parseJsonOrLines(value) {
  const text = String(value || '').trim()
  if (!text) return []
  try {
    const parsed = JSON.parse(text)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return splitLines(text)
  }
}

function parseJsonObjectInput(value, label = 'JSON') {
  const text = String(value || '').trim()
  if (!text) return {}
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
  } catch {
    // Fall through to the shared validation message below.
  }
  showValidation(`${label} must be a valid JSON object.`, 'error')
  return invalidEditorInput
}

function presetRules(value) {
  if (value === 'lan-direct') {
    return [
      'IP-CIDR,10.0.0.0/8,DIRECT',
      'IP-CIDR,172.16.0.0/12,DIRECT',
      'IP-CIDR,192.168.0.0/16,DIRECT',
      'IP-CIDR,127.0.0.0/8,DIRECT',
      'IP-CIDR,169.254.0.0/16,DIRECT',
      'MATCH,PROXY',
    ]
  }
  if (value === 'direct') return ['MATCH,DIRECT']
  return ['MATCH,PROXY']
}

function replaceGroupProxyName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.map((name) => (name === previousName ? nextName : name))
  }
}

function removeGroupProxyName(name) {
  if (!name || !state.model) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.filter((item) => item !== name)
    if (!group.proxies.length) group.proxies = ['DIRECT']
  }
}

function replaceGroupProxyNames(renameMap) {
  if (!state.model || !renameMap.size) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.map((name) => renameMap.get(name) || name)
  }
}

function replaceGroupProviderName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  for (const group of state.model.groups) {
    group.use = group.use.map((name) => (name === previousName ? nextName : name))
  }
}

function removeGroupProviderName(name) {
  if (!name || !state.model) return
  for (const group of state.model.groups) {
    group.use = group.use.filter((item) => item !== name)
  }
}

function pruneGroupProxyRefs(keptNames) {
  if (!state.model) return
  const groupNames = new Set(state.model.groups.map((group) => group.name))
  for (const group of state.model.groups) {
    group.proxies = group.proxies.filter((name) => {
      if (name === group.name || groupReferenceCreatesCycle(group.name, name)) return false
      return keptNames.has(name) || groupNames.has(name) || ['DIRECT', 'REJECT'].includes(name)
    })
    if (!group.proxies.length) group.proxies = keptNames.size ? [...keptNames] : ['DIRECT']
  }
}

function groupReferenceCreatesCycle(sourceName, targetName, groups = state.model?.groups || []) {
  if (!sourceName || !targetName) return false
  if (sourceName === targetName) return true

  const groupNames = new Set(groups.map((group) => group.name).filter(Boolean))
  if (!groupNames.has(targetName)) return false

  const graph = new Map(groups.map((group) => [
    group.name,
    (Array.isArray(group.proxies) ? group.proxies : []).filter((name) => groupNames.has(name)),
  ]))
  graph.set(sourceName, uniqueList([...(graph.get(sourceName) || []), targetName]))

  const seen = new Set()
  const stack = [targetName]
  while (stack.length) {
    const name = stack.pop()
    if (name === sourceName) return true
    if (seen.has(name)) continue
    seen.add(name)
    stack.push(...(graph.get(name) || []))
  }
  return false
}

function formatNodeName(proxy, index, pattern) {
  const originalName = proxy.name || proxy.server || proxy.type || 'proxy'
  const fallbackName = String(originalName).replaceAll(',', ' ').replace(/\s+/g, ' ').trim() || 'proxy'
  const number = String(index + 1)
  return pattern
    .replaceAll('{name}', originalName)
    .replaceAll('{type}', proxy.type || '')
    .replaceAll('{server}', proxy.server || '')
    .replaceAll('{port}', proxy.port ? String(proxy.port) : '')
    .replaceAll('{n}', number)
    .replaceAll('{nn}', number.padStart(2, '0'))
    .replaceAll(',', ' ')
    .replace(/\s+/g, ' ')
    .trim() || fallbackName
}

function makeLocalUniqueNames(proxies) {
  const seen = new Map()
  for (const proxy of proxies) {
    const base = proxy.name || `${proxy.type || 'proxy'}-${proxy.server || 'node'}`
    const count = seen.get(base) || 0
    seen.set(base, count + 1)
    proxy.name = count === 0 ? base : `${base} ${count + 1}`
  }
}

function proxySignature(proxy) {
  return [
    proxy.type,
    proxy.server,
    proxy.port,
    proxy.uuid,
    proxy.password,
    proxy.cipher,
  ].map((part) => String(part || '').trim().toLowerCase()).join('|')
}

function stripEnabled(proxy) {
  const cleanProxy = { ...proxy }
  delete cleanProxy.id
  delete cleanProxy.enabled
  return cleanProxy
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function downloadText(filename, text, type) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char])
}

function escapeAttr(value) {
  return escapeHtml(value)
}

function applyPlaceholders(root = document) {
  root.querySelectorAll('input[type="text"], textarea').forEach((field) => {
    if (field.placeholder) return
    const label = field.closest('label')?.querySelector('span')?.textContent?.trim() || ''
    const key = field.id || field.dataset.field || field.dataset.manualField || label
    const placeholder = placeholderForInput(key, label)
    if (placeholder) field.placeholder = placeholder
  })
}

function placeholderForInput(key, label = '') {
  const normalizedKey = String(key || '').replace(/:(number|list|policy|json|boolean-string)$/u, '')
  const examples = {
    'converter-input': 'vmess://...\nvless://...\ntrojan://...\n\nproxies:\n  - name: example\n    type: vless\n    server: example.com\n    port: 443',
    'filename-input': 'config-1.yaml',
    'name-pattern-input': '{nn} - {type} - {name}',
    'bulk-rename-pattern': '{nn} - {type} - {server}',
    'manual-node-name': 'SG VLESS WS',
    'group-name-input': 'PROXY',
    'proxy-provider-name': 'provider-main',
    'proxy-provider-url': 'https://example.com/provider.yaml',
    'rule-provider-name': 'reject-ads',
    'rule-provider-url': 'https://example.com/rules.yaml',
    'node-keyword-input': 'sg, vless, example.com',
    name: 'example-node',
    server: 'example.com',
    port: '443',
    uuid: '11111111-1111-1111-1111-111111111111',
    password: 'your-password',
    username: 'user',
    cipher: 'auto',
    alterId: '0',
    flow: 'xtls-rprx-vision',
    encryption: '',
    sni: 'example.com',
    'client-fingerprint': 'chrome',
    fingerprint: 'chrome',
    certificate: '-----BEGIN CERTIFICATE-----\n...',
    'reality.public-key': 'reality-public-key',
    'reality.short-id': '0123456789abcdef',
    'ech.config': 'base64_encoded_ech_config',
    'ech.query-server-name': 'public.example.com',
    'nested:reality-opts.public-key': 'reality-public-key',
    'nested:reality-opts.short-id': '0123456789abcdef',
    'nested:ech-opts.config': 'base64_encoded_ech_config',
    'nested:ech-opts.query-server-name': 'public.example.com',
    'dialer-proxy': 'PROXY',
    'interface-name': 'eth0',
    interfaceName: 'eth0',
    'routing-mark': '6666',
    routingMark: '6666',
    proxies: 'AUTO, DIRECT, SG-01',
    use: 'provider-main',
    url: 'https://www.gstatic.com/generate_204',
    interval: '300',
    timeout: '5000',
    maxFailedTimes: '3',
    filter: 'SG|Singapore',
    excludeFilter: 'test|expire',
    excludeType: 'direct',
    expectedStatus: '204',
    icon: 'https://example.com/icon.png',
    path: './providers/provider.yaml',
    proxy: 'DIRECT',
    sizeLimit: '0',
    header: 'User-Agent=clash.meta\nAuthorization=Bearer token',
    override: 'additional-prefix=SG',
    payload: 'DOMAIN-SUFFIX,example.com\nIP-CIDR,1.1.1.0/24',
    rawJson: '{\n  "name": "example-node",\n  "type": "vless"\n}',
    'plugin-opts': 'mode=websocket\nhost=example.com\npath=/ws',
    allowedIPs: '0.0.0.0/0\n::/0',
    'public-key': 'base64-public-key',
    'private-key': 'base64-private-key',
    presharedKey: 'base64-preshared-key',
    mtu: '1280',
    psk: 'snell-password',
    key: 'sudoku-key',
    ip: '172.16.0.2/32',
    'auth-str': 'auth-token',
    protocol: 'udp',
    obfs: 'salamander',
    'obfs-password': 'obfs-password',
    up: '50 Mbps',
    down: '100 Mbps',
    transport: 'TCP',
    'udp-relay-mode': 'native',
    'congestion-controller': 'bbr',
    'http.method': 'GET',
    'http.path': '/path\n/api',
    'http.headers': 'Host=example.com\nUser-Agent=Mozilla/5.0',
    'h2.host': 'example.com\ncdn.example.com',
    'h2.path': '/',
    'grpc.grpc-service-name': 'grpc-service',
    'grpc.grpc-user-agent': 'mihomo',
    'grpc.ping-interval': '30',
    'grpc.max-connections': '1',
    'grpc.min-streams': '0',
    'grpc.max-streams': '0',
    'ws.path': '/ws',
    'ws.headers': 'Host=example.com',
    'ws.max-early-data': '2048',
    'ws.early-data-header-name': 'Sec-WebSocket-Protocol',
    'xhttp.path': '/xhttp',
    'xhttp.host': 'example.com',
    'xhttp.headers': 'Host=example.com',
    'xhttp.x-padding-bytes': '100-1000',
    'xhttp.x-padding-key': 'x_padding',
    'xhttp.x-padding-header': 'Referer',
    'xhttp.session-key': 'session',
    'xhttp.seq-key': 'seq',
    'xhttp.uplink-data-key': 'data',
    'xhttp.uplink-chunk-size': '3072',
    'xhttp.sc-max-each-post-bytes': '1000000',
    'xhttp.sc-min-posts-interval-ms': '30',
    'xhttp.reuse-settings.max-concurrency': '4',
    'xhttp.reuse-settings.max-connections': '2',
    'xhttp.reuse-settings.c-max-reuse-times': '64',
    'xhttp.reuse-settings.h-max-request-times': '600',
    'xhttp.reuse-settings.h-max-reusable-secs': '180',
    'xhttp.reuse-settings.h-keep-alive-period': '0',
    'xhttp.download-settings': '{\n  "address": "example.com",\n  "port": 443\n}',
    'transport:http-opts.method': 'GET',
    'transport:http-opts.path': '/path\n/api',
    'transport:http-opts.headers': 'Host=example.com\nUser-Agent=Mozilla/5.0',
    'transport:h2-opts.host': 'example.com\ncdn.example.com',
    'transport:h2-opts.path': '/',
    'transport:grpc-opts.grpc-service-name': 'grpc-service',
    'transport:grpc-opts.grpc-user-agent': 'mihomo',
    'transport:grpc-opts.ping-interval': '30',
    'transport:grpc-opts.max-connections': '1',
    'transport:grpc-opts.min-streams': '0',
    'transport:grpc-opts.max-streams': '0',
    'transport:ws-opts.path': '/ws',
    'transport:ws-opts.headers': 'Host=example.com',
    'transport:ws-opts.max-early-data': '2048',
    'transport:ws-opts.early-data-header-name': 'Sec-WebSocket-Protocol',
    'transport:xhttp-opts.path': '/xhttp',
    'transport:xhttp-opts.host': 'example.com',
    'transport:xhttp-opts.headers': 'Host=example.com',
    'transport:xhttp-opts.x-padding-bytes': '100-1000',
    'transport:xhttp-opts.x-padding-key': 'x_padding',
    'transport:xhttp-opts.x-padding-header': 'Referer',
    'transport:xhttp-opts.session-key': 'session',
    'transport:xhttp-opts.seq-key': 'seq',
    'transport:xhttp-opts.uplink-data-key': 'data',
    'transport:xhttp-opts.uplink-chunk-size': '3072',
    'transport:xhttp-opts.sc-max-each-post-bytes': '1000000',
    'transport:xhttp-opts.sc-min-posts-interval-ms': '30',
    'transport:xhttp-opts.reuse-settings.max-concurrency': '4',
    'transport:xhttp-opts.reuse-settings.max-connections': '2',
    'transport:xhttp-opts.reuse-settings.c-max-reuse-times': '64',
    'transport:xhttp-opts.reuse-settings.h-max-request-times': '600',
    'transport:xhttp-opts.reuse-settings.h-max-reusable-secs': '180',
    'transport:xhttp-opts.reuse-settings.h-keep-alive-period': '0',
    'transport:xhttp-opts.download-settings': '{\n  "address": "example.com",\n  "port": 443\n}',
    'general-port': '7890',
    'general-socks-port': '7891',
    'general-redir-port': '7892',
    'general-tproxy-port': '7893',
    'general-mixed-port': '7890',
    'general-bind-address': '*',
    'general-lan-allowed-ips': '192.168.0.0/16\n10.0.0.0/8',
    'general-lan-disallowed-ips': '192.168.1.10/32',
    'general-authentication': 'user:pass',
    'general-skip-auth-prefixes': '127.0.0.1/8\n::1/128',
    'general-interface-name': 'wlan0',
    'general-routing-mark': '6666',
    'general-keep-alive-idle': '600',
    'general-keep-alive-interval': '15',
    'general-controller': '127.0.0.1:9090',
    'general-controller-tls': '127.0.0.1:9443',
    'general-controller-unix': '/run/mihomo.sock',
    'general-controller-pipe': '\\\\.\\pipe\\mihomo',
    'general-controller-cors': '*',
    'general-ui': './ui',
    'general-ui-name': 'zashboard',
    'general-ui-url': 'https://github.com/Zephyruso/zashboard',
    'general-secret': 'secret-token',
    'general-client-fingerprint': 'chrome',
    'general-ua': 'mihomo/1.19.0',
    'general-tls-certificate': '-----BEGIN CERTIFICATE-----\n...',
    'general-tls-private-key': '-----BEGIN PRIVATE KEY-----\n...',
    'dns-listen': '0.0.0.0:1053',
    'dns-fake-ip-range': '198.18.0.1/16',
    'dns-fake-ip-range6': 'fc00::/18',
    'dns-fake-ip-ttl': '300',
    'dns-fake-ip-filter': '*.lan\n*.local',
    'dns-default': '1.1.1.1\n8.8.8.8',
    'dns-nameservers': 'https://dns.google/dns-query\nhttps://cloudflare-dns.com/dns-query',
    'dns-fallback': 'tls://8.8.4.4\nhttps://1.1.1.1/dns-query',
    'dns-fallback-filter': 'geoip=true\ngeoip-code=CN',
    'dns-direct-nameserver': 'system\n223.5.5.5',
    'dns-proxy-server': 'https://dns.google/dns-query',
    'dns-proxy-policy': 'example.com=1.1.1.1',
    'dns-policy': 'geosite:cn=https://doh.pub/dns-query',
    'sniffer-sniff': 'TLS:443,8443\nHTTP:80,8080-8880\nQUIC:443,8443',
    'sniffer-force': '+.netflix.com\n+.youtube.com',
    'sniffer-skip': '+.apple.com\nMijia Cloud',
    'sniffer-skip-src': '192.168.0.0/16',
    'sniffer-skip-dst': '10.0.0.0/8',
    'tun-device': 'utun',
    'tun-mtu': '9000',
    'tun-gso-max-size': '65536',
    'tun-udp-timeout': '300',
    'tun-iproute2-table-index': '2022',
    'tun-iproute2-rule-index': '9000',
    'tun-dns-hijack': 'any:53\ntcp://any:53',
    'tun-route-address-set': 'geoip-cn',
    'tun-route-exclude-address-set': 'private',
    'tun-route-address': '0.0.0.0/1\n128.0.0.0/1',
    'tun-route-exclude-address': '192.168.0.0/16',
    'tun-include-interface': 'wlan0',
    'tun-exclude-interface': 'rmnet_data0',
    'tun-include-uid': '1000\n1001',
    'tun-include-uid-range': '1000:2000',
    'tun-exclude-uid': '0',
    'tun-exclude-uid-range': '0:999',
    'tun-include-android-user': '0',
    'tun-include-package': 'com.android.chrome',
    'tun-exclude-package': 'com.termux',
    'geo-update-interval': '24',
    'geo-url-geoip': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
    'geo-url-geosite': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
    'geo-url-mmdb': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb',
    'geo-url-asn': 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    'rules-editor': 'DOMAIN-SUFFIX,example.com,PROXY\nIP-CIDR,1.1.1.0/24,DIRECT\nMATCH,PROXY',
  }

  if (examples[normalizedKey] !== undefined) return examples[normalizedKey]
  const lowerLabel = String(label || normalizedKey).toLowerCase()
  if (normalizedKey.endsWith('.headers') || lowerLabel.includes('header')) return 'Host=example.com'
  if (normalizedKey.endsWith('.path') || lowerLabel.includes('path')) return '/'
  if (lowerLabel.includes('url')) return 'https://example.com/file.yaml'
  if (lowerLabel.includes('domain')) return '+.example.com'
  if (lowerLabel.includes('address')) return '192.168.0.0/16'
  if (lowerLabel.includes('interval')) return '300'
  if (lowerLabel.includes('timeout')) return '5000'
  if (lowerLabel.includes('port')) return '443'
  if (lowerLabel.includes('server') || lowerLabel.includes('host')) return 'example.com'
  if (lowerLabel.includes('name')) return 'example-name'
  return ''
}

function registerPwaServiceWorker() {
  if (!('serviceWorker' in navigator)) return
  const isSecureOrigin = window.location.protocol === 'https:' || window.location.hostname === 'localhost'
  if (!isSecureOrigin) return

  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-worker.js').catch(() => undefined)
  })
}

updateRulesState()
renderManualNodeFields()
setActiveEdit('general')
applyPlaceholders()
registerPwaServiceWorker()
