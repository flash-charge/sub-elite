import { state, manualNodeName, manualNodeType, manualNodeFields, invalidEditorInput } from './state.js'
import {
  networkOptions, networkSupportByType, clientFingerprintOptions,
  vmessCipherOptions, vlessFlowOptions, packetEncodingOptions, ipVersionOptions,
  trojanSsMethodOptions, tlsCapabilityByType, ssrCipherOptions, ssrProtocolOptions,
  ssrObfsOptions, hysteriaProtocolOptions, tuicUdpRelayModeOptions,
  tuicCongestionControllerOptions, mieruTransportOptions, httpMethodOptions,
  shadowsocksCipherOptions, shadowsocksPluginOptions,
} from './constants.ts'
import { escapeHtml, escapeAttr, isPlainObject, compactObject, splitLinesOrComma, normalizeProxyType } from './utils.ts'
import { applyPlaceholders, showValidation } from './app.js'
import { validEditableName, hasDuplicateName, hasNameInCollection } from './groups.js'
import { nodeExpansionKey } from './nodes.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { renderSelectOptions, renderAlpnCheckboxGroup, shadowsocksPluginOptExample, parseJsonObjectInput, setProxyNetwork, textToPolicy } from './proxy-fields.js'

export function renderManualNodeFields(values = {}) {
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
      ...manualCommonProxyFields(type, { udpChecked: true }),
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
      ...manualCommonProxyFields(type, { udpChecked: true }),
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
      { key: 'ipv6', label: 'IPv6' },
      { key: 'private-key', label: 'Private Key', required: true },
      { key: 'public-key', label: 'Public Key', required: true },
      { key: 'pre-shared-key', label: 'Preshared Key' },
      { key: 'reserved', label: 'Reserved', placeholder: '209,98,59' },
      { key: 'allowed-ips', label: 'Allowed IPs', type: 'textarea', wide: true },
      { key: 'mtu', label: 'MTU' },
      { key: 'persistent-keepalive', label: 'Keepalive' },
      { key: 'remote-dns-resolve', label: 'Remote DNS Resolve', type: 'checkbox' },
      { key: 'dns', label: 'DNS', placeholder: '1.1.1.1,8.8.8.8' },
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
  const udpChecked = options.udpChecked || false
  return [
    ...(includeUdp ? [{ key: 'udp', label: 'UDP', type: 'checkbox', checked: udpChecked }] : []),
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

export function readManualNodeValues() {
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

function parseReservedField(value) {
  const text = String(value || '').trim()
  if (!text) return undefined
  const parts = text.split(',').map((s) => s.trim())
  if (parts.every((p) => /^\d+$/.test(p))) return parts.map(Number)
  return text
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

export function compactManualObject(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => {
      if (value === '' || value === undefined || value === null) return false
      if (Array.isArray(value) && !value.length) return false
      if (isPlainObject(value) && !Object.keys(value).length) return false
      return true
    }),
  )
}

export function addManualNode() {
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
    proxy['pre-shared-key'] = values['pre-shared-key']
    proxy.ip = values.ip
    proxy.ipv6 = values.ipv6
    proxy.reserved = parseReservedField(values.reserved)
    proxy.mtu = parseManualNumber(values.mtu)
    proxy['persistent-keepalive'] = parseManualNumber(values['persistent-keepalive'])
    proxy['remote-dns-resolve'] = values['remote-dns-resolve'] || undefined
    proxy.dns = values.dns ? values.dns.split(',').map((s) => s.trim()).filter(Boolean) : undefined
    proxy.peers = [{
      server: values.server,
      port: parseManualNumber(values.port) || values.port,
      'public-key': values['public-key'],
      'pre-shared-key': values['pre-shared-key'] || undefined,
      reserved: parseReservedField(values.reserved),
      'allowed-ips': splitLinesOrComma(values['allowed-ips']),
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

export function toggleManualTlsFields(enabled) {
  manualNodeFields.querySelectorAll('[data-manual-tls-field]').forEach((field) => {
    field.toggleAttribute('hidden', !enabled)
  })
}
