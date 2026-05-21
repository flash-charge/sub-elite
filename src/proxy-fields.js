import { invalidEditorInput } from './state.js'
import {
  networkOptions, alpnOptions, clientFingerprintOptions,
  vmessCipherOptions, vlessFlowOptions, packetEncodingOptions, ipVersionOptions,
  trojanSsMethodOptions, tlsCapabilityByType, ssrCipherOptions, ssrProtocolOptions,
  ssrObfsOptions, hysteriaProtocolOptions, tuicUdpRelayModeOptions,
  tuicCongestionControllerOptions, mieruTransportOptions, httpMethodOptions,
  shadowsocksCipherOptions, shadowsocksPluginOptions, shadowsocksPluginOptExamples,
} from './constants.ts'
import { escapeHtml, escapeAttr, normalizeProxyType, isPlainObject, splitLinesOrComma, splitLines, valueOrEmpty } from './utils.ts'
import { normalizeAlpnValues, needsEndpoint, isNetworkSupported, showValidation } from './app.js'
import { cleanupEmptyNestedSection } from './groups.js'

export function renderAlpnCheckboxGroup({ label = 'ALPN', selected = new Set(), inputAttribute, extraAttributes = '' }) {
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

export function renderAlpnSelector(proxy) {
  return renderAlpnCheckboxGroup({
    selected: new Set(normalizeAlpnValues(proxy.alpn)),
    inputAttribute: 'data-field="alpn-option"',
  })
}

export function updateAlpnSelection(proxy, value, checked) {
  const selected = new Set(normalizeAlpnValues(proxy.alpn))
  if (checked) selected.add(value)
  else selected.delete(value)

  const ordered = alpnOptions.filter((option) => selected.has(option))
  if (ordered.length) proxy.alpn = ordered
  else if (proxy.network === 'xhttp') proxy.alpn = ['h2']
  else delete proxy.alpn
}

export function renderTlsFields(proxy) {
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

export function toggleNodeTlsFields(container, enabled) {
  container?.querySelector('.tls-config-panel')?.toggleAttribute('hidden', !enabled)
}


export function renderProtocolFields(proxy) {
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
      <label><span>Ports</span><input type="text" data-field="ports" value="${escapeAttr(proxy.ports || '')}" placeholder="443-8443"></label>
      <label><span>Hop Interval</span><input type="text" data-field="hop-interval" value="${escapeAttr(proxy['hop-interval'] || '')}" placeholder="30 or 15-30"></label>
      <label><span>Up</span><input type="text" data-field="up" value="${escapeAttr(proxy.up || '')}"></label>
      <label><span>Down</span><input type="text" data-field="down" value="${escapeAttr(proxy.down || '')}"></label>
      <label><span>BBR Profile</span><select data-field="bbr-profile">${renderSelectOptions(['', 'standard', 'conservative', 'aggressive'], proxy['bbr-profile'] || '')}</select></label>
      <label><span>Obfs</span><select data-field="obfs">${renderSelectOptions(['', 'salamander'], proxy.obfs || '')}</select></label>
      <label><span>Obfs Password</span><input type="text" data-field="obfs-password" value="${escapeAttr(proxy['obfs-password'] || '')}"></label>
      <label class="checkbox-row"><input type="checkbox" data-field="nested:realm-opts.enable:boolean" ${proxy['realm-opts']?.enable ? 'checked' : ''}> realm-opts.enable</label>
      <label><span>realm-opts.server-url</span><input type="text" data-field="nested:realm-opts.server-url" value="${escapeAttr(proxy['realm-opts']?.['server-url'] || '')}" placeholder="https://realm.hy2.io"></label>
      <label><span>realm-opts.token</span><input type="text" data-field="nested:realm-opts.token" value="${escapeAttr(proxy['realm-opts']?.token || '')}" placeholder="public"></label>
      <label><span>realm-opts.realm-id</span><input type="text" data-field="nested:realm-opts.realm-id" value="${escapeAttr(proxy['realm-opts']?.['realm-id'] || '')}" placeholder="my-cabin-1f3a8c2e9b"></label>
      <label class="wide-field"><span>realm-opts.stun-servers</span><textarea class="mini-editor" data-field="nested:realm-opts.stun-servers:list" placeholder="stun.nextcloud.com:3478&#10;stun.sip.us:3478">${escapeHtml(listForInput(proxy['realm-opts']?.['stun-servers']))}</textarea></label>
      <label><span>realm-opts.sni</span><input type="text" data-field="nested:realm-opts.sni" value="${escapeAttr(proxy['realm-opts']?.sni || '')}" placeholder="realm.hy2.io"></label>
      <label class="checkbox-row"><input type="checkbox" data-field="nested:realm-opts.skip-cert-verify:boolean" ${proxy['realm-opts']?.['skip-cert-verify'] ? 'checked' : ''}> realm-opts.skip-cert-verify</label>
      <label><span>realm-opts.fingerprint</span><input type="text" data-field="nested:realm-opts.fingerprint" value="${escapeAttr(proxy['realm-opts']?.fingerprint || '')}" placeholder="xxxx"></label>
      <label class="wide-field"><span>realm-opts.certificate</span><textarea class="mini-editor" data-field="nested:realm-opts.certificate">${escapeHtml(proxy['realm-opts']?.certificate || '')}</textarea></label>
      <label class="wide-field"><span>realm-opts.private-key</span><textarea class="mini-editor" data-field="nested:realm-opts.private-key">${escapeHtml(proxy['realm-opts']?.['private-key'] || '')}</textarea></label>
      <label><span>realm-opts.alpn</span><input type="text" data-field="nested:realm-opts.alpn:list" value="${escapeAttr(listForInput(proxy['realm-opts']?.alpn))}" placeholder="h3"></label>
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
      <label><span>IPv6</span><input type="text" data-field="ipv6" value="${escapeAttr(proxy.ipv6 || '')}"></label>
      <label><span>Private Key</span><input type="text" data-field="private-key" value="${escapeAttr(proxy['private-key'] || '')}"></label>
      <label><span>Public Key</span><input type="text" data-field="public-key" value="${escapeAttr(proxy['public-key'] || '')}"></label>
      <label><span>Preshared Key</span><input type="text" data-field="pre-shared-key" value="${escapeAttr(proxy['pre-shared-key'] || '')}"></label>
      <label><span>Reserved</span><input type="text" data-field="reserved" value="${escapeAttr(Array.isArray(proxy.reserved) ? proxy.reserved.join(',') : (proxy.reserved || ''))}" placeholder="209,98,59"></label>
      <label class="wide-field"><span>Allowed IPs</span><textarea class="mini-editor" data-field="allowed-ips:list">${escapeHtml(listForInput(proxy['allowed-ips'] || proxy.peers?.[0]?.['allowed-ips']))}</textarea></label>
      <label><span>MTU</span><input type="text" data-field="mtu:number" value="${escapeAttr(proxy.mtu || '')}"></label>
      <label><span>Keepalive</span><input type="text" data-field="persistent-keepalive:number" value="${escapeAttr(proxy['persistent-keepalive'] || '')}"></label>
      <label><span>Remote DNS</span><input type="checkbox" data-field="remote-dns-resolve:boolean" ${proxy['remote-dns-resolve'] ? 'checked' : ''}></label>
      <label><span>DNS</span><input type="text" data-field="dns:list" value="${escapeAttr(Array.isArray(proxy.dns) ? proxy.dns.join(',') : (proxy.dns || ''))}" placeholder="1.1.1.1,8.8.8.8"></label>
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

export function renderCommonProxyFields(proxy) {
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

export function renderNetworkOptions(proxy) {
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

export function renderTransportFields(proxy) {
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
      `<label><span>ws-opts.v2ray-http-upgrade</span><select data-field="transport:ws-opts.v2ray-http-upgrade:boolean-string">${renderSelectOptions(['false', 'true'], booleanSelectValue(proxy['ws-opts']?.['v2ray-http-upgrade']))}</select></label>`,
      `<label><span>ws-opts.v2ray-http-upgrade-fast-open</span><select data-field="transport:ws-opts.v2ray-http-upgrade-fast-open:boolean-string">${renderSelectOptions(['false', 'true'], booleanSelectValue(proxy['ws-opts']?.['v2ray-http-upgrade-fast-open']))}</select></label>`,
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

export function renderSelectOptions(options, value) {
  return options
    .map((option) => `<option value="${escapeAttr(option)}" ${option === value ? 'selected' : ''}>${escapeHtml(option || 'default')}</option>`)
    .join('')
}

export function booleanOptionValue(value) {
  if (value === true) return 'true'
  if (value === false) return 'false'
  return ''
}

function selectOptionsWithCurrent(options, value) {
  return value && !options.includes(value) ? [value, ...options] : options
}

export function shadowsocksPluginOptExample(plugin) {
  return shadowsocksPluginOptExamples[plugin] || 'mode=websocket\nhost=example.com\npath=/'
}

export function updateShadowsocksPluginOptsPlaceholder(root, plugin) {
  if (!root) return
  const pluginSelect = root.querySelector('[data-field="plugin"], [data-manual-field="plugin"]')
  const pluginOpts = root.querySelector('[data-field="plugin-opts:policy"], [data-manual-field="plugin-opts"]')
  if (!pluginOpts) return
  pluginOpts.placeholder = shadowsocksPluginOptExample(plugin ?? pluginSelect?.value)
}

export function cleanupProtocolSpecificFields(proxy) {
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
    'ports',
    'hop-interval',
    'up',
    'down',
    'bbr-profile',
    'obfs-password',
    'realm-opts',
    'udp-relay-mode',
    'congestion-controller',
    'transport',
    'key',
    'aead-method',
    'public-key',
    'private-key',
    'pre-shared-key',
    'allowed-ips',
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

export function applyProtocolDefaults(proxy) {
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

export function cleanupUnsupportedTlsFields(proxy) {
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

export function cleanupDisabledTlsFields(proxy) {
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

export function setProxyNetwork(proxy, value) {
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

export function updateNestedProxyField(proxy, field, target) {
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

export function updateTransportField(proxy, field, target) {
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

export function cleanupTransportOptions(proxy) {
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

export function isEmptyTransportValue(value) {
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

export function pruneEmptyTransportParents(root, parents) {
  for (let depth = parents.length; depth > 0; depth -= 1) {
    const path = parents.slice(0, depth)
    const parentPath = parents.slice(0, depth - 1)
    const key = path.at(-1)
    const parent = parentPath.reduce((object, part) => object?.[part], root)
    if (parent?.[key] && typeof parent[key] === 'object' && Object.keys(parent[key]).length === 0) delete parent[key]
  }
}

export function textToPolicy(value, { typedValues = false } = {}) {
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

export function policyToText(value = {}) {
  if (!isPlainObject(value)) return ''
  return Object.entries(value)
    .map(([key, resolvers]) => `${key}=${Array.isArray(resolvers) ? resolvers.join(',') : resolvers}`)
    .join('\n')
}

export function parsePolicyValue(value, typedValues = false) {
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

export function parseJsonOrLines(value) {
  const text = String(value || '').trim()
  if (!text) return []
  try {
    const parsed = JSON.parse(text)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return splitLines(text)
  }
}

export function parseJsonObjectInput(value, label = 'JSON') {
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
