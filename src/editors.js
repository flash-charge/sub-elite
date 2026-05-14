import { state, dnsEnable, dnsListen, dnsCacheAlgorithm, dnsPreferH3, dnsUseHosts, dnsUseSystemHosts, dnsRespectRules, dnsDefault, dnsNameservers, dnsEnhancedMode, dnsFakeIpRange, dnsFakeIpRange6, dnsFakeIpFilterMode, dnsFakeIpTtl, dnsFakeIpFilter, dnsFallback, dnsFallbackFilter, dnsDirectNameserver, dnsDirectFollowPolicy, dnsProxyServer, dnsProxyPolicy, dnsPolicy, generalPort, generalSocksPort, generalRedirPort, generalTproxyPort, generalMixedPort, generalMode, generalLogLevel, generalBindAddress, generalLanAllowedIps, generalLanDisallowedIps, generalAuthentication, generalSkipAuthPrefixes, generalInterfaceName, generalRoutingMark, generalKeepAliveIdle, generalKeepAliveInterval, generalFindProcessMode, generalController, generalControllerTls, generalControllerUnix, generalControllerPipe, generalControllerCors, generalUi, generalUiName, generalUiUrl, generalSecret, generalClientFingerprint, generalUa, generalTlsCertificate, generalTlsPrivateKey, generalAllowLan, generalIpv6, generalDisableKeepAlive, generalUnifiedDelay, generalTcpConcurrent, generalEtagSupport, profileStoreSelected, profileStoreFakeIp, snifferEnable, snifferOverride, snifferParseIp, snifferForceDnsMapping, snifferSniff, snifferForce, snifferSkip, snifferSkipSrc, snifferSkipDst, tunEnable, tunStack, tunDevice, tunAutoRoute, tunAutoRedirect, tunAutoDetect, tunStrictRoute, tunDnsHijack, tunMtu, tunGso, tunGsoMaxSize, tunUdpTimeout, tunIproute2TableIndex, tunIproute2RuleIndex, tunEndpointIndependentNat, tunRouteAddressSet, tunRouteExcludeAddressSet, tunRouteAddress, tunRouteExcludeAddress, tunIncludeInterface, tunExcludeInterface, tunIncludeUid, tunIncludeUidRange, tunExcludeUid, tunExcludeUidRange, tunIncludeAndroidUser, tunIncludePackage, tunExcludePackage, geoGeodataMode, geoAutoUpdate, geoGeodataLoader, geoUpdateInterval, geoUrlGeoip, geoUrlGeosite, geoUrlMmdb, geoUrlAsn } from './state.js'
import { splitLinesOrComma, splitLines, isPlainObject } from './utils.ts'
import { omitKeys, dnsFieldKeys, generalFieldKeys, profileFieldKeys, snifferFieldKeys, tunFieldKeys, geoFieldKeys } from './model.ts'
import { textToPolicy, policyToText } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'

export function renderDns() {
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

export function renderGeneral() {
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

export function renderSniffer() {
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

export function renderTun() {
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

export function renderGeo() {
  if (!state.model) return
  geoGeodataMode.checked = state.model.geo.geodataMode
  geoGeodataLoader.value = state.model.geo.geodataLoader || ''
  geoAutoUpdate.checked = state.model.geo.geoAutoUpdate
  geoUpdateInterval.value = state.model.geo.geoUpdateInterval
  geoUrlGeoip.value = state.model.geo.geoxUrl.geoip
  geoUrlGeosite.value = state.model.geo.geoxUrl.geosite
  geoUrlMmdb.value = state.model.geo.geoxUrl.mmdb
  geoUrlAsn.value = state.model.geo.geoxUrl.asn
}

export function updateDnsFromEditor() {
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

export function updateGeneralFromEditor() {
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

export function updateSnifferFromEditor() {
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

export function updateTunFromEditor() {
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

export function updateGeoFromEditor() {
  if (!state.model) return
  const extra = omitKeys(state.model.geo, geoFieldKeys)
  state.model.geo = {
    ...extra,
    geodataMode: geoGeodataMode.checked,
    geodataLoader: geoGeodataLoader.value,
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
