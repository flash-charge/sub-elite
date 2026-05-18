import { buildYamlFromModel, createConfigModel } from '../lib/converter.ts'
import { parseDocument } from 'yaml'
import { state, invalidEditorInput, nodeUiKeys, apiBaseUrl, linkProtocolPattern, input, fileInput, templateSelect, rulesSelect, namePatternInput, filenameInput, convertButton, blankConfigButton, sampleButton, copyButton, downloadButton, exportFormatSelect, formatYamlButton, validateYamlButton, autoFixButton, toggleDiffButton, resetYamlButton, createSubscriptionButton, copySubscriptionButton, openSubscriptionLink, subscriptionUrlInput, errorBanner, yamlEditor, diffPanel, diffSummary, diffViewer, validationBanner,  yamlSectionSelect, yamlSectionPreview,  statTotal, statConverted, statSkipped, nodeList, groupList, groupNameInput, groupTypeInput, addGroupButton, rulesEditor, dnsEnable, dnsListen, dnsCacheAlgorithm, dnsPreferH3, dnsUseHosts, dnsUseSystemHosts, dnsRespectRules, dnsDefault, dnsNameservers, generalPort, generalSocksPort, generalRedirPort, generalTproxyPort, generalMixedPort, generalMode, generalLogLevel, generalBindAddress, generalLanAllowedIps, generalLanDisallowedIps, generalAuthentication, generalSkipAuthPrefixes, generalInterfaceName, generalRoutingMark, generalKeepAliveIdle, generalKeepAliveInterval, generalFindProcessMode, generalController, generalControllerTls, generalControllerUnix, generalControllerPipe, generalControllerCors, generalUi, generalUiName, generalUiUrl, generalSecret, generalClientFingerprint, generalUa, generalTlsCertificate, generalTlsPrivateKey, generalAllowLan, generalIpv6, generalDisableKeepAlive, generalUnifiedDelay, generalTcpConcurrent, generalEtagSupport, profileStoreSelected, profileStoreFakeIp, dnsEnhancedMode, dnsFakeIpRange, dnsFakeIpRange6, dnsFakeIpFilterMode, dnsFakeIpTtl, dnsFakeIpFilter, dnsFallback, dnsFallbackFilter, dnsDirectNameserver, dnsDirectFollowPolicy, dnsProxyServer, dnsProxyPolicy, dnsPolicy, snifferEnable, snifferOverride, snifferParseIp, snifferForceDnsMapping, snifferSniff, snifferForce, snifferSkip, snifferSkipSrc, snifferSkipDst, tunEnable, tunStack, tunDevice, tunAutoRoute, tunAutoRedirect, tunAutoDetect, tunStrictRoute, tunDnsHijack, tunMtu, tunGso, tunGsoMaxSize, tunUdpTimeout, tunIproute2TableIndex, tunIproute2RuleIndex, tunEndpointIndependentNat, tunRouteAddressSet, tunRouteExcludeAddressSet, tunRouteAddress, tunRouteExcludeAddress, tunIncludeInterface, tunExcludeInterface, tunIncludeUid, tunIncludeUidRange, tunExcludeUid, tunExcludeUidRange, tunIncludeAndroidUser, tunIncludePackage, tunExcludePackage, geoGeodataMode, geoAutoUpdate, geoGeodataLoader, geoUpdateInterval, geoUrlGeoip, geoUrlGeosite, geoUrlMmdb, geoUrlAsn, ruleProviderName, ruleProviderUrl, addRuleProviderButton, addAdsProviderButton, applyLanRulesButton, ruleProviderList, ruleBuilderType, addRuleButton, addProxyProviderButton, proxyProviderList,  manualNodeType, manualNodeFields, addManualNodeButton, nodeFilterQuery, nodeFilterType, openNodeToolsButton, nodeToolsSheet, closeNodeToolsButton, bulkRenamePattern, applyBulkRenameButton, nodeSortField, sortNodesButton, deleteDuplicateNodesButton, fabCopy, fabDownload, toast, viewTabs, viewPanels, editTabs, editPanels, editorSectionSelect } from './state.js'
import {
  sampleLinks, MAX_IMPORT_FILE_BYTES, importFilePattern, networkSupportByType,
  alpnOptions, proxyTypeOptions, proxyTypeLabels,
} from './constants.ts'
import {
  splitLinesOrComma, isPlainObject,
  normalizeProxyType, clone, escapeHtml, escapeAttr,
  downloadText, normalizeFilename,
} from './utils.ts'
import { modelFromYamlObject, normalizeClientModel } from './model.ts'
import { renderManualNodeFields, addManualNode, readManualNodeValues, toggleManualTlsFields, compactManualObject } from './manual-node.js'
import {
  updateYamlFromModel, formatCurrentYaml, resetModel, autoFixCurrentModel,
  toggleDiffPanel, renderDiff, renderSectionPreview, buildExportYaml,
  validateCurrentYaml, renderWarnings, renderValidationIssues,
} from './yaml-tools.js'
import {
  renderDns, renderGeneral, renderSniffer, renderTun, renderGeo,
  updateDnsFromEditor, updateGeneralFromEditor, updateSnifferFromEditor,
  updateTunFromEditor, updateGeoFromEditor,
} from './editors.js'
import {
  renderRuleProviders, renderProxyProviders,
  addRuleProvider, addProxyProvider, addAdsProviderPreset, applyLanDirectRules,
} from './providers.js'
import {
  renderRules, policyTargetOptions, validPolicyTarget, addRuleFromBuilder,
  updateRuleBuilderState, replacePolicyTargetName, replacePolicyTargetNames,
  replaceRemovedPolicyTargets, fallbackPolicyTarget, refreshRenderedRuleProviderTargets,
  updateRulesFromEditor, presetRules, renderRuleTargetOptions,
} from './rules.js'
import {
  renderNodes, nodeExpansionKey, handleNodeClick, handleNodeInput,
  moveNode, openNodeTools, closeNodeTools, applyBulkRename, handleTokenClick,
  sortNodes, deleteDuplicateNodes, formatNodeName,
  makeLocalUniqueNames, proxySignature, stripEnabled, normalizeEditorModel,
} from './nodes.js'
import {
  renderGroups, addGroup, replaceGroupProxyName, removeGroupProxyName,
  replaceGroupProxyNames, replaceGroupProviderName, removeGroupProviderName,
  pruneGroupProxyRefs, groupReferenceCreatesCycle,
} from './groups.js'
import {
  updateAlpnSelection, renderTlsFields,
  toggleNodeTlsFields, renderProtocolFields, renderCommonProxyFields, renderNetworkOptions,
  renderTransportFields, renderSelectOptions,
  updateShadowsocksPluginOptsPlaceholder, cleanupProtocolSpecificFields, applyProtocolDefaults,
  cleanupUnsupportedTlsFields, cleanupDisabledTlsFields, setProxyNetwork, updateNestedProxyField,
  updateTransportField, cleanupTransportOptions, isEmptyTransportValue, pruneEmptyTransportParents,
  textToPolicy, parseJsonObjectInput,
} from './proxy-fields.js'


viewTabs.forEach((tab) => tab.addEventListener('click', () => setActiveView(tab.dataset.viewTarget)))
editTabs.forEach((tab) => tab.addEventListener('click', () => setActiveEdit(tab.dataset.editTarget)))
editorSectionSelect.addEventListener('change', () => setActiveEdit(editorSectionSelect.value))
populateNodeFilterTypes()
checkSubscriptionApiAvailability()
setupNetworkStatus()
sampleButton.addEventListener('click', useSample)
document.querySelector('#fetch-url-button').addEventListener('click', fetchSubscriptionUrl)
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
if (window.matchMedia('(max-width: 719px)').matches) {
  document.querySelectorAll('.edit-panel details[open]').forEach((d) => d.removeAttribute('open'))
}
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
  geoGeodataLoader,
  geoAutoUpdate,
  geoUpdateInterval,
  geoUrlGeoip,
  geoUrlGeosite,
  geoUrlMmdb,
  geoUrlAsn,
].forEach((field) => field.addEventListener(field.type === 'checkbox' ? 'change' : 'input', updateGeoFromEditor))
let yamlEditorDebounce = 0
yamlEditor.addEventListener('input', () => {
  state.yaml = yamlEditor.value
  state.yamlManualEdit = true
  resetSubscriptionUrl()
  clearTimeout(yamlEditorDebounce)
  yamlEditorDebounce = setTimeout(() => {
    validateCurrentYaml(false)
    renderDiff()
    renderSectionPreview()
  }, 300)
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
  convertButton.classList.add('is-loading')
  convertButton.querySelector('span').textContent = 'Converting...'
  copyButton.querySelector('span').textContent = 'Copy'
  clearError()
  showConvertSkeleton(true)

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
    convertButton.classList.remove('is-loading')
    convertButton.querySelector('span').textContent = 'Convert'
    showConvertSkeleton(false)
    updateSubmitState()
  }
}

async function convertLinksViaApi() {
  const response = await fetchWithTimeout(apiUrl('/api/convert'), {
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

  const model = normalizeClientModel(modelFromYamlObject(raw, { template: templateSelect.value, rulesPreset: rulesSelect.value }))
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
  const savedSecret = localStorage.getItem('sub-elite-secret')
  const isUpdate = Boolean(savedSecret)
  createSubscriptionButton.disabled = true
  createSubscriptionButton.classList.add('is-loading')
  createSubscriptionButton.textContent = isUpdate ? 'Updating...' : 'Creating...'

  try {
    if (isUpdate) {
      const response = await fetchWithTimeout(apiUrl(`/api/subscriptions/${savedSecret}`), {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ yaml: state.yaml }),
      })
      const payload = await readJsonResponse(response, 'Update failed.')
      if (!response.ok) throw new Error(payload.error || 'Update failed.')
      showToast('Subscription URL updated.')
    } else {
      const response = await fetchWithTimeout(apiUrl('/api/subscriptions'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ yaml: state.yaml, expiresIn: 'never', filename: filenameInput.value }),
      })
      const payload = await readJsonResponse(response, 'Subscription URL failed.')
      if (!response.ok) throw new Error(payload.error || 'Subscription URL failed.')
      state.subscriptionUrl = payload.url
      const secret = payload.url.split('/sub/')[1]?.split('/')[0]
      if (secret) localStorage.setItem('sub-elite-secret', secret)
      renderSubscriptionUrl()
      showToast('Subscription URL created.')
    }
  } catch (error) {
    showToast(error instanceof Error ? error.message : 'Subscription URL failed.', 'error')
  } finally {
    createSubscriptionButton.classList.remove('is-loading')
    updateSubscriptionButton()
  }
}

function updateSubscriptionButton() {
  const hasSecret = Boolean(localStorage.getItem('sub-elite-secret'))
  createSubscriptionButton.textContent = hasSecret ? 'Update URL' : 'Create URL'
  createSubscriptionButton.disabled = !state.yaml || !state.subscriptionApiAvailable
  document.querySelector('#new-subscription-button').hidden = !hasSecret
}
document.querySelector('#new-subscription-button').addEventListener('click', () => {
  localStorage.removeItem('sub-elite-secret')
  state.subscriptionUrl = ''
  renderSubscriptionUrl()
  updateSubscriptionButton()
  showToast('Ready to create a new subscription URL.')
})

async function copySubscriptionUrl() {
  if (!state.subscriptionUrl) return
  try {
    await navigator.clipboard.writeText(state.subscriptionUrl)
    showToast('Subscription URL copied.')
  } catch {
    showToast('Copy URL failed.', 'error')
  }
}


export function showToast(message, type = 'ok') {
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
  try {
    const exportKind = exportFormatSelect.value
    const text = buildExportYaml(exportKind)
    const filename = exportKind === 'full'
      ? normalizeFilename(filenameInput.value)
      : normalizeFilename(`${exportKind}.yaml`)
    downloadText(filename, text, 'application/yaml;charset=utf-8')
  } catch {
    showToast('Download failed. YAML may be invalid.', 'error')
  }
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

async function fetchSubscriptionUrl() {
  const url = prompt('Enter subscription URL:')
  if (!url || !url.trim()) return
  const trimmed = url.trim()
  if (!/^https?:\/\//i.test(trimmed)) {
    showError('URL must start with http:// or https://')
    return
  }
  const fetchBtn = document.querySelector('#fetch-url-button')
  fetchBtn.disabled = true
  fetchBtn.textContent = 'Fetching...'
  clearError()
  try {
    const response = await fetchWithTimeout(trimmed, { headers: { 'user-agent': 'clash.meta' } }, 15000)
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const text = await response.text()
    if (!text.trim()) throw new Error('Empty response')
    input.value = text
    clearConvertedState()
    updateSubmitState()
    showToast('URL fetched. Review it, then tap Convert.')
  } catch (error) {
    showError(`Fetch failed: ${error.message}`)
  } finally {
    fetchBtn.disabled = false
    fetchBtn.textContent = 'Fetch URL'
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

export function renderModel() {
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
  deferredEditorRender.dirty = true
  deferredEditorRender.rendered = false
  renderDeferredEditorSections()
}

const deferredEditorRender = { dirty: false, rendered: false }

function renderDeferredEditorSections() {
  if (!deferredEditorRender.dirty || deferredEditorRender.rendered) return
  deferredEditorRender.rendered = true
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
  if (view === 'edit') renderDeferredEditorSections()
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function setActiveEdit(target) {
  renderDeferredEditorSections()
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
  convertButton.disabled = !hasInput || convertButton.classList.contains('is-loading')
}

function hasHttpUrl(value) {
  return String(value || '')
    .split(/[\s,]+/)
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
  if (text.length < 10 || !/:\s/m.test(text)) return false
  const yamlKeys = /^(?:proxies|proxy-groups|rules|dns|sniffer|tun|ntp|mixed-port|proxy-providers|rule-providers)\s*:/m
  return yamlKeys.test(text)
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


export function syncYamlEditor() {
  yamlEditor.value = state.yaml
}

export function resetSubscriptionUrl() {
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
    
    return
  }

  try {
    const response = await fetchWithTimeout(apiUrl('/healthz'), {
      headers: { accept: 'application/json' },
      cache: 'no-store',
    }, 10000)
    const contentType = response.headers.get('content-type') || ''
    if (!response.ok || !contentType.includes('application/json')) throw new Error('Subscription API unavailable.')
    const payload = await response.json()
    state.subscriptionApiAvailable = payload?.ok === true
  } catch {
    state.subscriptionApiAvailable = false
  }
  updateSubscriptionButton()
  const savedSecret = localStorage.getItem('sub-elite-secret')
  if (savedSecret && state.subscriptionApiAvailable) {
    state.subscriptionUrl = `${location.origin}/sub/${savedSecret}/${filenameInput.value || 'config.yaml'}`
    renderSubscriptionUrl()
  }
}

function setupNetworkStatus() {
  window.addEventListener('online', () => {
    checkSubscriptionApiAvailability()
  })
  window.addEventListener('offline', () => {
    state.subscriptionApiAvailable = false
    
  })
}

function apiUrl(path) {
  return apiBaseUrl ? `${apiBaseUrl}${path}` : path
}

function fetchWithTimeout(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeoutMs)
  return fetch(url, { ...options, signal: controller.signal }).catch((error) => {
    if (error.name === 'AbortError') throw new Error('Request timed out.')
    throw error
  }).finally(() => clearTimeout(id))
}


function showError(message) {
  errorBanner.textContent = message
  errorBanner.hidden = false
}

function clearError() {
  errorBanner.textContent = ''
  errorBanner.hidden = true
}

function showConvertSkeleton(show) {
  const skeleton = document.querySelector('#convert-skeleton')
  skeleton.classList.toggle('active', show)
  yamlEditor.hidden = show
}

export function showValidation(message, type) {
  validationBanner.textContent = message
  validationBanner.className = `validation-banner ${type}`
  validationBanner.hidden = false
}

export function clearValidation() {
  validationBanner.textContent = ''
  validationBanner.hidden = true
  renderValidationIssues([])
}


export function supportedNetworksForProxy(proxy) {
  return networkSupportByType[normalizeProxyType(proxy.type)] || []
}

export function needsEndpoint(proxy) {
  return !['direct', 'dns'].includes(normalizeProxyType(proxy.type))
}

export function isNetworkSupported(proxy, network) {
  if (!network) return true
  const supportedNetworks = supportedNetworksForProxy(proxy)
  return supportedNetworks.includes(network)
}

export function normalizeAlpnValues(value) {
  if (!Array.isArray(value)) return []
  const selected = new Set(value.map((item) => String(item).trim()).filter(Boolean))
  return alpnOptions.filter((option) => selected.has(option))
}






export function applyPlaceholders(root = document) {
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
    'filename-input': 'config.yaml',
    'general-mixed-port': '7890',
    'general-bind-address': '*',
    'dns-listen': '0.0.0.0:1053',
    'dns-fake-ip-range': '198.18.0.1/16',
    'geo-update-interval': '24',
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
