import { state, nodeList, nodeUiKeys, nodeFilterQuery, nodeFilterType, nodeToolsSheet, bulkRenamePattern, nodeSortField, invalidEditorInput } from './state.js'
import { escapeHtml, escapeAttr, normalizeProxyType, isPlainObject, splitLinesOrComma } from './utils.ts'
import { proxyTypeOptions } from './constants.ts'
import { renderTlsFields, renderProtocolFields, renderCommonProxyFields, renderTransportFields, renderNetworkOptions, renderSelectOptions, updateShadowsocksPluginOptsPlaceholder, cleanupProtocolSpecificFields, applyProtocolDefaults, cleanupUnsupportedTlsFields, cleanupDisabledTlsFields, setProxyNetwork, updateNestedProxyField, updateTransportField, cleanupTransportOptions, updateAlpnSelection, toggleNodeTlsFields, textToPolicy, parseJsonObjectInput } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { replacePolicyTargetName, replacePolicyTargetNames, replaceRemovedPolicyTargets, renderRuleTargetOptions, policyTargetOptions, validPolicyTarget, fallbackPolicyTarget } from './rules.js'
import { showToast, showValidation, needsEndpoint, supportedNetworksForProxy, isNetworkSupported, clearValidation, applyPlaceholders } from './app.js'
import { renderGroups, replaceGroupProxyName, replaceGroupProxyNames, removeGroupProxyName, pruneGroupProxyRefs, rejectEmptyNameInput, rejectRuleSeparatorNameInput, nameHasRuleSeparator, hasDuplicateNameExcept, hasNameInCollection } from './groups.js'
import { compactManualObject } from './manual-node.js'

export function renderNodes() {
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
    row.addEventListener('dragend', () => {
      state.draggedNode = -1
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

export function nodeExpansionKey(proxy) {
  if (proxy.id) return `id:${proxy.id}`
  if (!nodeUiKeys.has(proxy)) {
    const randomPart = Math.random().toString(36).slice(2, 9)
    nodeUiKeys.set(proxy, `ui:${randomPart}`)
  }
  return nodeUiKeys.get(proxy)
}

export function nodeSummaryParts(proxy) {
  const parts = []
  if (needsEndpoint(proxy)) parts.push(`${proxy.server || 'server'}:${proxy.port || 'port'}`)
  if (proxy.network) parts.push(`network ${proxy.network}`)
  if (proxy.tls) parts.push('TLS')
  return parts.length ? parts : ['local node']
}

export function filteredNodeEntries() {
  const query = nodeFilterQuery.value.trim().toLowerCase()
  const type = nodeFilterType.value
  return (state.model?.proxies || [])
    .map((proxy, index) => ({ proxy, index }))
    .filter(({ proxy }) => {
      const proxyType = normalizeProxyType(proxy.type)
      if (type && proxyType !== type) return false
      if (!query) return true
      return [proxy.name, proxy.server, proxyType, proxy.network]
        .map((value) => String(value || '').toLowerCase())
        .some((value) => value.includes(query))
    })
}

export function handleNodeClick(event, index) {
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
      pruneGroupProxyRefs(new Set(state.model.proxies.map((item) => item.name)))
      replacePolicyTargetName(previousName, fallbackPolicyTarget())
    }
    updateYamlFromModel()
  }
}

export function handleNodeInput(event, index) {
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
      state.model.proxies[index] = parsed
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
  } else if (['flow', 'udp-relay-mode', 'congestion-controller', 'ports', 'hop-interval', 'bbr-profile', 'up', 'down', 'obfs', 'obfs-password'].includes(field) && !event.target.value) {
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




export function normalizeEditorModel() {
  if (!state.model) return
  const options = policyTargetOptions()
  state.model.proxies.forEach((proxy) => {
    if (proxy['dialer-proxy']) proxy['dialer-proxy'] = String(proxy['dialer-proxy']).trim()
    if (proxy['dialer-proxy'] && !options.includes(proxy['dialer-proxy'])) proxy['dialer-proxy'] = ''
  })
  state.model.ruleProviders.forEach((provider) => {
    provider.target = validPolicyTarget(String(provider.target || 'PROXY').trim(), options)
    if (provider.proxy) provider.proxy = String(provider.proxy).trim()
    if (provider.proxy && !options.includes(provider.proxy)) provider.proxy = ''
  })
  state.model.proxyProviders.forEach((provider) => {
    if (provider.proxy) provider.proxy = String(provider.proxy).trim()
    if (provider.proxy && !options.includes(provider.proxy)) provider.proxy = ''
  })
  state.model.tunnels.forEach((tunnel) => {
    if (tunnel.proxy) tunnel.proxy = String(tunnel.proxy).trim()
    if (tunnel.proxy && !options.includes(tunnel.proxy)) tunnel.proxy = ''
  })
  const enabledProxyNames = new Set(state.model.proxies.map((proxy) => proxy.name).filter(Boolean))
  pruneGroupProxyRefs(enabledProxyNames)
  const proxyProviderNames = new Set(state.model.proxyProviders.map((provider) => provider.name).filter(Boolean))
  state.model.groups.forEach((group) => {
    group.use = (Array.isArray(group.use) ? group.use : []).filter((name) => proxyProviderNames.has(name))
  })
}

function syncWireGuardPeerField(proxy, field) {
  if (normalizeProxyType(proxy?.type) !== 'wireguard') return
  if (!['server', 'port', 'public-key', 'pre-shared-key', 'allowed-ips'].includes(field)) return
  proxy.peers = Array.isArray(proxy.peers) && proxy.peers.length ? proxy.peers : [{}]
  const peer = proxy.peers[0]
  if (field === 'server') peer.server = proxy.server
  else if (field === 'port') peer.port = proxy.port
  else if (field === 'public-key') peer['public-key'] = proxy['public-key']
  else if (field === 'pre-shared-key') {
    if (proxy['pre-shared-key']) peer['pre-shared-key'] = proxy['pre-shared-key']
    else delete peer['pre-shared-key']
  } else if (field === 'allowed-ips') {
    if (Array.isArray(proxy['allowed-ips']) && proxy['allowed-ips'].length) peer['allowed-ips'] = proxy['allowed-ips']
    else delete peer['allowed-ips']
  }
  proxy.peers[0] = compactManualObject(peer)
}

export function moveNode(from, to) {
  if (!state.model || from === to || from < 0 || to < 0 || from >= state.model.proxies.length || to >= state.model.proxies.length) return
  const [item] = state.model.proxies.splice(from, 1)
  state.model.proxies.splice(to, 0, item)
  updateYamlFromModel()
}

export function moveNodeByVisibleOffset(index, offset) {
  const visibleIndexes = filteredNodeEntries().map((entry) => entry.index)
  const visibleIndex = visibleIndexes.indexOf(index)
  const targetIndex = visibleIndexes[visibleIndex + offset]
  if (targetIndex === undefined) return
  moveNode(index, targetIndex)
  const targetVisibleIndex = visibleIndex + offset
  const row = nodeList.children[targetVisibleIndex]
  if (row) { row.classList.add("node-moved"); row.addEventListener("animationend", () => row.classList.remove("node-moved"), { once: true }) }
}

export function openNodeTools() {
  if (!state.model) return
  nodeToolsSheet.hidden = false
}

export function closeNodeTools() {
  nodeToolsSheet.hidden = true
}

export function applyBulkRename() {
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

export function handleTokenClick(event) {
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

export function sortNodes() {
  if (!state.model) return
  const field = nodeSortField.value
  state.model.proxies.sort((left, right) => String(left[field] || '').localeCompare(String(right[field] || '')))
  updateYamlFromModel()
  showToast('Nodes sorted.')
}

export function deleteDuplicateNodes() {
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
    keptNames.add(proxy.name)
    return true
  })
  pruneGroupProxyRefs(keptNames)
  replaceRemovedPolicyTargets(removedNames, fallbackPolicyTarget())
  updateYamlFromModel()
  showToast(`${before - state.model.proxies.length} duplicate nodes removed.`)
}


export function formatNodeName(proxy, index, pattern) {
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

export function makeLocalUniqueNames(proxies) {
  const assigned = new Set()
  const seen = new Map()
  for (const proxy of proxies) {
    const base = proxy.name || `${proxy.type || 'proxy'}-${proxy.server || 'node'}`
    const count = seen.get(base) || 0
    seen.set(base, count + 1)
    let candidate = count === 0 ? base : `${base} ${count + 1}`
    while (assigned.has(candidate)) {
      seen.set(base, seen.get(base) + 1)
      candidate = `${base} ${seen.get(base)}`
    }
    proxy.name = candidate
    assigned.add(candidate)
  }
}

export function proxySignature(proxy) {
  return [
    proxy.type,
    proxy.server,
    proxy.port,
    proxy.uuid,
    proxy.password,
    proxy.cipher,
    proxy.network,
    proxy.tls,
  ].map((part) => String(part || '').trim().toLowerCase()).join('|')
}

export function stripEnabled(proxy) {
  const cleanProxy = { ...proxy }
  delete cleanProxy.id
  delete cleanProxy.enabled
  return cleanProxy
}
