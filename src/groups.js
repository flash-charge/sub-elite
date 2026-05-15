import { state, groupList, groupNameInput, groupTypeInput } from './state.js'
import { escapeHtml, escapeAttr, splitLinesOrComma } from './utils.ts'
import { renderSelectOptions, isEmptyTransportValue, pruneEmptyTransportParents } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { replacePolicyTargetName, fallbackPolicyTarget, renderRuleTargetOptions } from './rules.js'
import { showValidation, clearValidation, applyPlaceholders } from './app.js'

export function renderGroups() {
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
    row.open = false
    const healthFields = groupSupportsHealth(group)
    row.innerHTML = `
      <summary>
        <span class="group-summary">
          <strong>${escapeHtml(group.name || 'Unnamed group')}</strong>
          <em>${escapeHtml(group.type || 'select')}</em>
        </span>
        <small>${escapeHtml(groupSummaryText(group))}</small>
        <span class="group-move-buttons">
          <button type="button" class="ghost-button node-action-button" data-action="move-up" aria-label="Move up">↑</button>
          <button type="button" class="ghost-button node-action-button" data-action="move-down" aria-label="Move down">↓</button>
        </span>
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
          ${group.type === 'load-balance' ? `<label><span>Strategy</span><select data-field="strategy">
            ${['consistent-hashing', 'round-robin', 'sticky-sessions'].map((s) => `<option value="${s}" ${s === (group.strategy || 'consistent-hashing') ? 'selected' : ''}>${s}</option>`).join('')}
          </select></label>` : ''}
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
    row.querySelectorAll('.group-move-buttons button').forEach((btn) => {
      btn.addEventListener('click', (event) => {
        event.preventDefault()
        event.stopPropagation()
        const action = btn.dataset.action
        if (action === 'move-up' && index > 0) {
          const [item] = state.model.groups.splice(index, 1)
          state.model.groups.splice(index - 1, 0, item)
          updateYamlFromModel()
        }
        if (action === 'move-down' && index < state.model.groups.length - 1) {
          const [item] = state.model.groups.splice(index, 1)
          state.model.groups.splice(index + 1, 0, item)
          updateYamlFromModel()
        }
      })
    })
    row.addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]')?.dataset.action
      if (!action) return
      if (action === 'move-up' || action === 'move-down') return
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

export function groupSupportsHealth(group) {
  return ['url-test', 'fallback', 'load-balance'].includes(group.type)
}

export function groupSummaryText(group) {
  const proxyCount = Array.isArray(group.proxies) ? group.proxies.length : 0
  const providerCount = Array.isArray(group.use) ? group.use.length : 0
  const parts = [`${proxyCount} ${proxyCount === 1 ? 'proxy' : 'proxies'}`]
  if (providerCount || group.includeAllProviders) parts.push(`${providerCount} ${providerCount === 1 ? 'provider' : 'providers'}`)
  if (group.includeAll || group.includeAllProxies || group.includeAllProviders) parts.push('include all')
  return parts.join(' · ')
}

export function groupProxyOptions(group) {
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

export function uniqueList(items) {
  return [...new Set(items.map((item) => String(item || '').trim()).filter(Boolean))]
}

export function hasDuplicateName(items, name) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item) => String(item?.name || '').trim() === normalizedName)
}

export function hasDuplicateNameExcept(items, name, index) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item, itemIndex) => itemIndex !== index && String(item?.name || '').trim() === normalizedName)
}

export function hasNameInCollection(items, name) {
  const normalizedName = String(name || '').trim()
  return Boolean(normalizedName) && items.some((item) => String(item?.name || '').trim() === normalizedName)
}

export function rejectEmptyNameInput(target, previousName, label) {
  if (String(target.value || '').trim()) return false
  target.value = previousName || ''
  showValidation(`${label} name cannot be empty.`, 'error')
  return true
}

export function nameHasRuleSeparator(value) {
  return String(value || '').includes(',')
}

export function rejectRuleSeparatorNameInput(target, previousName, label) {
  if (!nameHasRuleSeparator(target.value)) return false
  target.value = previousName || ''
  showValidation(`${label} name cannot contain commas.`, 'error')
  return true
}

export function validEditableName(name, label) {
  if (!String(name || '').trim()) return `${label} name cannot be empty.`
  if (nameHasRuleSeparator(name)) return `${label} name cannot contain commas.`
  return ''
}

export function generatedProviderPath(basePath, name) {
  return `${basePath}/${name}.yaml`
}

export function syncGeneratedProviderPath(provider, previousName, nextName, basePath) {
  if (!provider || !previousName || !nextName || previousName === nextName) return
  const previousPath = generatedProviderPath(basePath, previousName)
  if (!provider.path || provider.path === previousPath) provider.path = generatedProviderPath(basePath, nextName)
}

export function cleanupEmptyNestedSection(proxy, section, parents) {
  pruneEmptyTransportParents(proxy[section], parents)
  if (isEmptyTransportValue(proxy[section])) delete proxy[section]
}

export function renderGroupProxyPicker(group) {
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

export function groupProviderOptions() {
  const providerNames = (state.model?.proxyProviders || [])
    .map((provider) => provider.name)
    .filter(Boolean)
  return uniqueList(providerNames)
    .map((value) => ({ value }))
}

export function renderGroupProviderPicker(group) {
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





export function addGroup() {
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

export function replaceGroupProxyName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.map((name) => (name === previousName ? nextName : name))
  }
}

export function removeGroupProxyName(name) {
  if (!name || !state.model) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.filter((item) => item !== name)
    if (!group.proxies.length) group.proxies = ['DIRECT']
  }
}

export function replaceGroupProxyNames(renameMap) {
  if (!state.model || !renameMap.size) return
  for (const group of state.model.groups) {
    group.proxies = group.proxies.map((name) => renameMap.get(name) || name)
  }
}

export function replaceGroupProviderName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  for (const group of state.model.groups) {
    group.use = group.use.map((name) => (name === previousName ? nextName : name))
  }
}

export function removeGroupProviderName(name) {
  if (!name || !state.model) return
  for (const group of state.model.groups) {
    group.use = group.use.filter((item) => item !== name)
  }
}

export function pruneGroupProxyRefs(keptNames) {
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

export function groupReferenceCreatesCycle(sourceName, targetName, groups = state.model?.groups || []) {
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
