import { state, ruleProviderName, ruleProviderUrl, ruleProviderBehavior, ruleProviderTarget, ruleProviderFormat, ruleProviderList, proxyProviderName, proxyProviderUrl, proxyProviderType, proxyProviderList } from './state.js'
import { escapeHtml, escapeAttr, splitLines, valueOrEmpty } from './utils.ts'
import { providerTypes } from './constants.ts'
import { renderSelectOptions, textToPolicy, policyToText, parseJsonOrLines } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { showToast, showValidation, validEditableName, hasDuplicateName, hasDuplicateNameExcept, rejectEmptyNameInput, rejectRuleSeparatorNameInput, generatedProviderPath, syncGeneratedProviderPath, applyPlaceholders, removeGroupProviderName, replaceGroupProviderName, renderGroups } from './app.js'
import { validPolicyTarget, policyTargetOptions, syncProviderRule, replaceProviderRuleName, removeRuleProviderRules, presetRules } from './rules.js'

export function renderRuleProviders() {
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
          <em>${escapeHtml(provider.type || 'http')}</em>
          <em>${escapeHtml(provider.behavior || 'classical')}</em>
          <em>${escapeHtml(provider.target || 'PROXY')}</em>
        </span>
        <small>${escapeHtml(provider.url || provider.path || 'No source configured')}</small>
      </summary>
      <div class="form-grid section-grid provider-edit-grid">
        <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(valueOrEmpty(provider.name))}"></label>
        <label><span>Type</span><select data-field="type">
          ${providerTypes.map((type) => `<option value="${type}" ${type === (provider.type || 'http') ? 'selected' : ''}>${type}</option>`).join('')}
        </select></label>
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

export function renderProxyProviders() {
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
          ${providerTypes.map((type) => `<option value="${type}" ${type === provider.type ? 'selected' : ''}>${type}</option>`).join('')}
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

export function handleRuleProviderInput(event, index) {
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
  else if (field === 'type') {
    provider.type = providerTypes.includes(event.target.value) ? event.target.value : 'http'
    updateYamlFromModel()
    return
  }
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

export function handleProxyProviderInput(event, index) {
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
  else if (field === 'type') {
    provider.type = providerTypes.includes(event.target.value) ? event.target.value : 'http'
    updateYamlFromModel()
    return
  }
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

export function upsertRuleProvider(provider) {
  const existing = state.model.ruleProviders.find((item) => item.name === provider.name)
  if (existing) Object.assign(existing, provider)
  else state.model.ruleProviders.push(provider)
}

export function ensureRule(rule, beforeMatch = false) {
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

export function ensureMatchRule() {
  if (!state.model.rules.some((rule) => rule.startsWith('MATCH,'))) state.model.rules.push('MATCH,PROXY')
}

export function addRuleProvider() {
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

export function addProxyProvider() {
  if (!state.model) return
  const name = proxyProviderName.value.trim()
  const type = proxyProviderType.value
  const nameIssue = validEditableName(name, 'Proxy provider')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.proxyProviders, name)) {
    showValidation(`Proxy provider "${name}" already exists.`, 'error')
    return
  }
  if (type !== 'inline' && !proxyProviderUrl.value.trim()) {
    showValidation('URL is required for http/file proxy providers.', 'error')
    return
  }
  state.model.proxyProviders.push({
    name,
    type,
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


export function addAdsProviderPreset() {
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

export function applyLanDirectRules() {
  if (!state.model) return
  for (const rule of presetRules('lan-direct').filter((item) => item !== 'MATCH,PROXY')) {
    ensureRule(rule, true)
  }
  ensureMatchRule()
  updateYamlFromModel()
  showToast('LAN DIRECT rules added.')
}
