import { state, ruleProviderName, ruleProviderUrl, ruleProviderBehavior, ruleProviderTarget, ruleProviderFormat, ruleProviderList, proxyProviderName, proxyProviderUrl, proxyProviderPath, proxyProviderType, proxyProviderList } from './state.js'
import { compactObject, escapeHtml, escapeAttr, isPlainObject, splitLines, valueOrEmpty } from './utils.ts'
import { providerTypes, proxyTypeLabels, proxyTypeOptions } from './constants.ts'
import { renderSelectOptions, textToPolicy, policyToText, parseJsonOrLines } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { showToast, showValidation, applyPlaceholders } from './app.js'
import { validEditableName, hasDuplicateName, hasDuplicateNameExcept, rejectEmptyNameInput, rejectRuleSeparatorNameInput, generatedProviderPath, syncGeneratedProviderPath, removeGroupProviderName, replaceGroupProviderName, renderGroups } from './groups.js'
import { validPolicyTarget, policyTargetOptions, syncProviderRule, replaceProviderRuleName, removeRuleProviderRules, presetRules } from './rules.js'

const proxyProviderOverrideTextFields = [
  ['additional-prefix', 'Additional Prefix', 'SG | '],
  ['additional-suffix', 'Additional Suffix', ' | Auto'],
  ['up', 'Upload', '50 Mbps'],
  ['down', 'Download', '200 Mbps'],
  ['dialer-proxy', 'Dialer Proxy', 'PROXY'],
  ['interface-name', 'Interface Name', 'eth0'],
  ['routing-mark', 'Routing Mark', '6666'],
  ['ip-version', 'IP Version', 'ipv4'],
]

const proxyProviderOverrideBooleanFields = [
  ['udp', 'UDP'],
  ['tfo', 'TCP Fast Open'],
  ['mptcp', 'MPTCP'],
  ['skip-cert-verify', 'Skip Cert Verify'],
  ['udp-over-tcp', 'UDP over TCP'],
]

const proxyProviderOverrideVisualKeys = new Set([
  ...proxyProviderOverrideTextFields.map(([key]) => key),
  ...proxyProviderOverrideBooleanFields.map(([key]) => key),
  'proxy-name',
])

function providerSourceSummary(provider) {
  if (provider.type === 'inline') return `${(provider.payload || []).length} inline nodes`
  return provider.url || provider.path || 'No source configured'
}

function optionalPolicyTargetOptions(value = '') {
  const options = policyTargetOptions()
  const selected = value && options.includes(value) ? value : ''
  return renderSelectOptions([
    { value: '', label: 'default' },
    ...options.map((option) => ({ value: option, label: option })),
  ], selected)
}

function parseExcludeTypes(value) {
  return new Set(String(value || '').split(/\||,|\s+/).map((item) => item.trim()).filter(Boolean))
}

function renderExcludeTypeChips(provider) {
  const selected = parseExcludeTypes(provider.excludeType)
  return `
    <div class="checkbox-list proxy-type-chip-list" role="group" aria-label="Exclude Type">
      ${proxyTypeOptions.map((type) => `
        <label class="checkbox-chip">
          <input type="checkbox" data-field="excludeTypeItem" value="${escapeAttr(type)}" ${selected.has(type) ? 'checked' : ''}>
          <span>${escapeHtml(proxyTypeLabels[type] || type)}</span>
        </label>
      `).join('')}
    </div>
  `
}

function proxyProviderOverride(provider) {
  if (!isPlainObject(provider.override)) provider.override = {}
  return provider.override
}

function rawOverrideForDisplay(provider) {
  const override = proxyProviderOverride(provider)
  return policyToText(Object.fromEntries(
    Object.entries(override).filter(([key]) => !proxyProviderOverrideVisualKeys.has(key)),
  ))
}

function visualOverrideEntries(provider) {
  const override = proxyProviderOverride(provider)
  return Object.fromEntries(Object.entries(override).filter(([key]) => proxyProviderOverrideVisualKeys.has(key)))
}

function renderOverrideTextField(provider, [key, label, placeholder]) {
  const value = proxyProviderOverride(provider)[key] ?? ''
  return `<label><span>${escapeHtml(label)}</span><input type="text" data-field="overrideText" data-override-key="${escapeAttr(key)}" value="${escapeAttr(value)}" placeholder="${escapeAttr(placeholder)}"></label>`
}

function renderOverrideToggle(provider, [key, label]) {
  return `<label class="checkbox-row"><input type="checkbox" data-field="overrideBoolean" data-override-key="${escapeAttr(key)}" ${proxyProviderOverride(provider)[key] ? 'checked' : ''}> ${escapeHtml(label)}</label>`
}

function proxyNameRules(provider) {
  const value = proxyProviderOverride(provider)['proxy-name']
  return Array.isArray(value) ? value.filter(isPlainObject) : []
}

function renderProxyNameRules(provider) {
  const rules = proxyNameRules(provider)
  return `
    <div class="wide-field proxy-name-rules">
      <span>Rename Rules</span>
      <div class="proxy-name-rule-list">
        ${rules.length ? rules.map((rule, ruleIndex) => `
          <div class="proxy-name-rule-row">
            <label><span>Pattern</span><input type="text" data-field="proxyNamePattern" data-rule-index="${ruleIndex}" value="${escapeAttr(rule.pattern || '')}" placeholder="IPLC-(.*?)x"></label>
            <label><span>Target</span><input type="text" data-field="proxyNameTarget" data-rule-index="${ruleIndex}" value="${escapeAttr(rule.target || '')}" placeholder="iplc x $1"></label>
            <button type="button" class="ghost-button proxy-name-rule-delete" data-action="delete-proxy-name-rule" data-rule-index="${ruleIndex}">Remove</button>
          </div>
        `).join('') : '<p class="field-hint">No rename rules yet.</p>'}
      </div>
      <button type="button" class="ghost-button proxy-name-rule-add" data-action="add-proxy-name-rule">Add Rename Rule</button>
    </div>
  `
}

function setOverrideValue(provider, key, value) {
  const override = proxyProviderOverride(provider)
  if (value === '' || value === undefined || value === null) delete override[key]
  else override[key] = value
}

function setProxyNameRuleValue(provider, ruleIndex, key, value) {
  const override = proxyProviderOverride(provider)
  const rules = proxyNameRules(provider)
  if (!rules[ruleIndex]) rules[ruleIndex] = {}
  rules[ruleIndex] = { ...rules[ruleIndex], [key]: value }
  override['proxy-name'] = rules
}

function mergeRawOverride(provider, value) {
  const raw = textToPolicy(value, { typedValues: true })
  provider.override = compactObject({
    ...raw,
    ...visualOverrideEntries(provider),
  })
}

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
    const providerType = provider.type || 'http'
    const remoteProvider = providerType === 'http'
    const localProvider = providerType === 'file'
    const inlineProvider = providerType === 'inline'
    const healthEnabled = provider.healthCheck?.enable
    const row = document.createElement('details')
    row.className = 'editor-field-section provider-row'
    row.open = index === 0
    row.innerHTML = `
      <summary>
        <span class="provider-summary">
          <strong>${escapeHtml(provider.name || 'Unnamed provider')}</strong>
          <em>${escapeHtml(providerType)}</em>
        </span>
        <small>${escapeHtml(providerSourceSummary(provider))}</small>
      </summary>
      <div class="provider-editor-stack">
        <details class="node-option-section provider-option-section" open>
          <summary>Source</summary>
          <div class="nested-node-fields form-grid provider-edit-grid">
            <label><span>Name</span><input type="text" data-field="name" value="${escapeAttr(valueOrEmpty(provider.name))}"></label>
            <label><span>Type</span><select data-field="type">
              ${providerTypes.map((type) => `<option value="${type}" ${type === providerType ? 'selected' : ''}>${type}</option>`).join('')}
            </select></label>
            ${remoteProvider ? `<label class="wide-field"><span>URL</span><input type="text" data-field="url" value="${escapeAttr(valueOrEmpty(provider.url))}"></label>` : ''}
            ${remoteProvider || localProvider ? `<label><span>Path</span><input type="text" data-field="path" value="${escapeAttr(valueOrEmpty(provider.path))}"></label>` : ''}
            ${remoteProvider || localProvider ? `<label><span>Interval</span><input type="text" data-field="interval" value="${escapeAttr(valueOrEmpty(provider.interval))}"></label>` : ''}
            ${remoteProvider ? `<label><span>Proxy</span><select data-field="proxy">${optionalPolicyTargetOptions(provider.proxy || '')}</select></label>` : ''}
            ${remoteProvider ? `<label><span>Size Limit</span><input type="text" data-field="sizeLimit" value="${escapeAttr(provider.sizeLimit || '')}" placeholder="0"></label>` : ''}
            ${remoteProvider ? `<label class="wide-field"><span>Header</span><textarea class="mini-editor" data-field="header">${escapeHtml(policyToText(provider.header))}</textarea></label>` : ''}
            ${inlineProvider ? `<label class="wide-field"><span>Inline Payload</span><textarea class="mini-editor provider-payload-editor" data-field="payload">${escapeHtml(JSON.stringify(provider.payload || [], null, 2))}</textarea></label>` : ''}
          </div>
        </details>
        <details class="node-option-section provider-option-section" open>
          <summary>Health Check</summary>
          <div class="nested-node-fields form-grid provider-edit-grid">
            <label class="checkbox-row wide-field"><input type="checkbox" data-field="healthCheckEnable" ${healthEnabled ? 'checked' : ''}> Enable health check</label>
            <div class="health-check-fields wide-field ${healthEnabled ? '' : 'is-disabled'}">
              <div class="form-grid provider-edit-grid">
                <label class="checkbox-row"><input type="checkbox" data-field="healthCheckLazy" ${provider.healthCheck?.lazy !== false ? 'checked' : ''} ${healthEnabled ? '' : 'disabled'}> Lazy Health Check</label>
                <label class="wide-field"><span>Health URL</span><input type="text" data-field="healthCheckUrl" value="${escapeAttr(provider.healthCheck?.url || 'https://www.gstatic.com/generate_204')}" ${healthEnabled ? '' : 'disabled'}></label>
                <label><span>Health Interval</span><input type="text" data-field="healthCheckInterval" value="${escapeAttr(provider.healthCheck?.interval || 300)}" ${healthEnabled ? '' : 'disabled'}></label>
                <label><span>Health Timeout</span><input type="text" data-field="healthCheckTimeout" value="${escapeAttr(provider.healthCheck?.timeout || 5000)}" ${healthEnabled ? '' : 'disabled'}></label>
                <label><span>Expected Status</span><input type="text" data-field="healthCheckExpectedStatus" value="${escapeAttr(provider.healthCheck?.expectedStatus || '')}" placeholder="204" ${healthEnabled ? '' : 'disabled'}></label>
              </div>
            </div>
          </div>
        </details>
        <details class="node-option-section provider-option-section" open>
          <summary>Filter</summary>
          <div class="nested-node-fields form-grid provider-edit-grid">
            <label><span>Filter</span><input type="text" data-field="filter" value="${escapeAttr(provider.filter || '')}" placeholder="(?i)singapore|sg"></label>
            <label><span>Exclude Filter</span><input type="text" data-field="excludeFilter" value="${escapeAttr(provider.excludeFilter || '')}" placeholder="(?i)expired|test"></label>
            <div class="wide-field">
              <span>Exclude Type</span>
              ${renderExcludeTypeChips(provider)}
            </div>
          </div>
        </details>
        <details class="node-option-section provider-option-section" open>
          <summary>Override</summary>
          <div class="nested-node-fields form-grid provider-edit-grid">
            ${proxyProviderOverrideTextFields.map((field) => renderOverrideTextField(provider, field)).join('')}
            <div class="wide-field compact-check-grid">
              ${proxyProviderOverrideBooleanFields.map((field) => renderOverrideToggle(provider, field)).join('')}
            </div>
            ${renderProxyNameRules(provider)}
          </div>
        </details>
        <details class="node-option-section provider-option-section">
          <summary>Raw Override</summary>
          <div class="nested-node-fields form-grid provider-edit-grid">
            <label class="wide-field"><span>Custom override keys</span><textarea class="mini-editor" data-field="rawOverride">${escapeHtml(rawOverrideForDisplay(provider))}</textarea></label>
          </div>
        </details>
        <div class="form-grid section-grid provider-edit-grid provider-subsection">
          <button type="button" class="ghost-button provider-delete-button" data-action="delete">Delete Provider</button>
        </div>
      </div>
    `
    row.addEventListener('input', (event) => handleProxyProviderInput(event, index))
    row.addEventListener('change', (event) => handleProxyProviderInput(event, index))
    row.addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]')?.dataset.action
      if (action === 'delete') {
        const previousName = state.model.proxyProviders[index]?.name
        state.model.proxyProviders.splice(index, 1)
        if (previousName) removeGroupProviderName(previousName)
        updateYamlFromModel()
      }
      if (action === 'add-proxy-name-rule') {
        const provider = state.model.proxyProviders[index]
        proxyProviderOverride(provider)['proxy-name'] = [...proxyNameRules(provider), { pattern: '', target: '' }]
        updateYamlFromModel()
      }
      if (action === 'delete-proxy-name-rule') {
        const provider = state.model.proxyProviders[index]
        const ruleIndex = Number(event.target.closest('[data-action]')?.dataset.ruleIndex)
        proxyProviderOverride(provider)['proxy-name'] = proxyNameRules(provider).filter((_, currentIndex) => currentIndex !== ruleIndex)
        if (!proxyProviderOverride(provider)['proxy-name'].length) delete proxyProviderOverride(provider)['proxy-name']
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
  else if (field === 'rawOverride') mergeRawOverride(provider, event.target.value)
  else if (field === 'overrideText') {
    const key = event.target.dataset.overrideKey
    setOverrideValue(provider, key, event.target.value.trim())
  }
  else if (field === 'overrideBoolean') {
    const key = event.target.dataset.overrideKey
    setOverrideValue(provider, key, event.target.checked ? true : '')
  }
  else if (field === 'proxyNamePattern') {
    setProxyNameRuleValue(provider, Number(event.target.dataset.ruleIndex), 'pattern', event.target.value)
  }
  else if (field === 'proxyNameTarget') {
    setProxyNameRuleValue(provider, Number(event.target.dataset.ruleIndex), 'target', event.target.value)
  }
  else if (field === 'excludeTypeItem') {
    const row = event.target.closest('.provider-row')
    const values = [...row.querySelectorAll('[data-field="excludeTypeItem"]:checked')].map((item) => item.value)
    provider.excludeType = values.join('|')
  }
  else if (field === 'payload') provider.payload = parseJsonOrLines(event.target.value)
  else if (field === 'healthCheckEnable') {
    provider.healthCheck.enable = event.target.checked
    updateYamlFromModel()
    return
  }
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
  else if (field === 'proxy') {
    provider.proxy = policyTargetOptions().includes(event.target.value) ? event.target.value : ''
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
  const url = proxyProviderUrl.value.trim()
  const path = proxyProviderPath.value.trim()
  const nameIssue = validEditableName(name, 'Proxy provider')
  if (nameIssue) {
    showValidation(nameIssue, 'error')
    return
  }
  if (hasDuplicateName(state.model.proxyProviders, name)) {
    showValidation(`Proxy provider "${name}" already exists.`, 'error')
    return
  }
  if (type === 'http' && !url) {
    showValidation('HTTP proxy provider requires URL.', 'error')
    return
  }
  if (type === 'file' && !path) {
    showValidation('File proxy provider requires path.', 'error')
    return
  }
  state.model.proxyProviders.push({
    name,
    type,
    url: type === 'http' ? url : '',
    path: type === 'inline' ? '' : (path || generatedProviderPath('./proxy_providers', name)),
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
  proxyProviderPath.value = ''
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
