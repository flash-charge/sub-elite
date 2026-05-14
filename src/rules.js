import { state, rulesEditor, ruleBuilderType, ruleBuilderValue, ruleBuilderTarget, ruleProviderList, ruleProviderTarget } from './state.js'
import { splitRuleParts } from './utils.ts'
import { renderSelectOptions } from './proxy-fields.js'
import { updateYamlFromModel } from './yaml-tools.js'
import { ensureRule } from './providers.js'
import { showToast, showValidation, nameHasRuleSeparator, uniqueList } from './app.js'

export function renderRules() {
  rulesEditor.value = state.model?.rules.join('\n') || ''
}

export function policyTargetOptions() {
  const groupNames = (state.model?.groups || [])
    .map((group) => group.name)
    .filter((name) => name && !nameHasRuleSeparator(name))
  const proxyNames = (state.model?.proxies || [])
    .filter((proxy) => proxy.enabled !== false)
    .map((proxy) => proxy.name)
    .filter((name) => name && !nameHasRuleSeparator(name))
  return uniqueList(['PROXY', 'DIRECT', 'REJECT', 'GLOBAL', ...groupNames, ...proxyNames])
}

export function renderRuleTargetOptions() {
  const options = policyTargetOptions()
  const ruleTarget = validPolicyTarget(ruleBuilderTarget.value, options)
  const providerTarget = validPolicyTarget(ruleProviderTarget.value, options)
  ruleBuilderTarget.innerHTML = renderSelectOptions(options, ruleTarget)
  ruleProviderTarget.innerHTML = renderSelectOptions(options, providerTarget)
  updateRuleBuilderState()
}

export function validPolicyTarget(value, options = policyTargetOptions()) {
  return options.includes(value) ? value : fallbackPolicyTarget()
}

export function addRuleFromBuilder() {
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

export function updateRuleBuilderState() {
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

export function syncProviderRule(name, target) {
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

export function replaceProviderRuleName(previousName, nextName) {
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

export function removeRuleProviderRules(name) {
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

export function replacePolicyTargetName(previousName, nextName) {
  if (!previousName || !nextName || previousName === nextName || !state.model) return
  state.model.rules = state.model.rules.map((rule) => replaceRuleTargetName(rule, previousName, nextName))
  mapSubRuleRules((rule) => replaceRuleTargetName(rule, previousName, nextName))
  state.model.proxies.forEach((proxy) => {
    if (proxy['dialer-proxy'] === previousName) proxy['dialer-proxy'] = nextName
  })
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

export function replacePolicyTargetNames(renameMap) {
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
  state.model.proxies.forEach((proxy) => {
    if (renameMap.has(proxy['dialer-proxy'])) proxy['dialer-proxy'] = renameMap.get(proxy['dialer-proxy'])
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

export function replaceRemovedPolicyTargets(removedNames, nextName) {
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
  state.model.proxies.forEach((proxy) => {
    if (removedNames.has(proxy['dialer-proxy'])) proxy['dialer-proxy'] = nextName
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

export function mapSubRuleRules(mapper) {
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


export function fallbackPolicyTarget() {
  if (!state.model) return 'DIRECT'
  return state.model.groups.find((group) => group.name && !nameHasRuleSeparator(group.name))?.name || 'DIRECT'
}

export function refreshRenderedRuleProviderTargets() {
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

export function updateRulesFromEditor() {
  if (!state.model) return
  state.model.rules = rulesEditor.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  updateYamlFromModel(false)
}

export function presetRules(value) {
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
