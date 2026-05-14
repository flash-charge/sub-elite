import { state, diffPanel, diffSummary, diffViewer, validationDetails, validationIssuesList, yamlSectionSelect, yamlSectionPreview, warnings, warningsList } from './state.js'
import { escapeHtml, clone, compactObject } from './utils.ts'
import { normalizeClientModel } from './model.ts'
import { autoFixConfigModel, buildYamlFromModel, validateConfigModel } from '../lib/converter.ts'
import { parseDocument, stringify } from 'yaml'
import { renderModel, showToast, showValidation, clearValidation, resetSubscriptionUrl, syncYamlEditor, normalizeEditorModel } from './app.js'

export function updateYamlFromModel(rerender = true) {
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

export function formatCurrentYaml() {
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

export function resetModel() {
  if (!state.originalModel) return
  state.model = clone(state.originalModel)
  updateYamlFromModel()
}

export function autoFixCurrentModel() {
  if (!state.model) return
  const result = autoFixConfigModel(state.model)
  state.model = normalizeClientModel(result.model)
  updateYamlFromModel()
  showToast(result.fixes.length ? `${result.fixes.length} issues fixed.` : 'No safe fixes required.')
}

export function toggleDiffPanel() {
  if (!state.yaml) return
  diffPanel.hidden = !diffPanel.hidden
  if (!diffPanel.hidden) renderDiff()
}

export function renderDiff() {
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

export function renderSectionPreview() {
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

export function buildExportYaml(kind) {
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

export function validateCurrentYaml(showOk = true) {
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

export function renderWarnings(items) {
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

export function renderValidationIssues(items) {
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
