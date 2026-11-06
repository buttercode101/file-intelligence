import { host } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

function FilePane() {
  return jsxs('div', {
    className: 'flex h-full flex-col gap-2 p-3 overflow-auto text-sm',
    children: [
      jsx('div', { className: 'font-medium', children: 'File Intelligence' }),
      jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: 'Static entry point (read-only). Scan/propose/apply via agent tools in chat (approvals enforced). This pane does not yet fetch scan/proposal data — results are returned as tool output.' }),
      jsx('div', { className: 'text-xs', children: 'Run: file_scan → file_propose in chat, then view proposals here.' }),
      jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: 'Sensitive files (.env, *.pem) are flagged only — never moved.' })
    ]
  })
}

export default {
  id: 'file-intelligence',
  name: 'File Intelligence',
  register(ctx) {
    ctx.register({
      id: 'pane', area: 'panes', title: 'file intelligence',
      data: { placement: 'right', width: '340px' },
      render: () => jsx(FilePane, {})
    })
    ctx.register({
      id: 'chip', area: 'statusBar.right', order: 130,
      render: () => jsx('button', {
        type: 'button', className: 'px-1.5 text-[0.6875rem] text-(--ui-text-tertiary)',
        onClick: () => host.notify({ kind: 'info', message: 'File Intelligence: run file_scan in chat' }),
        children: '🗂️ files'
      })
    })
  }
}
