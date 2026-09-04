import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { App } from './App'

describe('App', () => {
  it('renders the engineering baseline', () => {
    const html = renderToStaticMarkup(<App />)

    expect(html).toContain('Model Integrity Inspector')
    expect(html).toContain('M0-03')
    expect(html).toContain('Database jobs')
  })
})
