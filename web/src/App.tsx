const foundations = [
  ['Control API', 'Server role'],
  ['Database jobs', 'Worker role'],
  ['Analyzer', 'Versioned rules'],
  ['Reports', 'Canonical JSON + HTML'],
] as const

export function App() {
  return (
    <main className="shell">
      <p className="eyebrow">M0-03 · Engineering baseline</p>
      <h1>Model Integrity Inspector</h1>
      <p className="lede">
        独立部署的模型 API 完整性检测系统。工程骨架已经就绪，功能实现将按冻结的里程碑逐步接入。
      </p>
      <section aria-label="Runtime foundations" className="grid">
        {foundations.map(([title, detail]) => (
          <article className="card" key={title}>
            <span>{detail}</span>
            <h2>{title}</h2>
          </article>
        ))}
      </section>
    </main>
  )
}
