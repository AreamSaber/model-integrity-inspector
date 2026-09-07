package report

import (
	"bytes"
	"errors"
	"html/template"
	"strconv"
)

// No template.HTML/JS/CSS casts, script, active links or external assets. This
// standalone document remains usable with default-src 'none'. Every value
// flows through html/template text/attribute context escaping.
const htmlTemplate = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer"><title>模型完整性检测报告 · {{.Document.ReportID}}</title></head>
<body><main><h1>模型完整性检测报告</h1><p><strong>{{.Document.DevelopmentNotice}}</strong></p>
<dl><dt>报告 ID / 组织 ID</dt><dd>{{.Document.ReportID}} / {{.Document.OrganizationID}}</dd><dt>Run ID / 目标 ID / 分析修订</dt><dd>{{.Document.RunID}} / {{.Document.Run.TargetID}} / {{.Document.AnalysisRevision}}</dd><dt>生成时间（UTC）</dt><dd>{{.Generated}}</dd><dt>规范版本</dt><dd>{{.Document.SchemaVersion}} · {{.Document.CanonicalVersion}}</dd><dt>内容 SHA-256</dt><dd><code>{{.Hash}}</code></dd></dl>
<section><h2>算法评估</h2><dl><dt>模型完整性风险指数</dt><dd>{{measure .Document.Result.OverallRisk}} / 100 · {{risk .Document.Result.RiskLevel}}</dd><dt>置信度 / 证据等级 / 完整性</dt><dd>{{.Document.Result.Confidence}} / 100 · {{.Document.Result.EvidenceGrade}} · {{complete .Document.Result.Completeness}}</dd><dt>分析纳入 / 规划样本分母</dt><dd>{{.Document.Result.ValidSamples}} / {{.Document.Result.ExpectedSamples}}</dd><dt>实际请求 / 已记录 Token</dt><dd>{{.Document.Run.RequestCount}} / {{.Document.Run.TokenCount}}</dd><dt>估算费用（微货币单位）</dt><dd>{{integer .Document.Run.EstimatedCostMicros}}</dd></dl><p>缺失值是“未测”，不是 0 风险；请求与重试计数不等于独立样本分母。估算费用不等于供应商最终账单。</p>
<table><caption>四维算法风险</caption><thead><tr><th scope="col">维度</th><th scope="col">指数</th></tr></thead><tbody><tr><th scope="row">隐藏指令影响</th><td>{{measure .Document.Result.PromptRisk}}</td></tr><tr><th scope="row">Token 参数一致性</th><td>{{measure .Document.Result.TokenRisk}}</td></tr><tr><th scope="row">响应完整性</th><td>{{measure .Document.Result.ResponseRisk}}</td></tr><tr><th scope="row">协议与证据风险</th><td>{{measure .Document.Result.EvidenceRisk}}</td></tr></tbody></table>
<h3>冻结版本</h3><dl><dt>规则</dt><dd>{{.Document.Result.Versions.Rule}}</dd><dt>模板</dt><dd>{{.Document.Result.Versions.Template}}</dd><dt>评分</dt><dd>{{.Document.Result.Versions.Scoring}}</dd><dt>Tokenizer</dt><dd>{{.Document.Result.Versions.Tokenizer}}</dd></dl>
<h3>局限性</h3><ul>{{range .Document.Result.Limitations}}<li>{{.}}</li>{{else}}<li>仍适用开发版本及黑盒观测限制。</li>{{end}}</ul></section>
<section><h2>统计与分母</h2><p>以下是开发规则的描述性统计；区间和 p 值不是供应商欺诈概率，也不构成已校准或因果结论。</p>
{{with .Document.Result.Token}}<h3>Token 与流式比较</h3><p>Usage 样本分母 {{.UsageSamples}} · 中位相对误差 {{measure .UsageMedianError}}；流式配对分母 {{.StreamPairs}} · 中位相对差 {{measure .StreamMedianDifference}}</p>
<table><caption>输出档位（中位数 / MAD / 稳健 CV）</caption><thead><tr><th>系列 / 族 / 语言</th><th>请求上限</th><th>样本分母</th><th>中位数</th><th>MAD</th><th>稳健 CV</th></tr></thead><tbody>{{range .Tiers}}<tr><th scope="row"><code>{{.SeriesID}}</code> / {{.Family}} / {{.Language}}</th><td>{{.RequestedMaxTokens}}</td><td>{{.Samples}}</td><td>{{.Median}}</td><td>{{.MAD}}</td><td>{{.RobustCV}}</td></tr>{{end}}</tbody></table>
{{range .Plateaus}}<article><h4>平台比较 · {{.Family}} · {{.LowRequested}} → {{.HighRequested}}</h4><p>系列 <code>{{.SeriesID}}</code> · 增长比 {{.GrowthRatio}} · 开发强度 {{.Strength}} · 候选 {{.Candidate}} · 有限证据 {{.Limited}}</p><p>差分区间 [{{measure .Lower}}, {{measure .Upper}}] · 配对 {{.Paired}} · 独立组分母 {{.IndependentGroups}}</p><p>样本引用：{{range .SampleRefs}}<code>{{.}}</code> {{end}}</p><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul></article>{{end}}<ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>Token 聚合统计未提供。</p>{{end}}
{{with .Document.Result.Behavior}}<h3>行为模式与成对差分</h3><p>分析样本 {{.AnalyzedSamples}} · 仅辅助样本 {{.AuxiliarySamples}}（不纳入配对推断）。稳定模式不等于隐藏指令原文。</p>
{{range .Patterns}}<article><h4>{{.Kind}} · {{.State}}</h4><p>规范化指纹 <code>{{.Fingerprint}}</code></p><p>族 / 模板 / 语言覆盖 {{.FamilyCount}} / {{.TemplateCount}} / {{.LanguageCount}}</p><p>样本引用：{{range .SampleRefs}}<code>{{.}}</code> {{end}}</p></article>{{end}}
<table><caption>配对差分（B − A）</caption><thead><tr><th>指标 / 状态</th><th>完整配对分母</th><th>效应量</th><th>精确 p 值</th><th>调整 p 值</th></tr></thead><tbody>{{range .Differences}}<tr><th scope="row">{{.Metric}} / {{.State}}</th><td>{{.Pairs}}</td><td>{{measure .EffectSize}}</td><td>{{measure .PValue}}</td><td>{{measure .AdjustedP}}</td></tr>{{end}}</tbody></table><p>多重检验调整依赖原发布分析中的预声明检验族与依赖假设；本报告不重新选择检验或重算分数。</p><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>行为聚合统计未提供。</p>{{end}}</section>
<section><h2>发现与替代解释</h2>{{range .Document.Findings}}<article><h3>{{.Category}} · {{.RuleID}}</h3><p>规则版本 {{.RuleVersion}} · 指数 {{.RiskScore}} · 置信度 {{.Confidence}} · 证据 {{.EvidenceGrade}} · 级别 {{.Severity}}</p><p>以下为观测偏离，不是对供应商行为或隐藏提示原文的证明。</p><table><caption>规则统计</caption><thead><tr><th>统计量</th><th>观测值</th><th>单位</th></tr></thead><tbody>{{range .Statistics}}<tr><th scope="row">{{.Name}}</th><td>{{measure .Actual}}</td><td>{{.Unit}}</td></tr>{{end}}</tbody></table><p>样本引用：{{range .SampleRefs}}<code>{{.}}</code> {{end}}</p><h4>替代解释</h4><ul>{{range .Alternatives}}<li>{{.}}</li>{{else}}<li>模型随机性、协议或能力差异仍可能影响观测。</li>{{end}}</ul></article>{{else}}<p>没有已发布的发现项；不能据此证明没有异常。</p>{{end}}</section>
<section><h2>样本及重试链（正文已脱敏）</h2>{{range .Document.Samples}}<article><h3>样本 {{.Ordinal}} · {{.ID}}</h3><p>{{.Family}} / {{.Language}} · {{.Validity}} · 纳入分析 {{.Included}} · 仅辅助 {{.AuxiliaryOnly}}</p><p>请求上限 {{.RequestedMaxTokens}} · 流式 {{.Stream}} · 本地 {{integer .LocalCompletionTokens}} / 上游 {{integer .ReportedCompletionTokens}} Token · tokenizer {{.TokenizerQuality}}</p><p>最终 Attempt：{{text .FinalAttemptID}} · 停止原因：{{text .FinishReason}}</p><table><caption>Attempt 时间线</caption><thead><tr><th>序号 / ID</th><th>有效性</th><th>HTTP / 错误</th><th>输入 / 输出 / 合计 Token</th><th>耗时 ms</th></tr></thead><tbody>{{range .Attempts}}<tr><th scope="row">{{.AttemptNo}} / {{.ID}}</th><td>{{.Validity}}</td><td>{{smallint .HTTPStatus}} / {{text .ErrorCode}}</td><td>{{integer .PromptTokens}} / {{integer .CompletionTokens}} / {{integer .TotalTokens}}</td><td>{{integer .DurationMS}}</td></tr>{{end}}</tbody></table><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul></article>{{end}}</section>
<section><h2>人工复核</h2><p>本报告未纳入人工复核快照（review 为 null，review_state 为 not_included），不代表该 Run 没有历史复核。机器评估不代表 TL、OPS/SEC 或任何审核人批准。</p></section>
<section><h2>建议动作</h2><p>由具备权限的人员复核观测证据；必要时使用可信基线进行新的受控对照。不要将未校准开发结果作为供应商内部行为的证明。</p></section>
<section><h2>免责声明</h2><p>{{.Document.Disclaimer}}</p><p>本制品只呈现传入的 S1 投影，不包含 Endpoint、提示、响应正文、Header、密钥或可执行复现命令。来源和读取权限由上层受权服务验证，本渲染内核不认证来源。哈希用于内容一致性检查，不是数字签名或独立审批凭证。</p></section>
<details><summary>完整统计与可验证 JSON 快照</summary><p>以下与 JSON 制品相同，包含档位、平台区间、行为模式、配对差分、样本引用及独立局限性字段。未提供的统计保持 null。</p><pre>{{.JSON}}</pre></details>
</main></body></html>`

type boundedWriter struct{ buffer bytes.Buffer }

func (w *boundedWriter) Write(p []byte) (int, error) {
	if len(p) > MaxOutputBytes-w.buffer.Len() {
		return 0, ErrLimit
	}
	return w.buffer.Write(p)
}

func renderHTML(doc document, hash string, json []byte) ([]byte, error) {
	functions := template.FuncMap{
		"measure": func(v *float64) string {
			if v == nil {
				return "未测"
			}
			return strconv.FormatFloat(*v, 'g', -1, 64)
		},
		"integer": func(v *int64) string {
			if v == nil {
				return "未知 / 未测"
			}
			return strconv.FormatInt(*v, 10)
		},
		"smallint": func(v *int) string {
			if v == nil {
				return "未测"
			}
			return strconv.Itoa(*v)
		},
		"text": func(v *string) string {
			if v == nil {
				return "未测 / 无"
			}
			return *v
		},
		"risk": func(v string) string {
			return map[string]string{"low": "低", "watch": "关注", "medium": "中", "high": "高", "critical": "严重（黑盒统计判断）", "insufficient": "信息不足"}[v]
		},
		"complete": func(v string) string {
			return map[string]string{"full": "完整", "partial": "部分", "insufficient": "信息不足"}[v]
		},
	}
	tmpl, err := template.New("report").Funcs(functions).Parse(htmlTemplate)
	if err != nil {
		return nil, ErrRender
	}
	view := struct {
		Document              document
		Hash, Generated, JSON string
	}{doc, hash, doc.GeneratedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), string(json)}
	var output boundedWriter
	if err := tmpl.Execute(&output, view); err != nil {
		if errors.Is(err, ErrLimit) {
			return nil, ErrLimit
		}
		return nil, ErrRender
	}
	return output.buffer.Bytes(), nil
}
