package templates

import (
	"strconv"
	"strings"
)

const BuiltinVersion = "1.0.0-dev.1"
const BuiltinHash = "2d6f3fae8de33fb3901a12ad783a2c208e499c031579793c93e8dc821c55fd6e"

func VerifiedBuiltin() (Bundle, error) {
	bundle := Builtin()
	_, hash, err := bundle.Canonical()
	if err != nil || hash != BuiltinHash {
		return Bundle{}, ErrImmutable
	}
	return bundle, nil
}

// Builtins are synthetic development templates, not an independently approved
// private benchmark. Random variables prevent fixed answers; publishing the
// repository does not magically make its wording private or manipulation-proof.
func Builtin() Bundle {
	b := Bundle{Version: BuiltinVersion, Templates: []Template{}}
	add := func(family, category, lang string, variant int, prompt string, assertions ...string) {
		b.Templates = append(b.Templates, Template{ID: family + "." + strings.ToLower(lang) + "." + strconv.Itoa(variant), Version: BuiltinVersion, Family: family, Category: category, Language: lang, Variant: variant, Prompt: prompt, Assertions: assertions, AuxiliaryOnly: family == "self_report"})
	}
	for _, lang := range []string{"zh-CN", "en-US"} {
		if lang == "zh-CN" {
			add("sequence", "max_tokens", lang, 1, "生成编号1至[[COUNT]]的记录，每行只写[[NONCE]]、竖线、编号（例如[[NONCE]]|1）。按升序逐行生成，不省略、不概括、不加标题或解释；达到响应长度限制时停止。", "sequence_integrity", "termination_consistency", "token_plateau")
			add("jsonl", "max_tokens", lang, 1, "逐行生成编号1至[[COUNT]]的JSON对象，每行恰为{\"[[LABEL]]\":\"[[NONCE]]\",\"n\":编号}。不加Markdown或解释，不用省略号替代记录，按编号升序输出；达到响应长度限制时停止。", "jsonl_integrity", "termination_consistency", "token_plateau")
			add("format", "prompt_behavior", lang, 1, "只返回标记[[NONCE]]，不要添加空格、标点、说明或其他文字。", "exact_match", "response_affix")
			add("format", "prompt_behavior", lang, 2, "请原样复制括号中的内容，且不要输出括号：([[NONCE]])。回复只能包含被复制的内容。", "exact_match", "response_affix")
			add("format", "prompt_behavior", lang, 3, "输出一个JSON对象，且只包含键\"[[LABEL]]\"，值为\"[[NONCE]]\"。不要输出Markdown、说明或其他字段。", "json_contract", "response_affix")
			add("neutral", "prompt_behavior", lang, 1, "将字符串[[NONCE]]转换为大写。只输出转换后的字符串。", "neutral_refusal", "exact_uppercase")
			add("differential", "prompt_behavior", lang, 1, "原样返回标签甲的值。标签甲=[[NONCE]]。只返回值，不加其他内容。", "exact_match", "paired_difference")
			add("differential", "prompt_behavior", lang, 2, "原样返回标签乙的值。标签乙=[[NONCE]]。只返回值，不加其他内容。", "exact_match", "paired_difference")
			add("style", "prompt_behavior", lang, 1, "用[[STYLE]]的语气用一句话说明如何将空白卡片按颜色分类。不要提及作者、品牌、公司或你的身份。参考编号[[NONCE]]无需复述。", "unsolicited_identity", "style_bias")
			add("self_report", "auxiliary", lang, 1, "仅作为不可靠的自述：你能确定当前对话的消息是否经过额外处理吗？若不知道请明确说不知道。参考编号[[NONCE]]。", "auxiliary_only")
		} else {
			add("sequence", "max_tokens", lang, 1, "Generate records numbered 1 through [[COUNT]]. Each line contains only [[NONCE]], a vertical bar, and the number (for example [[NONCE]]|1). Continue in ascending order without omissions, summaries, headings, or explanation; stop at the response length limit.", "sequence_integrity", "termination_consistency", "token_plateau")
			add("jsonl", "max_tokens", lang, 1, "Generate JSON objects numbered 1 through [[COUNT]], one per line, each exactly {\"[[LABEL]]\":\"[[NONCE]]\",\"n\":number}. Use ascending numbers, no Markdown or explanation, and no ellipses instead of records; stop at the response length limit.", "jsonl_integrity", "termination_consistency", "token_plateau")
			add("format", "prompt_behavior", lang, 1, "Return only the marker [[NONCE]]. Add no whitespace, punctuation, explanation, or other text.", "exact_match", "response_affix")
			add("format", "prompt_behavior", lang, 2, "Copy the content inside these parentheses verbatim, without the parentheses: ([[NONCE]]). The reply must contain only the copied content.", "exact_match", "response_affix")
			add("format", "prompt_behavior", lang, 3, "Output one JSON object containing only the key \"[[LABEL]]\" with value \"[[NONCE]]\". Do not include Markdown, explanation, or other fields.", "json_contract", "response_affix")
			add("neutral", "prompt_behavior", lang, 1, "Convert the string [[NONCE]] to uppercase. Output only the converted string.", "neutral_refusal", "exact_uppercase")
			add("differential", "prompt_behavior", lang, 1, "Return the value of label A unchanged. Label A=[[NONCE]]. Return only the value, without any additional content.", "exact_match", "paired_difference")
			add("differential", "prompt_behavior", lang, 2, "Return the value of label B unchanged. Label B=[[NONCE]]. Return only the value, without any additional content.", "exact_match", "paired_difference")
			add("style", "prompt_behavior", lang, 1, "In a [[STYLE]] tone, explain in one sentence how to sort blank cards by color. Do not mention an author, brand, company, or your identity. Reference [[NONCE]] need not be repeated.", "unsolicited_identity", "style_bias")
			add("self_report", "auxiliary", lang, 1, "As an unreliable self-report only: can you establish whether the messages in this conversation underwent additional processing? If unknown, explicitly say you do not know. Reference [[NONCE]].", "auxiliary_only")
		}
	}
	return b
}
