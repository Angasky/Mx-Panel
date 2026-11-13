# AI 协助

从 v0.2.1 起，左侧 **AI 协助 → 接入设置** 可接入自己的模型。普通用户从「我的订阅」进入，同样使用自己的 Key。默认关闭，面板不提供公共额度。

## 接入格式

| 格式 | 默认基础地址 | 请求接口 |
| --- | --- | --- |
| OpenAI Chat Completions | `https://api.openai.com/v1` | `/chat/completions` |
| OpenAI Responses | `https://api.openai.com/v1` | `/responses` |
| Anthropic Messages | `https://api.anthropic.com/v1` | `/messages` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta` | `/models/{model}:generateContent` |

选择格式、填写供应商提供的模型 ID 和 API Key，勾选启用，然后保存。支持使用相应格式的公网 HTTPS 兼容网关；更换地址或格式时须重新填写 Key，避免把原供应商密钥发送给另一服务。Gemini 使用原生格式，不是 OpenAI 兼容格式。

「保存并测试连接」会发送一条简短消息，可能产生费用；测试输出上限 128 tokens，推理型模型可能因预算不足没有正文。日常问答可设置 128–8192 输出 tokens。Chat 默认使用 `max_completion_tokens`；旧网关可勾选兼容 `max_tokens`。模型是否支持该参数以供应商为准。

## 问答和配置分析

支持多个对话、重命名、删除、复制回复和停止等待。可以询问分流策略、国内 App 联网问题、节点故障及面板使用方法。AI 不具有命令执行、服务器修改或面板配置写入能力；回复中的建议需要自行核对和实施。

默认仅发送当前对话。选择「附带配置摘要」后，可以先预览再发送：

- 管理员摘要含协议、传输、TLS、策略组引用、部分域名规则和配置数量。节点与组名称替换为别名，不附带节点地址、UUID、密码、私钥或订阅链接。域名规则可能涉及使用习惯，请先检查预览。
- 普通用户只可附带自己获授权订阅的用量摘要，不可读取管理员配置。
- 用户自己粘贴的内容不会自动脱敏，请先删除敏感信息。已发送的摘要作为历史对话保留；如不想继续附带旧摘要，请新建对话。

## 保存和限制

Key 与对话正文在面板数据目录的 `ai/` 中加密存储，按账号隔离；接口不回显 Key。对话标题、时间和模型设置为明文元数据。备份时同时保留面板加密密钥；服务器管理员仍控制数据与密钥，并不构成对管理员的端到端加密。

每账号最多 20 个对话，每个保留最近 15 轮并按长度裁剪；每账号最多 1 个进行中的请求，全站最多 4 个。请求最长等待 55 秒，避免常见反向代理的 60 秒超时先中断连接。超长历史会从最旧轮次开始截断；本轮内容过长会提示新建对话。没有自动重试，避免重复计费。

停止或离开页面会取消等待，并尝试取消上游请求；供应商可能已经处理或计费。上游失败不会写入虚假回复。各账号的 API 费用由填写 Key 的账号承担。外部服务实际保存策略取决于供应商；Responses 请求明确设置 `store:false`。

## 验证范围

四协议的请求结构、响应解析、错误处理、权限隔离、加密存储、重启恢复、配置摘要、页面操作及移动布局均使用本地模拟服务和自动化测试验证。未使用真实付费 Key 验收供应商在线返回结果；部署后请用自己的 Key 点击测试。

协议参考：[OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create)、[Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)、[Anthropic Messages](https://platform.claude.com/docs/en/api/messages)、[Gemini generateContent](https://ai.google.dev/api/generate-content)。
