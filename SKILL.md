---
name: claude-code-account-risk
description: |
  反封号.skill — Claude Code 专用账号风险体检。用户说「测试一下我目前账号被封的可能性」「检查 Claude Code 封号风险」「账号被封帮我申诉」「检查 api.anthropic.com 路由」「反封号」时触发。自动综合评估 IP/网络出口、Claude API 路由、项目自动化、敏感数据、地区主体待确认项、审计控制，并输出风险分、风险等级和整改建议。禁止提供绕封号、绕地区、伪装身份/位置、代理池、IP 轮换、批量换号等规避风控方案。
allowed-tools: Read, Write, Edit, Bash, WebSearch, WebFetch
---

# 反封号 · Claude Code 账号风险体检

## 目标

用户触发后，直接做一次 Claude Code 封号风险评估。不要向用户暴露内部评分细节，除非用户追问。

典型触发：

- 测试一下我目前账号被封的可能性
- 检查 Claude Code 封号风险
- 用反封号 skill 检查这个项目
- 我 Claude 账号被封了，帮我整理申诉
- 看一下 api.anthropic.com 走什么出口

## 边界

可以：
- 风险检测
- 合规预检
- IP / 路由 / 分流检查
- 项目自动化风险检查
- 敏感数据暴露风险检查
- 审计控制检查
- 误封申诉材料整理

禁止：
- 绕封号
- 绕 unsupported region
- 伪装身份 / 伪装位置
- 批量换号
- 代理池 / IP 轮换策略
- 平台风控规避
- 批量注册、刷量、垃圾消息、平台操纵

如果用户要求规避风控，拒绝并转向「风险检测 / 合规整改 / 申诉材料」。

## 一次评估怎么做

按顺序执行。

### 1. 读取项目

优先读取存在的文件：

- `AGENTS.md`
- `CLAUDE.md`
- `.claude/settings.json`
- `.claude/settings.local.json`（只判断 key 名，不输出 secret 值）
- `scripts/`
- `cron/`
- `launchd/`
- `systemd/`
- `memory/` 最近日志
- `README.md`
- `package.json`

不要打印 token、API key、bot token、cookie、private key。

### 2. 检查网络

在本 skill 目录可运行：

```bash
bash scripts/egress_consensus_probe.sh
bash scripts/domain_route_probe.sh
```

重点看：

- 是否 `split_egress=true`
- `api.anthropic.com` 的 DNS / route / Cloudflare colo 是否稳定
- 是否能确认 Claude API 路径对应的 egress/source IP

注意：

- `remote_ip` 是 Claude API 目标 IP，不是公网出口 IP。
- 如果不能确认真实 source IP，标为「需要用户确认」。

### 3. IP 纯净度

如果用户提供 IP2Location / IPinfo JSON，运行：

```bash
python3 scripts/ip_cleanliness_score.py --ip2location <file> --ipinfo <file>
```

如果没有提供，只基于 route / egress probe 做初步判断，不编造 IP2Location 结论。

### 4. Claude Code 项目风险

检查这些风险：

- 长期 agent / daemon / cron / bridge
- 批量注册
- 批量消息
- 爬取
- 平台操纵
- credential stuffing
- 越权安全测试
- policy stress testing / jailbreak testing
- 外部动作没有人工确认
- 没有审计日志
- 没有 policy gate / allowlist / stop condition
- `.env` / token / API key / 敏感日志进入上下文
- 泄漏源码 / DMCA-risk mirror
- `/bug` 或 debug dump 可能上传完整上下文

### 5. 用户确认项

这些不能从本地可靠判断，列到「需要用户确认」：

- 账号地区
- 支付地区
- 手机号 / 身份验证
- 组织主体
- 是否真实位于 Anthropic supported country
- Anthropic warning / suspension 邮件内容
- Anthropic 服务端看到的真实 source IP
- Team / Enterprise / API 合同条款

涉及最新 supported countries / policy / appeal 流程时，浏览官方来源核实。

官方优先来源：

- https://www.anthropic.com/supported-countries
- https://docs.anthropic.com/en/api/supported-regions
- https://www.anthropic.com/legal/aup
- https://support.claude.com/en/articles/8241253-trust-and-safety-warnings-and-appeals
- https://support.claude.com/en/articles/14328960-identity-verification-on-claude
- https://docs.anthropic.com/en/docs/claude-code/data-usage
- https://docs.anthropic.com/en/docs/claude-code/monitoring-usage

## 评分

总分叫 `risk_score`，0-100，越高越危险。

权重：

- IP / network: 70%
- region / identity: 10%
- workflow: 10%
- sensitive data: 5%
- audit controls: 5%

判定：

- 85-100: critical
- 70-84: high
- 45-69: watch
- 25-44: low
- 0-24: minimal

硬性覆盖：

- unsupported region: 总风险至少 75
- 明显高风险 workflow: 总风险至少 90
- secrets in context: 总风险至少 85
- hosting/proxy 明确命中: 网络风险至少 95

可以用结构化 profile 运行：

```bash
python3 scripts/account_risk_score.py <profile.json>
```

没有完整 profile 时，手动按上述权重估算，标明哪些依据来自本地验证，哪些来自用户确认。

## 输出格式

默认用简洁中文。不要长篇解释内部规则。

```text
Claude Code 封号风险体检

风险等级：
总风险分：

已验证：
-

需要你确认：
-

高风险：
-

建议动作：
1.
2.
3.

如果已封号，申诉材料还缺：
-
```

## 申诉材料

如果用户已经被封，收集：

- 账号 email / org ID（不要输出 secret）
- 产品：Claude Code / Claude / Anthropic API
- plan 类型
- 封禁时间和时区
- warning 邮件原文或摘要
- 最后几次合法活动
- 业务用途
- 是否单账号或团队整体受影响
- billing 是否正常
- 地区和主体是否 supported
- 已停止的风险工作流
- 已整改动作
- 脱敏日志

不要编造事实。不要建议隐藏地区、身份或历史活动。

## 拒绝模板

```text
我不能帮助绕过封禁、规避地区限制、伪装身份/位置、批量换号或逃避平台风控。

我可以继续帮你做三件事：
1. 评估当前 Claude Code 账号/网络/工作流的封禁风险。
2. 建立合规预检和状态报告。
3. 整理误封申诉材料。
```
