<div align="center">

# 🛡️ 反封号.skill

> *「装到 Claude Code，问一句：我现在被封号的概率高吗？」*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-blueviolet)](https://claude.ai/code)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)

<br>

反封号.skill 是一个 **Claude Code 账号风险体检 skill**。  
它会从网络出口、Claude API 路由、项目自动化、敏感数据、地区主体、审计记录几个方向，  
给你的 Claude Code 使用环境做一次综合封号风险评估。

<br>

你不需要懂 IP2Location、ASN、Cloudflare colo、policy gate。  
装好后直接问：

```
测试一下我目前账号被封的可能性
```

它会自己检查能检查的部分，  
把不能确定的部分列成「需要你确认」。

<br>

[安装](#-安装) · [用法](#-用法) · [会检查什么](#-会检查什么) · [评分](#-评分) · [English](#english)

</div>

---

## ✨ 效果示例

```
你  ❯ 测试一下我目前 Claude Code 账号被封的可能性

反封号.skill ❯ 风险等级：watch
              总风险分：52/100

              已验证：
              - api.anthropic.com 当前命中 NRT Cloudflare edge
              - 检测到 split egress：不同 IP echo endpoint 返回了 2 个公网出口
              - 当前项目存在 Telegram bridge + long-running agent

              主要风险：
              1. 网络出口不一致，Claude API 路径需要单独确认 egress/source IP
              2. 长期 agent 自动化需要审计日志和外部动作确认机制
              3. 地区/支付/手机号/主体信息无法从本地判断，需要用户确认

              建议：
              - 优先确认 api.anthropic.com 分流路径对应的公网出口
              - 给外部动作加人工确认和日志
              - 不要把 .env、token、敏感日志放进上下文
```

---

## ⚡ 安装

```bash
git clone https://github.com/swaylq/account-risk-skill.git \
  ~/.claude/skills/claude-code-account-risk
```

确认 Claude Code 能看到 skill 后，直接在 Claude Code 里问：

```
测试一下我目前账号被封的可能性
```

或：

```
用反封号 skill 检查这个项目
```

---

## 🚀 用法

你可以用自然语言触发：

```
测试一下我目前账号被封的可能性
帮我做一次 Claude Code 封号风险体检
这个项目跑 Claude Code 长期 agent 安全吗
我 Claude 账号被封了，帮我整理申诉材料
检查一下当前 IP 和 api.anthropic.com 路由
```

skill 会输出：

- 风险等级
- 总风险分
- 已验证项
- 需要用户确认项
- 高风险项
- 建议动作
- 如果已封号：申诉材料清单

---

## 🔍 会检查什么

### 自动检查

Claude Code 能自己检查：

- 当前项目是否有长期 agent、cron、daemon、Telegram bridge 等自动化入口
- 是否存在批量注册、批量消息、爬取、平台操纵、越权测试等高风险工作流
- 是否有 `.env`、token、API key、敏感日志、泄漏源码进入上下文的风险
- 是否有审计日志、policy gate、外部动作人工确认
- 当前公网出口是否分流
- `api.anthropic.com` 的 DNS、路由、Cloudflare edge、socket 证据

### 需要用户确认

这些信息 Claude Code 不能可靠自证：

- 账号地区
- 支付地区
- 手机号 / 身份验证
- 组织主体
- 是否真实位于 Anthropic supported country
- Anthropic warning / suspension 邮件内容
- Anthropic 服务端看到的真实 source IP

skill 会把这些列出来，不会编。

---

## 📊 评分

总风险分是 0-100，越高越危险。

| 维度 | 权重 |
|---|---:|
| IP / network | 70% |
| region / identity | 10% |
| workflow | 10% |
| sensitive data | 5% |
| audit controls | 5% |

判定：

| 分数 | 等级 |
|---:|---|
| 85-100 | critical |
| 70-84 | high |
| 45-69 | watch |
| 25-44 | low |
| 0-24 | minimal |

IP 权重很高，因为网络出口、分流稳定性、proxy/hosting 信号会显著影响账号风控。

但这些硬风险不会被好 IP 抵消：

- unsupported region
- 明显违规工作流
- secrets in context
- hosting/proxy 明确命中

---

## 🧰 本地工具

通常不需要手动跑。Claude Code 会按需调用。

```bash
# 当前公网出口一致性 + Claude API 路由
bash scripts/egress_consensus_probe.sh

# 只看 api.anthropic.com 路由证据
bash scripts/domain_route_probe.sh

# IP 纯净度样例评分
npm run score:clean
npm run score:risky

# 总账号风险样例评分
npm run risk:clean
npm run risk:high
```

---

## ⚠️ 边界

这个 skill 不是绕封号工具。

它不会提供：

- 规避地区限制
- 伪装身份 / 伪装位置
- 批量换号
- IP 轮换
- 代理池策略
- 平台风控绕过

它只做：

- 风险检测
- 合规预检
- 误封排查
- 申诉材料整理

---

## English

`account-risk-skill` is a Claude Code-only account risk audit skill.

After installation, ask Claude Code:

```text
Check how likely my Claude Code account is to be suspended.
```

The skill audits:

- IP and egress consistency
- `api.anthropic.com` route evidence
- long-running agent / daemon / cron automation
- sensitive data exposure risk
- workflow policy risk
- audit controls
- appeal packet readiness

The total risk score is weighted heavily toward network quality:

| Component | Weight |
|---|---:|
| IP / network | 70% |
| region / identity | 10% |
| workflow | 10% |
| sensitive data | 5% |
| audit controls | 5% |

It does **not** provide ban evasion, proxy rotation, fake identity, or unsupported-region bypass guidance.

Install:

```bash
git clone https://github.com/swaylq/account-risk-skill.git \
  ~/.claude/skills/claude-code-account-risk
```

---

## 📜 License

MIT License © [swaylq](https://github.com/swaylq)
