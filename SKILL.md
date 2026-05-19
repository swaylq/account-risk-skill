---
name: account-ban-risk
description: Use this skill when assessing Claude Code / Anthropic / OpenAI account suspension risk, false-positive ban risk, region eligibility, IP/network reputation, or anti-ban compliance hardening. The skill must not help evade bans, bypass unsupported-region restrictions, disguise identity/location, rotate accounts, or defeat platform risk controls; it only provides legitimate risk detection, compliance preflight, and appeal preparation.
metadata:
  short-description: 反封号：账号封禁风险检测与合规预检
---

# 反封号：账号封禁风险检测与合规预检

## Boundary

This skill is for legitimate risk detection and false-positive reduction.

Allowed:
- Assess account suspension risk.
- Check official supported-region and usage-policy constraints.
- Evaluate IP/network reputation for compliance and stability.
- Explain likely false-positive triggers.
- Build preflight checks, status reports, and appeal packets.
- Recommend safer, compliant operating practices.

Disallowed:
- Do not provide ban evasion instructions.
- Do not help bypass unsupported-region restrictions.
- Do not recommend VPN/proxy procurement or IP rotation to disguise location.
- Do not help create/manage multiple accounts to circumvent limits or detection.
- Do not provide stealth tactics for platform abuse, scraping, spam, fake engagement, or automated account creation.
- If the user asks for evasion, redirect to compliance, risk detection, or appeal preparation.

## When To Browse

Browse current official sources when the user asks for latest policy, current region availability, appeal process, identity verification, or product terms.

Prefer official sources:
- Anthropic supported countries: https://www.anthropic.com/supported-countries
- Anthropic API supported regions: https://docs.anthropic.com/en/api/supported-regions
- Anthropic usage policy: https://www.anthropic.com/legal/aup
- Anthropic safeguards warnings and appeals: https://support.claude.com/en/articles/8241253-trust-and-safety-warnings-and-appeals
- Anthropic identity verification: https://support.claude.com/en/articles/14328960-identity-verification-on-claude
- Claude Code data usage: https://docs.anthropic.com/en/docs/claude-code/data-usage
- Claude Code monitoring: https://docs.anthropic.com/en/docs/claude-code/monitoring-usage
- OpenAI supported countries: https://help.openai.com/en/articles/5347006-which-countries-and-territories-are-supported-by-openai
- ChatGPT supported countries: https://help.openai.com/en/articles/7947663-chatgpt-supported-countries
- IP2Location usage type: https://blog.ip2location.com/knowledge-base/what-is-usage-type
- IP2Location.io docs: https://www.ip2location.io/ip2location-documentation
- IP2Proxy docs: https://www.ip2location.com/web-service/ip2proxy
- IPinfo privacy detection: https://ipinfo.io/developers/privacy-detection-extended
- IPinfo ASN database: https://ipinfo.io/developers/asn-database

## Known Baseline

Public Claude Code source-leak reporting showed DMCA takedown enforcement on GitHub repositories, not a confirmed Claude user-account ban mechanism.

Summarize accurately:
- Claude Code npm/source-map leak exposed internal source references.
- Copies/forks appeared on GitHub.
- Anthropic sent DMCA takedown requests.
- GitHub takedown scope reportedly overreached and hit many unrelated forks.
- Anthropic later acknowledged the takedown was too broad and narrowed it.

Do not claim leaked source revealed a reliable account-ban mechanism unless verified from public sources.

## Official Ban Risk Categories

Anthropic account risk commonly includes:
- Repeated Usage Policy violations.
- Terms of Service violations.
- Account creation or access from unsupported regions.
- Identity verification failure or underage verification.
- Platform integrity or fraud checks.
- API-account-level violation thresholds, not only single-request violations.

OpenAI risk commonly includes:
- Access from unsupported countries/territories.
- Violating usage policies or terms.
- Suspicious account, payment, location, or automation patterns.

For China mainland:
- Treat mainland China as unsupported for Anthropic and OpenAI unless official lists change.
- Stable IP does not override unsupported-region policy.
- Do not advise users to mask location or use proxy routes to bypass restrictions.
- Suggest compliant alternatives: supported-region legal entity, official enterprise channel, or local models/providers.

## Claude Code Specific Signals

Relevant public data/telemetry facts:
- Claude Code sends user prompts and model outputs to Anthropic API.
- Claude Code may collect operational metrics such as latency, reliability, and usage patterns.
- Sentry may be used for operational error logging.
- The `/bug` command may send full conversation history, including code.
- Data retention differs by account type and privacy setting.
- Team/Enterprise/API terms may differ from consumer settings.

Risk implications:
- Do not send leaked proprietary code, DMCA-risk mirrors, credentials, or suspicious policy-stress prompts through production accounts.
- Avoid autonomous workflows that perform bulk external actions.
- Keep audit logs of prompts, actions, tool calls, and user approvals.

## IP Cleanliness Assessment

Use IP reputation only for compliance and false-positive detection. Do not use it to bypass unsupported-region restrictions.

Use multiple sources:
1. IP2Location / IP2Proxy
2. IPinfo
3. RDAP / WHOIS / reverse DNS
4. Historical snapshots

### Hard Reject

Reject or mark high risk if any are true:
- IP2Location usage_type is DCH, CDN, SES, or RSV.
- IP2Location as_info.as_usage_type is DCH, CDN, SES, or RSV.
- IP2Proxy says is_proxy=true.
- IP2Proxy proxy_type is VPN, TOR, PUB, WEB, DCH, RES, CPN, or EPN.
- IP2Proxy says is_data_center, is_vpn, is_tor, is_residential_proxy, is_consumer_privacy_network, or is_spammer.
- IPinfo privacy flags show hosting, vpn, proxy, tor, relay, or anonymous.
- IPinfo ASN type is hosting.
- Threat fields show BOTNET, SPAM, or SCANNER.
- Fraud score is high.
- Region/country conflicts with the user's legitimate account, payment, phone, or legal entity context.

### Strong Pass

A low-risk IP usually has:
- IP2Location usage_type = ISP or MOB.
- IP2Location as_info.as_usage_type = ISP or MOB.
- net_speed = DSL preferred.
- IP2Proxy proxy=false.
- IPinfo privacy flags all false.
- IPinfo ASN type = isp or legitimate mobile/carrier type.
- ASN owner is a mainstream fixed-line or mobile operator, not cloud, VPS, hosting, proxy, CDN, transit, scraping, or security infrastructure.
- Hostname/reverse DNS looks consistent with fixed-line/mobile network allocation.
- Stable ASN/geolocation/reputation over time.

### Scoring

Start at 100.

Immediate reject:
- usage_type DCH/CDN/SES/RSV: score 0
- as_usage_type DCH/CDN/SES/RSV: score 0
- IP2Proxy proxy true: score 0
- IPinfo hosting/vpn/proxy/tor/relay true: score 0
- BOTNET threat: score 0
- fraud_score >= 70: score 0

Deduct:
- usage_type not ISP/MOB: -35
- as_usage_type not ISP/MOB: -35
- net_speed not DSL or unknown: -15
- IPinfo ASN type not isp/carrier: -30
- hostname missing: -10
- hostname/rDNS looks hosting-like: -30
- ASN owner not a mainstream ISP/mobile carrier: -30
- geo/account mismatch: -40
- reputation/geolocation changes frequently over 30 days: -25
- same exit IP shared by many unrelated accounts: -40
- vendor price suspiciously low for dedicated residential service: -20, auxiliary only

Add:
- usage_type ISP/MOB: +15
- as_usage_type ISP/MOB: +15
- net_speed DSL: +10
- IPinfo ASN type isp/carrier: +15
- IPinfo privacy all false: +20
- IP2Proxy all proxy flags false: +20
- mainstream fixed-line/mobile ASN owner: +15
- stable 30-day history: +10

Decision:
- 90-100 clean
- 75-89 acceptable
- 60-74 watch
- 40-59 risky
- 0-39 reject

Always return reasons, not only score.

## Account Risk Assessment Workflow

1. Clarify scope:
   - Claude Code, Claude web, Anthropic API, ChatGPT, Codex CLI, or OpenAI API?
   - Personal, Team, Enterprise, or API account?
   - Region, billing entity, and intended workload?
   - Is this for false-positive prevention, status reporting, or appeal?

2. Check official eligibility:
   - Supported country/region.
   - Terms and usage policy.
   - Identity verification requirements.
   - Commercial/entity restrictions.

3. Check workload risk:
   High-risk patterns include:
   - Jailbreak/policy stress testing on production accounts.
   - Security abuse, credential attacks, malware, spam, scraping, fake engagement.
   - Bulk registration or multi-account management.
   - Autonomous third-party platform actions.
   - Feeding leaked source code or DMCA-risk content.
   - Excessive resume/agent loops without human intent.
   - Inconsistent identity, billing, region, or device signals.

4. Check network risk:
   - Run IP cleanliness assessment.
   - Confirm stable, legitimate, non-proxy network.
   - Reject unsupported-region bypass framing.

5. Check automation hygiene:
   - Human approval for external actions.
   - Prompt/action audit logs.
   - Rate limits and cooldowns.
   - Local policy gate for banned categories.
   - Explicit stop conditions.
   - Status reporting for auth/region/rate-limit errors.

6. Output:
   - Overall risk: low / medium / high / reject.
   - Top reasons.
   - What to stop immediately.
   - What to change safely.
   - Appeal prep if already suspended.

## Appeal Packet

If the user is already banned/suspended, help prepare a factual appeal.

Collect:
- Account email or org ID, without exposing secrets.
- Product: Claude Code / Claude web / Anthropic API / ChatGPT / Codex CLI / OpenAI API.
- Plan type.
- Suspension time and timezone.
- Last known legitimate actions.
- Business purpose.
- Whether multiple users or only one account affected.
- Whether billing/payment is current.
- Whether region/entity is officially supported.
- Any warning emails.
- What corrective action was taken.
- Relevant logs with secrets redacted.

Do not fabricate facts. Do not suggest hiding region, identity, or prior activity.

## Output Template

Use this format:

```text
反封号风险评估

对象：
账号/产品：
地区/主体：
用途：

结论：
风险等级：
是否建议继续使用：

主要风险：
1.
2.
3.

IP 纯净度：
score:
decision:
reasons:
-

账号/策略风险：
-

建议动作：
1.
2.
3.

不能做：
-

申诉材料：
-
```

## Refusal Template

If the user asks for evasion:

```text
我不能帮助绕过封禁、规避地区限制、伪装身份/位置、批量换号或逃避平台风控。

我可以继续帮你做三件事：
1. 评估当前账号/网络/工作流的封禁风险。
2. 建立合规预检和状态报告。
3. 整理误封申诉材料。
```
