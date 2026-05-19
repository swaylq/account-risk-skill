# 反封号风险评估

对象：Claude Code 自动化 agent
账号/产品：Claude Code / Anthropic
地区/主体：中国大陆个人用户
用途：长期自动化开发与 Telegram 桥接

结论：中国大陆主体和地区是核心风险；稳定 IP 只能降低异常网络风险，不能解决 unsupported region。
风险等级：high
是否建议继续使用：不建议在不合规地区/主体下长期运行生产 agent。

主要风险：
1. mainland China 不在 Anthropic 官方 supported countries 列表中。
2. 长时间自动化 agent 行为可能不像普通交互用户。
3. 如果出口 IP 为机房、代理、VPN、住宅代理或共享出口，会叠加风控信号。

IP 纯净度：
score: 参考 scripts/ip_cleanliness_score.py
decision: watch/reject if proxy/hosting/data center signals appear
reasons:
- usage_type 和 as_usage_type 必须优先为 ISP/MOB。
- net_speed 优先 DSL。
- IP2Proxy / IPinfo privacy 应全 false。

建议动作：
1. 先确认官方支持地区和合法主体。
2. 保留 prompt、tool call、外部动作、人工确认的审计日志。
3. 对批量外部动作、注册、消息、爬取、越权安全测试加本地拦截。

不能做：
- 不要伪装地区。
- 不要用代理/IP 轮换绕过限制。
- 不要批量换号或共享账号。

申诉材料：
- 账号 email/org ID、plan、封禁时间、最后合法活动、业务用途、整改动作、脱敏日志。
