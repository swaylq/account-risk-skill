#!/usr/bin/env python3
"""Overall Claude Code account risk score.

Risk score is 0-100 where higher means more suspension risk. IP/network risk is
weighted heavily by design, but hard policy/region issues can still cap or
override the result because a clean network cannot make an unsupported or
policy-violating workflow safe.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


WEIGHTS = {
    "ip_network": 0.70,
    "region_identity": 0.10,
    "workflow": 0.10,
    "sensitive_data": 0.05,
    "audit_controls": 0.05,
}


def load_json(path: str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def clamp(n: float) -> int:
    return max(0, min(100, round(n)))


def boolish(obj: dict[str, Any], key: str) -> bool:
    return bool(obj.get(key, False))


def score_profile(profile: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    recommendations: list[str] = []
    hard_flags: list[str] = []

    ip = profile.get("ip_network", {}) if isinstance(profile.get("ip_network"), dict) else {}
    ip_cleanliness_score = ip.get("cleanliness_score")
    if ip_cleanliness_score is None:
        ip_risk = 65
        reasons.append("ip_network: missing cleanliness_score, default risk 65")
    else:
        ip_risk = 100 - float(ip_cleanliness_score)
        reasons.append(f"ip_network: cleanliness_score={ip_cleanliness_score}, base risk={ip_risk:g}")

    if boolish(ip, "split_egress"):
        ip_risk += 15
        reasons.append("ip_network: split_egress=true, +15 risk")
    if boolish(ip, "api_route_unverified"):
        ip_risk += 10
        reasons.append("ip_network: api_route_unverified=true, +10 risk")
    if boolish(ip, "hosting_or_proxy_detected"):
        ip_risk = max(ip_risk, 95)
        hard_flags.append("hosting_or_proxy_detected")
        reasons.append("ip_network: hosting/proxy detected, network risk floored at 95")
    ip_risk = clamp(ip_risk)

    region = profile.get("region_identity", {}) if isinstance(profile.get("region_identity"), dict) else {}
    region_risk = 0
    if boolish(region, "unsupported_region"):
        region_risk = 100
        hard_flags.append("unsupported_region")
        reasons.append("region_identity: unsupported_region=true")
    elif boolish(region, "unknown_region"):
        region_risk = 60
        reasons.append("region_identity: unknown_region=true")
    if boolish(region, "billing_mismatch"):
        region_risk = max(region_risk, 70)
        reasons.append("region_identity: billing_mismatch=true")
    if boolish(region, "phone_or_timezone_mismatch"):
        region_risk = max(region_risk, 50)
        reasons.append("region_identity: phone_or_timezone_mismatch=true")

    workflow = profile.get("workflow", {}) if isinstance(profile.get("workflow"), dict) else {}
    workflow_risk = 0
    high_risk_keys = [
        "bulk_registration",
        "bulk_messaging",
        "platform_manipulation",
        "credential_attacks",
        "malware_or_abuse",
        "policy_stress_testing",
        "unauthorized_security_testing",
    ]
    active_high = [key for key in high_risk_keys if boolish(workflow, key)]
    if active_high:
        workflow_risk = 100
        hard_flags.extend(active_high)
        reasons.append("workflow: high-risk flags true: " + ", ".join(active_high))
    elif boolish(workflow, "long_running_agent"):
        workflow_risk = 35
        reasons.append("workflow: long_running_agent=true")
    if boolish(workflow, "third_party_actions_without_approval"):
        workflow_risk = max(workflow_risk, 75)
        reasons.append("workflow: third_party_actions_without_approval=true")

    sensitive = profile.get("sensitive_data", {}) if isinstance(profile.get("sensitive_data"), dict) else {}
    sensitive_risk = 0
    if boolish(sensitive, "secrets_in_context"):
        sensitive_risk = 100
        hard_flags.append("secrets_in_context")
        reasons.append("sensitive_data: secrets_in_context=true")
    if boolish(sensitive, "dmca_or_leaked_source"):
        sensitive_risk = max(sensitive_risk, 80)
        reasons.append("sensitive_data: dmca_or_leaked_source=true")
    if boolish(sensitive, "bug_report_full_context"):
        sensitive_risk = max(sensitive_risk, 45)
        reasons.append("sensitive_data: bug_report_full_context=true")

    audit = profile.get("audit_controls", {}) if isinstance(profile.get("audit_controls"), dict) else {}
    audit_risk = 0
    if not boolish(audit, "has_audit_log"):
        audit_risk += 35
        reasons.append("audit_controls: has_audit_log=false")
    if not boolish(audit, "has_policy_gate"):
        audit_risk += 35
        reasons.append("audit_controls: has_policy_gate=false")
    if not boolish(audit, "has_human_approval_for_external_actions"):
        audit_risk += 30
        reasons.append("audit_controls: has_human_approval_for_external_actions=false")
    audit_risk = clamp(audit_risk)

    weighted = (
        ip_risk * WEIGHTS["ip_network"]
        + region_risk * WEIGHTS["region_identity"]
        + workflow_risk * WEIGHTS["workflow"]
        + sensitive_risk * WEIGHTS["sensitive_data"]
        + audit_risk * WEIGHTS["audit_controls"]
    )
    risk_score = clamp(weighted)

    if "unsupported_region" in hard_flags:
        risk_score = max(risk_score, 75)
        recommendations.append("Unsupported region cannot be fixed by IP quality; confirm official eligibility or stop Claude Code account activity.")
    if active_high:
        risk_score = max(risk_score, 90)
        recommendations.append("Stop high-risk workflow before continuing; a clean IP does not mitigate policy-violating automation.")
    if "secrets_in_context" in hard_flags:
        risk_score = max(risk_score, 85)
        recommendations.append("Remove secrets from context/logs, rotate exposed credentials, and add preflight secret scanning.")
    if "hosting_or_proxy_detected" in hard_flags:
        recommendations.append("Network appears to be hosting/proxy infrastructure; use a legitimate residential/mobile/business ISP network in a supported region.")

    if risk_score >= 85:
        decision = "critical"
    elif risk_score >= 70:
        decision = "high"
    elif risk_score >= 45:
        decision = "watch"
    elif risk_score >= 25:
        decision = "low"
    else:
        decision = "minimal"

    if not recommendations:
        recommendations.append("Keep monitoring api.anthropic.com route, IP cleanliness, workflow scope, and audit logs.")

    return {
        "risk_score": risk_score,
        "decision": decision,
        "weights": WEIGHTS,
        "components": {
            "ip_network": ip_risk,
            "region_identity": region_risk,
            "workflow": workflow_risk,
            "sensitive_data": sensitive_risk,
            "audit_controls": audit_risk,
        },
        "hard_flags": sorted(set(hard_flags)),
        "reasons": reasons,
        "recommendations": list(dict.fromkeys(recommendations)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score Claude Code account suspension risk.")
    parser.add_argument("profile", help="Risk profile JSON")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    result = score_profile(load_json(args.profile))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print("Claude Code account risk report")
    print()
    print(f"risk_score: {result['risk_score']}")
    print(f"decision: {result['decision']}")
    print()
    print("components:")
    for key, value in result["components"].items():
        print(f"- {key}: {value}")
    if result["hard_flags"]:
        print()
        print("hard_flags:")
        for flag in result["hard_flags"]:
            print(f"- {flag}")
    print()
    print("reasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")
    print()
    print("recommendations:")
    for recommendation in result["recommendations"]:
        print(f"- {recommendation}")


if __name__ == "__main__":
    main()
