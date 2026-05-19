#!/usr/bin/env python3
"""Score IP cleanliness from IP2Location/IP2Proxy and IPinfo JSON exports.

This script is intentionally offline-first: pass JSON responses saved from
providers. It does not call network APIs, store tokens, or help select a bypass
route. Use it for compliance preflight and false-positive risk assessment.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PASS_USAGE = {"ISP", "MOB"}
HARD_USAGE = {"DCH", "CDN", "SES", "RSV"}
HARD_PROXY_TYPES = {"VPN", "TOR", "PUB", "WEB", "DCH", "RES", "CPN", "EPN"}
HARD_THREATS = {"BOTNET"}
SOFT_THREATS = {"SPAM", "SCANNER"}


def load_json(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def get_nested(obj: dict[str, Any], *keys: str) -> Any:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def upper(value: Any) -> str:
    return str(value or "").strip().upper()


def lower(value: Any) -> str:
    return str(value or "").strip().lower()


def score(ip2location: dict[str, Any], ipinfo: dict[str, Any]) -> dict[str, Any]:
    score_value = 100
    hard_reject = False
    reasons: list[str] = []
    recommendations: list[str] = []

    usage_type = upper(ip2location.get("usage_type"))
    as_usage_type = upper(get_nested(ip2location, "as_info", "as_usage_type"))
    net_speed = upper(ip2location.get("net_speed"))
    fraud_score_raw = ip2location.get("fraud_score")
    threat = upper(ip2location.get("threat"))

    proxy_type = upper(ip2location.get("proxy_type") or get_nested(ip2location, "proxy", "proxy_type"))
    proxy_flags = {
        "is_proxy": ip2location.get("is_proxy", get_nested(ip2location, "proxy", "is_proxy")),
        "is_data_center": ip2location.get("is_data_center", get_nested(ip2location, "proxy", "is_data_center")),
        "is_vpn": ip2location.get("is_vpn", get_nested(ip2location, "proxy", "is_vpn")),
        "is_tor": ip2location.get("is_tor", get_nested(ip2location, "proxy", "is_tor")),
        "is_residential_proxy": ip2location.get(
            "is_residential_proxy", get_nested(ip2location, "proxy", "is_residential_proxy")
        ),
        "is_consumer_privacy_network": ip2location.get(
            "is_consumer_privacy_network", get_nested(ip2location, "proxy", "is_consumer_privacy_network")
        ),
        "is_spammer": ip2location.get("is_spammer", get_nested(ip2location, "proxy", "is_spammer")),
    }

    ipinfo_asn_type = lower(
        get_nested(ipinfo, "asn", "type")
        or get_nested(ipinfo, "company", "type")
        or ipinfo.get("asn_type")
    )
    ipinfo_privacy = ipinfo.get("privacy") if isinstance(ipinfo.get("privacy"), dict) else {}
    privacy_flags = {
        "hosting": ipinfo_privacy.get("hosting"),
        "vpn": ipinfo_privacy.get("vpn"),
        "proxy": ipinfo_privacy.get("proxy"),
        "tor": ipinfo_privacy.get("tor"),
        "relay": ipinfo_privacy.get("relay"),
        "anonymous": ipinfo_privacy.get("anonymous") or ipinfo_privacy.get("is_anonymous"),
    }

    def reject(reason: str) -> None:
        nonlocal hard_reject
        hard_reject = True
        reasons.append(f"reject: {reason}")

    def deduct(points: int, reason: str) -> None:
        nonlocal score_value
        score_value -= points
        reasons.append(f"-{points}: {reason}")

    def add(points: int, reason: str) -> None:
        nonlocal score_value
        score_value += points
        reasons.append(f"+{points}: {reason}")

    if usage_type in HARD_USAGE:
        reject(f"usage_type={usage_type}")
        recommendations.append("Stop using this network for account access; IP2Location classifies it as non-ISP infrastructure.")
    elif usage_type in PASS_USAGE:
        add(15, f"usage_type={usage_type}")
    elif usage_type:
        deduct(35, f"usage_type={usage_type} is not ISP/MOB")

    if as_usage_type in HARD_USAGE:
        reject(f"as_usage_type={as_usage_type}")
        recommendations.append("ASN usage type is high risk; switch to a legitimate fixed-line ISP/mobile/corporate ISP network in a supported region.")
    elif as_usage_type in PASS_USAGE:
        add(15, f"as_usage_type={as_usage_type}")
    elif as_usage_type:
        deduct(35, f"as_usage_type={as_usage_type} is not ISP/MOB")

    if net_speed == "DSL":
        add(10, "net_speed=DSL")
    elif net_speed:
        deduct(15, f"net_speed={net_speed} is not DSL")
    else:
        deduct(15, "net_speed missing")

    if proxy_type in HARD_PROXY_TYPES:
        reject(f"proxy_type={proxy_type}")
        recommendations.append("Do not use proxy/VPN/TOR/data-center/residential-proxy exits for account access.")

    bad_proxy_flags = [name for name, value in proxy_flags.items() if truthy(value)]
    if bad_proxy_flags:
        reject("IP2Proxy flags true: " + ", ".join(sorted(bad_proxy_flags)))
        recommendations.append("Remove anonymous/proxy/data-center network components before continuing; do not rotate to another proxy pool.")
    elif proxy_flags:
        add(20, "IP2Proxy proxy flags all false")

    if ipinfo_asn_type == "hosting":
        reject("IPinfo ASN type=hosting")
        recommendations.append("Hosting ASN detected; prefer a real ISP/mobile/business broadband network that matches the account's lawful region.")
    elif ipinfo_asn_type in {"isp", "carrier", "mobile"}:
        add(15, f"IPinfo ASN type={ipinfo_asn_type}")
    elif ipinfo_asn_type:
        deduct(30, f"IPinfo ASN type={ipinfo_asn_type}")

    bad_privacy = [name for name, value in privacy_flags.items() if truthy(value)]
    if bad_privacy:
        reject("IPinfo privacy flags true: " + ", ".join(sorted(bad_privacy)))
        recommendations.append("IPinfo privacy flags indicate anonymous or hosting infrastructure; treat this as unsuitable for sensitive account access.")
    elif privacy_flags:
        add(20, "IPinfo privacy flags all false")

    if threat in HARD_THREATS:
        reject(f"threat={threat}")
        recommendations.append("Threat reputation is severely polluted; stop using this exit and investigate abuse history.")
    elif threat in SOFT_THREATS:
        deduct(60, f"threat={threat}")
        recommendations.append("Threat reputation is polluted; stop using this exit and investigate abuse history before resuming.")

    fraud_score = None
    try:
        if fraud_score_raw not in (None, ""):
            fraud_score = float(fraud_score_raw)
    except (TypeError, ValueError):
        reasons.append(f"warn: invalid fraud_score={fraud_score_raw!r}")

    if fraud_score is not None:
        if fraud_score >= 70:
            reject(f"fraud_score={fraud_score:g}")
            recommendations.append("Fraud score is high; do not continue account activity from this network.")
        elif fraud_score >= 51:
            deduct(40, f"fraud_score={fraud_score:g}")
            recommendations.append("Fraud score is elevated; use a lower-risk legitimate network and keep an audit trail.")
        elif fraud_score >= 21:
            deduct(15, f"fraud_score={fraud_score:g}")
        else:
            reasons.append(f"pass: fraud_score={fraud_score:g}")

    score_value = max(0, min(100, score_value))
    if hard_reject:
        score_value = 0
        decision = "reject"
    elif score_value >= 90:
        decision = "clean"
    elif score_value >= 75:
        decision = "acceptable"
    elif score_value >= 60:
        decision = "watch"
    elif score_value >= 40:
        decision = "risky"
    else:
        decision = "reject"

    if not recommendations:
        if decision in {"clean", "acceptable"}:
            recommendations.append("Network looks acceptable; still verify account region, billing entity, and workload policy compliance.")
        else:
            recommendations.append("Reduce risk by using a supported-region account on a legitimate ISP/mobile/business network and stopping suspicious automation.")
    recommendations.append("If the account is already suspended, prepare a factual appeal packet with timestamps, business purpose, remediation steps, and redacted logs.")

    return {
        "score": score_value,
        "decision": decision,
        "reasons": reasons,
        "recommendations": list(dict.fromkeys(recommendations)),
        "observed": {
            "usage_type": usage_type or None,
            "as_usage_type": as_usage_type or None,
            "net_speed": net_speed or None,
            "proxy_type": proxy_type or None,
            "threat": threat or None,
            "fraud_score": fraud_score,
            "ipinfo_asn_type": ipinfo_asn_type or None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score IP cleanliness from provider JSON exports.")
    parser.add_argument("--ip2location", help="Path to IP2Location/IP2Proxy JSON response")
    parser.add_argument("--ipinfo", help="Path to IPinfo JSON response")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    result = score(load_json(args.ip2location), load_json(args.ipinfo))

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print("IP cleanliness report")
    print()
    print(f"score: {result['score']}")
    print(f"decision: {result['decision']}")
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
