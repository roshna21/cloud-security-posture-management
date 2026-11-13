"""Evaluate MBSS controls against a provider-neutral snapshot of the environment.

Controls are declarative (see config/mbss.json). Two check types cover them all:

* attr              - a field on every item of a collection must satisfy op/value
* sg_world_ingress  - no security group may expose the listed ports to 0.0.0.0/0

Because the checks only read the snapshot, the same MBSS works for any cloud
whose provider can produce that snapshot.
"""
from __future__ import annotations

from typing import Any, Dict, List

WORLD = ("0.0.0.0/0", "::/0")


def get_field(obj: Dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def set_field(obj: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    for part in parts[:-1]:
        obj = obj.setdefault(part, {})
    obj[parts[-1]] = value


def compare(actual: Any, op: str, value: Any) -> bool:
    if actual is None:
        return False
    if op == "eq":
        return actual == value
    if op == "ge":
        return actual >= value
    if op == "le":
        return actual <= value
    raise ValueError(f"unknown operator {op!r}")


def items_of(snapshot: Dict[str, Any], collection: str) -> List[Dict[str, Any]]:
    if collection == "account":
        return [snapshot["account"]]
    return snapshot.get(collection, [])


def world_rules(sg: Dict[str, Any], ports: List[int]) -> List[Dict[str, Any]]:
    return [
        r for r in sg.get("ingress", [])
        if r.get("cidr") in WORLD and any(r["from_port"] <= p <= r["to_port"] for p in ports)
    ]


RESOURCE_TYPES = {
    "account": "account", "iam_users": "iam_user", "s3_buckets": "s3_bucket",
    "security_groups": "security_group", "vpcs": "vpc", "trails": "cloudtrail",
    "instances": "ec2_instance",
}
OPS = {"eq": "to be", "ge": "to be at least", "le": "to be at most"}


def _result(control: Dict[str, Any], rtype: str, item: Dict[str, Any], ok: bool, detail: str) -> Dict[str, Any]:
    return {
        "control_id": control["id"],
        "resource_type": rtype,
        "resource_id": item["id"],
        "resource_name": item.get("name", item["id"]),
        "bu": item.get("bu") or "platform",
        "compliant": ok,
        "detail": detail,
    }


def evaluate(control: Dict[str, Any], snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return one result per resource the control applies to."""
    chk = control["check"]
    results: List[Dict[str, Any]] = []

    if chk["type"] == "attr":
        op = chk.get("op", "eq")
        for item in items_of(snapshot, chk["collection"]):
            if any(get_field(item, k) != v for k, v in chk.get("where", {}).items()):
                continue
            actual = get_field(item, chk["field"])
            ok = compare(actual, op, chk["value"])
            if ok:
                detail = "Compliant with the MBSS"
            elif actual is None:
                detail = "This setting could not be read, so it is treated as non-compliant"
            elif control.get("finding"):
                detail = control["finding"].format(actual=actual)
            else:
                detail = f"{chk['field']} is {actual!r}; the MBSS requires it {OPS[op]} {chk['value']!r}"
            results.append(_result(control, RESOURCE_TYPES[chk["collection"]], item, ok, detail))

    elif chk["type"] == "sg_world_ingress":
        for sg in snapshot.get("security_groups", []):
            bad = world_rules(sg, chk["ports"])
            if bad:
                ports = sorted({p for r in bad for p in chk["ports"] if r["from_port"] <= p <= r["to_port"]})
                detail = f"Anyone on the internet can reach port {', '.join(map(str, ports))}"
            else:
                detail = f"no internet ingress on port(s) {', '.join(map(str, chk['ports']))}"
            results.append(_result(control, "security_group", sg, not bad, detail))

    else:
        raise ValueError(f"unknown check type {chk['type']!r} in control {control['id']}")

    return results


def evaluate_all(controls: List[Dict[str, Any]], snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for control in controls:
        out.extend(evaluate(control, snapshot))
    return out
