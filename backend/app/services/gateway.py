"""LLM gateway: the ONLY code path that talks to a provider.

prompt -> scan -> policy -> (block | confirm | mask) -> verify -> provider
       -> scan response -> output policy -> (block | mask) -> user
"""
from __future__ import annotations
from ..config import MAX_INPUT_CHARS, llm_timeout
from ..engine import PLACEHOLDER_RE, Scanner, apply_masking
from ..policies.engine import evaluate
from ..providers.base import ProviderError
from .runtime import Runtime

# Only low-risk identifiers may ever be restored into a response. Credentials,
# financial and government identifiers are NEVER restored, whatever the policy.
RESTORABLE = {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "LOCATION", "IP_ADDRESS"}


def _report(findings, decision) -> list[dict]:
    out = []
    for f, it in zip(findings, decision.items):
        d = f.to_dict()
        d["action"], d["reason"] = it["action"], it["reason"]
        out.append(d)
    return out


def _verify_outbound(rt: Runtime, outbound: str) -> bool:
    """Defence in depth: re-scan the exact text about to be sent, using the
    deterministic rules scanner, and fail closed if any MASK/BLOCK-level
    pattern survived."""
    neutral = PLACEHOLDER_RE.sub("REDACTED", outbound)
    sc = rt.get_scanner("rules")
    res = sc.scan(neutral)
    d = evaluate(res.clusters, rt.policy)
    return not any(a in ("MASK", "BLOCK") for a in d.cluster_actions)


def _base(status: str, message: str, rt: Runtime) -> dict:
    return {"status": status, "message": message,
            "provider": {"name": rt.provider.name, "is_mock": rt.provider.is_mock},
            "provider_called": False, "input": None, "sent_to_model": None,
            "response": None, "output": None,
            "input_modified": False, "output_modified": False}


def run(rt: Runtime, prompt: str, mode: str = "rules",
        confirm_warnings: bool = False, restore: bool = False) -> dict:
    scanner: Scanner = rt.get_scanner(mode)          # may raise ScannerUnavailable
    policy = rt.policy

    # ---- 1. scan + decide on the INPUT ----
    scan = scanner.scan(prompt)
    dec = evaluate(scan.clusters, policy)
    rt.store.log_scan("gateway_input", mode, dec.overall, dec.items)
    inp = {"overall": dec.overall, "messages": dec.messages,
           "findings": _report(scan.findings, dec)}

    if dec.overall == "BLOCK":
        r = _base("blocked", "Blocked by policy: the prompt contains "
                  "high-risk data. Nothing was sent to the model.", rt)
        r["input"] = inp
        return r
    if dec.overall == "WARN" and not confirm_warnings:
        r = _base("needs_confirmation", "Some items need your review. Tick the "
                  "confirmation box to send them as-is, or edit the prompt.", rt)
        r["input"] = inp
        return r

    # ---- 2. sanitise ----
    want_restore = restore and policy.allow_placeholder_restoration
    act_in = {id(c): a for c, a in zip(scan.clusters, dec.cluster_actions)}
    outbound, mapping = apply_masking(
        prompt, scan.clusters, lambda c: act_in[id(c)] == "MASK", numbered=want_restore)

    # ---- 3. verify (fail closed) ----
    if not _verify_outbound(rt, outbound):
        r = _base("blocked", "Blocked: sanitisation could not be verified. "
                  "Nothing was sent to the model.", rt)
        r["input"] = inp
        return r

    # ---- 4. call provider ----
    try:
        raw = rt.provider.complete(outbound, llm_timeout())
    except ProviderError as exc:
        r = _base("provider_error", f"The model provider failed ({exc}). "
                  "Your prompt was sanitised before sending.", rt)
        r.update(input=inp, sent_to_model=outbound, provider_called=True,
                 input_modified=outbound != prompt)
        return r
    except Exception:
        r = _base("provider_error", "The model provider failed unexpectedly.", rt)
        r.update(input=inp, sent_to_model=outbound, provider_called=True,
                 input_modified=outbound != prompt)
        return r

    # ---- 5. scan + decide on the OUTPUT ----
    if len(raw) > MAX_INPUT_CHARS:
        r = _base("response_blocked", "The model response was too large to scan "
                  "and was withheld.", rt)
        r.update(input=inp, sent_to_model=outbound, provider_called=True,
                 input_modified=outbound != prompt)
        return r
    out_scan = scanner.scan(raw)
    out_dec = evaluate(out_scan.clusters, policy, output=True)
    rt.store.log_scan("gateway_output", mode, out_dec.overall, out_dec.items)
    out_rep = {"overall": out_dec.overall, "messages": out_dec.messages,
               # offsets omitted on purpose: the raw response is never shown
               "findings": [{"entity_type": i["entity_type"], "action": i["action"],
                             "reason": i["reason"]} for i in out_dec.items]}
    r = _base("ok", "", rt)
    r.update(input=inp, sent_to_model=outbound, provider_called=True,
             input_modified=outbound != prompt, output=out_rep)
    if out_dec.overall == "BLOCK":
        r["status"] = "response_blocked"
        r["message"] = "The model's response contained high-risk data and was withheld."
        return r
    act_out = {id(c): a for c, a in zip(out_scan.clusters, out_dec.cluster_actions)}
    final, _ = apply_masking(raw, out_scan.clusters, lambda c: act_out[id(c)] == "MASK")
    r["output_modified"] = final != raw

    # ---- 6. optional, tightly limited restoration ----
    if want_restore and mapping:
        for ph, original in mapping.items():
            etype = ph[1:-1].rsplit("_", 1)[0]
            if etype in RESTORABLE:
                final = final.replace(ph, original)
    r["response"] = final
    parts = []
    if r["input_modified"]:
        parts.append("Your prompt was modified (sensitive values masked) before sending; "
                     "the answer may be less specific because of that.")
    if r["output_modified"]:
        parts.append("The response was modified because it contained sensitive data.")
    r["message"] = " ".join(parts) or "Prompt and response passed policy unchanged."
    return r
