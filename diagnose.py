"""
diagnose.py -- isolate which part of the API request is failing.

WHY THIS EXISTS
    explainer.py sends one request with several features stacked on it: a model
    choice, an effort setting, and a structured-output schema. When that request
    fails, the traceback tells you it failed -- not which of those pieces caused it.

    So this sends four requests, each adding one piece to the last. The first one
    that fails identifies the culprit. This is bisection: the same technique as
    commenting out half your code to find a bug, applied to an API call.

    Every exception is caught and printed by TYPE and MESSAGE, because the type is
    what tells you the category of problem (auth vs. bad request vs. a bug in the
    SDK's response parsing) and explainer.py's handlers were clearly missing one.

Run:  python diagnose.py
Cost: four tiny requests, well under a cent total.
"""

import os
import sys
import traceback

import anthropic

MODEL = "claude-sonnet-5"

SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def attempt(label, **extra_kwargs):
    """Make one request and report exactly what happened."""
    print(f"\n{'=' * 70}")
    print(f"TEST: {label}")
    print("=" * 70)

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=2000,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
            **extra_kwargs,
        )
    except Exception as exc:
        # Deliberately catching bare Exception -- the whole point is to discover
        # which type we're dealing with, so narrowing it would defeat the purpose.
        print(f"  FAILED")
        print(f"  Exception type : {type(exc).__module__}.{type(exc).__name__}")
        print(f"  Message        : {exc}")
        # status_code exists on anthropic API errors; getattr avoids blowing up
        # when the exception is something else entirely.
        status = getattr(exc, "status_code", None)
        if status:
            print(f"  HTTP status    : {status}")
        return False

    text = next((b.text for b in response.content if b.type == "text"), "(no text block)")
    print(f"  OK")
    print(f"  stop_reason    : {response.stop_reason}")
    print(f"  block types    : {[b.type for b in response.content]}")
    print(f"  text           : {text[:200]}")
    print(f"  tokens in/out  : {response.usage.input_tokens}/{response.usage.output_tokens}")
    return True


if not os.environ.get("ANTHROPIC_API_KEY"):
    sys.exit("ANTHROPIC_API_KEY is not set in this shell.")

print(f"anthropic SDK version: {anthropic.__version__}")
client = anthropic.Anthropic()

# Each test adds ONE thing to the previous. The first failure names the culprit.
results = {}
results["1. bare request"] = attempt("bare request (model + messages only)")
results["2. + effort"] = attempt(
    "with output_config.effort", output_config={"effort": "medium"}
)
results["3. + format"] = attempt(
    "with output_config.format",
    output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
)
results["4. + both"] = attempt(
    "with BOTH effort and format (what explainer.py sends)",
    output_config={
        "effort": "medium",
        "format": {"type": "json_schema", "schema": SCHEMA},
    },
)

print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
