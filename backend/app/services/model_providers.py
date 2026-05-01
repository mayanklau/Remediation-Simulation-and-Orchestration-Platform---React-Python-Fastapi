import time
import httpx
from app.config import get_settings


ProviderName = str


def configured_model_providers() -> list[dict]:
    settings = get_settings()
    return [
        {"provider": "deterministic", "configured": True, "model": "rules-engine", "purpose": "Always-on fallback for governed dry-run planning."},
        {"provider": "openai_compatible", "configured": bool(settings.llm_base_url and settings.llm_api_key), "model": settings.llm_model or "configured-model", "purpose": "Enterprise model gateway, OpenAI-compatible API, vLLM, or Ollama proxy."},
        {"provider": "anthropic_compatible", "configured": bool(settings.anthropic_api_key), "model": settings.anthropic_model or "configured-anthropic-model", "purpose": "Anthropic-compatible message endpoint."},
        {"provider": "gemini_compatible", "configured": bool(settings.gemini_api_key), "model": settings.gemini_model or "configured-gemini-model", "purpose": "Gemini-compatible generateContent endpoint."},
        {"provider": "local_slm", "configured": bool(settings.local_slm_url), "model": settings.local_slm_model or "local-small-language-model", "purpose": "Private local SLM endpoint."},
    ]


def select_provider(preferred: str | None = None) -> str:
    providers = configured_model_providers()
    if preferred and any(p["provider"] == preferred and p["configured"] for p in providers):
        return preferred
    configured = next((p for p in providers if p["provider"] != "deterministic" and p["configured"]), None)
    return configured["provider"] if configured else "deterministic"


async def complete_with_model(system: str, prompt: str, provider: str | None = None) -> dict:
    started = time.time()
    selected = select_provider(provider)
    if selected == "deterministic":
        return deterministic_response(system, prompt, started)
    try:
        settings = get_settings()
        if selected == "openai_compatible":
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                    headers={"authorization": f"Bearer {settings.llm_api_key}"},
                    json={"model": settings.llm_model or "configured-model", "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}], "temperature": 0.1},
                )
                response.raise_for_status()
                data = response.json()
                return {"provider": selected, "model": settings.llm_model or "configured-model", "output": data.get("choices", [{}])[0].get("message", {}).get("content", ""), "used_external_model": True, "latency_ms": int((time.time() - started) * 1000)}
        if selected == "local_slm":
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(settings.local_slm_url, json={"model": settings.local_slm_model, "system": system, "prompt": prompt})
                response.raise_for_status()
                data = response.json()
                return {"provider": selected, "model": settings.local_slm_model or "local-small-language-model", "output": data.get("output") or data.get("response") or data.get("text", ""), "used_external_model": True, "latency_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        fallback = deterministic_response(system, prompt, started)
        fallback["output"] += f"\n\nModel gateway fallback reason: {exc}"
        return fallback
    return deterministic_response(system, prompt, started)


def deterministic_response(system: str, prompt: str, started: float) -> dict:
    focus = "Prioritize virtual patching and attack-path interruption before permanent change." if "virtual" in prompt.lower() or "path" in prompt.lower() else "Prioritize risk reduction with approval and evidence gates."
    output = "\n".join(
        [
            focus,
            "Recommended agent steps:",
            "1. Gather tenant risk context, top findings, assets, workflows, simulations, policies, and evidence.",
            "2. Select highest business-risk remediation actions with stale or missing simulations.",
            "3. Run simulation before execution and require rollback planning for production assets.",
            "4. Use virtual patching or path breakers for internet-exposed, high-criticality, or unpatchable assets.",
            "5. Route approvals through security, service owner, risk owner, and CAB as needed.",
            "6. Keep execution dry-run until credentials, change windows, policy approvals, and evidence gates are verified.",
        ]
    )
    return {"provider": "deterministic", "model": "rules-engine", "output": output, "used_external_model": False, "latency_ms": int((time.time() - started) * 1000)}

