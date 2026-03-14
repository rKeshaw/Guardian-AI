from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def unpack_query_result(raw_result: Any) -> Any | None:
    if raw_result is None:
        return None
    if isinstance(raw_result, tuple) and len(raw_result) == 2:
        payload, err = raw_result
        if err:
            logger.debug("LLM query returned error: %s", err)
            return None
        return payload
    return raw_result


def charge_ledger(ledger, component: str, prompt: str) -> bool:
    from guardian.core.ai_client import estimate_tokens

    tokens = estimate_tokens(prompt)
    try:
        return bool(ledger.charge(tokens, component=component))
    except TypeError:
        return bool(ledger.charge(component, tokens))


