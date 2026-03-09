from __future__ import annotations

import logging
from pathlib import Path

from guardian.core.knowledge_index import estimate_tokens, knowledge_index, parse_knowledge_file

logger = logging.getLogger(__name__)


class RagHelper:
    def get_probe_context(
        self,
        owasp_category: str,
        vuln_name: str,
        token_budget: int = 800,
    ) -> str:
        files = knowledge_index.files_for_vulnerability(owasp_category, vuln_name)
        selected_files = files[:2]
        if not selected_files:
            logger.debug(
                "RAG probe context: files_found=0 category=%s vuln=%s",
                owasp_category,
                vuln_name,
            )
            return ""

        chunks: list[str] = []
        per_file_budget = max(1, token_budget // 2)
        for file_path in selected_files:
            extracted = parse_knowledge_file(file_path, token_budget=per_file_budget)
            if not extracted:
                continue
            chunks.append(f"\n--- Source: {Path(file_path).name} ---\n{extracted}")

        if not chunks:
            logger.debug(
                "RAG probe context: files_found=%d tokens_returned=0",
                len(selected_files),
            )
            return ""

        content = (
            "=== RELEVANT ATTACK KNOWLEDGE (from PayloadsAllTheThings) ===\n"
            + "\n".join(chunks)
            + "\n=== END KNOWLEDGE CONTEXT ==="
        )

        max_chars = max(1, token_budget * 4)
        if len(content) > max_chars:
            content = content[:max_chars]

        logger.debug(
            "RAG probe context: files_found=%d tokens_returned≈%d",
            len(selected_files),
            estimate_tokens(content),
        )
        return content


rag_helper = RagHelper()
