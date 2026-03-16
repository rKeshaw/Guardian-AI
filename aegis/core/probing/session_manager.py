from __future__ import annotations

import base64
import logging
from urllib.parse import urljoin

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class SessionManager:
    async def authenticate(self, auth_config: dict, session) -> bool:
        auth_type = (auth_config or {}).get("type", "none")

        try:
            if auth_type == "none":
                return True

            if auth_type == "bearer":
                token = auth_config.get("bearer_token", "")
                session.headers["Authorization"] = f"Bearer {token}"
                return True

            if auth_type == "basic":
                user = auth_config.get("user", "")
                password = auth_config.get("password", "")
                encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
                session.headers["Authorization"] = f"Basic {encoded}"
                return True

            if auth_type == "form":
                login_url = auth_config.get("login_url", "")
                credentials = auth_config.get("credentials", {})
                success_indicator = auth_config.get("success_indicator", "")
                if not login_url or not isinstance(credentials, dict):
                    return False

                async with session.get(login_url) as resp:
                    login_html = await resp.text(errors="replace")

                soup = BeautifulSoup(login_html, "html.parser")
                form = soup.find("form")
                if form is None:
                    return False

                action = form.get("action") or login_url
                method = str(form.get("method", "post")).upper()
                post_url = action if action.startswith(("http://", "https://")) else urljoin(login_url, action)

                payload: dict[str, str] = {}
                for hidden in form.find_all("input", {"type": "hidden"}):
                    name = hidden.get("name")
                    if name:
                        payload[name] = hidden.get("value", "")

                for k, v in credentials.items():
                    payload[str(k)] = str(v)

                if method == "GET":
                    async with session.get(post_url, params=payload) as resp:
                        body = await resp.text(errors="replace")
                else:
                    async with session.post(post_url, data=payload) as resp:
                        body = await resp.text(errors="replace")

                ok = bool(success_indicator and success_indicator in body)
                logger.info("Form authentication result login_url=%s success=%s", login_url, ok)
                return ok

            return False

        except Exception as exc:
            logger.error("Authentication failed auth_type=%s error=%s", auth_type, exc)
            return False
