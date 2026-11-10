"""Process-wide wiring: store, policy, scanners, provider, admin key."""
from __future__ import annotations
import os
import secrets
import threading

from ..config import db_path
from ..engine import Scanner
from ..policies.engine import PolicySettings, default_policy
from ..providers.openai_compat import build_provider
from .store import Store


class ScannerUnavailable(Exception):
    pass


class Runtime:
    def __init__(self):
        self.store = Store(db_path(), database_url=os.getenv("DATABASE_URL"))
        saved = self.store.get_setting("policy")
        try:
            self.policy = PolicySettings(**saved) if saved else default_policy()
        except Exception:
            self.policy = default_policy()
        self.provider = build_provider()
        # The admin key must come from the environment. No hard-coded fallback:
        # a default key in source code is public to anyone who reads the repo.
        configured_admin_key = os.getenv("ADMIN_API_KEY")
        if os.getenv("VERCEL") and not configured_admin_key:
            raise RuntimeError("Set ADMIN_API_KEY in Vercel Environment Variables.")
        self.admin_key_generated = not configured_admin_key
        # Locally with no key set, use a random per-process key (settings stay
        # locked until you set ADMIN_API_KEY). Never printed or logged.
        self.admin_key = configured_admin_key or secrets.token_urlsafe(32)
        self._scanners: dict[str, Scanner] = {}
        self._lock = threading.Lock()

    def get_scanner(self, mode: str) -> Scanner:
        with self._lock:
            if mode not in self._scanners:
                try:
                    sc = Scanner(mode)
                except Exception:
                    raise ScannerUnavailable(
                        f"'{mode}' mode is unavailable: spaCy/Presidio or the en_core_web_sm model "
                        "is not installed on this server (e.g. the lightweight Vercel build). "
                        "Use 'rules' mode.") from None
                sc.set_keywords(self.policy.custom_keywords)
                self._scanners[mode] = sc
            return self._scanners[mode]

    def set_policy(self, policy: PolicySettings) -> None:
        with self._lock:
            self.policy = policy
            self.store.set_setting("policy", policy.model_dump())
            for sc in self._scanners.values():
                sc.set_keywords(policy.custom_keywords)

    def reset(self) -> None:
        """Tests only."""
        self.store.reset()
        self.set_policy(default_policy())


rt = Runtime()
