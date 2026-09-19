"""OS credential storage, with an explicit memory-only fallback."""

import os


class CredentialStore:
    service = "MEAP.Triage"
    username = "api-key"

    def __init__(self, backend=None):
        self._session_key = None
        self.mode = "session only"
        if backend is None:
            try:
                import keyring

                candidate = keyring.get_keyring()
                # Do not silently accept third-party plaintext/fallback backends.
                module = type(candidate).__module__
                if module.startswith(
                    (
                        "keyring.backends.Windows",
                        "keyring.backends.macOS",
                        "keyring.backends.SecretService",
                        "keyring.backends.kwallet",
                    )
                ):
                    backend = candidate
            except Exception:
                pass
        self.backend = backend

    def get(self):
        configured = os.environ.get("TRIAGE_API_KEY", "")
        if configured:
            return configured
        if self._session_key is not None:
            return self._session_key
        if self.backend:
            try:
                return self.backend.get_password(self.service, self.username) or ""
            except Exception:
                pass
        return ""

    def save(self, value):
        self._session_key = value.strip()
        self.mode = "session only"
        if self.backend:
            try:
                if value.strip():
                    self.backend.set_password(
                        self.service, self.username, value.strip()
                    )
                else:
                    self.backend.delete_password(self.service, self.username)
                self.mode = "OS credential store"
            except Exception:
                pass
        return self.mode

    def migrate(self, database):
        row = database.conn.execute(
            "SELECT value FROM settings WHERE key='api_key'"
        ).fetchone()
        if row and row[0]:
            # Keep the imported value available for this session even without a
            # secure backend. Do not preserve a plaintext fallback on disk.
            self.save(row[0])
        database.conn.execute("PRAGMA secure_delete=ON")
        database.conn.execute("DELETE FROM settings WHERE key='api_key'")
        database.conn.commit()
