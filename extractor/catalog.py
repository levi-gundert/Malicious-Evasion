"""Offline candidates and explicit authenticated catalog imports."""

import base64
from datetime import datetime, timezone
import json
from pathlib import Path

from extractor.models.artifact import Artifact

BUNDLED = Path(__file__).resolve().parent.parent / "catalog" / "windows-candidates.json"


def load_catalog(path=BUNDLED, signature=None, trusted_key=None, minimum_version=1):
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Catalog exceeds 1 MiB")
    payload = path.read_bytes()
    if path.resolve() != BUNDLED.resolve():
        if not signature or not trusted_key:
            raise ValueError(
                "External catalogs require an Ed25519 signature and an independently trusted public key"
            )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(Path(trusted_key).read_text().strip(), validate=True)
        )
        key.verify(
            base64.b64decode(Path(signature).read_text().strip(), validate=True),
            payload,
        )
    data = json.loads(payload)
    if (
        data.get("schema_version") != 1
        or type(data.get("catalog_version")) is not int
        or data["catalog_version"] < minimum_version
    ):
        raise ValueError("Unsupported schema or catalog rollback")
    expiry = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("Catalog expired; review and revalidate before use")
    names = set()
    for recipe in data["recipes"]:
        if recipe["name"] in names or any(
            name not in names for name in recipe.get("dependencies", [])
        ):
            raise ValueError("Duplicate recipe or unordered/missing dependency")
        names.add(recipe["name"])
        recipe["artifact"] = Artifact.model_validate(recipe["artifact"]).model_dump(
            mode="json"
        )
    return data
