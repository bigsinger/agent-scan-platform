import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "assessment" / "static"
REMOTE_PATTERN = re.compile(r"https?://|//unpkg|//cdn|//cdnjs|fonts\.googleapis", re.IGNORECASE)


def test_frontend_assets_are_local_and_boot_guarded():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    assert 'id="boot-status"' in html
    assert 'id="boot-error"' in html
    assert "v-cloak" in html
    assert "/static/vendor/vue.global.prod.js" in html
    for path in [
        STATIC / "assessment" / "index.html",
        STATIC / "assessment" / "app.js",
        STATIC / "assessment" / "seed.js",
        STATIC / "assessment" / "style.css",
    ]:
        assert not REMOTE_PATTERN.search(path.read_text(encoding="utf-8")), path


def test_vendor_manifest_matches_vue_runtime():
    manifest = json.loads((STATIC / "vendor" / "vendor-manifest.json").read_text(encoding="utf-8"))
    vue = STATIC / "vendor" / "vue.global.prod.js"
    assert hashlib.sha256(vue.read_bytes()).hexdigest() == manifest["vue.global.prod.js"]["sha256"]

