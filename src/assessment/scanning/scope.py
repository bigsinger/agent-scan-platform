from pathlib import Path

from ..store import REPO_ROOT


SELF_TEST_RELATIVE_ROOTS = (
    Path("tests") / "fixtures",
    Path(".agents"),
)

SELF_TEST_FILE_NAMES = {".mcp.json", "mcp.json", "SKILL.md"}


def _resolve(path: Path) -> Path:
    try:
        return path.expanduser().resolve()
    except OSError:
        return path.expanduser().absolute()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def self_test_roots() -> list[Path]:
    return [_resolve(REPO_ROOT / relative) for relative in SELF_TEST_RELATIVE_ROOTS]


def is_self_project_path(path: Path) -> bool:
    return _is_relative_to(_resolve(path), _resolve(REPO_ROOT))


def is_self_test_asset_path(path: Path) -> bool:
    resolved = _resolve(path)
    if not _is_relative_to(resolved, _resolve(REPO_ROOT)):
        return False
    if any(_is_relative_to(resolved, root) for root in self_test_roots()):
        return True
    return resolved.is_file() and resolved.name in SELF_TEST_FILE_NAMES


def may_contain_self_test_asset(path: Path) -> bool:
    resolved = _resolve(path)
    if not _is_relative_to(resolved, _resolve(REPO_ROOT)):
        return False
    if is_self_test_asset_path(resolved):
        return True
    return any(_is_relative_to(root, resolved) for root in self_test_roots())


def should_skip_self_project_path(path: Path) -> bool:
    return is_self_project_path(path) and not is_self_test_asset_path(path)


def filter_self_project_dirs(current: Path, dirs: list[str]) -> None:
    resolved = _resolve(current)
    if not _is_relative_to(resolved, _resolve(REPO_ROOT)):
        return
    if is_self_test_asset_path(resolved):
        return
    if not may_contain_self_test_asset(resolved):
        dirs[:] = []
        return
    kept: list[str] = []
    for dirname in dirs:
        child = resolved / dirname
        if is_self_test_asset_path(child) or may_contain_self_test_asset(child):
            kept.append(dirname)
    dirs[:] = kept


def self_project_scope(path: Path | None) -> dict:
    if path is None:
        return {"applies": False, "source_excluded": False, "allowed_roots": []}
    resolved = _resolve(path)
    if not _is_relative_to(resolved, _resolve(REPO_ROOT)):
        return {"applies": False, "source_excluded": False, "allowed_roots": []}
    allowed_roots = [
        str(root.relative_to(_resolve(REPO_ROOT))).replace("\\", "/")
        for root in self_test_roots()
        if root.exists() or root.parent.exists()
    ]
    return {
        "applies": True,
        "source_excluded": should_skip_self_project_path(resolved),
        "allowed_roots": allowed_roots,
        "policy": "skip-agent-scan-platform-source-and-docs",
        "message": "本项目源码、文档和运维目录默认排除；仅扫描本项目内显式测试 MCP/Skill 资产。",
    }
