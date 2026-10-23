"""Path boundaries for private offline review material; not a storage sandbox."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def private_path(path):
    """Reject our checkout and other Git checkouts, including symlink targets."""
    resolved = Path(path).resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError("Private review files must be outside the repository")
    if any((parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file()
           for parent in (resolved, *resolved.parents)):
        raise ValueError("Private review files must be outside Git checkouts")
    return resolved


def read_private(path, limit=20_000_000):
    with private_path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Private review file exceeds size limit")
    return data
