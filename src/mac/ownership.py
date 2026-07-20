from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from pathspec import GitIgnoreSpec

from .errors import MacIssue


def _pattern_spec(patterns: list[str]) -> GitIgnoreSpec:
    return GitIgnoreSpec.from_lines(patterns)


def pattern_specificity(pattern: str) -> tuple[int, int]:
    literal = sum(1 for char in pattern if char not in "*?[]!")
    segments = sum(1 for part in PurePosixPath(pattern).parts if not any(char in part for char in "*?[]"))
    return segments, literal


@dataclass(frozen=True, slots=True)
class OwnershipMatch:
    status: str
    owners: tuple[str, ...]
    matched_patterns: tuple[str, ...] = ()
    issues: tuple[MacIssue, ...] = ()


class OwnershipResolver:
    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def resolve(self, path: str) -> OwnershipMatch:
        candidates: list[tuple[tuple[int, int], int, str, str]] = []
        for name, raw in self.document.get("owners", {}).items():
            include = [str(value) for value in raw.get("include", [])]
            exclude = [str(value) for value in raw.get("exclude", [])]
            if exclude and _pattern_spec(exclude).match_file(path):
                continue
            matching = [pattern for pattern in include if _pattern_spec([pattern]).match_file(path)]
            if not matching:
                continue
            best = max(matching, key=pattern_specificity)
            candidates.append((pattern_specificity(best), int(raw.get("priority", 0)), str(name), best))
        if not candidates:
            return OwnershipMatch("unassigned", (), issues=(MacIssue("OWNERSHIP_UNASSIGNED", "path has no owner", path),))
        candidates.sort(reverse=True)
        top_specificity, top_priority = candidates[0][:2]
        winners = [candidate for candidate in candidates if candidate[:2] == (top_specificity, top_priority)]
        if len(winners) > 1:
            owners = tuple(sorted(item[2] for item in winners))
            return OwnershipMatch("ambiguous", owners, tuple(item[3] for item in winners), (MacIssue("OWNERSHIP_AMBIGUOUS", f"path matches owners {', '.join(owners)}", path),))
        return OwnershipMatch("resolved", (winners[0][2],), (winners[0][3],))

    def sensitive(self, path: str) -> tuple[set[str], set[str]]:
        risk_tags: set[str] = set()
        required_gates: set[str] = set()
        for rule in self.document.get("sensitive_paths", []):
            if _pattern_spec([str(rule["pattern"])]).match_file(path):
                risk_tags.update(str(value) for value in rule.get("risk_tags", []))
                required_gates.update(str(value) for value in rule.get("required_gates", []))
        return risk_tags, required_gates
