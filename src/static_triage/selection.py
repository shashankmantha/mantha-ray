from __future__ import annotations

from fnmatch import fnmatch


class Selection:
    """The files a targeted scan was asked to look at.

    Patterns are matched against a file's path relative to the scan root,
    the form every report and summary prints, so a path can be copied
    straight out of one. Matching ignores case, because the paths come
    from Windows software. A pattern may be an exact path, a glob, a
    folder (which takes everything beneath it), or a bare file name.
    """

    __slots__ = ("patterns", "_used")

    def __init__(self, patterns: tuple[str, ...]) -> None:
        self.patterns = patterns
        self._used: set[str] = set()

    @classmethod
    def of(cls, patterns: object) -> "Selection | None":
        """Build a selection, or None when nothing was asked for."""

        if not patterns:
            return None
        cleaned: list[str] = []
        for pattern in patterns:
            text = str(pattern).strip().strip("/").replace("\\", "/")
            if text and text not in cleaned:
                cleaned.append(text)
        if not cleaned:
            return None
        return cls(tuple(cleaned))

    def matches(self, relative_path: str) -> bool:
        path = relative_path.replace("\\", "/").lower()
        name = path.rsplit("/", 1)[-1]
        hit = False
        for pattern in self.patterns:
            wanted = pattern.lower()
            if (
                path == wanted
                or path.startswith(wanted + "/")
                or fnmatch(path, wanted)
                or ("/" not in wanted and fnmatch(name, wanted))
            ):
                self._used.add(pattern)
                hit = True
        return hit

    @property
    def unmatched(self) -> tuple[str, ...]:
        return tuple(p for p in self.patterns if p not in self._used)

    def to_dict(self, matched: int) -> dict[str, object]:
        return {
            "patterns": list(self.patterns),
            "matched": matched,
            "unmatched": list(self.unmatched),
            "note": (
                "Only the files named here were inventoried and analyzed. "
                "Every count in this report, coverage included, describes "
                "those files and not the whole folder."
            ),
        }
