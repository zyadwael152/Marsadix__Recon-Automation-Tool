"""Classify Nuclei templates by optional engine requirements."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re

@dataclass(frozen=True)
class TemplateRequirements:
    code: bool = False
    file: bool = False
    headless: bool = False
    dast: bool = False
    self_contained: bool = False

    def enabled_flags(self) -> tuple[str,...]:
        flags=[]
        if self.code: flags.append("-code")
        if self.file: flags.append("-file")
        if self.headless: flags.append("-headless")
        if self.dast: flags.append("-dast")
        if self.self_contained: flags.append("-enable-self-contained")
        return tuple(flags)

_KEY_MAP={"code":"code","file":"file","headless":"headless","dast":"dast","self-contained":"self_contained","self_contained":"self_contained"}
def classify_template_text(text: str) -> TemplateRequirements:
    keys=set()
    for line in (text or "").splitlines():
        match=re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:",line)
        if match: keys.add(match.group(1).lower())
    values = {name: False for name in TemplateRequirements.__dataclass_fields__}
    for key, field in _KEY_MAP.items():
        values[field] = values[field] or key in keys
    return TemplateRequirements(**values)
def classify_template_file(path: str | Path) -> TemplateRequirements:
    return classify_template_text(Path(path).read_text(encoding="utf-8",errors="replace"))
def classify_template_paths(paths) -> TemplateRequirements:
    found={name:False for name in TemplateRequirements.__dataclass_fields__}
    for path in paths:
        req=classify_template_file(path)
        for name in found: found[name]=found[name] or getattr(req,name)
    return TemplateRequirements(**found)
