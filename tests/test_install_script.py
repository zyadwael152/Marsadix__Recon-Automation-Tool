"""Static checks for the Linux tool installer (no root / no network needed)."""

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-tools.sh"


def test_massdns_is_built_as_a_c_program_not_installed_as_a_go_module():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "install_go_tool massdns" not in text
    assert "git clone --depth 1 https://github.com/blechschmidt/massdns.git" in text
    assert "make -C \"$src\"" in text
    assert "bin/massdns" in text
