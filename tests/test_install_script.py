"""Static checks for the Linux tool installer (no root / no network needed)."""

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-tools.sh"


def test_massdns_is_built_as_a_c_program_not_installed_as_a_go_module():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "install_go_tool massdns" not in text
    assert "git clone --depth 1" in text
    assert "https://github.com/blechschmidt/massdns.git" in text
    assert "make -C \"$src\"" in text
    assert "bin/massdns" in text


def test_windows_installer_never_runs_go_install_for_massdns():
    ps1 = (SCRIPT.parent / "install-tools.ps1").read_text(encoding="utf-8")
    assert "massdns/bin/massdns" not in ps1          # it is a C program, not a Go module
    assert "WSL" in ps1 and "Docker" in ps1          # tells the user what to do instead


def test_linux_installer_does_not_depend_on_getent_alone():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "getent" in text and "dscl" in text and 'REAL_HOME="$HOME"' in text   # macOS fallback


def test_puredns_is_installed_from_its_real_module_path():
    # puredns keeps main.go at the module root (go install github.com/d3mondev/puredns/v2@latest);
    # a /cmd/puredns suffix does not exist and made the installer report "failed: puredns".
    sh = SCRIPT.read_text(encoding="utf-8")
    ps1 = (SCRIPT.parent / "install-tools.ps1").read_text(encoding="utf-8")
    assert "d3mondev/puredns/v2/cmd/puredns" not in sh + ps1
    assert "install_go_tool puredns     github.com/d3mondev/puredns/v2\n" in sh
    assert "github.com/d3mondev/puredns/v2@latest" in ps1
