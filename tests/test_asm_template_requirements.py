from marsadix.asm.templates import (
    TemplateRequirements, classify_template_paths, classify_template_text,
)


def test_classifies_optional_nuclei_engines_from_top_level_keys():
    requirements = classify_template_text(
        "id: sample\ninfo:\n  name: sample\ncode:\n  - engine: sh\n"
        "file:\n  - extensions: [all]\nheadless:\n  - steps: []\n"
        "dast:\n  - path: /\nself-contained: true\n"
    )
    assert requirements == TemplateRequirements(
        code=True, file=True, headless=True, dast=True, self_contained=True
    )


def test_does_not_misclassify_nested_keys():
    requirements = classify_template_text("id: sample\ninfo:\n  name: sample\n  code: false\n")
    assert requirements == TemplateRequirements()


def test_enabled_flags_are_stable():
    requirements = TemplateRequirements(code=True, headless=True, self_contained=True)
    assert requirements.enabled_flags() == ("-code", "-headless", "-enable-self-contained")


def test_classify_template_paths_unions_requirements(tmp_path):
    first = tmp_path / "one.yaml"
    second = tmp_path / "two.yaml"
    first.write_text("id: one\ncode:\n  - engine: sh\n", encoding="utf-8")
    second.write_text("id: two\nheadless:\n  - steps: []\n", encoding="utf-8")
    assert classify_template_paths([first, second]) == TemplateRequirements(code=True, headless=True)
