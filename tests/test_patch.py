"""Patch boundaries and transactional replacement tests."""
from pathlib import Path
import subprocess

import pytest

from sio2.tools.patch import PatchRefused, apply_patch
from sio2.workspace import Workspace


@pytest.fixture
def workspace(tmp_path):
    source = tmp_path / "source"
    (source / "radicale" / "tests").mkdir(parents=True)
    (source / "radicale/app.py").write_text("x = 1\ny = 2\n")
    (source / "radicale/tests/test_app.py").write_text("x = 1\n")
    with Workspace(source, "radicale") as ws:
        yield ws
    assert (source / "radicale/app.py").read_text() == "x = 1\ny = 2\n"


def edit(old="x = 1", new="x = 3", path="radicale/app.py"):
    return {"path": path, "old_text": old, "new_text": new}


def test_exact_replacements_produce_reviewable_diff(workspace):
    patch = apply_patch(workspace, [edit(), edit("y = 2", "y = 4")], {"radicale/app.py"})
    assert (workspace.root / "radicale/app.py").read_text() == "x = 3\ny = 4\n"
    assert patch.before == {"radicale/app.py": "x = 1\ny = 2\n"}
    assert patch.after == {"radicale/app.py": "x = 3\ny = 4\n"}
    assert "--- a/radicale/app.py" in patch.diff
    assert "+x = 3" in patch.diff


@pytest.mark.parametrize("bad", [
    edit("missing"), edit("", "x"), edit("x = 1", "x = 1"),
    edit(path="../outside.py"), edit(path="/etc/passwd"),
    edit(path="radicale/tests/test_app.py"), edit(path=".hidden.py"),
    edit(new="x = 3  # nosec B101"), edit(new="x = 3  # noqa"),
    {"path": "radicale/app.py", "old_text": 1, "new_text": "x"},
])
def test_invalid_patch_leaves_workspace_unchanged(workspace, bad):
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit("y = 2", "y = 4"), bad],
                    {"radicale/app.py", "radicale/tests/test_app.py", ".hidden.py"})
    assert (workspace.root / "radicale/app.py").read_text() == "x = 1\ny = 2\n"


def test_overlapping_and_duplicate_matches_are_refused(workspace):
    for edits in ([edit(), edit("x = 1\ny = 2", "z = 3")], [edit(" = ", "=")]):
        with pytest.raises(PatchRefused):
            apply_patch(workspace, edits, {"radicale/app.py"})


def test_symlink_is_not_a_write_alias(workspace):
    (workspace.root / "radicale/alias.py").symlink_to("app.py")
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit(path="radicale/alias.py")], {"radicale/app.py"})


def test_unlisted_source_file_is_refused(workspace):
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit()], {"radicale/other.py"})


def test_existing_suppression_cannot_hide_a_new_statement(workspace):
    source = workspace.root / "radicale/app.py"
    original = "x = 1  # nosec B307\neval(value)\n"
    source.write_text(original)
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit("x = 1", "eval(value)"), edit("\neval(value)\n", "\n")],
                    {"radicale/app.py"})
    assert source.read_text() == original


def test_existing_suppression_cannot_be_broadened(workspace):
    source = workspace.root / "radicale/app.py"
    source.write_text("x = 1  # nosec B101\n")
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit("B101", "B307")], {"radicale/app.py"})


def test_diff_for_source_without_final_newline_is_applicable(workspace):
    source = workspace.root / "radicale/app.py"
    source.write_text("x = 1")
    patch = apply_patch(workspace, [edit()], {"radicale/app.py"})
    source.write_text("x = 1")
    result = subprocess.run(["git", "apply", "-"], input=patch.diff, text=True,
                            capture_output=True, cwd=workspace.root)
    assert result.returncode == 0, result.stderr
    assert source.read_text() == "x = 3"


def test_write_failure_restores_original_files(workspace, monkeypatch):
    other = workspace.root / "radicale/other.py"
    other.write_text("x = 1\n")
    replace = Path.replace

    def fail_second(path, target):
        if Path(target) == other:
            raise OSError("disk failure")
        return replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_second)
    with pytest.raises(PatchRefused):
        apply_patch(workspace, [edit(), edit(path="radicale/other.py")],
                    {"radicale/app.py", "radicale/other.py"})
    assert (workspace.root / "radicale/app.py").read_text() == "x = 1\ny = 2\n"
    assert other.read_text() == "x = 1\n"
