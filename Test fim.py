"""
Tests for fim.py. Run with:  python -m pytest
(install pytest first with:  pip install pytest)

Each test is a small function whose name starts with "test_".
'assert' means: "this must be true, or the test fails."
pytest gives each test a temporary folder (tmp_path) that is deleted afterwards.
"""

from fim import hash_file, compare, scan_folder


def test_same_file_gives_same_hash(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert hash_file(f) == hash_file(f)


def test_changing_one_character_changes_hash(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    before = hash_file(f)
    f.write_text("hellp")  # one letter different
    assert hash_file(f) != before


def test_compare_finds_modified_new_and_deleted():
    baseline = {
        "a.txt": {"sha256": "1"},
        "b.txt": {"sha256": "2"},
        "c.txt": {"sha256": "3"},
    }
    current = {
        "a.txt": {"sha256": "1"},        # unchanged
        "b.txt": {"sha256": "CHANGED"},  # modified
        "d.txt": {"sha256": "4"},        # new (c.txt is gone = deleted)
    }
    result = compare(baseline, current)
    assert result["modified"] == ["b.txt"]
    assert result["deleted"] == ["c.txt"]
    assert result["new"] == ["d.txt"]


def test_excluded_files_are_skipped(tmp_path):
    (tmp_path / "keep.txt").write_text("keep me")
    (tmp_path / "skip.tmp").write_text("ignore me")
    files, errors = scan_folder(str(tmp_path), ["*.tmp"])
    assert "keep.txt" in files
    assert "skip.tmp" not in files


# TODO (your turn): add a test for an empty folder,
# and one for a file inside a subfolder.