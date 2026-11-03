from pathlib import Path

from ip_analyser.disk_usage import analyze_path, format_bytes


def test_analyze_path_counts_nested_content(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "small.txt").write_bytes(b"a" * 10)
    (nested / "large.bin").write_bytes(b"b" * 30)

    result = analyze_path(tmp_path, max_files=100)

    assert result.total_size == 40
    assert result.file_count == 2
    assert result.folder_count == 2
    assert result.largest_files[0].path.name == "large.bin"
    assert result.folders[0].path == tmp_path.resolve()
    nested_row = next(folder for folder in result.folders if folder.path.name == "nested")
    assert nested_row.size == 30
    assert nested_row.files == 1


def test_analyze_path_respects_file_limit(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text(str(index), encoding="utf-8")

    result = analyze_path(tmp_path, max_files=2)

    assert result.file_count == 2
    assert result.limited is True


def test_format_bytes_is_human_readable() -> None:
    assert format_bytes(0) == "0 B"
    assert format_bytes(1536) == "1.5 KB"
