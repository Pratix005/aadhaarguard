import io
import json
import sys

from aadhaarguard.cli import main

SAMPLE = "Customer PAN ABCPE1234F\nphone +91 98765 43210\n"


def run(monkeypatch, capsys, argv, stdin=""):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_stdin_masks_by_default(monkeypatch, capsys):
    code, out, err = run(monkeypatch, capsys, ["scan"], SAMPLE)
    assert code == 1
    assert "<stdin>:1:14: pan XXXXXX234F" in out
    assert "<stdin>:2:7: phone" in out
    assert "ABCPE1234F" not in out
    assert "2 finding(s)" in err


def test_scan_show(monkeypatch, capsys):
    _, out, _ = run(monkeypatch, capsys, ["scan", "--show"], SAMPLE)
    assert "ABCPE1234F" in out


def test_scan_clean_exit_zero(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["scan"], "nothing to see")
    assert code == 0 and out == ""


def test_scan_json(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["scan", "--json", "--kinds", "pan"], SAMPLE)
    data = json.loads(out)
    assert code == 1 and [d["kind"] for d in data] == ["pan"]
    assert data[0]["line"] == 1


def test_scan_directory_skips_binary_and_git(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.txt").write_text(SAMPLE, encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"\0\0PAN ABCPE1234F")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "c.txt").write_text(SAMPLE, encoding="utf-8")
    code, out, _ = run(monkeypatch, capsys, ["scan", str(tmp_path)])
    assert code == 1
    assert "a.txt" in out and "b.bin" not in out and ".git" not in out


def test_redact_file_output(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    dst = tmp_path / "out.txt"
    src.write_text(SAMPLE, encoding="utf-8")
    code, _, _ = run(monkeypatch, capsys, ["redact", str(src), "-o", str(dst)])
    assert code == 0
    assert dst.read_text(encoding="utf-8") == "Customer PAN [PAN]\nphone [PHONE]\n"


def test_redact_in_place(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    src.write_text(SAMPLE, encoding="utf-8")
    run(monkeypatch, capsys, ["redact", str(src), "-i", "--style", "partial"])
    assert "XXXXXX234F" in src.read_text(encoding="utf-8")


def test_redact_stdin(monkeypatch, capsys):
    _, out, _ = run(monkeypatch, capsys, ["redact", "--style", "mask"], "PAN ABCPE1234F")
    assert out == "PAN XXXXXXXXXX"


def test_unknown_kind(monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys, ["scan", "--kinds", "nope"], SAMPLE)
    assert code == 2 and "unknown kind" in err


def test_kinds_list(monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, ["kinds"])
    assert code == 0 and "aadhaar" in out and "needs keyword" in out


def test_ignore_case_flag(monkeypatch, capsys):
    code, _, _ = run(monkeypatch, capsys, ["scan"], "pan abcpe1234f")
    assert code == 0
    code, _, _ = run(monkeypatch, capsys, ["scan", "-I"], "pan abcpe1234f")
    assert code == 1
