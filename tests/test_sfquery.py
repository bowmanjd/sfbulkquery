"""Tests for sfbulkquery."""

import pathlib
import runpy
import secrets
import sys
from multiprocessing import Process
from urllib.request import urlopen

import sfbulkquery


def test_bookmarklet_js():
    snippet = pathlib.Path("tests/bookmarklet.js").read_text()
    bookmarklet = f"javascript:{snippet}".strip()
    assert bookmarklet == sfbulkquery.bookmarklet().strip()


def test_bookmarklet_html():
    html = pathlib.Path("tests/bookmarklet.html").read_text().strip()
    assert html == sfbulkquery.bookmarklet_html().strip()


def test_bookmarklet_instructions():
    port = secrets.choice(range(1024, 49151))
    p = Process(target=sfbulkquery.run, args=(["bookmark", "-p", str(port)],))
    p.start()
    p.join(0.5)
    with urlopen(f"http://localhost:{port}") as response:
        html = response.read().decode().strip()
    snippet = pathlib.Path("tests/bookmarklet.js").read_text()
    javascript = f"javascript:{snippet}".strip()
    marklet = javascript.replace("\n", "").replace("  ", "")
    template = pathlib.Path("tests/bookmarklet.html").read_text().strip()
    content = template.format(marklet=marklet, javascript=javascript).strip()
    assert content == html


def test_run_file(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sfbulkquery"])
    runpy.run_module("sfbulkquery", run_name="__main__")
    captured = capsys.readouterr()
    assert "Commands available" in captured.out


def test_query(capsys):
    query = "SELECT Id FROM Contact LIMIT 5"
    sfbulkquery.run(["-q", query])
    captured = capsys.readouterr()
    assert query in captured.out
