"""Tests for sfbulkquery."""

import pathlib
import runpy
import secrets
import sys
from multiprocessing import Process
from urllib.request import urlopen

import sfbulkquery


def gen_session_id():
    org_id = secrets.token_urlsafe(15)
    part1 = secrets.token_urlsafe(41)
    part2 = secrets.token_urlsafe(53)
    return f"{org_id}!{part1}.{part2}"


def gen_domain():
    return secrets.token_urlsafe(secrets.randbelow(40)) + ".my.salesforce.com"


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


def test_latest_session_and_destroy():
    domain = gen_domain()
    session_id = gen_session_id()
    sfbulkquery.session_write(domain, session_id)
    session_path = sfbulkquery.session_file_path(domain)
    assert session_path.exists()
    new_domain = sfbulkquery.session_latest_domain()
    new_session_id = sfbulkquery.session_read(new_domain)
    sfbulkquery.session_destroy(session_path)
    assert not session_path.exists()
    assert domain == new_domain
    assert session_id == new_session_id


def test_destroy_all_sessions():
    for _ in range(secrets.randbelow(100)):
        sfbulkquery.session_write(gen_domain(), gen_session_id())
    assert len(tuple(sfbulkquery.session_list_all()))
    sfbulkquery.session_destroy_all()
    assert not len(tuple(sfbulkquery.session_list_all()))


def test_latest_session_none():
    sfbulkquery.session_destroy_all()
    new_domain = sfbulkquery.session_latest_domain()
    assert not new_domain


def test_query(capsys):
    query = "SELECT Id FROM Contact LIMIT 5"
    sfbulkquery.run(["-q", query])
    captured = capsys.readouterr()
    assert query in captured.out
