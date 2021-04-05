"""Tests for sfbulkquery."""

import io
import json
import pathlib
import runpy
import secrets
import sys
import time
from multiprocessing import Process
from urllib.request import urlopen

import pytest

import sfbulkquery

FAKE_DOMAIN = "fake-dev-ed.my.salesforce.com"
FAKE_SESSION_ID = "00D7f111111tgVe!ZHz2ibKYjcbg10mT9TmqJY7gIipNcE6GUAvDXVwlX0YrrWOz_XPVM68.v_sNvAcM_l-I9masbK6lMy1W8VGd5Z9nw2BYfdPFkgVIWlj_hWZyjF09V-JOAnn1w16qNvQ"  # noqa: E501
FAKE_ORG_ID = "00D7f111111tgVeRBP"
FAKE_USER_ID = "0054a101010TkPiJJB"
DOMAIN = "devhub-bowmanjd-dev-ed.my.salesforce.com"


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "filter_headers": [("Authorization", f"Bearer {FAKE_SESSION_ID}")],
    }


def new_session(mydomain, session_id, org_id, user_id, username, timestamp):
    template = pathlib.Path("tests/sample_session.json").read_text()
    raw = template.format(
        mydomain=mydomain,
        session_id=session_id,
        org_id=org_id,
        user_id=user_id,
        username=username,
        timestamp=timestamp,
    )
    session_dict = json.loads(raw)
    session_dict["users"] = {
        k: sfbulkquery.SessionUser(**v) for k, v in session_dict["users"].items()
    }
    return sfbulkquery.Session(**session_dict)


def gen_session():
    org_id = f"00D{secrets.token_urlsafe(15)}"
    user_id = f"005{secrets.token_urlsafe(15)}"
    mydomain = secrets.token_urlsafe(secrets.randbelow(40))
    username = secrets.token_urlsafe(8) + "@example.org"
    timestamp = time.time()
    part_1 = secrets.token_urlsafe(41)
    part_2 = secrets.token_urlsafe(53)
    session_id = f"{org_id[:15]}!{part_1}.{part_2}"
    return new_session(mydomain, session_id, org_id, user_id, username, timestamp)


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
    sfbulkquery.session_destroy_all()
    session = gen_session()
    sfbulkquery.session_write(session)
    session_path = sfbulkquery.session_file_path(session.domain)
    assert session_path.exists()
    new_domain = sfbulkquery.session_latest_domain()
    new_session = sfbulkquery.session_read(new_domain)
    sfbulkquery.session_destroy(session_path)
    assert not session_path.exists()
    assert session.domain == new_domain
    assert session.recent_user().session_id == new_session.recent_user().session_id


def test_destroy_all_sessions():
    for _ in range(secrets.randbelow(100)):
        sfbulkquery.session_write(gen_session())
    assert len(tuple(sfbulkquery.session_list_all()))
    sfbulkquery.session_destroy_all()
    assert not len(tuple(sfbulkquery.session_list_all()))


def test_latest_session_none():
    sfbulkquery.session_destroy_all()
    new_domain = sfbulkquery.session_latest_domain()
    assert not new_domain


def test_read_session_nonexistent_domain():
    sfbulkquery.session_destroy_all()
    assert sfbulkquery.session_read("nonexistent.my.salesforce.com") is None


def test_session_prompt(monkeypatch):
    session = gen_session()
    user_input = io.StringIO(
        json.dumps([session.domain, session.recent_user().session_id])
    )
    monkeypatch.setattr("sys.stdin", user_input)
    new_domain, new_session_id = sfbulkquery.session_prompt()
    sfbulkquery.session_destroy_all()
    assert session.domain == new_domain
    assert session.recent_user().session_id == new_session_id


def test_query(capsys):
    query = "SELECT Id FROM Contact LIMIT 5"
    sfbulkquery.run(["-q", query])
    captured = capsys.readouterr()
    assert query in captured.out
