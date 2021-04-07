"""Tests for sfbulkquery."""

import io
import json
import pathlib
import runpy
import secrets
import sys
import time
import typing
import urllib.error
from multiprocessing import Process
from urllib.request import urlopen

import pytest

import sfbulkquery

FAKE_MYDOMAIN = "fake-dev-ed"
FAKE_DOMAIN = f"{FAKE_MYDOMAIN}.my.salesforce.com"
FAKE_SESSION_ID = "00D7f111111tgVe!ZHz2ibKYjcbg10mT9TmqJY7gIipNcE6GUAvDXVwlX0YrrWOz_XPVM68.v_sNvAcM_l-I9masbK6lMy1W8VGd5Z9nw2BYfdPFkgVIWlj_hWZyjF09V-JOAnn1w16qNvQ"  # noqa: E501
FAKE_ORG_ID = "00D7f111111tgVeRBP"
FAKE_USER_ID = "0054a101010TkPiJJB"
FAKE_NAME = "Sylvester Green"
FAKE_EMAIL = "sgreen@example.org"
FAKE_PHONE = "5555551234"


class SFSession(typing.NamedTuple):
    domain: str
    session_id: str


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


@pytest.fixture(scope="module")
def sf_global_session(vcr):
    if vcr.record_mode == "none":
        domain = FAKE_DOMAIN
        session_id = FAKE_SESSION_ID
    else:
        domain, session_id = sfbulkquery.session_prompt()
    return SFSession(domain, session_id)


def sanitize_cassette(content, sf_session):
    new_content = content.replace(
        sf_session.domain.split(".")[0], FAKE_MYDOMAIN
    ).replace(sf_session.session_id, FAKE_SESSION_ID)
    session = sfbulkquery.session_read(sf_session.domain)
    if session:
        user = session.recent_user()
        if user.user_id:
            new_content = new_content.replace(user.user_id, FAKE_USER_ID)
        if session.org_id:
            new_content = new_content.replace(session.org_id, FAKE_ORG_ID)
        if user.username:
            new_content = new_content.replace(user.username, FAKE_EMAIL)
            new_content = new_content.replace(
                user.username.split("@")[0], FAKE_EMAIL.split("@")[0]
            )
        if user.phone:
            new_content = new_content.replace(user.phone[-10:], FAKE_PHONE)
        if user.display_name:
            new_first, new_last = FAKE_NAME.split(" ")
            first_last = user.display_name.split(" ")
            new_content = new_content.replace(first_last[0], new_first)
            new_content = new_content.replace(first_last[-1], new_last)
    return new_content


@pytest.fixture()
def sf_session(sf_global_session, vcr_cassette):
    sfbulkquery.session_read.cache_clear()
    sfbulkquery.session_endpoints.cache_clear()
    sfbulkquery.session_id_info.cache_clear()
    sfbulkquery.session_org_info.cache_clear()
    yield sf_global_session
    if vcr_cassette.play_count == 0:
        vcr_cassette._save()
        cassette_path = pathlib.Path(vcr_cassette._path)
        if cassette_path.exists():
            content = cassette_path.read_text()
            new_content = sanitize_cassette(content, sf_global_session)
            cassette_path.write_text(new_content)
    sfbulkquery.session_destroy_all()


def test_session_domain(sf_session):
    assert sf_session.domain == sfbulkquery.session_domain(sf_session.domain)


def test_session_domain_url(sf_session):
    mydomain = sf_session.domain.split(".")[0]
    url = f"https://{mydomain}.lightning.force.com/lightning/setup/SetupOneHome/home"
    assert sf_session.domain == sfbulkquery.session_domain(url)


def test_session_update(sf_session, monkeypatch):
    user_input = io.StringIO(json.dumps([sf_session.domain, sf_session.session_id]))
    monkeypatch.setattr("sys.stdin", user_input)
    session = sfbulkquery.session_update()
    sample_session = new_session(
        FAKE_MYDOMAIN,
        FAKE_SESSION_ID,
        FAKE_ORG_ID,
        FAKE_USER_ID,
        FAKE_EMAIL,
        session.recent_user().timestamp,
    )
    assert session == sample_session


def test_session_update_invalid(sf_session, monkeypatch):
    bad_try = json.dumps([sf_session.domain, "bad_session"])
    good_try = json.dumps([sf_session.domain, sf_session.session_id])
    user_input = io.StringIO(f"{bad_try}\n{good_try}")
    monkeypatch.setattr("sys.stdin", user_input)
    session = sfbulkquery.session_update()
    assert session.domain == sf_session.domain
    assert session.recent_user().session_id == sf_session.session_id


def test_session_id_repeatedly_invalid(sf_session, monkeypatch):
    bad_try = json.dumps([sf_session.domain, "bad_session"])
    user_input = io.StringIO()
    user_input.writelines([f"{bad_try}\n"] * 7)
    user_input.seek(0)
    monkeypatch.setattr("sys.stdin", user_input)
    with pytest.raises(urllib.error.HTTPError) as e:
        sfbulkquery.session_org_info(sf_session.domain)
    assert e.value.code == 401


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
