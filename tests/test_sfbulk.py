"""Tests for sfbulk."""

import io
import json
import pathlib
import re
import runpy
import secrets
import sys
import tempfile
import time
import typing
import urllib.error
from email.message import Message
from multiprocessing import Process
from urllib.request import urlopen

import pytest

import sfbulk

FAKE_MYDOMAIN = "fake-dev-ed"
FAKE_DOMAIN = f"{FAKE_MYDOMAIN}.my.salesforce.com"
FAKE_SESSION_ID = "00D7f111111tgVe!ZHz2ibKYjcbg10mT9TmqJY7gIipNcE6GUAvDXVwlX0YrrWOz_XPVM68.v_sNvAcM_l-I9masbK6lMy1W8VGd5Z9nw2BYfdPFkgVIWlj_hWZyjF09V-JOAnn1w16qNvQ"  # noqa: E501
FAKE_ORG_ID = "00D7f111111tgVeRBP"
FAKE_USER_ID = "0054a101010TkPiJJB"
FAKE_NAME = "Sylvester Green"
FAKE_EMAIL = "sgreen@example.org"
FAKE_PHONE = "+1 5555551234"
FAKE_COMPANY = "Green Endeavors"


class SFSession(typing.NamedTuple):
    domain: str
    session_id: str


def new_session(**kwargs):
    template = pathlib.Path("tests/sample_session.json").read_text()
    raw = template.format(**kwargs)
    session_dict = json.loads(raw)
    session_dict["users"] = {
        k: sfbulk.SessionUser(**v) for k, v in session_dict["users"].items()
    }
    return sfbulk.Session(**session_dict)


def gen_session():
    org_id = f"00D{secrets.token_urlsafe(15)}"
    session_dict = {
        "org_id": org_id,
        "user_id": f"005{secrets.token_urlsafe(15)}",
        "mydomain": secrets.token_urlsafe(secrets.randbelow(40)),
        "username": secrets.token_urlsafe(8) + "@example.org",
        "display_name": " ".join([secrets.token_urlsafe(7), secrets.token_urlsafe(10)]),
        "company": " ".join([secrets.token_urlsafe(10), secrets.token_urlsafe(3)]),
        "phone": "+1 " + "".join(str(secrets.randbelow(10)) for _ in range(10)),
        "timestamp": time.time(),
        "session_id": (
            f"{org_id[:15]}!{secrets.token_urlsafe(41)}.{secrets.token_urlsafe(53)}"
        ),
    }

    return new_session(**session_dict)


@pytest.fixture(scope="module")
def sf_global_session(vcr):
    if vcr.record_mode == "none":
        domain = FAKE_DOMAIN
        session_id = FAKE_SESSION_ID
    else:
        domain, session_id = sfbulk.session_prompt()
    return SFSession(domain, session_id)


def sanitize_cassette(content, sf_session):
    new_content = content.replace(
        sf_session.domain.split(".")[0], FAKE_MYDOMAIN
    ).replace(sf_session.session_id, FAKE_SESSION_ID)
    session = sfbulk.session_read(sf_session.domain)
    if session:
        if session.org_name:
            pattern = session.org_name.replace(" ", r"\s+")
            new_content = re.sub(pattern, FAKE_COMPANY, new_content)
        user = session.recent_user()
        if user.user_id:
            new_content = new_content.replace(user.user_id, FAKE_USER_ID)
        if session.org_id:
            new_content = new_content.replace(session.org_id, FAKE_ORG_ID)
            new_content = new_content.replace(session.org_id[:15], FAKE_ORG_ID[:15])
        if user.email:
            new_content = new_content.replace(user.email, FAKE_EMAIL)
        if user.username:
            new_content = new_content.replace(user.username, FAKE_EMAIL)
            new_content = new_content.replace(
                user.username.split("@")[0], FAKE_EMAIL.split("@")[0]
            )
        if user.phone:
            new_content = new_content.replace(user.phone[-10:], FAKE_PHONE[-10:])
        if user.display_name:
            new_first, new_last = FAKE_NAME.split(" ")
            first_last = user.display_name.split(" ")
            new_content = new_content.replace(first_last[0], new_first)
            new_content = new_content.replace(first_last[-1], new_last)
    return new_content


@pytest.fixture()
def sf_session(sf_global_session, vcr_cassette):
    sfbulk.session_read.cache_clear()
    sfbulk.session_endpoints.cache_clear()
    sfbulk.session_id_info.cache_clear()
    sfbulk.session_org_info.cache_clear()
    yield sf_global_session
    if vcr_cassette.play_count == 0:
        vcr_cassette._save()
        cassette_path = pathlib.Path(vcr_cassette._path)
        if cassette_path.exists():
            content = cassette_path.read_text()
            new_content = sanitize_cassette(content, sf_global_session)
            cassette_path.write_text(new_content)
    sfbulk.session_destroy_all()


def test_session_domain(sf_session):
    assert sf_session.domain == sfbulk.session_domain(sf_session.domain)


def test_session_domain_url(sf_session):
    mydomain = sf_session.domain.split(".")[0]
    url = f"https://{mydomain}.lightning.force.com/lightning/setup/SetupOneHome/home"
    assert sf_session.domain == sfbulk.session_domain(url)


def test_session_update(sf_session, monkeypatch):
    user_input = io.StringIO(json.dumps([sf_session.domain, sf_session.session_id]))
    monkeypatch.setattr("sys.stdin", user_input)
    session = sfbulk.session_update()
    sample_session = new_session(
        mydomain=FAKE_MYDOMAIN,
        session_id=FAKE_SESSION_ID,
        org_id=FAKE_ORG_ID,
        user_id=FAKE_USER_ID,
        username=FAKE_EMAIL,
        display_name=FAKE_NAME,
        phone=FAKE_PHONE,
        company=FAKE_COMPANY,
        timestamp=session.recent_user().timestamp,
    )
    assert session.domain == sf_session.domain
    assert session.recent_user().session_id == sf_session.session_id
    if sf_session.domain == FAKE_DOMAIN:
        assert session == sample_session


def test_session_update_invalid(sf_session, monkeypatch):
    bad_try = json.dumps([sf_session.domain, "bad_session"])
    good_try = json.dumps([sf_session.domain, sf_session.session_id])
    user_input = io.StringIO(f"{bad_try}\n{good_try}")
    monkeypatch.setattr("sys.stdin", user_input)
    session = sfbulk.session_update()
    assert session.domain == sf_session.domain
    assert session.recent_user().session_id == sf_session.session_id


def test_session_id_repeatedly_invalid(sf_session, monkeypatch):
    bad_try = json.dumps([sf_session.domain, "bad_session"])
    user_input = io.StringIO()
    user_input.writelines([f"{bad_try}\n"] * 7)
    user_input.seek(0)
    monkeypatch.setattr("sys.stdin", user_input)
    with pytest.raises(urllib.error.HTTPError) as e:
        sfbulk.session_org_info(sf_session.domain)
    assert e.value.code == 401


def test_bookmarklet_js():
    snippet = pathlib.Path("tests/bookmarklet.js").read_text()
    bookmarklet = f"javascript:{snippet}".strip()
    assert bookmarklet == sfbulk.bookmarklet().strip()


def test_bookmarklet_html():
    html = pathlib.Path("tests/bookmarklet.html").read_text().strip()
    assert html == sfbulk.bookmarklet_html().strip()


def test_bookmarklet_instructions():
    port = secrets.choice(range(1024, 49151))
    p = Process(target=sfbulk.run, args=(["bookmark", "-p", str(port)],))
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
    monkeypatch.setattr(sys, "argv", ["sfbulk"])
    runpy.run_module("sfbulk", run_name="__main__")
    captured = capsys.readouterr()
    assert "Commands available" in captured.out


def test_latest_session_and_destroy():
    sfbulk.session_destroy_all()
    session = gen_session()
    sfbulk.session_write(session)
    session_path = sfbulk.session_file_path(session.domain)
    assert session_path.exists()
    new_domain = sfbulk.session_latest_domain()
    new_session = sfbulk.session_read(new_domain)
    sfbulk.session_destroy(session_path)
    assert not session_path.exists()
    assert session.domain == new_domain
    assert session.recent_user().session_id == new_session.recent_user().session_id


def test_destroy_all_sessions():
    for _ in range(secrets.randbelow(100)):
        sfbulk.session_write(gen_session())
    assert len(tuple(sfbulk.session_list_all()))
    sfbulk.session_destroy_all()
    assert not len(tuple(sfbulk.session_list_all()))


def test_latest_session_none():
    sfbulk.session_destroy_all()
    new_domain = sfbulk.session_latest_domain()
    assert not new_domain


def test_read_session_nonexistent_domain():
    sfbulk.session_destroy_all()
    assert sfbulk.session_read("nonexistent.my.salesforce.com") is None


def test_session_prompt(monkeypatch):
    session = gen_session()
    user_input = io.StringIO(
        json.dumps([session.domain, session.recent_user().session_id])
    )
    monkeypatch.setattr("sys.stdin", user_input)
    new_domain, new_session_id = sfbulk.session_prompt()
    sfbulk.session_destroy_all()
    assert session.domain == new_domain
    assert session.recent_user().session_id == new_session_id


def test_query(sf_session, monkeypatch):
    query = "SELECT Id, Name FROM Contact LIMIT 5"
    credentials = json.dumps([sf_session.domain, sf_session.session_id])
    user_input = io.StringIO(f"{credentials}\n")
    monkeypatch.setattr("sys.stdin", user_input)
    temp_path = pathlib.Path(tempfile.gettempdir(), "sfbulktest") / "query.csv"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    sfbulk.run(["query", "-o", str(temp_path), query])
    # assert "JobComplete" in captured.out
    assert '"Id","Name"' in temp_path.read_text()


def test_response_not_json():
    response = sfbulk.Response(
        "This is not JSON", Message(), 200, "https://example.org"
    )
    assert response.json() == ""
