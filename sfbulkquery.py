#!/usr/bin/env python3
"""Bulk query client for Salesforce."""

import argparse
import functools
import json
import logging
import pathlib
import sys
import tempfile
import time
import typing
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer

SESSION_DIR = pathlib.Path(tempfile.gettempdir(), "sfbulk")

logging.basicConfig(format="%(message)s", level=logging.INFO)


class AuthHandler(urllib.request.BaseHandler):
    """Handler for 401 statuses from REST API."""

    def __init__(self) -> None:
        """Initialize Handler."""
        self.retries = 0

    def http_error_401(
        self,
        req: urllib.request.Request,
        fp: typing.BinaryIO,
        code: int,
        msg: str,
        headers: Message,
    ) -> HTTPResponse:
        """Handle 401 responses.

        Args:
            req: request
            fp: file-like object with HTTP error body
            code: HTTP status code
            msg: HTTP status message
            headers: headers

        Returns:
            HTTP Response
        """
        retry = self.retry_auth(req, headers)
        self.retries = 0
        return retry

    def retry_auth(self, req: urllib.request.Request, headers: Message) -> HTTPResponse:
        """Handle retries.

        Args:
            req: request
            headers: headers

        Returns:
            HTTP Response

        Raises:
            HTTPError: If retried more than 5 times
        """
        if self.retries > 5:
            raise urllib.error.HTTPError(
                req.full_url, 401, "Auth failed", dict(headers), None
            )
        else:
            self.retries += 1

        sf_session = session_update()
        req.add_unredirected_header(
            "Authorization", f"Bearer {sf_session.recent_user().session_id}"
        )
        response = self.parent.open(req)
        return response


class SafeOpener(urllib.request.OpenerDirector):
    """A URL opener with configurable set of handlers."""

    def __init__(self, handlers: typing.Iterable = None):
        """
        Instantiate an OpenDirector with selected handlers.

        Args:
            handlers: an Iterable of handler classes
        """
        super().__init__()
        handlers = handlers or (
            urllib.request.UnknownHandler,
            urllib.request.HTTPDefaultErrorHandler,
            urllib.request.HTTPRedirectHandler,
            urllib.request.HTTPSHandler,
            urllib.request.HTTPErrorProcessor,
            AuthHandler,
        )

        for handler_class in handlers:
            handler = handler_class()
            self.add_handler(handler)


opener = SafeOpener()


class Response(typing.NamedTuple):
    """Container for HTTP response."""

    body: str
    headers: Message
    status: int
    url: str

    def json(self) -> typing.Any:
        """
        Decode body's JSON.

        Returns:
            Pythonic representation of the JSON object
        """
        try:
            output = json.loads(self.body)
        except json.JSONDecodeError:
            output = ""
        return output


def request(
    url: str,
    data: dict = None,
    params: dict = None,
    headers: dict = None,
    method: str = "GET",
    data_as_json: bool = True,
    sf_domain: str = None,
) -> Response:
    """
    Perform HTTP request.

    Args:
        url: url to fetch
        data: dict of keys/values to be encoded and submitted
        params: dict of keys/values to be encoded in URL query string
        headers: optional dict of request headers
        method: HTTP method , such as GET or POST
        data_as_json: if True, data will be JSON-encoded
        sf_domain: optional explicit domain

    Returns:
        A dict with headers, body, status code, and, if applicable, object
        rendered from JSON
    """
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json, text/csv", **headers}

    if method == "GET":
        params = {**params, **data}
        data = None

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()

    sf_domain = sf_domain or urllib.parse.urlparse(url).netloc
    sf_session = session_read(sf_domain)
    if sf_session:
        headers["Authorization"] = f"Bearer {sf_session.recent_user().session_id}"

    httprequest = urllib.request.Request(
        url,
        data=request_data,
        headers=headers,
        method=method,
    )

    with opener.open(
        httprequest,
    ) as httpresponse:
        response = Response(
            headers=httpresponse.headers,
            status=httpresponse.status,
            body=httpresponse.read().decode(
                httpresponse.headers.get_content_charset("utf-8")
            ),
            url=httpresponse.url,
        )

    return response


def bookmarklet() -> str:
    """Return the full bookmarklet.

    Returns:
        The contents of the bookmarklet, ready to be installed
    """
    snippet = """(() => {
  let apipath = '/services/data/';
  if (location.pathname === apipath) {
    let sessid = (';' + document.cookie).split('; sid=')[1].split('; ')[0];
    let domain = location.host;
    let output = JSON.stringify([domain, sessid]);
    navigator.clipboard.writeText(output);
  } else {
    window.open(location.origin + apipath, '_blank');
  }
})();"""
    return f"javascript:{snippet}"


def bookmarklet_html() -> str:
    """Return HTML for serving the bookmarklet.

    Returns:
        HTML with instructions and links
    """
    return """
<!DOCTYPE html>
<html>
  <head>
    <title>Salesforce Session ID Bookmarklet</title>
    <script>
      function copyId() {{
          var idField = document.getElementById("marklet");
          idField.select();
          document.execCommand("copy");
      }}
    </script>
  </head>
  <body>
    <h1>Salesforce Session ID Bookmarklet</h1>
    <p>
      Once in your bookmarks, clicking on this bookmarklet while on a Salesforce
      page will first open a new window with the canonical Salesforce domain for
      that org. Clicking again will copy a JSON array to your clipboard,
      consisting of the domain and Salesforce Session Id for the currently
      logged in user.
    </p>
    <h2>The Bookmarklet Link</h2>
    <p>Drag the link below to your bookmarks.</p>
    <a href="{marklet}">SF Session ID</a>
    <h2>The Bookmarklet Code</h2>
    <p>Or copy the text below into a new bookmark.</p>
    <p><input id="marklet" type="text" value="{marklet}" /></p>
    <p><button onclick="copyId()">Copy Bookmarklet</button></p>
    <h2>The code from the bookmarklet, pretty printed:</h2>
    <pre><code>{javascript}</code></pre>
  </body>
</html>
    """


class BookmarkletServer(BaseHTTPRequestHandler):
    """Server for bookmarklet instructions."""

    def do_GET(self) -> None:  # noqa: N802
        """Respond to GET requests with HTML instructions."""
        javascript = bookmarklet()
        marklet = javascript.replace("\n", "").replace("  ", "")
        content = bookmarklet_html().format(marklet=marklet, javascript=javascript)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())


def bookmark_serve(args: argparse.Namespace) -> None:
    """Serve bookmarklet instructions.

    Args:
        args: argparse namespace with address and port
    """
    server = HTTPServer((args.address, args.port), BookmarkletServer)
    server.timeout = args.timeout
    logging.info(f"Go to\nhttp://{args.address}:{args.port}\nto install bookmarklet")
    server.handle_request()


def query(args: argparse.Namespace) -> None:
    """Query Salesforce.

    Args:
        args: argparse namespace with address and port
    """
    print(args.query)


def run(arg_list: list = None) -> None:
    """Process and execute command-line.

    Args:
        arg_list: list of command line arguments
    """
    if not arg_list:
        arg_list = sys.argv[1:]

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-q",
        "--query",
        help="SELECT SOQL query",
        type=str,
    )

    parser.set_defaults(func=query)
    subparsers = parser.add_subparsers(title="Commands available")

    bookmark_help = "Serve instructions for SF Session authentication via bookmarklet"
    bookmark_parser = subparsers.add_parser(
        "bookmark",
        description=bookmark_help,
        help=bookmark_help,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    bookmark_parser.add_argument(
        "-a",
        "--address",
        help="Address from which to serve bookmarklet instructions",
        default="localhost",
        type=str,
    )
    bookmark_parser.add_argument(
        "-p",
        "--port",
        help="Port to use for serving bookmarklet instructions",
        default=8888,
        type=int,
    )
    bookmark_parser.add_argument(
        "-t",
        "--timeout",
        help="Seconds bookmarklet instruction server should wait for browser request",
        default=None,
        type=float,
    )
    bookmark_parser.set_defaults(func=bookmark_serve)
    if not arg_list:
        parser.print_help()
    else:
        args = parser.parse_args(arg_list)
        args.func(args)


class SessionUser(typing.NamedTuple):
    """Session user info."""

    session_id: str
    timestamp: float
    display_name: str = ""
    email: str = ""
    language: str = ""
    locale: str = ""
    phone: str = ""
    timezone: str = ""
    user_id: str = ""
    username: str = ""


class Session(typing.NamedTuple):
    """Session info."""

    domain: str
    rest_url: str
    users: typing.Dict[str, SessionUser]
    endpoints: typing.Mapping[str, str] = {}
    instance: str = ""
    lang_locale: str = ""
    org_id: str = ""
    org_name: str = ""
    org_type: str = ""
    sandbox: bool = False
    timezone: str = ""

    def recent_user(self) -> SessionUser:
        """Get most recent user.

        Returns:
            Recent user info
        """
        return max(self.users.values(), key=lambda u: u.timestamp)


def session_destroy(session_path: pathlib.Path) -> None:
    """Zero fill and delete specified session file.

    Args:
        session_path: path to session file
    """
    with session_path.open("wb") as handle:
        handle.seek(150)
        handle.write(b"\0")
    session_path.unlink()


def session_destroy_all() -> None:
    """Destroy all session files found."""
    for session_path in session_list_all():
        session_destroy(session_path)


def session_file_path(domain: str) -> pathlib.Path:
    """Get path to session file for this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Path to file
    """
    return SESSION_DIR / f"{domain}.session"


@functools.lru_cache(maxsize=None)
def session_endpoints(domain: str) -> dict:
    """Get latest supported endpoint URLs for the given domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        API version string
    """
    url = session_url(domain)
    response = request(url)
    endpoints = response.json()
    for endpoint, endpoint_url in endpoints.items():
        if not endpoint_url.startswith("http"):
            endpoints[endpoint] = f"https://{domain}{endpoint_url}"
    return endpoints


@functools.lru_cache(maxsize=None)
def session_id_info(domain: str) -> dict:
    """Get identity info from this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Dict with identity info
    """
    endpoints = session_endpoints(domain)
    response = request(endpoints["identity"], sf_domain=domain)
    return response.json()


@functools.lru_cache(maxsize=None)
def session_org_info(domain: str) -> dict:
    """Get org info from this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Org info dict
    """
    endpoints = session_endpoints(domain)
    org_id = next(x for x in endpoints["identity"].split("/") if x.startswith("00D"))
    response = request(
        f"{endpoints['sobjects']}/Organization/{org_id}",
        params={
            "fields": "Name,InstanceName,TimeZoneSidKey,"
            "OrganizationType,IsSandbox,LanguageLocaleKey"
        },
    )
    return response.json()


@functools.lru_cache(maxsize=None)
def session_url(domain: str) -> str:
    """Get latest supported API version for the given domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        API data URL
    """
    response = request(f"https://{domain}/services/data/")
    domain = urllib.parse.urlparse(response.url).netloc
    url_path = response.json()[-1]["url"]
    return f"https://{domain}{url_path}"


def session_domain(url: str) -> str:
    """Get canonical API domain from URL.

    Args:
        url: Salesforce org url or domain for API access

    Returns:
        domain string
    """
    if not url.startswith("http"):
        url = f"https://{url}"
    domain = urllib.parse.urlparse(url).netloc
    response = request(f"https://{domain}/services/data/")
    domain = urllib.parse.urlparse(response.url).netloc
    return domain


def session_update(username: str = None) -> Session:
    """Update given session object.

    Args:
        username: optional Salesforce username

    Returns:
        Refreshed Session object
    """
    tmp_user = "placeholder@example.org"
    if not username:
        username = tmp_user
    domain, session_id = session_prompt()
    rest_url = session_url(domain)
    domain = urllib.parse.urlparse(rest_url).netloc
    old_session = session_read(domain)
    if old_session:
        session_dict = old_session._asdict()
        session_dict["users"] = old_session.users
    else:
        session_dict = {"users": {}}
    session_dict["users"][username] = SessionUser(
        session_id=session_id, timestamp=time.time()
    )
    session_dict["domain"] = domain
    session_dict["rest_url"] = rest_url

    skinny_session = Session(**session_dict)
    session_write(skinny_session)

    endpoints = session_endpoints(domain)
    id_info = session_id_info(domain)
    org_info = session_org_info(domain)

    verify_session = session_read(domain)
    if verify_session:
        session_id = verify_session.recent_user().session_id

    session_dict["endpoints"] = endpoints
    session_dict["org_id"] = id_info["organization_id"]
    session_dict["org_name"] = org_info["Name"]

    session_dict["instance"] = org_info["InstanceName"]
    session_dict["timezone"] = org_info["TimeZoneSidKey"]
    session_dict["org_type"] = org_info["OrganizationType"]
    session_dict["sandbox"] = org_info["IsSandbox"]
    session_dict["lang_locale"] = org_info["LanguageLocaleKey"]
    session_dict["users"].pop(tmp_user, None)
    session_dict["users"][id_info["username"]] = SessionUser(
        display_name=id_info["display_name"],
        email=id_info["email"],
        session_id=session_id,
        user_id=id_info["user_id"],
        username=id_info["username"],
        phone=id_info["mobile_phone"],
        language=id_info["language"],
        locale=id_info["locale"],
        timezone=id_info["timezone"],
        timestamp=time.time(),
    )

    session = Session(**session_dict)
    session_write(session)
    return session


@functools.lru_cache(maxsize=None)
def session_read(domain: str) -> typing.Optional[Session]:
    """Get Session ID for this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Session ID
    """
    try:
        with session_file_path(domain).open() as handle:
            session = json.load(handle)
            session["users"] = {
                k: SessionUser(**v) for k, v in session["users"].items()
            }
            session = Session(**session)
    except (FileNotFoundError, json.JSONDecodeError):
        session = None
    return session


def session_latest_domain() -> typing.Optional[str]:
    """Get most recent session file.

    Returns:
        Latest file path
    """
    try:
        recent = max(session_list_all(), key=lambda s: s.stat().st_ctime).stem
    except ValueError:
        recent = None
    return recent


def session_list_all() -> typing.Iterator:
    """List all session files.

    Returns:
        List of file paths
    """
    return SESSION_DIR.glob("*.session")


def session_prompt() -> tuple:
    """Credential entry helper.

    Returns:
        credentials
    """
    credentials_json = input('Enter ["domain", "session_id"]: ')
    domain, session_id = json.loads(credentials_json)
    return domain, session_id


def session_write(session: Session) -> None:
    """Create/update session file with Session ID.

    Args:
        session: Session object
    """
    session_path = session_file_path(session.domain)
    session_dir = session_path.parent
    session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    session_path.touch(mode=0o600, exist_ok=True)
    session_dict = session._asdict()
    session_dict["users"] = {k: v._asdict() for k, v in session.users.items()}
    with session_path.open("w") as handle:
        json.dump(session_dict, handle, indent=2)
    session_read.cache_clear()


if __name__ == "__main__":
    run()
