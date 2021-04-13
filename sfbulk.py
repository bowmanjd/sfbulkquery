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
    json_data: dict = None,
    text_data: str = None,
    params: dict = None,
    headers: dict = None,
    method: str = "GET",
    data_type: str = "application/json; charset=UTF-8",
    sf_domain: str = None,
) -> Response:
    """
    Perform HTTP request.

    Args:
        url: url to fetch
        json_data: dict of keys/values to be encoded and submitted
        text_data: unicode string to be encoded and submitted
        params: dict of keys/values to be encoded in URL query string
        headers: optional dict of request headers
        method: HTTP method , such as GET or POST
        data_type: content type for uploaded data
        sf_domain: optional explicit domain

    Returns:
        A dict with headers, body, status code, and, if applicable, object
        rendered from JSON
    """
    method = method.upper()
    headers = headers or {}
    params = params or {}
    headers = {"Accept": "application/json, text/csv", **headers}

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    request_data = None

    if json_data or text_data:
        headers["Content-Type"] = data_type

    if json_data:
        request_data = json.dumps(json_data).encode()
    elif text_data:
        request_data = text_data.encode()

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


@functools.lru_cache(maxsize=None)
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


def session_update(
    domain: str = None, session_id: str = None, username: str = None
) -> Session:
    """Update given session object.

    Args:
        domain: Salesforce API domain
        session_id: Salesforce session ID
        username: optional Salesforce username

    Returns:
        Refreshed Session object
    """
    tmp_user = "placeholder@example.org"
    if not username:
        username = tmp_user
    if not (domain and session_id):
        domain, session_id = session_prompt()
    session_id = session_id or ""
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
    """Retrieve Session for this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Session or None if not found
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


def session_obtain(url: str = None, session_id: str = None) -> Session:
    """Retrieve or create Session for this domain.

    Args:
        url: Salesforce org url or domain for API access

    Returns:
        Session
    """
    session = None
    if not url:
        session = session_update()
    else:
        domain = session_domain(url)
        session = session_read(domain)
        if not session:
            session = session_update(domain, session_id)
        if session.domain != domain:
            logging.warning("Warning: requested domain has changed")
            logging.warning(f"Originally requested: {domain}")
            logging.warning(
                f"This will be overridden by newly requested {session.domain}"
            )
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


def sf_request(
    domain: str,
    endpoint: str,
    path: str,
    json_data: dict = None,
    text_data: str = None,
    params: dict = None,
    data_type: str = "application/json; charset=UTF-8",
    method: str = "GET",
) -> Response:
    """Salesforce REST API request.

    Args:
        domain: Salesforce domain for API access
        endpoint: specific key for endpoint
        path: remaining path after endpoint
        json_data: optional dict of keys/values for request
        text_data: optional text data
        params: optional dict of keys/values to be encoded in URL query string
        data_type: content type for uploaded data
        method: HTTP method , such as GET or POST

    Returns:
        Response object
    """
    session = session_obtain(domain)
    endpoint = session.endpoints[endpoint]
    url = "/".join((endpoint, path))
    return request(
        url, json_data=json_data, text_data=text_data, params=params, method=method
    )


def job_create(
    domain: str,
    operation: str = "query",
    sf_object: str = None,
    query: str = None,
    line_ending: str = "CRLF",
) -> str:
    """Query Salesforce.

    Args:
        domain: Salesforce domain for API access
        operation: query, insert, update, upsert, delete, or hardDelete
        sf_object: Salesforce object name, such as Contact
        query: SOQL query string
        line_ending: CRLF or LF

    Returns:
        Job ID

    Raises:
        ValueError: if operation does not have query or object specified as appropriate
    """
    session = session_obtain(domain)
    request_body = {"operation": operation, "lineEnding": line_ending}
    if operation == "query" and query:
        request_body["query"] = query
        job_type = "query"
    elif sf_object:
        request_body["object"] = sf_object
        job_type = "ingest"
    else:
        raise ValueError(
            "Job must be a query operation with query specified, "
            "or other operation with object specified."
        )

    response = sf_request(
        session.domain, "jobs", job_type, json_data=request_body, method="POST"
    )
    submission_response = response.json()
    return submission_response["id"]


def job_status(domain: str, job_id: str, job_type: str = "query") -> str:
    """Get status of Bulk Job.

    Args:
        domain: Salesforce domain for API access
        job_id: Bulk Job ID
        job_type: query or ingest

    Returns:
        Job status
    """
    session = session_obtain(domain)
    response = sf_request(session.domain, "jobs", f"{job_type}/{job_id}")
    return response.json()["state"]


def job_upload(domain: str, job_id: str, content: str) -> None:
    """Upload CSV content.

    Args:
        domain: Salesforce domain for API access
        job_id: Bulk Job ID
        content: CSV string
    """
    session = session_obtain(domain)
    response = sf_request(
        session.domain,
        "jobs",
        f"ingest/{job_id}/batches/",
        text_data=content,
        data_type="text/csv",
        method="PUT",
    )


def job_wait(
    domain: str,
    job_id: str,
    job_type: str = "query",
    timeout: int = 60,
) -> str:
    """Get status of Bulk Job.

    Args:
        domain: Salesforce domain for API access
        job_id: Bulk Job ID
        job_type: query or ingest
        timeout: Number of seconds to wait for job to complete, polling for status

    Returns:
        Job status
    """
    session = session_obtain(domain)
    start_time = time.time()
    while int(time.time() - start_time) <= timeout:
        status = job_status(session.domain, job_id)
        logging.info(f"Job status: {status}")
        if status == "JobComplete" or timeout == 0:
            break
        time.sleep(0.5)
    return status


def results(
    domain: str,
    job_id: str,
) -> str:
    """Get results of Bulk Job.

    Args:
        domain: Salesforce domain for API access
        job_id: Bulk Job ID

    Returns:
        Job result body
    """
    session = session_obtain(domain)
    response = sf_request(session.domain, "jobs", f"query/{job_id}/results")
    return response.body


def query_cmd(args: argparse.Namespace) -> None:
    """Query Salesforce.

    Args:
        args: argparse namespace with domain, output filename, and timeout
    """
    session = session_obtain(args.domain, args.session)
    job_id = job_create(session.domain, query=args.query)
    status = job_wait(session.domain, job_id, args.timeout)
    logging.info(f"Status for job {job_id}: {status}")
    if status == "JobComplete":
        args.output.write(results(session.domain, job_id).encode("utf-8-sig"))
        logging.info(f"Saved file to {args.output.name}")


def api_cmd(args: argparse.Namespace) -> None:
    """Perform API request from command line.

    Args:
        args: argparse namespace with domain, object, operation, and timeout
    """
    session = session_obtain(args.domain)
    params = {
        "domain": session.domain,
        "endpoint": args.endpoint,
        "path": args.path,
        "method": args.method,
    }
    if not args.input.isatty():
        params["text_data"] = args.input.read()

    response = sf_request(**params)
    sys.stdout.write(response.body)


def upload_cmd(args: argparse.Namespace) -> None:
    """Upload data to Salesforce.

    Args:
        args: argparse namespace with domain, object, operation, and timeout
    """
    session = session_obtain(args.domain)
    job_id = job_create(session.domain, sf_object=args.object, operation=args.operation)
    status = job_wait(session.domain, job_id, job_type="ingest", timeout=args.timeout)
    logging.info(f"Status for job {job_id}: {status}")
    if status == "JobComplete":
        args.output.write(results(session.domain, job_id).encode("utf-8-sig"))
        logging.info(f"Saved file to {args.output.name}")


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
    request_parser = argparse.ArgumentParser(add_help=False)
    request_parser.add_argument(
        "-d",
        "--domain",
        default=None,
        help="Salesforce instance domain for API access",
        type=str,
    )
    request_parser.add_argument(
        "-s",
        "--session",
        default=None,
        help="Salesforce session ID",
        type=str,
    )
    request_parser.add_argument(
        "-t",
        "--timeout",
        default=60,
        help="Time in seconds to wait for job to finish before quitting",
        type=int,
    )

    request_parser.add_argument(
        "-o",
        "--output",
        default=sys.stdout.buffer,
        help="Output filename",
        nargs="?",
        type=argparse.FileType("wb"),
    )
    request_parser.add_argument(
        "-i",
        "--input",
        default=sys.stdin.buffer,
        help="Input filename",
        nargs="?",
        type=argparse.FileType("rb"),
    )

    subparsers = parser.add_subparsers(title="Commands available")

    api_help = "Send/receive data from designated API endpoint"
    api_parser = subparsers.add_parser(
        "api",
        description=api_help,
        help=api_help,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[request_parser],
    )
    api_parser.add_argument(
        "-e",
        "--endpoint",
        help="the endpoint name",
        default="jobs",
        type=str,
    )
    api_parser.add_argument(
        "-p",
        "--path",
        help="additional url path, after the endpoint name",
        type=str,
    )
    api_parser.add_argument(
        "-m",
        "--method",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
        help="HTTP method",
        default="GET",
        type=str,
    )
    api_parser.set_defaults(func=api_cmd)

    query_help = "Query objects and fields using SOQL or SOSL"
    query_parser = subparsers.add_parser(
        "query",
        description=query_help,
        help=query_help,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[request_parser],
    )
    query_parser.add_argument(
        "query",
        help="The SELECT query to use",
        type=str,
    )
    query_parser.set_defaults(func=query_cmd)

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


if __name__ == "__main__":
    run()
