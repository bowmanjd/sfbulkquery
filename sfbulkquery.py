#!/usr/bin/env python3
"""Bulk query client for Salesforce."""
import argparse
import json
import pathlib
import sys
import tempfile
import typing
from http.server import BaseHTTPRequestHandler, HTTPServer

SESSION_DIR = pathlib.Path(tempfile.gettempdir(), "sfbulk")


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
    print(f"Go to\nhttp://{args.address}:{args.port}\nto install bookmarklet")
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


def session_destroy(session_path: pathlib.Path) -> None:
    """Zero fill and delete specified session file.

    Args:
        session_path: path to session file
    """
    with session_path.open("wb") as handle:
        handle.seek(150)
        handle.write(b"\0")
    session_path.unlink(True)


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


def session_obtain(domain: str = None) -> tuple:
    """Get login ID and key from file or prompt.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Tuple of API Login ID and Transaction Key
    """
    if not domain:
        domain = session_latest_domain()

    if domain:
        try:
            session_id = session_read(domain)
        except FileNotFoundError:
            domain = None

    if not domain:
        new_domain, session_id = session_prompt()
        session_write(new_domain, session_id)
        domain = new_domain
    return domain, session_id


def session_read(domain: str) -> str:
    """Get Session ID for this domain.

    Args:
        domain: Salesforce domain for API access

    Returns:
        Session ID
    """
    return session_file_path(domain).read_text()


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


def session_write(domain: str, session_id: str) -> None:
    """Create/update session file with Session ID.

    Args:
        domain: Salesforce domain for API access
        session_id: the Salesforce Session ID to be recorded
    """
    session_path = session_file_path(domain)
    session_dir = session_path.parent
    session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    session_path.touch(mode=0o600, exist_ok=True)
    session_path.write_text(session_id)


if __name__ == "__main__":
    run()
