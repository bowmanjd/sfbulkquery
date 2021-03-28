#!/usr/bin/env python3
"""Bulk query client for Salesforce."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


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


def serve_bookmark(args: argparse.Namespace) -> None:
    """Serve bookmarklet instructions.

    Args:
        args: argparse namespace with address and port
    """
    server = HTTPServer((args.address, args.port), BookmarkletServer)
    print(f"Go to\nhttp://{args.address}:{args.port}\nto install bookmarklet")
    server.handle_request()


def query(args: argparse.Namespace) -> None:
    """Query Salesforce.

    Args:
        args: argparse namespace with address and port
    """
    print(args)


def run() -> None:
    """Process and execute command-line."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
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
    bookmark_parser.set_defaults(func=serve_bookmark)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    run()
