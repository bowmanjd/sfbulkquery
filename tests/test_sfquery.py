"""Tests for sfquery."""

import sfquery


def test_version():
    assert "navigator.clipboard" in sfquery.bookmarklet()
