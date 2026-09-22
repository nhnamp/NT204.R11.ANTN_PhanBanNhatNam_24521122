"""Smoke test: the package imports before any module is implemented."""


def test_ids_package_imports() -> None:
    """Fail fast when the package layout or the test path is broken."""
    import ids

    assert ids.__name__ == "ids"
