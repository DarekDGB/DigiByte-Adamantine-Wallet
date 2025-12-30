def test_runtime_package_import_is_lightweight():
    # Importing the package must not trigger orchestrator/WSQK circular imports.
    import core.runtime  # noqa: F401
