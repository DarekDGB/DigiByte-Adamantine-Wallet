def test_public_api_exports_exist():
    # EQC public imports should always work
    from core.eqc import EQCEngine, EQCContext, VerdictType, EQCDecision  # noqa: F401

    # WSQK public imports should always work (runtime depends on these)
    from core.wsqk import (  # noqa: F401
        bind_scope_from_eqc,
        WSQKBindError,
        execute_with_scope,
        WSQKExecutionError,
    )
