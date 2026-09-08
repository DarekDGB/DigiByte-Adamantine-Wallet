from __future__ import annotations

import ast
import hashlib
import inspect
import json
import re
import tomllib
from pathlib import Path

import pytest

from adamantine.v1.contracts.reason_ids import ReasonId
from adamantine.v1.integrations.shield_orchestrator_receipt_v4_verifier import (
    _verify_test_only_signature,
)
from adamantine.v1.integrations.shield_v4_verification_audit import (
    ShieldV4AuditSinkError,
    verify_shield_v4_orchestrator_receipt_with_audit,
)
from adamantine.v1.policy.final_policy_engine import (
    FinalPolicyEngineState,
    LocalPolicyGateResult,
    evaluate_final_policy_engine,
)
from tests.integrations.test_shield_v410b_verification_audit import RecordingSink
from tests.integrations.test_shield_v49_external_verification_contract import (
    _SupportingEvidence,
    _fixture,
    _result_contract,
)

ROOT = Path(__file__).resolve().parents[1]
PACK = 'docs/PROOF_PACKS/ADAMANTINEOS_SHIELD_V4_FINAL_VERIFIER_PROOF_PACK.md'
STATUS = 'docs/ADAMANTINEOS_SHIELD_V4_RELEASE_STATUS.md'
DOCS = (
    'README.md', 'CHANGELOG.md', 'SECURITY.md', PACK, STATUS,
    'docs/ADAMANTINEOS_FINAL_PROOF_PACK_INDEX.md', 'docs/INDEX.md',
    'docs/ADAMANTINEOS_SHIELD_V4_PQC_VERIFIER.md',
    'docs/ADAMANTINEOS_SHIELD_V4_REAL_CRYPTO_BACKEND.md',
    'docs/ADAMANTINEOS_SHIELD_V4_THREAT_MODEL.md',
    'docs/ADAMANTINEOS_SHIELD_V4_TEST_MATRIX.md',
)
COPY_FILES = DOCS + (
    'tests/test_milestone_17_rebrand_and_proof_pack_alignment.py',
    'tests/test_v410f_final_verifier_proof_pack.py',
)
FROZEN = {
    'pyproject.toml': '8f58ee198d8f22803f8daa8acf62eb6ee5667f0f4217b4d7f61a300d8926e5aa',
    '.github/workflows/shield-v4-real-oqs.yml': '254361fbd6dd1410fa4b0428906a6b95ae83cb97dd8c252b96befcbfe3ada1fc',
    '.github/workflows/shield-v4-performance-dos.yml': '574376eab69a7e951db40007060845e1be19eb2256cd2f2b2269e59dc5c603fe',
    'docs/ADAMANTINEOS_FULL_INTEGRATION_BUILD_LEDGER.md': '65012247d0fcc90c7a1e84bad3ba296bee01679138753f8ceeeab7890ec9f295',
    'docs/ADAMANTINEOS_V3_0_0_RELEASE_NOTES.md': '5b068715a06bd300168c8b855e7349669109d1ae256f907bf2c10f158e519831',
    'docs/ADAMANTINEOS_MILESTONE_19_TAG_DECISION.md': '9ee6b453914bf7f676bff05bf96edacc370d70f5a2de709d4734460b1d246bde',
}
KAT_HASHES = {
    'deny_signed_receipt.json': '13383abdef83188c78f4d2b54ce544673362549155695cca486699ecbfcd428c',
    'external_verifier_contract_v1_kat.json': '308b9aadd993cf07665a125c4294d8e22cbe3f747419e346e104f127093e951f',
    'fn_dsa_signed_message_draft_profile_kat.json': '529ab8f976290f062dc18911ceb18ae14ba4bca3d4c4f7e21a41086c3816bef4',
    'full_multi_repo_v4_allow_flow.json': 'b1031e999b87f61643748848e6d121f153c3cbdc7c87ceef9a62c766bc8b7ced',
    'full_multi_repo_v4_fn_dsa_allow_flow.json': '8856a89fb031ebd168efacd8c3055d3bcfe6367a70b06f27ad134406338b944d',
    'full_multi_repo_v4_real_backend_allow_flow.json': '85e996801f20226ad2c6624b2f85e3e6a1d6d1fd84a2329971e31af925907e90',
    'tampered_signature_deny.json': 'ab2522f9b0256aaee218f7dd432bd167cf7f23c9e21942497df87b2220a252ae',
    'v3_downgrade_rejected.json': '1d861240e2924c8bd4b8fca8a00582242ab0fde1a28b1ce1bbc2599cb76b3394',
    'valid_allow_signed_receipt.json': '0e63cb9cf049f74d312a9244c6b25a8a0abf699b68330c0343dcc1711aa4964d',
}
NATIVE_MODULES = (
    'tests/integrations/test_shield_v48g_real_oqs_mldsa_backend.py',
    'tests/integrations/test_shield_v48g_real_oqs_full_chain.py',
    'tests/integrations/test_shield_v48h_e_real_oqs_falcon_full_chain.py',
)
NATIVE_NAMES = (
    'test_v48g_real_oqs_mldsa65_adamantineos_verify_only_backend_positive_and_negatives',
    'test_v48g_r4_real_oqs_mldsa_full_chain_verifies_through_adamantineos',
    'test_v410b_real_oqs_mldsa_full_chain_requires_durable_audit_ack',
    'test_v48g_r4_real_oqs_mldsa_full_chain_rejects_tampered_orchestrator_mldsa',
    'test_v48h_e_real_oqs_mldsa_and_falcon_full_chain_verifies_through_adamantineos',
    'test_v48h_e_real_oqs_full_chain_rejects_tampered_falcon_signature',
)
ORDER = ('shield', 'wsqk_v2', 'qid', 'adaptive_core', 'ai_gateway',
         'replay', 'wallet_policy', 'human', 'final_adamantineos_decision')


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding='utf-8', errors='strict')


def _audited(fixture, sink, **overrides):
    parameters = dict(fixture['inputs'])
    parameters.update(
        trusted_key_registry=fixture['verifier_controlled_test_registry'],
        signature_verifier=_verify_test_only_signature,
        # Test transport bytes for this exact receipt, not the enclosing KAT file.
        artifact_transport_hash=hashlib.sha256(
            json.dumps(fixture['receipt'], sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False).encode('utf-8')
        ).hexdigest(),
        audit_sink=sink,
    )
    parameters.update(overrides)
    return verify_shield_v4_orchestrator_receipt_with_audit(fixture['receipt'], **parameters)


def _final(shield, blocked=None):
    supporting = _SupportingEvidence()
    gates = {
        gate: LocalPolicyGateResult(gate, gate != blocked,
                                   ReasonId.OK_ALLOW if gate != blocked else ReasonId.DENY_POLICY)
        for gate in ('replay', 'wallet_policy', 'human')
    }
    return evaluate_final_policy_engine(
        shield=shield, wsqk_v2=supporting, qid=supporting,
        adaptive_core=supporting, ai_gateway=supporting,
        **gates, expected_context_hash='a' * 64, shield_v4_required=True,
    )


def test_v410f_independent_no_bump_and_frozen_history() -> None:
    project = tomllib.loads(_text('pyproject.toml'))['project']
    assert project['version'] == '3.0.0'
    assert project['name'] == 'adamantine-wallet-os'
    assert project['authors'] == [{'name': 'DarekDGB'}]
    for name, expected in FROZEN.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    for path in (ROOT / 'src').rglob('*.py'):
        tree = ast.parse(path.read_text())
        targets = [target.id for node in ast.walk(tree) if isinstance(node, ast.Assign)
                   for target in node.targets if isinstance(target, ast.Name)]
        assert '__version__' not in targets and 'server_version' not in targets


def test_v410f_all_shield_fixtures_remain_byte_frozen() -> None:
    directory = ROOT / 'src/adamantine/v1/fixtures/shield_v4'
    assert {p.name for p in directory.glob('*.json')} == set(KAT_HASHES)
    for name, expected in KAT_HASHES.items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected


def test_v410f_native_gate_is_exact_six_named_nodes() -> None:
    workflow = _text('.github/workflows/shield-v4-real-oqs.yml')
    nodes = re.findall(r'--require-testcase "([^"]+)"', workflow)
    assert len(nodes) == len(set(nodes)) == 6
    assert tuple(node.split('::')[1] for node in nodes) == NATIVE_NAMES
    collected = []
    for module in NATIVE_MODULES:
        tree = ast.parse(_text(module))
        collected.extend(f'{module}::{node.name}' for node in tree.body
                         if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
    assert collected == nodes
    assert '--min-tests 6' in workflow
    for flag in ('SHIELD_V4_REAL_OQS', 'SHIELD_V4_REAL_OQS_FALCON'):
        assert f'{flag}: "1"' in workflow
    backend = _text('docs/ADAMANTINEOS_SHIELD_V4_REAL_CRYPTO_BACKEND.md')
    assert re.findall(r'--require-testcase "([^"]+)"', backend) == nodes


def test_v410f_document_links_and_proof_test_paths_exist() -> None:
    for name in DOCS:
        content = _text(name)
        for target in re.findall(r'\]\(([^)]+)\)', content):
            if target.startswith(('https://', 'http://', 'mailto:', '#')):
                continue
            resolved = (ROOT / name).parent / target.split('#', 1)[0]
            assert resolved.is_file(), (name, target)
    pack = _text(PACK)
    paths = re.findall(r'`(tests/[^`]+\.py)`', pack)
    assert len(set(paths)) >= 15
    for name in paths:
        tree = ast.parse(_text(name))
        assert any(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in tree.body)


def test_v410f_candidate_claims_and_compatibility_are_explicit() -> None:
    content = _text(PACK) + _text(STATUS)
    for phrase in ('no-bump', '3.0.0', 'historical', '925', '4097',
                   'shield_v4_required=False', 'shield_v4_required=True',
                   'TEST-ONLY classical', 'fips206-draft-falcon1024-v1',
                   'post-commit', 'not a release', 'durability', 'native PQC latency'):
        assert phrase in content, phrase
    assert inspect.signature(evaluate_final_policy_engine).parameters['shield_v4_required'].default is False
    for name in ('src/adamantine/v2/runtime_host/host.py',
                 'src/adamantine/v1/execution/orchestrator_v2.py'):
        assert 'shield_v4_required=True' not in _text(name)


def test_v410f_copy_payloads_are_ascii_safe() -> None:
    # Exact first-party copy paths only: generated caches, egg-info and coverage
    # output are not source files and are never recursively scanned here.
    for name in COPY_FILES:
        raw = (ROOT / name).read_bytes()
        assert raw.isascii() and raw.endswith(b'\n'), name
        assert b'\r' not in raw and b'\x00' not in raw, name
        assert not any(0x80 <= byte <= 0x9F for byte in raw), name
    for name in (PACK, STATUS):
        assert _text(name).count('Author attribution: DarekDGB') == 1


def test_v410f_real_backends_expose_no_signing_or_private_key_resolver() -> None:
    for name in ('shield_v4_real_crypto_backend.py', 'shield_v4_oqs_mldsa_backend.py',
                 'shield_v4_oqs_falcon_backend.py'):
        tree = ast.parse(_text('src/adamantine/v1/integrations/' + name))
        names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        assert not names & {'sign', 'sign_message', 'broadcast', 'resolve_private_key'}


def test_v410f_shared_kat_audit_and_final_policy_compose_without_upstream_authority() -> None:
    fixture = _fixture()
    before = json.dumps(fixture, sort_keys=True)
    sink = RecordingSink()  # Contract ACK only; this does not prove disk durability.
    shield = _audited(fixture, sink)
    assert _result_contract(shield) == fixture['expected_result']
    assert shield.final_approval is False
    assert len(sink.calls) == 1
    events = [json.loads(raw) for raw in sink.calls[0]]
    signatures = [event for event in events if event['event_type'] == 'signature_verification']
    assert len(events) == 20 and len(signatures) == 18
    assert [event['algorithm'] for event in signatures] == ['classical-ed25519'] * 6 + ['ml-dsa'] * 6 + ['fn-dsa'] * 6
    assert [event['artifact_id'] for event in signatures] == ['adn', 'dqsn', 'guardian_wallet', 'qwg', 'sentinel_ai', 'shield_orchestrator'] * 3
    assert all(event['verification_passed'] is True for event in signatures)
    final = _final(shield)
    assert final.state is FinalPolicyEngineState.ALLOW_FINAL_ADAMANTINEOS_DECISION
    assert final.final_approval is True and final.evaluation_order == ORDER
    assert json.dumps(fixture, sort_keys=True) == before


@pytest.mark.parametrize('blocked', ['replay', 'wallet_policy', 'human'])
def test_v410f_valid_audited_shield_cannot_override_local_gate(blocked) -> None:
    shield = _audited(_fixture(), RecordingSink())
    final = _final(shield, blocked)
    assert final.final_approval is False and final.outcome == 'DENY'
    assert final.stopped_at == blocked
    assert final.evaluation_order == ORDER[:ORDER.index(blocked) + 1]


def test_v410f_missing_durable_ack_prevents_final_policy_handoff() -> None:
    class RejectingSink(RecordingSink):
        def append_batch(self, records):
            ack = super().append_batch(records)
            ack['durably_committed'] = False
            return ack

    reached_final = []
    sink = RejectingSink()
    with pytest.raises(ShieldV4AuditSinkError):
        shield = _audited(_fixture(), sink)
        reached_final.append(_final(shield))
    assert len(sink.calls) == 1 and reached_final == []
