"""Negative tests for the crypto review findings (C1-C3, H1-H5, M1-M3, M5).

Each test is built from the matching reproducer (R1-R14) of the review.
"""
import json
import os
import re
import subprocess

import pytest
from click.testing import CliRunner


from pqblocks_agility.cbom import (
    CBOMParseError, InvalidGradeError, MissingGradeError, parse_cbom_dict,
)
from pqblocks_agility.ci_gate import evaluate_gate
from pqblocks_agility.cli import cli, compute_cars_score

R = CliRunner()


def comp(name, grade=None, loc=None, qv=None, level=None, extra=None):
    p = []
    if grade:
        p.append({"name": "pqblocks-scan.grade", "value": grade})
    if loc:
        p.append({"name": "pqblocks-scan.location", "value": loc})
    if qv is not None:
        p.append({"name": "pqblocks-scan.quantum_vulnerable", "value": qv})
    c = {"type": "cryptographic-asset", "name": name, "properties": p}
    if level is not None:
        c["cryptoProperties"] = {"algorithmProperties": {"primitive": name},
                                 "nistQuantumSecurityLevel": level}
    if extra:
        c.update(extra)
    return c


def doc(cs):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": cs}


def gate(d, args, diff=None):
    with R.isolated_filesystem():
        json.dump(d, open("c.json", "w"))
        if diff is not None:
            open("pr.diff", "w").write(diff)
        r = R.invoke(cli, ["gate", "--cbom", "c.json"] + args)
        return r.exit_code, r.output


DIFF = "diff --git a/src/a.py b/src/a.py\n+++ b/src/a.py\n+rsa.generate_private_key(1024)\n"
# one RSA-3072 (grade D, vulnerable but not F) so only the firewall can fail it
MIXD = doc([comp("RSA-3072", loc="src/a.py:1")] + [comp("ML-KEM-768", loc="k.py:1")] * 9)
FW = ["--fail-on-regression", "--diff-file", "pr.diff"]


# ---- C1 ----
def _staged(content):
    os.system("git init -q . && printf '%s' '" + content + "' > k.pem && git add k.pem")


def test_c1_check_staged_rejects_pem_private_key():
    with R.isolated_filesystem():
        _staged("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
        r = R.invoke(cli, ["check-staged"])
    assert r.exit_code == 1 and "Clean" not in r.output
    assert "MIIE" not in r.output  # never echo key material


def test_c1_check_staged_clean_file_passes():
    with R.isolated_filesystem():
        _staged("hello\n")
        r = R.invoke(cli, ["check-staged"])
    assert r.exit_code == 0


def test_c1_check_staged_rejects_disallowed_primitive():
    with R.isolated_filesystem():
        _staged("import hashlib; hashlib.md5(b'x')\n")
        assert R.invoke(cli, ["check-staged"]).exit_code == 1


# ---- C2 ----
def test_c2_missing_diff_file_exits_2():
    code, _ = gate(MIXD, ["--fail-on-regression", "--diff-file", "nope.diff"])
    assert code == 2


def test_c2_firewall_without_any_diff_source_exits_2():
    assert gate(MIXD, ["--fail-on-regression"])[0] == 2


def test_c2_git_diff_failure_exits_2():
    code, _ = gate(MIXD, ["--fail-on-regression", "--diff-base", "origin/does-not-exist"])
    assert code == 2


def test_c2_baseline_diff_is_caught():
    assert gate(MIXD, FW, DIFF)[0] == 1


@pytest.mark.parametrize("location,diff", [
    ("src/a.py:1", "diff --git src/a.py src/a.py\n+rsa\n"),  # no-prefix
    ("./src/a.py:1", DIFF),
    ("/repo/src/a.py:1", DIFF),
    ("src/my a.py:1", 'diff --git "a/src/my a.py" "b/src/my a.py"\n+rsa\n'),
    ("src/my a.py:1", "diff --git a/src/my a.py b/src/my a.py\n+rsa\n"),
    (None, DIFF),  # vulnerable, no location: cannot be cleared
])
def test_c2_path_forms_still_flagged(location, diff):
    d = doc([comp("RSA-3072", loc=location)] + [comp("ML-KEM-768", loc="k.py:1")] * 9)
    assert gate(d, FW, diff)[0] == 1


def test_c2_unparsable_nonempty_diff_exits_2():
    assert gate(MIXD, FW, "garbage with no headers\n")[0] == 2


# ---- C3 ----
def test_c3_declared_grade_a_cannot_upgrade_rsa():
    with pytest.raises(InvalidGradeError):
        parse_cbom_dict(doc([comp("RSA-1024", grade="A", loc="src/a.py:1")]))


def test_c3_qv_false_cannot_mask_grade_f():
    c = parse_cbom_dict(doc([comp("RSA-1024", grade="F", qv="false")])).components[0]
    assert c.quantum_vulnerable is True


@pytest.mark.parametrize("bad", ["y", "TRUE!", 2])
def test_c3_non_boolean_qv_rejected(bad):
    with pytest.raises(CBOMParseError):
        parse_cbom_dict(doc([comp("ML-KEM-768", qv=bad)]))


# ---- H1 ----
@pytest.mark.parametrize("name,level", [
    ("Camellia-256", 5), ("HMAC-SHA256", 2), ("TripleDES", 1), ("BLAKE2b-512", 5),
    ("SHA-224", 1), ("Ed25519", 1),
])
def test_h1_level_never_gives_grade_a(name, level):
    c = parse_cbom_dict(doc([comp(name, level=level)])).components[0]
    assert c.grade != "A"


@pytest.mark.parametrize("level", [True, 7, -1, 2.5, "5"])
def test_h1_malformed_level_rejected(level):
    with pytest.raises(CBOMParseError):
        parse_cbom_dict(doc([comp("ML-KEM-768", level=level)]))


def test_h1_unknown_algorithm_with_level_raises():
    with pytest.raises(MissingGradeError):
        parse_cbom_dict(doc([comp("TotallyNewAlgo", level=5)]))


def test_h1_declared_a_on_unknown_algorithm_rejected():
    with pytest.raises(InvalidGradeError):
        parse_cbom_dict(doc([comp("TotallyNewAlgo", grade="A")]))


def test_h1_claimed_level_must_match_parameter_set():
    with pytest.raises(InvalidGradeError):
        parse_cbom_dict(doc([comp("ML-KEM-512", level=5)]))


@pytest.mark.parametrize("name", ["MLKEM768-X25519", "MLDSA65-RSA3072-PSS-SHA512"])
def test_h1_hybrid_names_are_not_pure_a(name):
    assert parse_cbom_dict(doc([comp(name)])).components[0].grade == "B"


# ---- H2 ----
def test_h2_nested_component_is_graded():
    parent = comp("ML-KEM-768", loc="k.py:1", extra={"components": [comp("RSA-1024", loc="src/a.py:1")]})
    algs = [c.algorithm for c in parse_cbom_dict(doc([parent])).components]
    assert algs == ["ML-KEM-768", "RSA-1024"]


def test_h2_depth_cap():
    node = comp("RSA-1024")
    for _ in range(100):
        node = comp("ML-KEM-768", extra={"components": [node]})
    with pytest.raises(CBOMParseError):
        parse_cbom_dict(doc([node]))


# ---- H3 ----
def test_h3_single_f_fails_default_gate():
    d = doc([comp("RSA-1024", loc="src/a.py:1")] + [comp("ML-KEM-768", loc="k.py:1")] * 9)
    code, out = gate(d, [])
    assert code == 1 and "Grade F" in out


def test_h3_allow_disallowed_opts_out():
    d = doc([comp("RSA-1024", loc="src/a.py:1")] + [comp("ML-KEM-768", loc="k.py:1")] * 9)
    assert gate(d, ["--allow-disallowed"])[0] == 0


# ---- H4 ----
@pytest.mark.parametrize("payload", [
    "[" * 200000 + "]" * 200000,
    '{"specVersion":"1.6","components":null}',
    '{"specVersion":"1.6","components":{"a":1}}',
    '{"specVersion":"1.6","components":[1]}',
    '{"specVersion":"1.6","components":[{"name":"Foo","cryptoProperties":{"nistQuantumSecurityLevel":Infinity}}]}',
    '{"specVersion":"1.6","x":' + "9" * 5000 + "}",
    '{"specVersion":"1.6","components":[{"name":"x","cryptoProperties":[]}]}',
])
def test_h4_wrong_shapes_exit_2_without_traceback(payload):
    with R.isolated_filesystem():
        open("c.json", "w").write(payload)
        r = R.invoke(cli, ["gate", "--cbom", "c.json"])
    assert r.exit_code == 2 and not isinstance(r.exception, (RecursionError, TypeError, AttributeError, OverflowError))


def test_h4_non_crypto_components_skipped():
    d = doc([{"type": "library", "name": "mlkem-native"}, {"type": "library", "name": "requests"},
             comp("ML-KEM-768")])
    assert [c.algorithm for c in parse_cbom_dict(d).components] == ["ML-KEM-768"]


def test_h4_wrong_bomformat_rejected():
    d = doc([])
    d["bomFormat"] = "SPDX"
    with pytest.raises(CBOMParseError):
        parse_cbom_dict(d)


# ---- H5 ----
def test_h5_api_and_cli_agree():
    d = doc([comp("RSA-1024", loc="src/a.py:1")] + [comp("ML-KEM-768", loc="src/k.py:1")] * 3)
    cbom = parse_cbom_dict(d)
    api = evaluate_gate(cbom, allow_disallowed=True)["cars_score"]
    assert api == compute_cars_score(cbom)[0]
    with R.isolated_filesystem():
        json.dump(d, open("c.json", "w"))
        r = R.invoke(cli, ["gate", "--cbom", "c.json", "--allow-disallowed", "--json-out", "o.json"])
        assert json.load(open("o.json"))["cars_score"] == api


# ---- M1 ----
@pytest.mark.parametrize("v", ["nan", "-1", "101", "inf"])
def test_m1_bad_threshold_rejected(v):
    assert gate(doc([comp("ML-KEM-768")]), ["--min-cars", v])[0] == 2


# ---- M2 ----
def test_m2_diff_base_option_injection_rejected():
    with R.isolated_filesystem():
        json.dump(doc([comp("ML-KEM-768", loc="k.py:1")]), open("c.json", "w"))
        r = R.invoke(cli, ["gate", "--cbom", "c.json", "--fail-on-regression",
                           "--diff-base", "--output=pwned.txt"])
        assert r.exit_code == 2 and not os.path.exists("pwned.txt")


# ---- M3 ----
def test_m3_missing_cbom_and_policy_fail_have_distinct_codes():
    with R.isolated_filesystem():
        assert R.invoke(cli, ["gate", "--cbom", "nope.json"]).exit_code == 2
    assert gate(doc([comp("RSA-1024")]), [])[0] == 1


def test_m3_evaluate_honours_min_cars():
    with R.isolated_filesystem():
        json.dump(doc([comp("RSA-1024")]), open("c.json", "w"))
        assert R.invoke(cli, ["evaluate", "--cbom", "c.json", "--min-cars", "90"]).exit_code == 1


# ---- M5 ----
def test_m5_readme_cli_examples_use_real_options():
    path = os.path.join(os.path.dirname(__file__), "..", "README.md")
    if not os.path.exists(path):
        pytest.skip("README.md not shipped next to the tests")
    readme = open(path, encoding="utf-8").read()
    for line in re.findall(r"^pqblocks-agility ((?:evaluate|gate|check-staged|scan)\b.*)$", readme, re.M):
        sub = line.split()[0]
        helptext = R.invoke(cli, [sub, "--help"]).output
        for opt in re.findall(r"(--[a-z0-9-]+)", line):
            assert opt in helptext, (line, opt)
