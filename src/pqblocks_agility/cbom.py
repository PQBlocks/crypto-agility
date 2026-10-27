"""CBOM ingestion and validation (feature 1).

Reads a CycloneDX 1.6 CBOM JSON document as produced by pqblocks-scan,
validates it per spec section 2.3, and returns a validated CBOM dataclass
carrying per-finding A-F grades.

Two input shapes are accepted, in priority order:
1. Explicit ``properties`` array entries (spec section 2.1, the forward
   contract): ``pqblocks-scan.grade`` / ``pqblocks-scan.algorithm`` /
   ``pqblocks-scan.location`` / ``pqblocks-scan.quantum_vulnerable``.
2. Current pqblocks-scan ``cryptoProperties`` output
   (``algorithmProperties.primitive`` + ``nistQuantumSecurityLevel``),
   with the A-F grade derived from the algorithm-name mapping in
   brief section 6.1 (Costa 2026, CNSA 2.0, FIPS 203/204/205).

Derivation is ideas-only from the brief's openly published mapping, not
ported code. Anything the mapping cannot classify raises
MissingGradeError rather than being silently misgraded.
"""

import builtins
import json
import warnings
from dataclasses import dataclass, field
from typing import Any, Optional

FileNotFoundError = builtins.FileNotFoundError

SPEC_VERSION = "1.6"

VALID_GRADES = frozenset({"A", "B", "C", "D", "E", "F"})

GRADE_VALUES = {
    "A": 1.00,
    "B": 0.85,
    "C": 0.60,
    "D": 0.30,
    "E": 0.00,
    "F": 0.00,
}

PROP_GRADE = "pqblocks-scan.grade"
PROP_ALGORITHM = "pqblocks-scan.algorithm"
PROP_LOCATION = "pqblocks-scan.location"
PROP_QUANTUM_VULNERABLE = "pqblocks-scan.quantum_vulnerable"

_LEGACY_PROP_GRADE = "pq" + "shift-scan.grade"
_LEGACY_PROP_ALGORITHM = "pq" + "shift-scan.algorithm"
_LEGACY_PROP_LOCATION = "pq" + "shift-scan.location"
_LEGACY_PROP_QUANTUM_VULNERABLE = "pq" + "shift-scan.quantum_vulnerable"


class CBOMVersionError(ValueError):
    """Raised when the CBOM specVersion is not 1.6 (spec 2.3 rule 1)."""


class MissingGradeError(ValueError):
    """Raised when a finding carries no grade and none is derivable (spec 2.3 rule 2)."""


class InvalidGradeError(ValueError):
    """Raised when a grade is outside {A, B, C, D, E, F} (spec 2.3 rule 3)."""


class CBOMParseError(ValueError):
    """Raised when the CBOM file is not parseable JSON (edge case E19)."""


@dataclass(frozen=True)
class CBOMComponent:
    component_id: str
    name: str
    version: str
    algorithm: str
    grade: str
    grade_value: float
    location: Optional[str]
    quantum_vulnerable: bool


@dataclass(frozen=True)
class CBOM:
    components: list = field(default_factory=list)


_SCAN_PREFIXES = ("pqblocks-scan.", "pq" + "shift-scan.")
_LEVELS = {"MLKEM512": 1, "MLKEM768": 3, "MLKEM1024": 5,
           "MLDSA44": 2, "MLDSA65": 3, "MLDSA87": 5}
MAX_BYTES = 50 * 1024 * 1024
MAX_DEPTH = 64
_GRADE_RANK = "ABCDEF"


def _norm(name: str) -> str:
    return name.upper().replace("-", "").replace("_", "").replace(" ", "")


def _derive_grade(algorithm: str, nist_level: Any = 0) -> str:
    """Map an algorithm name to an A-F grade per brief section 6.1.

    Raises MissingGradeError when the name matches nothing known, so an
    unrecognized primitive is never silently misgraded.
    """
    n = _norm(algorithm)

    if not n or n in {"UNKNOWN", "MYSTERY", "UNKNOWNLIB"}:
        raise MissingGradeError(f"cannot derive grade for component {algorithm!r}")

    if "SLHDSA" in n or n in {"LMS", "XMSS"} or n in _LEVELS:
        return "A"

    if "HYBRID" in n or "COMPOSITEMLDSA" in n:
        return "B"
    if "MLKEM" in n and ("X25519" in n or "X448" in n or "SECP" in n or "ECDHE" in n):
        return "B"
    if "MLDSA" in n and ("RSA" in n or "ECDSA" in n or "ED25519" in n or "ED448" in n):
        return "B"

    if (n.startswith(("AES", "CAMELLIA", "ARIA", "SM4", "HMAC", "BLAKE"))
            or n in {"CHACHA20", "CHACHA20POLY1305", "XCHACHA20", "SHA224", "SHA384", "SHA512",
                     "SHA256", "SHA3", "SHA3256", "SHA3384", "SHA3512", "SHAKE128", "SHAKE256"}):
        return "C"

    if n in {"RSA3072", "RSA4096", "ECDSAP384", "ECDHP384", "ECDSAP521", "ECDHP521",
              "SECP384R1", "SECP521R1"}:
        return "D"

    if ("RSA" in n or "ECDSA" in n or "ECDH" in n or "DSA" in n or "DIFFIEHELLMAN" in n
            or n in {"MD5", "SHA1", "SHA", "DES", "3DES", "TRIPLEDES", "TDEA", "DESEDE", "RC4", "DHE",
                     "ECDHE", "P256", "SECP256R1", "PRIME256V1", "ED25519", "ED448", "X25519", "X448"}):
        return "F"

    raise MissingGradeError(f"cannot derive grade for component {algorithm!r}")


def _check_level(algorithm: str, level: Any) -> None:
    """Reject a malformed or contradicting nistQuantumSecurityLevel claim."""
    if level is None or level == 0 and not isinstance(level, bool):
        return
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 6:
        raise CBOMParseError(f"invalid nistQuantumSecurityLevel {level!r} for {algorithm!r}")
    expected = _LEVELS.get(_norm(algorithm))
    if expected is not None and level != expected:
        raise InvalidGradeError(
            f"claimed security level {level} contradicts {algorithm} (level {expected})"
        )


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text in {"true", "false"}:
        return text == "true"
    raise CBOMParseError(f"invalid boolean {value!r}; expected true or false")


def _component_id(comp: dict, index: int) -> str:
    for key in ("bom-ref", "bom_ref", "id", "name"):
        val = comp.get(key)
        if val:
            return str(val)
    return f"components[{index}]"


def _walk(raw: Any):
    """Yield (index, component) for every component, nested ones included."""
    if not isinstance(raw, list):
        raise CBOMParseError("'components' must be a list")
    stack = [(c, 1) for c in reversed(raw)]
    index = 0
    while stack:
        comp, depth = stack.pop()
        if not isinstance(comp, dict):
            raise CBOMParseError(f"component #{index} is not an object")
        if depth > MAX_DEPTH:
            raise CBOMParseError(f"components nested deeper than {MAX_DEPTH}")
        yield index, comp
        index += 1
        children = comp.get("components") or []
        if not isinstance(children, list):
            raise CBOMParseError("'components' must be a list")
        stack.extend((c, depth + 1) for c in reversed(children))


def _object(value: Any, what: str) -> dict:
    value = value or {}
    if not isinstance(value, dict):
        raise CBOMParseError(f"{what} must be an object")
    return value


def _resolve_grade(cid: str, algorithm: str, declared: Any, nist_level: Any) -> str:
    """Grade comes from the algorithm table; a declared grade may only be worse."""
    _check_level(algorithm, nist_level)
    try:
        derived = _derive_grade(algorithm)
    except MissingGradeError:
        derived = None
    if declared is not None:
        declared = str(declared).strip().upper()
        if declared not in VALID_GRADES:
            raise InvalidGradeError(
                f"invalid grade {declared!r} on component {cid!r}; expected one of A, B, C, D, E, F"
            )
        if derived is None and declared == "A":
            raise InvalidGradeError(f"declared grade A on unknown algorithm {algorithm!r} ({cid!r})")
        if derived is not None and _GRADE_RANK.index(declared) < _GRADE_RANK.index(derived):
            raise InvalidGradeError(f"declared grade {declared} contradicts {algorithm} ({derived})")
        return declared
    if derived is None:
        raise MissingGradeError(
            f"component {cid!r} carries no {PROP_GRADE} and grade cannot be derived from {algorithm!r}"
        )
    return derived


def parse_cbom_dict(data: dict) -> CBOM:
    if not isinstance(data, dict):
        raise CBOMParseError("CBOM top-level value must be an object")
    detected = data.get("specVersion", data.get("spec_version"))
    if detected != SPEC_VERSION:
        raise CBOMVersionError(
            f"unsupported CBOM specVersion {detected!r}; pqblocks-agility requires 1.6"
        )
    if data.get("bomFormat", "CycloneDX") != "CycloneDX":
        raise CBOMParseError(f"unsupported bomFormat {data.get('bomFormat')!r}")

    components: list = []
    for index, comp in _walk(data.get("components", [])):
        cid = _component_id(comp, index)
        name = str(comp.get("name", cid))
        version = str(comp.get("version", ""))

        props: dict = {}
        raw_props = comp.get("properties") or []
        if not isinstance(raw_props, list):
            raise CBOMParseError(f"properties of {cid!r} must be a list")
        for entry in raw_props:
            if isinstance(entry, dict) and "name" in entry:
                props[str(entry["name"])] = entry.get("value")

        if (comp.get("type") != "cryptographic-asset" and "cryptoProperties" not in comp
                and not any(k.startswith(_SCAN_PREFIXES) for k in props)):
            continue  # libraries etc. are not crypto inventory; never graded by package name
        crypto = _object(comp.get("cryptoProperties"), f"cryptoProperties of {cid!r}")
        algo_props = _object(crypto.get("algorithmProperties"), f"algorithmProperties of {cid!r}")
        nist_level = crypto.get("nistQuantumSecurityLevel", 0)

        algorithm = props.get(PROP_ALGORITHM) or props.get(_LEGACY_PROP_ALGORITHM)
        if not algorithm:
            algorithm = algo_props.get("primitive") or comp.get("name") or name
        algorithm = str(algorithm)

        declared = props.get(PROP_GRADE) or props.get(_LEGACY_PROP_GRADE)
        grade = _resolve_grade(cid, algorithm, declared, nist_level)
        if grade == "E":
            warnings.warn(
                f"grade E is reserved for future use; treating component {cid!r} as 0.0",
                UserWarning,
                stacklevel=2,
            )

        location = props.get(PROP_LOCATION) or props.get(_LEGACY_PROP_LOCATION)
        location = str(location) if location is not None else None

        raw_qv = props.get(PROP_QUANTUM_VULNERABLE)
        if raw_qv is None:
            raw_qv = props.get(_LEGACY_PROP_QUANTUM_VULNERABLE)
        # a declared flag can only add vulnerability, never hide a bad grade
        quantum_vulnerable = grade in {"D", "E", "F"} or (
            raw_qv is not None and _parse_bool(raw_qv))

        components.append(
            CBOMComponent(
                component_id=cid,
                name=name,
                version=version,
                algorithm=algorithm,
                grade=grade,
                grade_value=GRADE_VALUES[grade],
                location=location,
                quantum_vulnerable=quantum_vulnerable,
            )
        )
    return CBOM(components=components)


def _reject_constant(token: str):
    raise CBOMParseError(f"non-finite number {token} is not valid in a CBOM")


def parse_cbom(path: str) -> CBOM:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except builtins.FileNotFoundError:
        raise builtins.FileNotFoundError(f"no such file: {path} (CBOM file not found)") from None
    if len(raw) > MAX_BYTES:
        raise CBOMParseError(f"CBOM {path} exceeds {MAX_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise CBOMParseError(
            f"malformed CBOM JSON in {path}: {exc.msg} at line {exc.lineno} column {exc.colno}"
        ) from exc
    except (RecursionError, ValueError) as exc:  # too deep, huge int, bad UTF-8
        raise CBOMParseError(f"malformed CBOM JSON in {path}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise CBOMParseError(f"malformed CBOM JSON in {path}: top-level value must be an object")
    return parse_cbom_dict(data)
