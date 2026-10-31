"""Agent Quality Toolkit evidence records (spec 0.1)."""

from .canonical import (CanonicalError, bytes_hash, canonical_json, content_hash, parse_canonical_line, parse_json,
                        parse_record, sha256_hex)
from .chain import (GENESIS, ChainResult, checkpoint_matches, checkpoint_problems, link, make_checkpoint,
                    verify_chain, verify_checkpoint)
from .crypto import (Signer, generate_key, key_id, load_public_key, load_signer, public_key_from_raw, sign_record,
                     sign_statement, signer_from_seed, verify_record_signatures, verify_statement)
from .record import (ACTOR_KINDS, MEANINGS, SPEC_VERSION, actor, new_id, new_record, record_content_hash, record_hash, subject,
                     unsigned, utc_now, validate_record)
from .conformance import ConformanceResult, conformance
from .messages import Text, coded, text_join
from .session import AgentContext, HumanCheckError, detect_agent_context, process_chain, require_human
from .sink import (ERROR_CODES, JsonlSink, RecordLineError, Sink, SinkError, SinkUnavailable, SocketSink,
                   evidence_sources, iter_evidence, open_sink, read_jsonl, resolve_sink, spool_file, state_dir)

__version__ = "0.1.0"

__all__ = [
    "ACTOR_KINDS", "AgentContext", "GENESIS", "HumanCheckError", "MEANINGS", "SPEC_VERSION", "CanonicalError", "ChainResult", "JsonlSink",
    "Signer", "Sink", "SinkError", "SocketSink", "actor", "bytes_hash", "canonical_json",
    "checkpoint_matches", "content_hash", "detect_agent_context", "generate_key", "key_id", "link", "load_public_key",
    "load_signer", "make_checkpoint", "new_id", "process_chain", "require_human", "new_record", "open_sink", "read_jsonl", "record_content_hash", "record_hash", "evidence_sources", "iter_evidence",
    "sha256_hex", "sign_record", "state_dir", "subject", "unsigned", "utc_now", "validate_record",
    "verify_chain", "verify_checkpoint", "verify_record_signatures",
    "ERROR_CODES", "SinkUnavailable", "parse_json", "parse_record", "resolve_sink", "spool_file",
    "public_key_from_raw", "sign_statement", "signer_from_seed", "verify_statement",
    "ConformanceResult", "conformance",
    "RecordLineError", "checkpoint_problems", "parse_canonical_line",
    "Text", "coded", "text_join",
]
