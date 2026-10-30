#!/usr/bin/env bash
# Interactive walk-through in a throw-away directory. You type the passphrases yourself.
set -euo pipefail
demo=$(mktemp -d)
export XDG_CONFIG_HOME="$demo/config" XDG_STATE_HOME="$demo/state" AQT_SINK="file:$demo/evidence.jsonl"
cd "$demo"
printf '# Release notes 1.2\n' > notes.md

aqt-signoff init --id human:alice --name "Alice Example" --role quality-manager      # the first signer counts at once
aqt-signoff init --id human:bob --name "Bob Example" --role developer
bob_key=$(aqt-signoff --json signers list | python3 -c 'import json,sys; d=json.load(sys.stdin); print([k["key_id"] for s in d["signers"] if s["id"]=="human:bob" for k in s["keys"]][0])')
aqt-signoff signers check || echo "-> Bob's enrolment waits for an approval"
aqt-signoff signers approve human:bob --key "$bob_key" --signer human:alice --reason "Bob is our developer"
aqt-signoff signers check
aqt-signoff sign notes.md --meaning approved --reason "Reviewed against CR-12" --signer human:alice
aqt-signoff verify notes.md
aqt-signoff manifest notes.md

printf 'late edit\n' >> notes.md
aqt-signoff verify notes.md || echo "-> the signature no longer applies"

AQT_ACTOR=agent:demo:s1 aqt-signoff --json prepare --request-key publish-1.2 --description "Publish notes" \
    -- sh -c 'echo published' > action.json
id=$(python3 -c 'import json; print(json.load(open("action.json"))["id"])')
hash=$(python3 -c 'import json; print(json.load(open("action.json"))["action_sha256"])')
aqt-signoff show "$id"
aqt-signoff approve "$id" --hash "$hash" --reason "argv reviewed" --signer human:alice
AQT_ACTOR=agent:demo:s1 aqt-signoff run "$id"
AQT_ACTOR=agent:demo:s1 aqt-signoff run "$id" || echo "-> a second run is refused"
echo "evidence: $demo/evidence.jsonl"
