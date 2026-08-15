.PHONY: install test replay run record eval corpus verify clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -q -e ".[dev]"

# No network, no API key. Every request is served from the committed cassettes,
# so this produces the same decisions I recorded.
replay:
	.venv/bin/gatekeeper triage --mode replay

# Against the live boards. Needs network; still needs no key and no account.
run:
	.venv/bin/gatekeeper triage --mode auto

# Re-record the cassettes from the live APIs. Changes what `make replay` shows.
record:
	.venv/bin/gatekeeper triage --mode record

test:
	.venv/bin/pytest -q

# Precision/recall of the screening decision against the labelled corpus.
eval:
	.venv/bin/gatekeeper eval

corpus:
	.venv/bin/python tools/build_corpus.py

# Re-hash the most recent run's audit log and check the chain.
verify:
	@ls -t runs/*.jsonl 2>/dev/null | head -1 | xargs -I{} .venv/bin/gatekeeper verify {} \
		|| echo "no runs yet -- try 'make replay' first"

clean:
	rm -rf runs/ .pytest_cache/ __pycache__/
