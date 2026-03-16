.PHONY: check test test-integration lint

check:
	python tools/ci/check_scope_boundaries.py
	python tools/ci/check_stale_references.py
	python tools/ci/validate_artifact_contract.py
	python tools/ci/validate_language_detector_contract.py
	python tools/ci/test_language_detector_fixtures.py

test:
	python -m pytest tests/ -v

test-integration:
	python -m pytest tests/ -v -m integration

lint:
	python -m ruff check .
