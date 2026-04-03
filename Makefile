.PHONY: test test-verbose test-quick lint

test:
	python3 -m pytest tests/ -v --tb=short

test-verbose:
	python3 -m pytest tests/ -v --tb=long -s

test-quick:
	python3 -m pytest tests/ -q --tb=line

lint:
	python3 -m py_compile src/supportutils_scrub/*.py
	python3 -m py_compile src/supportutils_scrub/modes/*.py
