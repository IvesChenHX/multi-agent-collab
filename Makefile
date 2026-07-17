.PHONY: test validate build clean

test:
	python -m pytest

validate:
	python -m mac.cli validate --repo .

build:
	python -m mac.cli validate --repo .
	python -m build

clean:
	python -c "from pathlib import Path; [p.unlink() for p in Path('.').rglob('*.tmp') if p.is_file()]"
