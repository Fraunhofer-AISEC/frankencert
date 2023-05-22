
.PHONY: lint
lint:
	ruff frankencert
	mypy frankencert

.PHONY: fmt
fmt:
	ruff check --fix-only frankencert
	black frankencert
