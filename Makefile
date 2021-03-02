SHELL := /bin/bash -euo pipefail

.PHONY: diff.patch
diff.patch:
	(git diff --no-index --ignore-all-space --ignore-blank-lines --diff-algorithm=patience warrant/ pycognito/ || true) > $@
