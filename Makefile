# Vigía · development commands. Run `make help` to list them.

VM := vigia-dev
# Run a command inside the dev VM, in this same folder.
VM_SH := limactl shell --workdir "$(CURDIR)" $(VM) -- sh -c
# Inside the VM, the Linux virtualenv lives outside the shared folder (the Mac uses .venv).
# Recursive (=) on purpose: $$HOME must reach the VM's shell unexpanded.
UV_VM = UV_PROJECT_ENVIRONMENT="$$HOME/.venvs/vigia" uv run --locked

.PHONY: help test lint fmt it ataques vm-up vm-shell vm-down vm-delete

help: ## List the available commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'

test: ## Unit tests (on the Mac)
	uv run pytest

lint: ## Check formatting and lint
	uv run ruff format --check .
	uv run ruff check .

fmt: ## Auto-fix lint issues and format
	uv run ruff check --fix .
	uv run ruff format .

it: ## Integration tests inside the VM
	$(VM_SH) '$(UV_VM) pytest -m integration'

ataques: ## Attack suite inside the VM (created in T05)
	@echo "The attack suite is created in T05."

vm-up: ## Create (first time) and start the dev VM
	@status=$$(limactl list --format '{{.Status}}' $(VM) 2>/dev/null); \
	if [ "$$status" = "Running" ]; then \
	  echo "$(VM) is already running"; \
	elif [ -n "$$status" ]; then \
	  limactl start $(VM); \
	else \
	  limactl start --name=$(VM) --tty=false \
	    --set '.mounts = [{"location": "$(CURDIR)", "writable": true}]' \
	    lima/vigia-dev.yaml; \
	fi

vm-shell: ## Open a shell inside the VM
	limactl shell --workdir "$(CURDIR)" $(VM)

vm-down: ## Stop the VM
	limactl stop $(VM)

vm-delete: ## Delete the VM (your code stays on the Mac)
	limactl delete --force $(VM)
