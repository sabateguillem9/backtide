# Vigía · development commands. Run `make help` to list them.

VM := vigia-dev
# Run a command inside the dev VM, in this same folder.
VM_SH := limactl shell --workdir "$(CURDIR)" $(VM) -- sh -c
# Inside the VM, the Linux virtualenv lives outside the shared folder (the Mac uses .venv).
# Recursive (=) on purpose: $$HOME must reach the VM's shell unexpanded.
UV_VM = UV_PROJECT_ENVIRONMENT="$$HOME/.venvs/vigia" uv run --locked
# The recordable demo (docs/demo.md): scripts/demo/demo.py, inside the VM.
DEMO_VM = $(UV_VM) python -m scripts.demo.demo

.PHONY: help test lint fmt it ataques demo demo-crear demo-archivos demo-borrar demo-instantaneas \
	demo-rebobinar demo-parar vm-up vm-shell vm-down vm-delete

help: ## List the available commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

test: ## Unit tests (on the Mac)
	uv run pytest

lint: ## Check formatting and lint
	uv run ruff format --check .
	uv run ruff check .

fmt: ## Auto-fix lint issues and format
	uv run ruff check --fix .
	uv run ruff format .

it: ## Integration tests inside the VM (only some: make it IT=tests/integration/test_x.py; no ' in IT)
	@case "$(IT)" in *"'"*) echo "IT cannot contain single quotes: it goes inside sh -c '...'" >&2; exit 2;; esac
	$(VM_SH) '$(UV_VM) pytest -m integration $(IT)'

ataques: ## Evil-agent battery inside the VM (only some: make ataques ATK="-k nested"; no ' in ATK)
	@case "$(ATK)" in *"'"*) echo "ATK cannot contain single quotes: it goes inside sh -c '...'" >&2; exit 2;; esac
	$(VM_SH) '$(UV_VM) pytest -m ataques -q --tb=short tests/attacks $(ATK)'

demo: ## Demo: volume + `vigia vigilar` in front (terminal 1; docs/demo.md)
	$(VM_SH) '$(DEMO_VM) up'

demo-crear: ## Demo: the agent creates some files
	$(VM_SH) '$(DEMO_VM) crear'

demo-archivos: ## Demo: show the agent's files
	$(VM_SH) '$(DEMO_VM) archivos'

demo-borrar: ## Demo: the agent deletes some of them
	$(VM_SH) '$(DEMO_VM) borrar'

demo-instantaneas: ## Demo: list the snapshots
	$(VM_SH) '$(DEMO_VM) instantaneas'

demo-rebobinar: ## Demo: rewind (ID=<snapshot>, default the one demo-crear left; SI=1 skips the question)
	@case "$(ID)" in *[!0-9A-Za-z._-]*) echo "ID has odd characters: copy it from make demo-instantaneas" >&2; exit 2;; esac
	$(VM_SH) '$(DEMO_VM) rebobinar $(ID) $(if $(SI),--si)'

demo-parar: ## Demo: stop everything, unmount and delete the demo volume
	$(VM_SH) '$(DEMO_VM) parar'

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
