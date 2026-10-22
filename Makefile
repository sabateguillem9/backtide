# backtide · development commands. Run `make help` to list them.

VM := vigia-dev
# Run a command inside the dev VM, in this same folder.
VM_SH := limactl shell --workdir "$(CURDIR)" $(VM) -- sh -c
# Inside the VM, the Linux virtualenv lives outside the shared folder (the Mac uses .venv).
# Recursive (=) on purpose: $$HOME must reach the VM's shell unexpanded.
UV_VM = UV_PROJECT_ENVIRONMENT="$$HOME/.venvs/vigia" uv run --locked
# The recordable demo (docs/demo.md): scripts/demo/demo.py, inside the VM.
DEMO_VM = $(UV_VM) python -m scripts.demo.demo

# The web of the demo (docs/demo.md): in the VM, on the config that `make demo` writes. A port
# apart from the Mac's own `make web-demo`, so both can be open at once (Lima forwards the VM's).
DEMO_WEB_CONFIG = $$HOME/backtide-demo-run/backtide.toml
DEMO_WEB_PORT = 8766
# The founder's hands-on test (docs/probar.md): the real OpenClaw thinking with Claude. It lives
# where the demo lives (same folder, config path and web port), so the two never run together.
PROBAR_VM = $(UV_VM) python -m scripts.demo.probar
MODEL ?= claude-sonnet-5-5

.PHONY: help test lint fmt it ataques demo demo-crear demo-archivos demo-borrar demo-instantaneas \
	demo-rebobinar demo-parar demo-web web-demo probar probar-web probar-pedir probar-instantaneas \
	probar-rebobinar probar-parar probar-entrar probar-tarea probar-importar probar-exportar vm-up vm-shell vm-estado vm-limpiar vm-down vm-delete

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

# Where `make ataques` looks for scenarios: ATK_PATH=tests/attacks/test_x.py runs one file only.
ATK_PATH ?= tests/attacks

ataques: ## Evil-agent battery inside the VM (only some: make ataques ATK="-k nested" or ATK_PATH=tests/attacks/test_x.py; no ' in either)
	@case "$(ATK)$(ATK_PATH)" in *"'"*) echo "ATK and ATK_PATH cannot contain single quotes: they go inside sh -c '...'" >&2; exit 2;; esac
	$(VM_SH) '$(UV_VM) pytest -m ataques -q --tb=short $(ATK_PATH) $(ATK)'

demo: ## Demo: volume + `backtide vigilar` in front (terminal 1; docs/demo.md)
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

demo-parar: ## Demo: stop everything, unmount and delete the demo volume (also the old vigia-demo-* names)
	$(VM_SH) '$(DEMO_VM) parar'

demo-web: ## Demo: the web of the running demo, in the VM (open the link on the Mac; docs/demo.md)
	@case "$(DEMO_WEB_CONFIG)$(DEMO_WEB_PORT)" in *"'"*) echo "no ' in DEMO_WEB_*" >&2; exit 2;; esac
	@if lsof -nP -iTCP:$(DEMO_WEB_PORT) -sTCP:LISTEN >/dev/null 2>&1; then \
	  echo "El puerto $(DEMO_WEB_PORT) del Mac ya está ocupado: Lima no podría reenviarlo y el enlace llegaría a otro programa" >&2; exit 2; fi
	$(VM_SH) 'test -f "$(DEMO_WEB_CONFIG)" || { echo "No hay demo en marcha: lanza antes make demo (terminal 1)" >&2; exit 2; }; $(UV_VM) backtide web --config "$(DEMO_WEB_CONFIG)" --puerto $(DEMO_WEB_PORT) --rebobinar --aprobar'

probar: ## Prueba real: OpenClaw con Claude (MODEL=..., por defecto claude-sonnet-5-5; PERFIL=claude-code para Claude Code; LOCAL=<modelo de tu Ollama> en vez de Claude), en primer plano (terminal 1; docs/probar.md)
	@case "$(MODEL)" in ""|*[!0-9A-Za-z._:/@+-]*) echo "MODEL tiene caracteres raros" >&2; exit 2;; esac
	@case "$(FALSO)" in ""|1) ;; *) echo "FALSO solo puede valer 1" >&2; exit 2;; esac
	@case "$(LOCAL)" in *[!0-9A-Za-z._:/@+-]*) echo "LOCAL tiene caracteres raros" >&2; exit 2;; esac
	@case "$(PERFIL)" in ""|openclaw|claude-code) ;; *) echo "PERFIL es openclaw o claude-code" >&2; exit 2;; esac
	$(VM_SH) '$(PROBAR_VM) up --modelo $(MODEL) $(if $(FALSO),--internet-falso) $(if $(PERFIL),--perfil $(PERFIL)) $(if $(LOCAL),--local $(LOCAL))'

probar-web: ## Prueba real: la web con Ajustes, aprobar y rebobinar (abre el enlace en el Mac; docs/probar.md)
	@case "$(DEMO_WEB_CONFIG)$(DEMO_WEB_PORT)" in *"'"*) echo "no ' in DEMO_WEB_*" >&2; exit 2;; esac
	@if lsof -nP -iTCP:$(DEMO_WEB_PORT) -sTCP:LISTEN >/dev/null 2>&1; then \
	  echo "El puerto $(DEMO_WEB_PORT) del Mac ya está ocupado: Lima no podría reenviarlo y el enlace llegaría a otro programa" >&2; exit 2; fi
	$(VM_SH) 'test -f "$(DEMO_WEB_CONFIG)" || { echo "No hay prueba en marcha: lanza antes make probar (terminal 1)" >&2; exit 2; }; $(UV_VM) backtide web --config "$(DEMO_WEB_CONFIG)" --puerto $(DEMO_WEB_PORT) --ajustes --aprobar --rebobinar'

probar-pedir: ## Prueba real: un mensaje al agente y su respuesta (MSG="...")
	@test -n "$$MSG" || { echo 'Di qué le pides: make probar-pedir MSG="..."' >&2; exit 2; }
	@m=$$(printf '%s' "$$MSG" | base64 | tr -d '\n'); \
	$(VM_SH) '$(PROBAR_VM) pedir '"$$m"

probar-entrar: ## Prueba con Claude Code: ábrelo en tu terminal (CONTINUAR=1 sigue la última conversación)
	@case "$(CONTINUAR)" in ""|1) ;; *) echo "CONTINUAR solo puede valer 1" >&2; exit 2;; esac
	$(VM_SH) '$(PROBAR_VM) entrar $(if $(CONTINUAR),--continue)'

probar-tarea: ## Prueba con Claude Code: una tarea y su respuesta (MSG="..."; CONTINUAR=1 sigue la conversación)
	@test -n "$$MSG" || { echo 'Di qué le pides: make probar-tarea MSG="..."' >&2; exit 2; }
	@case "$(CONTINUAR)" in ""|1) ;; *) echo "CONTINUAR solo puede valer 1" >&2; exit 2;; esac
	@m=$$(printf '%s' "$$MSG" | base64 | tr -d '\n'); \
	$(VM_SH) '$(PROBAR_VM) tarea '"$$m"' $(if $(CONTINUAR),--continue)'

probar-importar: ## Prueba con Claude Code: copia una carpeta de la VM a su carpeta de trabajo (RUTA=...; REEMPLAZAR=1 escribe encima; SECRETOS=1 incluye lo que parece un secreto)
	@case "$(RUTA)" in ""|*[!0-9A-Za-z._/~+-]*) echo "Di la carpeta: make probar-importar RUTA=<ruta, sin espacios ni comillas>" >&2; exit 2;; esac
	@case "$(REEMPLAZAR)" in ""|1) ;; *) echo "REEMPLAZAR solo puede valer 1" >&2; exit 2;; esac
	@case "$(SECRETOS)" in ""|1) ;; *) echo "SECRETOS solo puede valer 1" >&2; exit 2;; esac
	$(VM_SH) '$(PROBAR_VM) importar $(if $(REEMPLAZAR),--reemplazar) $(if $(SECRETOS),--incluir-secretos) -- $(RUTA)'

probar-exportar: ## Prueba con Claude Code: copia su carpeta de trabajo a una carpeta nueva de la VM (RUTA=...; GIT=<carpeta> saca solo los commits de ese repositorio, como un bundle)
	@case "$(RUTA)" in ""|*[!0-9A-Za-z._/~+-]*) echo "Di la carpeta nueva: make probar-exportar RUTA=<ruta, sin espacios ni comillas>" >&2; exit 2;; esac
	@case "$(GIT)" in *[!0-9A-Za-z._/-]*) echo "GIT es una carpeta de /workspace/work, sin espacios ni comillas" >&2; exit 2;; esac
	$(VM_SH) '$(PROBAR_VM) exportar $(if $(GIT),--git $(GIT)) -- $(RUTA)'

probar-instantaneas: ## Prueba real: lista las instantáneas
	$(VM_SH) '$(PROBAR_VM) instantaneas'

probar-rebobinar: ## Prueba real: rebobina (ID=<instantánea>; SI=1 salta la pregunta)
	@case "$(ID)" in ""|*[!0-9A-Za-z._-]*) echo "Di la instantánea: make probar-rebobinar ID=<id> (mira make probar-instantaneas)" >&2; exit 2;; esac
	$(VM_SH) '$(PROBAR_VM) rebobinar $(ID) $(if $(SI),--si)'

probar-parar: ## Prueba real: para todo, desmonta y borra el volumen (y la clave que pusiste en Ajustes)
	$(VM_SH) '$(DEMO_VM) parar'

web-demo: ## Web demo on the Mac, no VM: made-up black box and snapshots + the web; Ctrl-C stops (docs/demo.md)
	@dir=$$(mktemp -d "$${TMPDIR:-/tmp}/backtide-web-demo.XXXXXX") || exit 1; \
	seeder=; trap 'kill $$seeder 2>/dev/null; rm -rf "$$dir"' EXIT INT TERM; \
	uv run python scripts/web-demo/seed.py "$$dir" --live >/dev/null & seeder=$$!; \
	n=0; while [ ! -e "$$dir/.ready" ]; do \
	  n=$$((n+1)); if [ $$n -gt 240 ]; then echo "The demo data did not appear" >&2; exit 1; fi; \
	  sleep 0.5; done; \
	uv run python scripts/web-demo/serve.py "$$dir/backtide.toml"

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

vm-estado: ## VM: contenedores con su CPU y memoria, restos de Docker, montajes btrfs y los 5 procesos que más CPU gastan
	$(VM_SH) 'sh scripts/vm-estado.sh'

vm-limpiar: ## VM: borra solo restos nuestros (backtide-*, vigia-demo-*, volúmenes sin usar); no toca imágenes. FORZAR=1 si hay pytest en marcha
	@case "$(FORZAR)" in ""|1) ;; *) echo "FORZAR solo puede valer 1" >&2; exit 2;; esac
	$(VM_SH) 'FORZAR=$(FORZAR) sh scripts/vm-limpiar.sh'

vm-down: ## Stop the VM
	limactl stop $(VM)

vm-delete: ## Delete the VM (your code stays on the Mac)
	limactl delete --force $(VM)
