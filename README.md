# Vigía

Caja negra para agentes de IA: graba desde fuera todo lo que hace tu agente, te deja rebobinar a cualquier momento y frena lo irreversible antes de que salga a internet.

> En desarrollo. Nombre provisional.

- Producto: docs/07-producto-caja-negra-para-agentes.md (internal note)
- Plan y arquitectura: docs/08-plan-de-desarrollo.md (internal note)
- Tareas: docs/backlog.md (internal note)

## Desarrollo

Necesitas macOS con [uv](https://docs.astral.sh/uv/) y [Lima](https://lima-vm.io/).

```bash
make vm-up   # crea y arranca la VM Fedora de desarrollo
make test    # tests unitarios
make it      # tests de integración dentro de la VM
make help    # todos los comandos
```
