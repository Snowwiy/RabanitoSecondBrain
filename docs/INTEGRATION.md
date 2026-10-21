# Integraciones preparadas, no instaladas

Los tres clientes llaman la misma CLI desde un checkout local autorizado con configuración privada y SQLite compartida. No existe dependencia del proveedor/modelo ni se inyecta toda la memoria.

## Paquetes y configuración

- Codex: `.agents/skills/rabanito-second-brain/SKILL.md`.
- Claude Code: `.claude/skills/rabanito-second-brain/SKILL.md`.
- Hermes: `skills/rabanito-second-brain/SKILL.md`, frontmatter escalar compatible con el parser inspeccionado.
- Comandos públicos: `integrations/CYBER_TOOLS.md`.

Las Skills usan `<SECOND_BRAIN_ROOT>` y `<ACTIVE_PROJECT_ROOT>`, no rutas personales. Antes de usarlas, establece el checkout y la raíz exacta del proyecto en el contexto local autorizado del cliente; no adivines rutas ni ejecutes literalmente los marcadores. Valida Python/FTS5 con el preflight. El intervalo comprobado en el checkout Hermes inspeccionado es 3.11–3.14; no certifica futuras versiones.

## Instalación posterior autorizada

No ejecutar contra perfiles globales durante el desarrollo. El operador debe resolver el directorio real de Skills de su cliente/perfil y autorizar esa escritura. Desde el checkout, con una raíz existente y explícita:

En Hermes, el nombre visible no es necesariamente el ID o nombre de carpeta.
Un perfil raíz puede mostrar un nombre personalizado y seguir siendo `default`;
no construir `profiles/<nombre visible>` por conjetura. La presencia de un home
en disco tampoco acredita el perfil de la sesión activa. Desktop distingue la
preferencia del próximo arranque del perfil que lanzó su backend, y puede usar
otra conexión. Confirmar home/backend real antes de elegir `<SKILL_ROOT_AUTORIZADO>`;
no abrir registros de conexión con credenciales ni iniciar Hermes CLI para averiguarlo.

```powershell
& '.\integrations\scripts\Install-HermesSkill.ps1' -SkillRoot '<SKILL_ROOT_AUTORIZADO>' -WhatIf
& '.\integrations\scripts\Install-HermesSkill.ps1' -SkillRoot '<SKILL_ROOT_AUTORIZADO>'
```

Para Codex/Claude, usar `Install-CodexSkill.ps1` / `Install-ClaudeSkill.ps1`. El instalador conserva un manifiesto/hash, rechaza reparse points, no reemplaza destinos ajenos/modificados y es idempotente para una copia idéntica. No activa hooks, MCP, servicios, tareas ni routing. El SkillRoot de Hermes debe pertenecer al perfil elegido, no a una ubicación supuesta.

## Prueba, actualización y reversión

1. En el cliente real: preflight, `stats`, `context` acotado con filtro exacto de proyecto y citas; `cyber context` y `security context` offline. No guardes una decisión sintética en memoria real.
2. Solo registra memoria privada después de mostrar el borrador y obtener aprobación explícita, con evidencia y validación.
3. Para actualizar: desinstala la copia intacta con el script del mismo cliente/raíz y luego instala la versión revisada. Un destino editado o con archivos adicionales queda protegido; no fuerces su reemplazo.
4. Reversión: `& '.\integrations\scripts\Uninstall-HermesSkill.ps1' -SkillRoot '<SKILL_ROOT_AUTORIZADO>' -WhatIf`; ejecutar sin `-WhatIf` solo tras autorización. Equivalentes Claude/Codex disponibles. Solo elimina la copia poseída e intacta, no la memoria ni las notas.
5. Recuperación: conserva configuración privada y respaldos fuera de Git. Revisa `backup` / `restore --help` antes de una restauración explícita. No reemplaces una DB en uso.

## Evidencia y límites

Se prueban formatos, preflight y scripts en raíces temporales Unicode, además de recuperación CLI local. También se ensayaron el [cargador completo de Hermes](HERMES_LOADER_VALIDATION.md) y su [handler nativo de terminal](HERMES_TERMINAL_VALIDATION.md), con dependencias existentes y un home temporal: cuatro consultas de memoria real coincidieron con la CLI directa, conservaron citas y límites históricos y no instalaron un perfil.

Esto no equivale a instalar o validar sesiones nuevas de Hermes Desktop, Claude Code, Opus/Luna ni OAuth. El perfil real puede usar otros permisos, runtime o home mode; debe verificarse en la etapa autorizada de activación. No se modifica Jev, perfiles o configuración global para certificar compatibilidad. Los metadatos de hooks no son memorias verificadas: la captura automática queda pendiente de revisión/autorización.
