# Transporte real de herramientas Hermes, en hogar temporal

El validador opt-in importa los módulos completos reales de `tools.skills_tool`
y `tools.terminal_tool`, y utiliza el handler nativo `_handle_terminal` para
consultar la CLI del Second Brain. No es un mock, AST aislado, conversación de
un modelo, instalación en Rabanito ni lanzamiento de Hermes CLI.

## Reproducir

Antes de ejecutar, inspeccionar la revisión local de Hermes y los scripts de
inicio del Git for Windows indicado. Sustituir los marcadores por rutas reales:

```powershell
& '<Python Windows compatible ya instalado>' -B scripts/validate_hermes_terminal.py --hermes-repo '<checkout Hermes inspeccionado>' --git-root '<Git for Windows inspeccionado>'
```

Debe existir configuración del Second Brain en este mismo checkout, documentos
autorizados con fragmentos coincidentes y una experiencia documentada revisada
recuperable por la consulta fija. Si faltan datos, devuelve validación incompleta;
no fabrica notas, instala dependencias, registra proyectos o confirma memorias.
Python debe coincidir exactamente con la selección PM existente (3.11–3.14).

## Alcance de la comprobación

- Home temporal dentro de `tests/.test-temp`, con solo la Skill de este repo y
  configuración de fixture. Ningún perfil real se copia, instala o modifica.
- Terminal local nativo, sin Docker/WSL. Hermes utiliza Bash de Git for Windows,
  no PowerShell. Se respeta su resolver; el audit hook solo admite el Git
  inspeccionado. No se fuerza un reemplazo de backend ni se repara su instalación.
- `TERMINAL_HOME_MODE=profile` aplica el contrato nativo de hogar aislado en el
  proceso hijo. No cambia el HOME del host. No hereda credenciales, `BASH_ENV`,
  `PYTHONPATH`, YOLO ni configuraciones privadas del agente.
- Carga la Skill completa, comprueba su cuerpo y ejecuta cuatro consultas fijas:
  estadísticas, contexto Obsidian160chars, contexto proyectos160chars y memoria
  documentada200chars. No extrae comandos de notas ni de resultados.
- Compara cada JSON con la CLI directa; verifica IDs, autorización actual, rutas
  y líneas físicas de los dos contextos. La experiencia debe conservar sus límites
  `partial`/`pending`, sin convertirse en solución históricamente verificada.
- Solo imprime metadatos/booleanos/contadores/hashes de código; no fragmentos,
  títulos, rutas privadas, excepciones con contenido ni logs capturados. Verifica
  originales indexados, estadísticas y huellas de código/arranque antes/después.
- Exige limpieza del entorno y temporal. Exit0 solo con todas las comprobaciones;
  exit1 significa resultado incompleto. No reejecutar si un proceso sigue vivo.

La suite habitual prueba su contrato sin importar Hermes. El ensayo real es una
operación separada y explícita, no una prueba simulada de proveedores.

## Seguridad y límites

El audit hook rechaza red Python, lecturas sensibles y escrituras Python fuera
del temporal, salvo el dispositivo NUL; se prueba una denegación sintética. La
excepción para `secrets.py` es únicamente el módulo estándar del runtime, no
credenciales. El guard distingue el formato Windows de `Popen`, que puede traer
`executable=None` y una cadena de argumentos renderizada.

Es defensa adicional para código local inspeccionado, **no sandbox del SO**:
los procesos nativos y sus descendientes no heredan el audit hook de Python.
Por eso solo se ejecutan las consultas fijas y los scripts de inicio revisados,
con hogar vacío/aislado. El ensayo histórico precede a las
[vistas documentales query-only](DOCUMENT_READERS.md), que ya no inicializan
DDL/backfills desde consultas. Igualdad de estadísticas por sí sola sigue sin
demostrar igualdad de todas las columnas o ausencia de mantenimiento físico WAL.
No se indexa, sincroniza, llama a un modelo ni promueve conocimiento.

Probes opcionales de procedencia Git, Linux/container y red pueden quedar
rechazados; no se relajan controles para satisfacerlos. Una disponibilidad de
terminal en este fixture no demuestra que el perfil real use igual runtime,
permisos o home mode. No valida sesiones Opus/Luna/Claude, Jev/OAuth, UI, permisos
globales ni un aislamiento forense de toda la máquina. La activación sigue
requiriendo su etapa autorizada; no ejecutar Hermes CLI/bootstrap para forzarla.
