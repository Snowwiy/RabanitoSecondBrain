# Rabanito Second Brain

Memoria técnica local, incremental y trazable para documentación Markdown, Obsidian y proyectos de software. Recupera fragmentos con citas y conserva decisiones revisadas e inteligencia pública de vulnerabilidades, sin depender de un modelo de IA ni enviar conocimiento privado a Internet.

## Funcionalidades reales

- Indexación incremental de documentos, frontmatter YAML común, etiquetas, wikilinks, enlaces relativos y rutas Unicode; detección de modificaciones, ausencias, duplicados y referencias ambiguas.
- Búsqueda SQLite FTS5 con ranking, fragmentos y citas de archivo/línea; filtros de fuente, categoría, etiqueta y proyecto, con presupuestos de contexto.
- Descubrimiento de proyectos de primer nivel y raíces VCS propias anidadas. Fichas derivadas de documentación/metadatos: no copia repositorios ni ejecuta manifiestos.
- Decisiones y experiencias con estados explícitos, evidencia y revisión humana; recuperación similar y recurrencias descriptivas, no entrenamiento.
- Onboard, Audit, Link, Level Up y entrevistas que requieren aprobación para guardar. Las sugerencias y contradicciones heurísticas no son hechos confirmados.
- Cyber Threat Knowledge: CISA KEV, NVD, FIRST EPSS y OSV; procedencia, fechas, consultas offline, caché HTTP, límites y sincronización explícita. La paginación NVD densa conserva checkpoints y publica solo ventanas completas.
- Security Architecture: catálogo inicial de 28 referencias, controles y conceptos con resúmenes propios sobre Zero Trust y estándares. No es una biblioteca normativa completa ni prueba de cumplimiento.
- Inspección defensiva offline de CycloneDX/SPDX, package-lock npm y requisitos Python exactos contra OSV local. Devuelve candidatos, no vulnerabilidad demostrada ni estado instalado.
- Dashboard local y grafo 3D de datos reales; vistas separadas de documentos, vulnerabilidades y estándares. Sin CDN, telemetría ni servicios públicos obligatorios.
- Respaldos SQLite verificados, restauración protegida, bloqueos de escritura y migraciones aditivas.

## Arquitectura

Python estándar contiene indexador, recuperación, CLI y servidor HTTP. Una SQLite/FTS5 comparte dominios con tablas/esquemas separados; Markdown conserva memoria revisable y JSON configuración e intercambio. El frontend existente usa HTML, JavaScript y canvas locales.

| Componente | Ubicación |
| --- | --- |
| Documentos, proyectos y memoria | `rabanito/` |
| Vulnerabilidades y sincronización | `rabanito/cyber/` |
| Estándares y subgrafos públicos | `rabanito/security.py`, `rabanito/public_graph.py` |
| Configuración portable y catálogo | `config/` |
| Dashboard existente | `web/` |
| Skills y scripts reversibles | `.agents/`, `.claude/`, `skills/`, `integrations/scripts/` |
| Pruebas reproducibles | `tests/` |

Ver [arquitectura](ARCHITECTURE.md), [contratos HTTP](docs/API_CONTRACT.md), [dependencias](DEPENDENCY_SECURITY.md), [Coding Memory](CODING_MEMORY.md) y [conectores adicionales](VENDOR_CONNECTORS.md).

## Requisitos

- Windows nativo y Python 3.11+ con SQLite FTS5. La matriz actual se ejecuta en Python 3.14.7 / SQLite 3.53.1; no certifica todos los intérpretes soportados.
- Cero dependencias Python de terceros para ejecutar desde el checkout. No requiere WSL, Docker ni API de IA.
- PowerShell para instaladores opcionales y sus pruebas. Node.js solo para pruebas JavaScript, no para servir el dashboard.
- Internet solo para actualizar fuentes públicas y Git; las consultas del índice funcionan offline.

## Preparación e inicio

En PowerShell, desde la raíz del checkout:

```powershell
python -c "import sys,sqlite3; print(sys.version); c=sqlite3.connect(':memory:'); c.execute('CREATE VIRTUAL TABLE probe USING fts5(body)'); print('FTS5 OK')"
```

Si falla, selecciona explícitamente un intérprete compatible ya instalado; no cambies configuraciones globales.

En un checkout nuevo, copia la configuración **solo si no existe**:

```powershell
if (Test-Path -LiteralPath 'config/settings.json') { throw 'Conserva y revisa la configuración existente.' }
Copy-Item -LiteralPath 'config/settings.example.json' -Destination 'config/settings.json'
```

Revisa ese JSON antes de indexar. `vault_root` y `projects_root` apuntan a carpetas vacías de ejemplo bajo `sources/`: sustitúyelas por fuentes autorizadas o crea esas carpetas para probar sin datos privados. `project_root: "."` se resuelve respecto a la raíz del checkout. Las salidas `knowledge_dir` y `data_dir` deben permanecer en el proyecto, nunca en una fuente original. Conserva exclusiones y host `127.0.0.1`.

```powershell
python -m rabanito --help
python -m rabanito index
python -m rabanito stats
python -m rabanito search "arquitectura" --limit 8
python -m rabanito context "decisiones de almacenamiento" --max-chars 6000
python -m rabanito audit
python -m rabanito security index
python -m rabanito security context "Zero Trust" --max-chars 4000
python -m rabanito dashboard
```

Dashboard: [http://127.0.0.1:8765/](http://127.0.0.1:8765/). Detener con Ctrl+C. No instala servicios ni tareas.

Git **no contiene la memoria del usuario**. Un checkout nuevo no tiene notas, proyectos indexados, decisiones privadas ni bases. Se generan desde fuentes autorizadas. Una fuente inaccesible produce cobertura parcial/error, no un escaneo vacío válido; se conservan sus documentos anteriores.

## Inteligencia pública y mantenimiento

```powershell
python -m rabanito cyber status
python -m rabanito cyber sync --source kev
python -m rabanito cyber sync --source nvd
python -m rabanito cyber search --kev --limit 10
python -m rabanito cyber context "Log4j" --max-chars 4000
python -m rabanito cyber pending
python -m rabanito backup
```

NVD procesa ventanas de modificaciones, no todo su histórico. `backlog` y límites forman parte del resultado. Un `partial` reanudable se continúa repitiendo NVD; exit code sigue siendo 1. EPSS/OSV son selectivos: ausencia de un aviso no significa seguridad. CVSS, EPSS y explotación observada son señales distintas. Cadencia desactivada por defecto.

Guía: [integrations/CYBER_TOOLS.md](integrations/CYBER_TOOLS.md). No enviar notas, código, nombres privados de paquetes ni informes locales a APIs públicas.

## Agentes

Skills preparadas para Claude Code, Codex y Hermes consultan la misma CLI y DB local. Sustituye `<SECOND_BRAIN_ROOT>` y `<ACTIVE_PROJECT_ROOT>` por rutas autorizadas verificadas en cada entorno: no ejecutar literalmente esos marcadores.

[Instalación reversible](docs/INTEGRATION.md), sin cambios globales automáticos. Las pruebas de formato/CLI no validan por sí solas una sesión real de todos los clientes/modelos. No se modifican Jev, perfiles ni OAuth.

## Pruebas

```powershell
python -B -m unittest discover -s tests -v
python -B -O -m unittest discover -s tests -v
node --test tests/test_cyber_ui.mjs tests/test_graph_filter.mjs tests/test_knowledge_ui.mjs
```

Fixtures bajo `tests/.test-temp/`, sin notas/credenciales reales. Las pruebas de red reales son separadas: un fixture no valida un proveedor. [Estado y limitaciones](docs/PROJECT_STATUS.md).

## Privacidad y respaldo

Fuentes originales de solo lectura; documentos importados son datos no confiables, nunca instrucciones ni autorizaciones para ejecutar comandos. El dashboard no es multiusuario ni debe exponerse por túneles o puertos públicos.

Git incluye código, pruebas, documentación técnica y configuración de ejemplo. Excluye `data/`, `knowledge/`, configuración real, checkpoints privados, logs, cachés, entornos, bases, respaldos, secretos y exportaciones. Ignorar no sustituye revisar blobs e historial: [publicación segura](docs/PUBLICATION.md).

GitHub respalda el **software**, no las notas ni la memoria operativa. Conserva fuentes y respaldos privados por separado. No se publica una licencia de uso: queda pendiente de decisión del propietario.
