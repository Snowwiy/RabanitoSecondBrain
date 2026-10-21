# Contrato local para el frontend existente y futuro

Servidor HTTP Python estándar, bind `127.0.0.1:8765`. Conservar el frontend actual. No incorporar worktrees ni rediseñar estilos en la fase de backend. Los handlers y pruebas de integración son la fuente de verdad: `rabanito/server.py`, `tests/test_knowledge_api.py`, `tests/test_core.py`.

## Transporte y seguridad

ASVS registrado conserva `asvs.assessment=not_performed`, `source_dataset` y `source_license` con commit/SHA/atribución/CC BY-SA 4.0; `knowledge_type=licensed_publisher_requirement` no es un resumen propio ni prueba de cumplimiento. El filtro `level` es L exacto del editor, no un perfil acumulativo. Ver [contrato ASVS](ASVS.md). Captura y registro son operaciones CLI explícitas, sin endpoints nuevos ni red implícita en búsquedas.

JSON UTF-8. Las consultas que pueden contener texto privado utilizan POST, no URLs. Validar Host y Origin locales, `Content-Type: application/json`, tamaño y campos; no habilitar CORS público. GET de rutas de consulta devuelve error para evitar filtrar términos en URLs. Las respuestas pueden contener datos privados: no persistirlas en almacenamiento del navegador, telemetría ni logs. Usar DOM textContent, nunca HTML del documento. Esta protección no convierte un servicio loopback en autenticación multiusuario.

## Rutas vigentes

[Retiro incremental protegido](INDEX_RETIREMENT.md): no se retiran filas de una
raíz anterior por escanear otra del mismo tipo. Cobertura incompleta y caídas
masivas producen `partial`/`error`, no `ok`. POST `/api/index` no habilita aprobación
de retiros ni cambia sus campos compactos; leer `status`, no solo HTTP200. La CLI
completa expone cobertura/plan y un flag de aprobación exacta, nunca un bypass.

[Autorización de fuentes](SOURCE_AUTHORIZATION.md): los lectores documentales
ocultan caché de raíces retiradas, cambiadas o deshabilitadas antes de recuperar
resultados. Misma API; sin borrar el índice ni exigir sincronización para revocar.

[Inventario de Audit](AUDIT_INVENTORY.md): sección aditiva `source_inventory`,
metadata-only y acotada. Distingue archivos elegibles aún no indexados y cobertura
parcial; no cambia contadores previos, no indexa ni incorpora proyectos. El
contrato se documentó antes de implementar la ampliación. Level Up consume estos
avisos con el formato de recomendaciones existente; no añade campos o rutas ni
autoriza una sincronización implícita.

[Lecturas documentales](DOCUMENT_READERS.md): mismas respuestas/campos, sin
DDL/backfills implícitos al consultar. Primera consulta sin índice usa una vista
vacía en RAM, no crea la base persistente. Un esquema existente inválido no se
oculta como base vacía. Los respaldos requieren un índice persistente existente.

[Lecturas KG](GRAPH_SNAPSHOT.md): reutilizan una prueba global completa solo en
el mismo snapshot limpio; mismos campos, cursores, permisos y presupuestos.

[Publicación Cyber](CYBER_PUBLICATION.md): limpieza FTS por lotes en la misma
transacción, sin campos/rutas/esquemas nuevos. Preserva atomicidad, fechas,
historial y límites de proveedores; no sincroniza ni migra por una consulta.

[Contexto Cyber por proveedor](CYBER_CONTEXT.md): corrección de recuperación
Python y selector CLI opcional `cyber context --source`; no añade ruta HTTP ni
campos al lector Markdown. Sin selector conserva el contexto multisource.

[Indexación protegida](INDEX_STORAGE.md): mismas respuestas y descubrimiento;
IDs estables al actualizar perfiles, copias anteriores recuperables y bitácora
sin reemplazo. No hay nuevas rutas ni migraciones de API por este almacenamiento.
El arranque CLI valida y fija los directorios propios antes de inicializarlos;
conserva su contrato de configuración portable. No añade campos HTTP ni implica
que todas las operaciones que abren SQLite compartan el guard del indexador.

[Informes generados](REPORT_STORAGE.md): `audit --write`/`level-up` conservan sus
campos y ubicación; publicación protegida sin nuevos endpoints. Una exportación
fallida entre formatos no devuelve un par completo ni borra trabajo concurrente.

La protección de [publicación de decisiones](DECISION_STORAGE.md) corresponde a
la CLI/API Python, no agrega endpoints de escritura. POST `/api/decisions` sigue
siendo una consulta; el lector POST `/api/doc/content` conserva su contrato.

[Grill Me](INTERVIEWS.md) también sigue siendo CLI interactiva: revisión del
candidato exacto y `APROBAR` antes de publicación. No se expone un escritor de
entrevistas por HTTP ni se amplían los campos del lector Markdown.

El guardado de experiencias documentadas es exclusivamente CLI, con revisión
humana previa y digest exacto; ver [Documented Memory](DOCUMENTED_MEMORY.md).
No añade endpoint ni campos a `/api/doc/content`. Sus eventos de `/api/scans`
usan `partial`/files_seen=1/source_summary.internal porque solo se indexó una
nota, no se sincronizaron todas las fuentes. No interpretar ese evento como
frescura de Obsidian, proyectos o conectores públicos. No cambia los enums
existentes ni requiere un renderer nuevo.

| Operación | Método/ruta | Datos principales |
| --- | --- | --- |
| Salud y resumen | GET `/api/health`, `/api/stats` | métricas locales |
| Estado de conectores | GET `/api/cyber/status` | fuentes, fechas, scope/backlog y staging |
| Documentos y contexto | POST `/api/search`, `/api/context` | q, source, category, project_id, tag, limit/max_chars |
| Detalle y relaciones | GET `/api/doc/{id}`, `/api/related/{id}` | identificador devuelto por búsqueda |
| Proyectos y metadatos | GET `/api/projects`, `/api/categories`, `/api/tags` | inventario autorizado/acotado |
| Historial | GET `/api/scans`, `/api/changes` | metadatos acotados; no explica causas |
| Decisiones | POST `/api/decisions` | filtros de proyecto/consulta |
| CVE/avisos | POST `/api/cyber/search`, `/api/cyber/get` | q/source/kev/since/min_epss/sort/limit/offset o id |
| Revisiones observadas | POST `/api/cyber/history` | id, source opcional, limit0–50, before opcional positivo; metadata/cursor/activación |
| Estándares | POST `/api/security/search`, `/api/security/get` | q/framework/kind/status/release/level/limit/offset o id; release exacta revisada, level entero 1–3 para L exacto ASVS; no evaluación ni consulta online de última edición |
| Experiencias revisadas | POST `/api/coding/similar`, `/api/coding/patterns` | q, project, technology, limit/max_chars según operación |
| Experiencias documentadas de entorno | POST `/api/coding/documented` | q/context/technology/limit/max_chars; aprobación registrada, evidencia parcial/pendiente, fully_verified=false; sin registro de proyectos ni promoción |
| Grafo | POST `/api/graph` | domain documents/cyber/security, filtros y limit; no inventar aristas |
| Grafo unificado paginado | POST `/api/knowledge-graph`, `/api/knowledge-graph/neighbors` | filtros tipados, cursor, máximo200; vecinos requiere id; include_inactive booleano para flags históricos ATT&CK; solo lectura |
| Proyección explícita del grafo | POST `/api/knowledge-graph/sync` | confirm_graph_sync=true, max_inputs1–5000, max_bytes8–64MiB; partial reanudable |
| Auditoría | GET `/api/audit/latest`; POST `/api/audit` | auditoría local; no sincroniza por sí sola |
| Sincronización | POST `/api/index`, `/api/cyber/sync` | Cyber: source, ids opcional de máximo un ID, confirm_public_sync=true; MSRC requiere month YYYY-Mmm en lugar de ids, no acepta rutas/capture |
| Fuentes | GET `/api/sources`; POST `/api/source-preview`, `/api/source-approve`, `/api/source-impact`, `/api/source-toggle` | preview/impacto antes de aprobar; conservar permisos |
| Exclusiones | POST `/api/project-exclusion` | alcance exacto aprobado |
| Abrir original | POST `/api/open/{id}` | solo IDs existentes/rutas autorizadas, no rutas arbitrarias |
| Lector Markdown real | POST `/api/doc/content` | document_id entero positivo seguro JS, max_bytes entero1–65536; ambos obligatorios, sin campos extra/duplicados. Lectura RO sin sincronizar; formato compatible con Frontend-Design |

`/api/changes` aplica autorización actual de origen, asociación y elegibilidad
documental antes del límite de eventos, incluidos contextos de entorno excluidos.
No elimina filas históricas, reconstruye el índice ni oculta eventos de borrado
de documentos cuyo origen y ruta siguen autorizados. Mismos campos y filtros;
la configuración se evalúa con un snapshot por consulta.

Consultar las validaciones del handler para los nombres exactos/campos opcionales. No ampliar silenciosamente límites ni convertir `null` en acceso global. No todas las operaciones CLI tienen endpoint: inspección de dependencias, VEX y captura revisada no deben simularse desde la UI.

Security source_release admite publicación YYYY-MM cuando la fuente no da día y devuelve published_on_precision="month". Verificación/revisión siguen siendo YYYY-MM-DD; los objetos diarios anteriores no cambian. CISA2.0 conserva2023-04 sin inventar2023-04-01. LOCAL-ZT/LOCAL-ZTMM son identificadores locales de conceptos, no control IDs normativos o madurez local. Ver [catálogo](SECURITY_CATALOG.md); no se añade endpoint ni scoring de cumplimiento.

El análisis de dependencias CLI/programático usa engine_version6 y conserva el formato existente de citas/localizadores/cobertura; admite uv.lock, pylock1.0 seleccionado y orden público PEP440 acotado. Pylock añade coverage.selection/identity/artifacts y metadata de ámbito/artefactos declarados, nunca URLs/paths de orígenes ni verificación de attestations. Evidencias `pep440_public_version_equivalence`, `local_build_applicability_not_verified` y `oversized_affected_versions` no son estados de instalación/seguridad. Ver [PEP440](PEP440.md), [uv.lock](UV_LOCK.md) y [pylock](PYLOCK.md). No existe un endpoint HTTP nuevo para inspeccionar rutas de manifiestos ni persistir esos informes.

## Estados que no deben ocultarse

El [contrato exacto del lector Markdown](../FRONTEND_BACKEND_CONTRACT.md) fija
cinco campos: document_id/content_markdown/bytes_returned/truncated/references.
Referencias explícitas resueltas y reautorizadas, máximo512; ningún caller path.
El contenido es una vista UTF-8 no confiable con redacción de patrones sensibles,
no una exportación byte a byte. Un cambio desde el índice devuelve409, no refresca
fuentes. Errores JSON `{"error":"codigo_estable"}`, Cache-Control:no-store.
El cuerpo JSON se limita a2048bytes, el original y el texto devuelto al presupuesto
solicitado; no se siguen reparse/symlinks ni se envía contenido a proveedores.
Consultar la sección de límites para prefijos truncados y protección DLP parcial.

MITRE ATT&CK® separa la [cuarentena](ATTACK_CAPTURE.md) de la
[publicación SQLite/FTS/API](ATTACK_INDEX.md). No es una fuente `cyber sync`.
`attack_capture.capture_release` descarga un dominio/edición/commit/blob/tamaño
explícitos y su licencia; `attack.inspect_capture` valida offline;
`attack.capture_context` devuelve `{total_matches, fragments, used_chars,
max_chars, truncated, requests:0, database_written:false, retrieval,
license, license_sha256, untrusted_data:true}`. Cada fragmento lleva STIX ID,
tipo, ATT&CK IDs, versión, modified, flags, cita al blob fijado, locator JSON,
SHA256, edición, captured_at y text_truncated. `attack context` sin `--capture`
consulta FTS; `attack index --capture` es publicación local explícita por CLI.
POST `/api/attack/{status,search,get,context,relations,history}` ofrece solo lectura,
con whitelists de campos, límites/tipos/booleans estrictos y rechazo de claves
duplicadas. Ver tabla exacta y respuestas en ATTACK_INDEX. No hay endpoint de
indexado/captura ni selección arbitraria de rutas. Get sin matches404, ambigüedad
200 con bandera; GET405. El [grafo backend ATT&CK](ATTACK_GRAPH.md) usa las rutas KG
existentes, kinds nuevos, source=attack y category=dominio. Por defecto oculta
revoked/deprecated (también SRO/endpoints); include_inactive=true conserva flags,
no revive retirados ni altera permisos. Cursores ligados a esa opción. No hay
renderer nuevo ni prueba de controles implantados, explotación o aplicabilidad.

- Consultas vacías o sin datos, cobertura parcial y truncamiento son estados distintos de error.
- Conservar citas, líneas/localizadores, fecha de consulta, versión y procedencia.
- Cyber: `partial` reanudable conserva datos sin publicar; repetir explícitamente la sincronización continúa staging. Un timeout del navegador no prueba que una escritura falló: consultar estado antes de repetir.
- Grafo: respetar IDs/tipos y totales/truncamiento. Las sugerencias no son enlaces factuales ni aplicabilidad a proyectos.
- Coding Memory: `passed_as_recorded_not_rerun` no representa una prueba recién ejecutada. No promover propuestas a confirmadas desde el frontend.
- Historia Cyber: disponible solo después de migración3 durante sync explícito; baseline perezoso y ninguna historia anterior inventada. Lista vacía no implica vulnerabilidad ausente. [Contrato](CYBER_HISTORY.md).
- Grafo unificado: [contrato completo](KNOWLEDGE_GRAPH.md). No sustituir la vista existente todavía. Page entrega raíces, neighbors un salto; respetar cursor, requires_sync, claims/sugerencias y presupuestos. Las lecturas no crean la proyección ni refrescan fuentes. No enviar datos privados a servicios de layout externos.

Las pruebas HTTP y JavaScript verifican contratos/estados; la QA visual y de lector de pantalla permanece pendiente.
