# Contrato local para el frontend existente y futuro

Servidor HTTP Python estándar, bind `127.0.0.1:8765`. Conservar el frontend actual. No incorporar worktrees ni rediseñar estilos en la fase de backend. Los handlers y pruebas de integración son la fuente de verdad: `rabanito/server.py`, `tests/test_knowledge_api.py`, `tests/test_core.py`.

## Transporte y seguridad

JSON UTF-8. Las consultas que pueden contener texto privado utilizan POST, no URLs. Validar Host y Origin locales, `Content-Type: application/json`, tamaño y campos; no habilitar CORS público. GET de rutas de consulta devuelve error para evitar filtrar términos en URLs. Las respuestas pueden contener datos privados: no persistirlas en almacenamiento del navegador, telemetría ni logs. Usar DOM textContent, nunca HTML del documento. Esta protección no convierte un servicio loopback en autenticación multiusuario.

## Rutas vigentes

| Operación | Método/ruta | Datos principales |
| --- | --- | --- |
| Salud y resumen | GET `/api/health`, `/api/stats` | métricas locales |
| Estado de conectores | GET `/api/cyber/status` | fuentes, fechas, scope/backlog y staging |
| Documentos y contexto | POST `/api/search`, `/api/context` | q, source, category, project_id, tag, limit/max_chars |
| Detalle y relaciones | GET `/api/doc/{id}`, `/api/related/{id}` | identificador devuelto por búsqueda |
| Markdown autorizado | POST `/api/doc/content` | `document_id` indexado y `max_bytes` 1..65536; vista UTF-8 de solo lectura, sanitizada y limitada; nunca recibe rutas |
| Proyectos y metadatos | GET `/api/projects`, `/api/categories`, `/api/tags` | inventario autorizado/acotado |
| Historial | GET `/api/scans`, `/api/changes` | metadatos acotados; no explica causas |
| Decisiones | POST `/api/decisions` | filtros de proyecto/consulta |
| CVE/avisos | POST `/api/cyber/search`, `/api/cyber/get` | q/source/kev/since/min_epss/sort/limit/offset o id |
| Estándares | POST `/api/security/search`, `/api/security/get` | q/framework/kind/status/limit/offset o id |
| Experiencias revisadas | POST `/api/coding/similar`, `/api/coding/patterns` | q, project, technology, limit/max_chars según operación |
| Grafo | POST `/api/graph` | domain documents/cyber/security, filtros y limit; no inventar aristas |
| Auditoría | GET `/api/audit/latest`; POST `/api/audit` | auditoría local; no sincroniza por sí sola |
| Sincronización | POST `/api/index`, `/api/cyber/sync` | Cyber: source, ids opcional de máximo un ID, confirm_public_sync=true |
| Fuentes | GET `/api/sources`; POST `/api/source-preview`, `/api/source-approve`, `/api/source-impact`, `/api/source-toggle` | preview/impacto antes de aprobar; conservar permisos |
| Exclusiones | POST `/api/project-exclusion` | alcance exacto aprobado |
| Abrir original | POST `/api/open/{id}` | solo IDs existentes/rutas autorizadas, no rutas arbitrarias |

Consultar las validaciones del handler para los nombres exactos/campos opcionales. No ampliar silenciosamente límites ni convertir `null` en acceso global. No todas las operaciones CLI tienen endpoint: inspección de dependencias, VEX y captura revisada no deben simularse desde la UI.

### `POST /api/doc/content`

Usa el contrato reconciliado en `FRONTEND_BACKEND_CONTRACT.md`. Acepta exactamente `document_id` (entero seguro positivo) y `max_bytes` (entero entre 1 y 65,536), sin claves duplicadas, query string o rutas. Requiere `Host`/`Origin` loopback del mismo puerto, JSON UTF-8 y un cuerpo máximo de 2,048 bytes; `GET` devuelve 405. La respuesta exacta es `{document_id,content_markdown,bytes_returned,truncated,references[]}` y lleva `Cache-Control: no-store`.

El backend solo resuelve IDs activos y revalida fuente, exclusiones, proyecto, rutas y estado antes de leer. Lee por descriptor/handle de solo lectura, aplica límite UTF-8 y redacción de patrones detectables de credenciales/rutas, y nunca indexa ni actualiza el archivo. Un documento cambiado devuelve 409; no dispara indexado automático. Referencias son solo enlaces explícitos resueltos y autorizados, acotados a 512. Errores estructurados: 400 entrada/codificación, 403 origen/formato, 404 ausente o no autorizado, 409 fuente obsoleta/no disponible, 413 límite, 503 índice no disponible. No se devuelven rutas absolutas ni errores del SO.

## Estados que no deben ocultarse

- Consultas vacías o sin datos, cobertura parcial y truncamiento son estados distintos de error.
- Conservar citas, líneas/localizadores, fecha de consulta, versión y procedencia.
- Cyber: `partial` reanudable conserva datos sin publicar; repetir explícitamente la sincronización continúa staging. Un timeout del navegador no prueba que una escritura falló: consultar estado antes de repetir.
- Grafo: respetar IDs/tipos y totales/truncamiento. Las sugerencias no son enlaces factuales ni aplicabilidad a proyectos.
- Coding Memory: `passed_as_recorded_not_rerun` no representa una prueba recién ejecutada. No promover propuestas a confirmadas desde el frontend.

Las pruebas HTTP, Python y JavaScript verifican contratos/estados; la QA visual real del Inspector Markdown se completó el 2026-10-20. La certificación con lector de pantalla y la QA visual integral del resto de vistas siguen pendientes.
