# Revisiones observadas de vulnerabilidades

Backend `rabanito/cyber/history.py`, migración Cyber3 **aditiva**. DDL1 y DDL2 permanecen exactamente iguales. Actualizar un binario/checkout no migra una base al consultar: la migración se aplica únicamente durante una sincronización explícita, con backup íntegro previo. El ledger registra activación y checksum.

## Consulta local acotada

```powershell
python -m rabanito cyber history CVE-2021-44228 --limit 20
python -m rabanito cyber history CVE-2021-44228 --source nvd --limit 10
```

API programática: `vulnerability_history(settings, identifier, source=None, limit=20, before=None)`. HTTP local: POST `/api/cyber/history`, JSON `{"id":"CVE-2021-44228","source":"nvd","limit":20}`; `before` es un cursor positivo de revisión, no una fecha. Respuesta metadata-only, máximo50elementos por página, `next_before`, total y truncamiento explícitos. No devuelve payloads completos, notas ni rutas locales. El endpoint usa las mismas protecciones loopback/Origin/JSON del servidor; GET no consulta filtros en URL. El dashboard aún no tiene una vista histórica nueva.

## Qué demuestra y qué no

- `observed`, `modified`, `reactivated` y `retired` describen cambios de contenido/estado realmente publicados en la base local. Sin cambios de fingerprint/actividad no se añade otra revisión aunque se refresque la fecha de consulta.
- `baseline_captured` conserva la fila anterior que realmente existía cuando se observa su primer cambio tras activar la función. No es una descarga de historia del proveedor ni una fecha inventada de publicación/decisión.
- `retrieved_at` conserva la consulta del dato; `recorded_at` cuándo se capturó la revisión y `source_modified` la fecha declarada por el proveedor. No son intercambiables. En una retirada de snapshot, el payload/consulta anterior se conserva y el evento se registra al observar su ausencia; no implica que la vulnerabilidad haya dejado de existir.
- Baseline perezoso: registros preexistentes sin cambios todavía no tienen revisiones. Una lista vacía **no significa que no haya una vulnerabilidad local**; consultar `cyber get`. Antes de migración, `history_available=false` declara explícitamente la ausencia de esta capacidad en esa base.
- Los aliases se conservan por revisión para encontrar referencias antiguas aunque el proveedor las cambie. Un GHSA con varias CVE es un aviso que las referencia, no prueba que sean equivalentes. Cada resultado conserva su `source` y `source_id`, indicando si coincidió por alias.

La ordenación/cursor usa el ordinal local de revisión, no pretende reconstruir una secuencia global perfecta por fechas del proveedor. El texto público sigue siendo dato no confiable, nunca instrucciones del agente.

## Atomicidad, integridad y crecimiento

Snapshots vigentes, entidades, FTS, caché, watermark y revisiones comparten la transacción de publicación. Páginas NVD pendientes no añaden revisiones. Fallar al publicar revierte también la historia; una observación staged más vieja protegida por `protect_newer` no genera una versión falsa. Duplicados de una misma respuesta tampoco crean eventos extra.

`cyber_revisions` conserva el payload normalizado y metadatos; `cyber_revision_identifiers` permite búsquedas indexadas por referencias y cursor, sin analizar todos los JSON para listar. Solo se almacenan cambios observados; no hay purga automática de historia. El espacio crecerá según los cambios públicos realmente sincronizados. El máximo por registro permanece2MiB y las consultas no cargan esos cuerpos. Una futura política de archivo/retención requerirá una decisión explícita, no eliminación silenciosa.

Los respaldos/restauración existentes incluyen estas tablas. Migraciones fallidas conservan el ledger y los datos anteriores; las lecturas verifican el checksum de la migración de historia. Las bases/respaldos siguen en `data/`, excluidos de Git. Este desarrollo posterior al respaldo inicial no se publica automáticamente.

## Evidencia de pruebas

15regresiones locales: arranque sin DB/upgrade2→3, baseline honesto, deduplicación, modificaciones, retirada/reactivación, aliases cambiantes, rollback, páginas pendientes, protección de datos posteriores, cursor/límites, backup/restore, checksum, CLI/HTTP y error seguro ante DB corrupta. Inicialmente se corrigieron dos expectativas de fixtures: el normalizador conserva `Z` y un KEV vacío debe fallar cerrado, así que se usa un snapshot no vacío para demostrar retirada. No se relajó esa protección.

La ejecución integral y eventual migración real se registran separadamente en los checkpoints locales; una prueba fixture no demuestra cambios históricos reales de un proveedor.
