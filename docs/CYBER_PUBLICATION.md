# Publicación incremental Cyber y limpieza FTS

`sync_source` conserva la transacción de publicación: observaciones, aliases,
revisiones, entidades agregadas, FTS, caché y watermark solo se confirman cuando
el ámbito está completo. Staging NVD y los límites de red no cambian.

La limpieza FTS usa lotes de hasta 500 identificadores afectados y respeta el
límite de parámetros de la conexión. Los valores se enlazan como parámetros,
nunca se interpolan como SQL. `vulnerability_id` es una columna FTS5 no indexada:
agrupar la limpieza evita recorrer toda la tabla una vez por entidad.

Después de limpiar se reconstruyen únicamente las entidades afectadas, incluidas
las identidades anteriores cuando cambian aliases o se retiran observaciones.
Se eliminan todas las filas FTS duplicadas de esas identidades, no las ajenas.
Si falla la reconstrucción, el caller revierte la transacción completa. No hay
limpieza global, nueva migración, DDL modificada o cambio del contrato HTTP/CLI.
Los `rowid` internos de FTS no son IDs públicos ni referencias de documentos.

Requisitos conservados: Python 3.11+ (`Connection.getlimit`) y SQLite con FTS5.
No se instala ninguna dependencia. El cambio actúa en publicaciones posteriores;
consultar el índice no lo migra ni escribe automáticamente.

```powershell
python -B -m unittest tests.test_cyber_fts_batch tests.test_cyber_pending tests.test_cyber_history -v
```

Las regresiones prueban lotes, presupuesto reducido de parámetros, duplicados,
aliases heredados tratados como datos, filas ajenas, retiros, metadata de consulta,
historial sin versiones falsas y rollback después de la limpieza. No usan red ni
persisten experiencias sintéticas como conocimiento de producción.

Un replay offline del mismo lote público de 2.759 registros, sobre dos copias
del mismo respaldo histórico, midió 57,041 s antes y 1,713 s después para publicar
y confirmar, con perfilador activado: 2.759 borrados frente a seis. Coincidieron
huellas lógicas de observaciones/aliases/entidades/FTS/historia, consultas y
contexto; se excluyó únicamente el `recorded_at` del reloj del replay de la
comparación histórica. Fechas de fuente y recuperación se conservaron.

Son mediciones de ese host/dataset, no un SLA, una sincronización nueva del
proveedor o una promesa de velocidad de red. Backups, lectura y normalización
quedan fuera de ese tiempo. La cobertura y el backlog se consultan por separado
en `cyber status`; una optimización local no vuelve frescos los datos existentes.
