# Arquitectura

```text
Obsidian (solo lectura) ─┐
                         ├─> enumeración segura ─> parser ─> SQLite/FTS5 ─> recuperación/graph/API
Hermes/Proyectos (docs) ─┘             └──────────> memoria derivada por proyecto
```

## Límites de datos

La política inicial de `source_policy.projects` excluye rutas convencionales de conversaciones, historiales de chat, logs y transcripciones, además de nombres de exportación conocidos; las listas se configuran en `config/settings.json`. La detección es por directorio/nombre, no por clasificación semántica: texto de conversación embebido en un archivo con nombre genérico no se reconoce automáticamente y requiere configurar la exclusión explícita. Los documentos técnicos sobre arquitectura conversacional fuera de esas rutas siguen siendo indexables.

La inspección de manifiestos de dependencias es de lectura acotada y con decodificación UTF-8 estricta. Cada proyecto guarda por separado el inventario y las advertencias; una advertencia solo contiene ruta relativa y clase del error, nunca contenido o mensaje de parser. La ficha generada y las proyecciones de Audit/HTTP validan y limitan esos metadatos, y los proyectos excluidos no se exponen.

`documents` guarda identidad, procedencia, hash, metadatos y el cuerpo derivado necesario para FTS5. `project_root_path` vincula documentos fuente, fichas y decisiones internas con la raíz exacta del proyecto; los filtros por ruta absoluta incluyen esos tipos sin mezclar proyectos homónimos. La ruta original y el hash permiten verificar que la fuente no fue sustituida. `document_chunks` permite devolver solo fragmentos. `links` clasifica `resolved`, `broken`, `ambiguous`, `external`, `attachment`, `directory` e `ignored`, con razón de resolución y línea de origen. Los destinos Markdown con espacios y Unicode se conservan íntegros; una carpeta existente no se presenta como nota. `link_suggestions` no altera el grafo factual.

La tabla `projects` mantiene `dependencies_json` con nombres y rutas relativas de manifiestos que los declararon y `dependency_errors_json` con pares de ruta relativa/clase de error para manifiestos inaccesibles, sobredimensionados o malformados. Los lectores son estáticos, limitados por bytes, número de manifiestos (20 por defecto) y entradas (500 por defecto); no ejecutan gestores ni instalan paquetes. Los límites se ajustan por `source_policy.projects`. La migración de advertencias es aditiva; las fichas generadas pasan a esquema 7. Audit y Level Up muestran estas incidencias como solicitudes de revisión, sin guardar ni devolver contenido del manifiesto o mensajes del parser. El endpoint del dashboard entrega solo proyecciones acotadas para proyectos activos; la exclusión oculta inventario y advertencias hasta reactivar el proyecto. Las dependencias son declaraciones, no evidencia de instalación, uso en ejecución ni decisiones arquitectónicas.

La recuperación FTS5 admite filtros por fuente, categoría, raíz absoluta de proyecto y etiqueta exacta. `--tag`/`tag` consulta la tabla indexada (acepta un `#` inicial) y filtra tanto documentos recientes como fragmentos citados; no requiere reconstruir el índice. `related` resuelve enlaces explícitos entrantes y salientes con deduplicación, además de sugerencias etiquetadas por separado.

La vista de proyecto del grafo puede expandirse a notas Obsidian mediante vecinos de `link_suggestions` solo cuando el usuario activa “sugerencias”. La respuesta marca estos nodos como `related_via_suggestion`, limita el total al presupuesto de nodos, no incluye otros proyectos/registros internos y la interfaz los etiqueta como hipótesis.

El contenido del índice es regenerable. El archivo original nunca se sobrescribe. Los cambios y eliminaciones se observan por `size_bytes`, `mtime_ns`, hash y tombstones de documentos eliminados. Las lecturas se serializan con un bloqueo local/proceso; un fallo de enumeración evita retirar registros antiguos. Los escaneos omiten symlinks y reparse-points de Windows. Las fichas se actualizan desde nombres y metadatos permitidos; un proyecto ausente tras un escaneo completo se marca `missing`, sin borrar su ficha Markdown.

Las copias SQLite usan la API online de backup, reservan el nombre para no sobrescribir respaldos previos, cambian el destino a `journal_mode=DELETE` y verifican integridad y claves foráneas antes de éxito. El `.db` queda autónomo, sin necesitar WAL/SHM; el destino se cierra explícitamente para liberar el archivo en Windows. La restauración exige `--yes`, valida esquema e integridad, prepara una copia en el mismo directorio y reemplaza de forma atómica; guarda un respaldo pre-restauración y se niega a reemplazar mientras haya sidecars WAL/SHM activos. Las escrituras atómicas de archivos propagan errores y conservan el original ante fallos.

## Cuatro C

- Context: `knowledge/`, metadata de proyectos y documentos indexados.
- Connections: fuentes locales configuradas; integraciones externas quedan desactivadas.
- Capabilities: CLI, FTS5, audit, link, onboard, level-up, interview y graph.
- Cadence: `python -m rabanito watch` ejecuta ciclos incrementales en foreground, solo cuando el operador lo inicia; intervalo configurable (60 min por defecto, mínimo 5), salida limitada a métricas sin rutas y stop por `Ctrl+C`. No crea tareas programadas/servicios ni se inicia con Hermes.
