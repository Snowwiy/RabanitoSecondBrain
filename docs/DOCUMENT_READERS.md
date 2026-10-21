# Consultas documentales sin inicialización persistente

Las consultas de búsqueda/contexto, detalle, relaciones, estadísticas, Audit,
decisiones, cambios y grafo documental no deben ejecutar migraciones, crear
índices SQL ni rellenar columnas de documentos al abrir la base. La resolución
de IDs/proyectos y las vistas previas de impacto siguen esa misma regla.
Los campos HTTP/CLI, filtros, límites, IDs y citas no cambian.

## Apertura y primer uso

Las vistas documentales usan una conexión `mode=rw` sin creación, con
`PRAGMA query_only=ON` antes de las consultas. Esa conexión rechaza DML y DDL,
sin ejecutar el inicializador de `Database`. No usa `immutable` ni ignora WAL:
debe ver cambios confirmados por escritores concurrentes.

SQLite conserva su coordinación y cierre seguro de WAL/SHM. No se promete cero
I/O físico: su mantenimiento puede consolidar transacciones ya confirmadas.
Abrir siempre con `mode=ro` dejó auxiliares después del último lector en una
regresión de restauración. No se borran auxiliares manualmente ni se relaja la
protección de restauración para ocultarlo. El modo estricto `read_only=True`
de los lectores públicos/KG y otros callers anteriores no cambia.

Si todavía no existe el índice, `empty_if_missing=True` conserva la respuesta
vacía anterior mediante un esquema temporal en RAM, también query-only. No crea
la base o sus padres. `parser_version=null`, ausencia de scan o resultados vacíos
no prueban cobertura/frescura: indexar es una operación explícita diferente.
El cargador de configuración puede preparar sus directorios propios autorizados;
eso no inicializa SQLite desde la consulta.

Un archivo existente vacío, corrupto o con otro esquema no se interpreta como
índice ausente ni se repara silenciosamente. Los errores de almacenamiento siguen
el manejo existente del caller. Una migración/reconstrucción requiere la operación
de indexación explícita y un respaldo verificado, no volver a consultar para repararla.

## Respaldos y recuperación

La lectura del origen de `backup` y del respaldo previo de `restore` tampoco debe
ejecutar backfills/DDL. `backup` requiere un índice persistente existente: no crea
un índice vacío para presentar esa creación como un respaldo de memoria previa.
Esta es una precondición deliberada frente al antiguo bootstrap implícito.
La restauración sigue exigiendo `--yes`, preserva el respaldo previo y rechaza
auxiliares de una base activa; no hay restauración automática desde una consulta.

## Alcance de seguridad

No se expone SQL arbitrario. La precomprobación de rutas rechaza reparse points
inspeccionados; no es una sandbox del SO ni garantiza identidad continua frente
a un administrador que sustituya rutas concurrentemente. Obsidian y proyectos
siguen siendo fuentes de solo lectura, independientes de la base derivada.
Indexación, generación de sugerencias y otras escrituras explícitas conservan sus
locks, guardas e inicialización; no se cambia globalmente todo constructor SQLite.

```powershell
python -B -m unittest tests.test_document_readers -v
```

La regresión inicial reprodujo backfills/DDL y creación persistente desde lecturas
en fixtures, incluidos handlers HTTP. Las comprobaciones cubren salida vacía,
query-only, esquema existente incorrecto, rutas redirigidas y convivencia con WAL.
Los resultados actuales de la matriz completa se registran por separado; estos
fixtures no representan nuevas memorias confirmadas o una activación de clientes.
