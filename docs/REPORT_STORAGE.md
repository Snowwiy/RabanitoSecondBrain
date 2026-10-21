# Informes generados: aislamiento y publicación

`audit --write` y `level-up` conservan sus respuestas y rutas relativas
`json_path`/`markdown_path`, bajo `knowledge/quality-reports/`. El `audit` sin
`--write` sigue siendo una consulta sin exportación de informes. No hay nuevos
campos ni endpoints; la acción existente del dashboard conserva su contrato.

Dos regresiones demostraron que el escritor anterior aceptaba `knowledge`
solapado con una fuente y podía seguir una junction creada después del primer
check. La publicación ahora reutiliza las protecciones nativas ya probadas.

## Controles

- Windows nativo; otros sistemas fallan de forma explícita al exportar.
- Raíces propias dentro del checkout, separadas de fuentes incluso desactivadas.
  Se rechazan reparse points y se fijan padres mediante HANDLEs durante toda la
  publicación; el lock compartido no puede ser un hardlink ajeno.
- JSON estricto y Markdown UTF-8 se serializan antes de crear archivos. Máximo
  de8MiB por formato, con nombres acotados y hasta1000alternativas de colisión.
- Temporal propio, flush/fsync y rename sin reemplazo. No se sobrescriben archivos
  existentes ni se borran rutas publicadas al fallar, porque otro actor podría
  haberlas sustituido.
- La CLI pasa su `config_path`, revalidado y fijado bajo lock. La API Python lo
  acepta opcionalmente; de otro modo usa una copia de los `Settings` del caller,
  sin consultar configuración global. Esta capa no abre ni inicializa SQLite.

La exclusión de `quality-reports` del **índice** evita autoindexar informes, no
desactiva esta exportación explícita. Los informes se construyen con las vistas
metadata-only existentes: no incorporan notas completas, valores sensibles ni
raíces absolutas de las fuentes. El almacén no sustituye esas proyecciones de
privacidad ni transforma el contenido en instrucciones.

## Fallos entre los dos formatos

Cada archivo se publica completo y atómicamente; dos nombres no son una
transacción del sistema de archivos. Si falla el segundo, puede quedar un primer
archivo completo y recuperable. `ReportPublicationError` indica
`generated_report_pair_incomplete` y expone al caller Python los artefactos
relativos conocidos en `published`. Nunca se devuelve éxito de un par incompleto.

No borrar automáticamente esos archivos ni los que aparezcan concurrentemente.
Un reintento selecciona otro nombre sin reemplazarlos. Revisar un artefacto sin
contraparte antes de cualquier limpieza autorizada. Los temporales de la propia
operación se limpian; un corte abrupto puede dejar temporales y requiere revisión,
no una afirmación de atomicidad conjunta o recuperación mágica tras apagar el SO.

## Validación

```powershell
python -B -m unittest discover -s tests -p test_report_storage.py -v
python -B scripts/validate_report_storage.py
```

19regresiones nuevas cubren los escapes, pins, serialización/tamaño, colisiones,
fallos parciales recuperables, configuración cambiada, ausencia de SQLite y
reportes mayores que el presupuesto de notas documentadas. Los tests existentes
de exclusividad y ocho escritores concurrentes se conservan. El script ejecuta
seis CLI con fuentes sintéticas, dos pares, contexto citado y backup/restauración
con dos FTS, sin modificar notas originales o memorias de producción.
