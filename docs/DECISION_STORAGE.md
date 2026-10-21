# Publicación segura de decisiones de proyecto

`decision add` conserva su formato Markdown y sus campos de respuesta. La
protección de almacenamiento ya no confía únicamente en `mkdir` y una escritura
atómica: una junction preexistente podía redirigir una nota a una fuente importada.
La regresión se reprodujo y corrigió con fixtures; no se usaron notas privadas.

## Frontera de escritura

- Escritura con semántica nativa de Windows; otros sistemas fallan de forma
  explícita. Las consultas no adquieren esta dependencia de escritura.
- `knowledge` y `data` deben estar dentro del root autorizado del checkout, ser
  distintos y no solaparse con ninguna fuente importada, incluso desactivada.
- Se rechazan traversal, nombres de dispositivo/ADS, reparse points, y hardlinks
  de DB, lock y sidecars existentes antes de abrir el índice.
- Se reutilizan los HANDLEs de directorios que niegan borrado/renombrado durante
  la publicación. El proyecto debe continuar activo y autorizado bajo el lock.
- Se aplica la política interna de extensiones/exclusiones y un límite de64KiB
  UTF-8 por nota, o el límite configurado si es menor. No se ignora una exclusión
  solo porque la escritura provenga de un agente.
- La publicación usa temporal propio, flush/fsync y rename sin reemplazo. Una
  colisión no sobrescribe trabajo ajeno; un fallo limpia solo ese temporal.

La API Python `add_memory_record` acepta opcionalmente `config_path` para
recomprobar y fijar la configuración del caller bajo el lock. La CLI siempre lo
proporciona. Sin él, la API usa una copia de los `Settings` explícitos del caller,
no pretende descubrir ni actualizar configuración global.

## Lo que no cambia

La aprobación humana sigue siendo una responsabilidad explícita del caller y
las Skills: la seguridad de rutas no autentica consentimiento. Una referencia
local existente no demuestra por sí sola una causa histórica ni que se haya
ejecutado una prueba. `passed_as_recorded_not_rerun` mantiene ese límite.

El escritor Python crea la nota y solo consulta un índice existente, sin DDL ni
indexación implícita. La CLI mantiene sus actualizaciones incrementales comunes
antes y después de la captura; rechaza una junction conocida antes del primer
refresh. No cambia el esquema, la API HTTP ni instala hooks. No sustituye la
autorización de configuración/fuentes de la aplicación ni es un sandbox del SO.

Este flujo antiguo conserva nombres cronológicos, no un identificador idempotente
por borrador. Si se guarda una nota y falla una indexación posterior, conservarla
y ejecutar una sincronización autorizada; no repetir ciegamente `decision add`.
Para experiencias ambientales con aprobación exacta y reintento idempotente usar
el flujo separado [Documented Memory](DOCUMENTED_MEMORY.md).

## Pruebas

```powershell
python -B -m unittest discover -s tests -p test_decision_storage.py -v
python -B scripts/validate_decision_storage.py
```

Las regresiones prueban junctions reales, sustitución de directorios, colisiones,
fallos de publicación, hardlinks, exclusiones, límites, configuración cambiada,
concurrencia y recuperación citada. El segundo comando ejecuta cuatro CLI reales
en raíz sintética, bloquea una junction antes de crear el índice, guarda/recupera
un fixture y verifica backup/restauración y dos FTS. Nunca confirma una experiencia
de producción ni escribe en fuentes reales o perfiles externos.
