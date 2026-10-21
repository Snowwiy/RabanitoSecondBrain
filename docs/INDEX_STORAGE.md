# Indexación: almacenamiento protegido y recuperación de perfiles

La indexación mantiene su esquema, IDs y respuestas, pero ya no confía en rutas
derivadas o en `data_dir` sin comprobarlas. Tres regresiones reales demostraron
escapes por junction en perfiles/historial y SQLite creado sobre una fuente.

## Antes de escribir

- El arranque `load_settings` valida todas las ubicaciones antes de inicializar
  data/knowledge y fija sus padres nativos mientras los crea. Conserva el inicio
  portable, pero una configuración que solapa fuentes (incluso desactivadas) se
  rechaza antes de mkdir. No abre DB ni crea el lock; sus identidades siguen
  siendo responsabilidad de cada operación. No es un cargador puramente de lectura:
  puede crear los dos directorios propios cuando todavía no existen.
- El mutex valida su directorio y fija sus padres y lock nativos de Windows antes
  de crearlos. Admite también callers públicos/minimales sin fuentes privadas.
  No abre una base por sí mismo. El binding de almacenamiento se vuelve a comprobar
  después de esperar el lock.
- La ejecución de indexación valida `knowledge`, datos y DB dentro del checkout,
  sin solapamiento con fuentes incluso desactivadas ni reparse points. Una copia
  restaurada puede estar en otra carpeta del mismo root, no necesariamente `data`.
- El indexador fija los directorios de perfiles e historial antes de abrir SQLite.
  DB/sidecars se verifican por HANDLE contra hardlinks y redirecciones; los pins
  de sidecars se liberan antes del cierre de SQLite para no impedir su limpieza.
- `projects --json` usa el mismo contexto protegido para descubrir y persistir
  metadatos. No cambia la regla de primer nivel y raíces VCS propias.

En `index_all` con Settings explícitos, una fuente interna ausente no se recrea
para simular un escaneo correcto. Se
conserva el estado `partial`/`error` y no se tombstonean sus documentos. Si esa
fuente está inaccesible no se genera el JSON de historial allí; `scan_runs` sigue
siendo el registro autoritativo de la ejecución.
La inicialización de directorios propios del cargador CLI es una operación
anterior distinta, descrita arriba; no es una recuperación implícita del motor.

## Perfiles: texto manual y colisiones

Solo se escriben `knowledge/projects/<carpeta>/PROJECT_MEMORY.md`. Las lecturas
existentes son acotadas, UTF-8 y con identidad de archivo verificada; no se siguen
hardlinks o junctions para determinar si un perfil pertenece a un proyecto.
Se conserva la lógica de regiones generadas y texto manual existente.

Un perfil sin cambios no se reescribe ni genera backup. Para actualizarlo:

1. Se comprueban los bytes actuales contra la versión leída.
2. Se rota el archivo anterior a un nombre privado único `.rabanito-profile-*.bak`.
3. Se vuelven a comprobar esos bytes, manteniéndolos abiertos en solo lectura, y
   se publica la nueva versión completa con rename sin reemplazo.

El backup conserva el perfil completo anterior, incluido el texto manual. No se
indexa como otra nota ni se elimina automáticamente. Una edición concurrente se
detecta y se intenta restaurar sin sobrescribir un nombre ocupado. Si no puede
restaurarse, `ProfileRecoveryError` informa `project_profile_recovery_required` y
una ruta relativa `backup`; se conservan tanto la copia anterior como el trabajo
concurrente. Revisarlos antes de restaurar o limpiar manualmente.

Esta rotación no es una transacción de dos nombres: el nombre público puede faltar
brevemente y los lectores deben manejar ausencia/cambio. No hay truncado in-place
ni una promesa de atomicidad conjunta con SQLite. Tras un corte abrupto, conservar
backups y reindexar desde fuentes autorizadas después de revisar contenido manual.
Límite de2MiB por perfil; no se repara silenciosamente un perfil inválido.

## Bitácora y alcance

El historial usa publicación atómica sin reemplazo, hasta8MiB por archivo y1000
alternativas ante colisión. No sustituye un registro previo si coinciden relojes.
Un fallo del JSON posterior al commit no revierte la DB; consultar `scan_runs` y
reintentar una indexación normal, sin forzar ni modificar fuentes.

El mutex protege el binding/directorio del lock, no certifica por sí solo todos
los callers que abren SQLite. Los guards de DB descritos aquí pertenecen al
contexto del indexador. No se cambian esquemas aplicados, configuraciones globales,
repositorios fuente, reglas de evidencia ni permisos de Skills.

## Pruebas

```powershell
python -B -m unittest discover -s tests -p test_index_storage.py -v
python -B -m unittest discover -s tests -p test_config_storage.py -v
python -B scripts/validate_index_storage.py
```

Regresiones nativas de escapes, cambios de directorio/archivo, hardlinks, recovery,
IDs/mtime, copias restauradas, mutex minimal y fuentes ausentes. El script ejecuta
nueve CLI con fuentes sintéticas: rechazo antes de DB, descubrimiento, incremento,
texto manual/backup íntegros, no duplicación, contexto citado y backup/restauración
reales con dos FTS. No captura conocimiento de producción ni envía datos a red.
