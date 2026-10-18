# Reutilización local de análisis de inventarios

El motor de dependencias6 puede reutilizar informes guardados explícitamente por `dependency snapshot --save`. Consultar con `dependency inspect`, previews y vistas VEX **no escribe ni crea un caché**. No se descubren inventarios automáticamente ni se envían nombres de paquetes a APIs. El cambio de motor por pylock.toml invalida resultados anteriores sin borrarlos ni migrarDDL; el motor5 había ampliado el orden PEP440 y el4 añadido uv.lock.

No añade esquema: usa `dependency_analyses` existente con migración1/checksum intactos. `dependency_cache.py` contiene únicamente lectura, identidad/checksum y anotaciones. Un snapshot de un motor anterior permanece conservado; no se recicla como resultado del motor nuevo. La próxima operación de guardado autorizada agrega el nuevo análisis.

## Uso

```powershell
python -m rabanito dependency inspect --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json'
python -m rabanito dependency snapshot --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json' --save
python -m rabanito dependency inspect --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json'
```

También funciona con los manifiestos admitidos (`--manifest requirements.txt`, `package-lock.json`, `uv.lock` o `pylock[.nombre].toml`). La primera consulta sin un snapshot compatible devuelve `cache.status=computed`. Tras un guardado explícito, una consulta compatible devuelve `reused_saved_analysis`: evita parsear de nuevo el inventario, los payloads OSV y los rangos de versiones. Sigue leyendo/hashando los bytes autorizados y comprobando metadatos locales; no es coste cero ni un benchmark de latencia garantizada.

`analyzed_at` conserva la fecha de evaluación guardada; `cache.checked_at` indica la verificación actual de entradas. `cache.validation=current_inventory_bytes_and_local_osv_metadata`; no prueba estado instalado, mitigación aplicada ni frescura mundial de OSV. `cache.writes=0` describe la inspección, no el comando explícito de guardado que la invoque.

## Invalidación y aislamiento

La firma de entrada incluye motor, tipo, proyecto/raíz/nombre autorizados (la raíz solo entra al digest, no se expone), ruta relativa, SHA256 de bytes, configuración/política y metadatos del prefijo OSV examinado: IDs/fingerprints/fechas/tamaños y total de registros activos. Se revalidan permisos, exclusiones y archivo antes de buscar el informe. Cambios de igual tamaño/mtime, raíz reubicada, nuevo motor/límites, revisión/retirada OSV o cobertura diferente obligan a recomputar. Una nueva observación después del prefijo acotado también invalida la antigua afirmación de cobertura completa.

Metadatos y payloads OSV pertenecen a la misma transacción de lectura SQLite: una publicación concurrente no mezcla dos revisiones. No se mantienen conexiones ni objetos de notas en un caché global. Cambios ajenos del conjunto OSV examinado o de fechas pueden provocar misses conservadores; se prefiere perder una reutilización a afirmar frescura incorrecta.

Límites de bytes/componentes/observaciones/candidatos siguen vigentes; máximo32MiB de payloads OSV examinados y4MiB por informe reutilizable. Los objetos JSON/estructuras añaden overhead; no se promete un límite exacto deRAM. Excluir una extensión explícitamente también bloquea el inventario/evidencia correspondiente. Extensiones permitidas para indexación documental no convierten el inspector en un lector indiscriminado de archivos.

## Corrupción, seguridad y recuperación

Se comprueban schemas/checksums conocidos, identidad/scope de la fila, tipo de informe, tamaño y `result_sha256`. Duplicados JSON o no-finitos no son resultados válidos. Un informe corrupto no se reutiliza: la lectura calcula de nuevo sin alterar el guardado. Intentar guardar el mismo ID inválido falla con `existing_analysis_not_reusable_review_required`, conservando el registro para revisión/recuperación; no afirma que lo haya reparado.

El checksum detecta corrupción accidental, **no autentica contra un administrador que pueda falsificar la DB y recalcular hashes**. Los fingerprints OSV son los de la publicación normalizada local; no se valida de nuevo por Internet. Todo contenido sigue siendo dato no confiable, nunca instrucción de agente.

Antes de cualquier recuperación que sustituya el índice, respaldar y probar restauración en un destino temporal con los comandos existentes; detener escritores antes de reemplazar la DB viva. No editar ni borrar filas para ocultar un error. Una consulta nueva funciona sin confiar en el resultado corrupto, pero la reparación persistente requiere revisión explícita.

VEX no participa como supresión ni como entrada a la evaluación OSV: el candidato original permanece, aunque exista un claim `not_affected`. Las vistas decoradas con revisiones no son lo que se persiste como análisis base: separan su checksum como `analysis_result_sha256`, no presentan el hash anterior como checksum del cuerpo modificado. Backup/restore conserva snapshots y permite reutilizarlos cuando sus entradas y permisos aún coinciden.

## Pruebas

`python -B -m unittest tests.test_dependency_cache -v` usa fixtures locales. Comprueba hits sin parseo/evaluación, lecturas sin escrituras/migraciones/red, igualmtime/tamaño, cambios OSV/cobertura/fecha/motor/límites, exclusiones, corrupción, esquema desconocido, concurrencia, manifiestos, restore y VEX sin supresión. No equivale a haber inspeccionado un inventario privado de producción ni demostrado una vulnerabilidad instalada.
