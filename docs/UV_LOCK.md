# Inventario defensivo de uv.lock

Lectura local de un archivo seleccionado, no ejecución de uv ni resolución de dependencias. Mantiene el proyecto original en solo lectura y contrasta únicamente con el OSV ya presente en SQLite. No transmite nombres de paquetes, rutas, credenciales ni consultas privadas a APIs.

```powershell
python -m rabanito dependency inspect --project '<PROYECTO_ACTIVO_EXACTO>' --manifest 'uv.lock'
```

## Contrato y alcance

Se inspeccionaron las fuentes oficiales de [estructura del proyecto](https://docs.astral.sh/uv/concepts/projects/layout/), [fuentes de dependencias](https://docs.astral.sh/uv/concepts/projects/dependencies/) y [workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/), además del [modelo del lock](https://raw.githubusercontent.com/astral-sh/uv/main/crates/uv-lock/src/lock/mod.rs), [serialización](https://raw.githubusercontent.com/astral-sh/uv/main/crates/uv-lock/src/lock/serialize.rs) y [deserialización](https://raw.githubusercontent.com/astral-sh/uv/main/crates/uv-lock/src/lock/deserialize.rs). La ubicación antigua en uv-resolver respondió404; la implementación revisada reside en uv-lock. No se instaló ni ejecutó ese código.

El lector propio usa tomllib de Python3.11+, admite version1 y revisiones0–5 verificadas; revision ausente significa0. Una revisión futura o versión desconocida falla cerrada. Exige requires-python, pero no evalúa esa expresión. Este lector estructural de inventario no afirma conformidad completa con el formato de uv, que es específico del proveedor.

uv.lock es universal:puede contener versiones y fuentes alternativas, paquetes de extras/grupos y miembros de workspace. **Presencia en el lock no demuestra instalación, selección para Windows ni despliegue productivo.** Se recorren todos los registros package; no se resuelve alcanzabilidad, marcadores, extras o grupos, ni se abre pyproject.toml. La cobertura del informe lo declara.

| Fuente declarada | Identidad usada para OSV | Tratamiento |
| --- | --- | --- |
| registry exactamente https://pypi.org/simple, con slash final opcional | PyPI + nombre normalizado | Contraste de versión declarada, no origen atestiguado |
| Otro registro, mirror o registro local | Sin ecosistema confirmado | needs_review, sin asumir equivalencia con PyPI |
| git, url, path, directory, editable, virtual | Sin ecosistema confirmado | needs_review; no fetch, includes, comandos o seguimiento de archivos |
| Fuente ambigua/desconocida o identidad no válida | No resuelta | needs_review; valores sensibles no se copian al informe |

No se deduce PyPI por un nombre conocido. Tampoco se importan URLs de wheels/sdist ni metadatos arbitrarios. Las referencias de origen/condiciones se conservan como SHA256 de ámbito, no como texto de rutas, marcadores o URLs potencialmente privadas. El nombre y versión de un inventario pueden ser privados:conservar el informe localmente.

## Evidencia, duplicados y límites

`source.sha256` vincula el informe a los bytes seleccionados. Cada componente/finding usa un pointer como `/package/3`:es un localizador del **árbol TOML decodificado**, no un JSON original ni número de línea inventado. `locator_kind=parsed_toml_tree` lo declara. Una cadena multilínea con texto `[[package]]` no crea una entrada falsa.

Coordenadas públicas iguales con el mismo ámbito se consolidan y conservan hasta5localizadores adicionales. Alternativas con condiciones o fuentes diferentes permanecen separadas. Identidades no confirmadas no se fusionan por similitud de nombre. `inventory_scope_sha256` participa en el ID del nodo de dependencias; los IDs anteriores sin ese campo permanecen estables. El grafo distingue procedencia y environment_selection, sin aristas de vulnerabilidad probada.

Conserva los límites configurables de dependency_analysis:bytes2MiB por defecto (máximo16MiB),2000registros y cobertura OSV/findings acotada. El cap se aplica antes de deduplicar. Además hay límites de100000nodos TOML/64niveles y de listas/texto de marcadores. tomllib carga el archivo acotado en memoria; no es un parser streaming ni un deadline CPU absoluto. Errores TOML/no-finitos se convierten en códigos estáticos, sin repetir líneas privadas.

El contraste usa [orden PEP440 acotado](PEP440.md) para versiones públicas, incluidos epochs, pre/post/dev y normalización. Builds locales/formas no soportadas continúan needs_review salvo evidencia literal positiva aplicable. No evalúa specifiers ni resuelve entornos. `potentially_affected` es candidato contra un aviso local; `outside_observed_ranges`/`no_local_advisory` nunca significa seguro. No ejecuta pruebas ni aplica actualizaciones.

## Caché, memoria y grafo

Motor de análisis6 invalida reutilización de informes anteriores, conservando los snapshots. El loader TOML acotado se comparte con pylock; se conservan presupuestos y errores públicos de uv. No altera DependencySCHEMA1 ni crea tablas al consultar. Solo puede reutilizar un análisis guardado explícitamente con bytes/permisos/OSV/configuración compatibles. Guardar snapshots, decisiones o VEX mantiene su autorización/revisión independiente; no hacerlo por acelerar una lectura.

El motor del grafo3 conserva KG1, añade ámbito de inventario a identidades uv y su procedencia. Actualizar la proyección exige graph-sync explícito y un recorrido completo; no reconstruye las fuentes. El renderer y la API anteriores se conservan.

## Validación repetible y ejemplo público

```powershell
python -B -m unittest tests.test_uv_lock -v
python -B scripts/validate_uv_lock.py capture
python -B scripts/validate_uv_lock.py rehearse '<manifest_devuelto.metadata.json>'
```

capture consulta **un blob público fijo** del repositorio astral-sh/uv, no una URL libre ni un archivo local. Límite2MiB de cuerpo/4MiB de respuesta, sin proxy/credenciales/redirecciones, verifica el objeto Git y conserva SHA256/bytes/procedencia en data/uv-lock-research ignorado. No incluye un actualizador general de lockfiles, SDK, comandos de instalación ni búsquedas de paquetes. Es una herramienta de ensayo, no un conector periódico del núcleo.

rehearse no realiza red:verifica el cuerpo capturado y crea un proyecto público temporal en una copia de la base real para contrastarlo con OSV local. Guarda un snapshot **solo en la copia**, prueba reutilización/grafo/SQLite/FK/4FTS y restauración, elimina ese temporal y no cambia la base operativa ni registra un inventario privado como evaluado.

Captura real17oct2026:blob31308b5bda05d7dcab481e3a4b576542a622f321,349106bytes,SHA2564530569df205f5a85c63e76c7a06c76e78354a56d609d640d11641a2163c6de2.96componentes/0duplicados, revisión5. Ensayo offline:95sin aviso local y1needs_review, contra **una sola observación OSV local**;0findings no acredita seguridad.96nodos temporales, reutilización y restauración iguales,0requests externos durante ensayo. No se ha analizado ni guardado un inventario privado de producción en esta etapa.
