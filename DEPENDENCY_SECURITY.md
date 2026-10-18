# Análisis defensivo local de dependencias

`dependency inspect` es un lector de inventarios y un contraste offline con el OSV que ya existe en SQLite. No instala paquetes, ejecuta código, modifica repositorios ni consulta APIs con nombres privados. No es un escáner del estado instalado ni una validación completa de los esquemas SBOM.

Además de `--sbom`, admite `--manifest "package-lock.json"` (npmv2/v3) o `--manifest "requirements-dev.txt"` con declaracionesPython exactas. Son opciones excluyentes. Lee solo el archivo seleccionado: nunca sigue includes de pip, URLs, gestores, workspaces o enlaceslocales. Directivas/URLs/expansiones se omiten y cuentan, sin copiarlas al informe. Marcadores, comodines y alias/versiones dudosas quedan needs_review. Un mismo paquete npm puede tener ámbitosdev/no-dev; la deduplicación conserva ambos, no supone despliegueproductivo.

También admite [uv.lock seleccionado](docs/UV_LOCK.md), version1/revisiones0–5:lectorTOMLstdlib, alternativas universales no evaluadas como instalación. Solo coordenadas del registro públicoPyPI declarado se contrastan automáticamente; registros privados/mirrors/Git/path/workspace siguen needs_review. Orígenes y condiciones se conservan por hash sin copiar URLs/rutas/secretos ni seguirlos. `/package/N` es localizador del árbolTOML, no JSON ni líneas inventadas.

También admite [pylock.toml/pylock.nombre.toml](docs/PYLOCK.md) PyPA1.0: distingue artefactos PyPI públicos declarados de índices privados, paths, VCS, directorios y archivos directos; no descarga artefactos, verifica attestations ni evalúa condiciones. `/packages/N` es localizador del árbol TOML y los hashes declarados no son hashes verificados. No escanea automáticamente esos archivos en proyectos.

Desde `<SECOND_BRAIN_ROOT>`:

```powershell
python -m rabanito dependency inspect --project "Nombre exacto del proyecto" --sbom "docs/inventario.json"
```

El proyecto debe existir como activo en el inventario actual y no estar excluido. La ruta JSON es relativa a ese proyecto; se rechazan traversal, ADS de Windows, symlinks/junctions, archivos sensibles y directorios excluidos. Un proyecto padre no puede consultar el SBOM de una raíz de proyecto anidada registrada. No se descubren ni leen SBOM automáticamente.

## Formatos e identidad

- Subconjunto de CycloneDX JSON1.4–1.6: `components`, incluidos componentes anidados, `name`, `group`, `version`, `purl`.
- Subconjunto de SPDX JSON2.2/2.3: `packages`, `versionInfo` y referencias externas `purl`.
- Tipos PURL reconocidos: PyPI, npm (incluidos scopes), Maven, crates.io y NuGet. PyPI normaliza guiones/puntos/underscore y NuGet mayúsculas; no se emparejan nombres de distintos ecosistemas.
- PURL con qualifiers/subpath, identidad/versión contradictoria, versión ausente o ecosistema no soportado: `needs_review`. No se adivina una identidad a partir de una palabra de producto.

Estos formatos se consultaron en sus fuentes oficiales: [CycloneDX1.6](https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json), [SPDX2.3](https://spdx.github.io/spdx-spec/v2.3/), [PURL](https://www.packageurl.org/docs/purl/introduction), [OSV](https://ossf.github.io/osv-schema/) y [SemVer2.0](https://semver.org/). El lector conserva un subconjunto explícito, no afirma conformidad completa ni resuelve archivos/referencias remotas dentro de un SBOM.

## Interpretación del resultado

Una versión incluida explícitamente en `affected.versions`, o incluida en un rango OSV de tipo `SEMVER` válido, produce `potentially_affected`. Se distinguen límites exclusivos `fixed`/`limit` e inclusivo `last_affected`; se manejan prereleases y build metadata de SemVer. Las versiones documentadas como corregidas se muestran como referencias, no como una actualización ya aprobada o compatible.

Para PyPI, los rangos ECOSYSTEM usan [orden PEP440 acotado](docs/PEP440.md): epochs, releases de longitud variable, pre/post/dev, alias y normalización. Las listas explícitas reconocen equivalencias públicas. No aplica reglas de specifiers de pip. Builds locales, versiones legacy y rangos no soportados o inválidos permanecen needs_review salvo evidencia literal positiva; normalizar no demuestra equivalencia de un parche downstream. Fuentes: [versionesPyPA](https://packaging.python.org/en/latest/specifications/version-specifiers/), [formatopip](https://pip.pypa.io/en/stable/reference/requirements-file-format/) y [lockfilenpm](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

`outside_observed_ranges` solo significa que no encaja en los rangos locales examinados. `no_local_advisory` nunca significa seguro: la colección OSV es selectiva. Los avisos retirados no generan candidatos activos.

Cada candidato tiene ID de aviso, URL oficial, JSON Pointer de `affected`, localizador del componente y versión. El informe contiene hash SHA256 del inventario, fecha, cobertura, límites y `analysis_id` determinista. El motor6 puede [reutilizar análisis guardados explícitamente](docs/DEPENDENCY_CACHE.md) cuando coinciden bytes/OSV/configuración/motor/permisos; invalida reutilización de motores anteriores sin borrar sus snapshots. Consultar nunca persiste un caché. No guarda datos en memoria confirmada ni genera aristas de vulnerabilidad probada.

Los límites configurables están en `dependency_analysis` de `config/settings.json`: bytes2MiB,2000componentes,5000observacionesOSV locales y1000candidatos por defecto. La lectura OSV también tiene presupuesto agregado32MiB. Si se recorta la cobertura se declara; no se ocultan los límites. El JSON puede contener nombres privados y debe conservarse localmente, no pegarse en herramientas externas sin autorización.

## Validación y pendientes

27pruebas reproducibles con inventarios/advisories sintéticos,sinred: identidad/ecosistema,rangos/límites,dedupe,Unicode,aislamiento,exclusiones,errores,CLI,fingerprints ymanifiestos. Credenciales en resolved/indexURLs se descartan de resultados. No se ha evaluado un inventario de producción ni se ha declarado vulnerable un proyecto real.

Backend adicional de snapshots incrementales y VEX revisado: [docs/DEPENDENCY_MEMORY.md](docs/DEPENDENCY_MEMORY.md). Preview/aprobación exacta, caducidad, evidencia, revocación y exportación estructural local;25pruebas focales, sin evaluaciones de producción. No suprime candidatos ni importa automáticamente VEX de documentos. La reutilización del motor3 tiene16pruebas adicionales; no confundir validar entradas con ejecutar otra vez las pruebas de una mitigación.

uv.lock agrega27regresiones reproducibles:orígenes/condiciones/privacidad,permisos,límites,errores,cachéversionada,CLI,snapshot/grafo/restauración ycaptura pública acotada. Un lock real del proveedor normalizó96componentes ypasóensayoofflineencopia, no es una evaluación de proyectos privados. El orden PEP440 tiene pruebas y ensayo adicional con un aviso público real, descritos en su contrato. Pendiente:otroslockfiles/ecosistemas yverificación deinstalación/alcance. No declarar vulnerable o seguro un despliegue por un inventario declarado.
