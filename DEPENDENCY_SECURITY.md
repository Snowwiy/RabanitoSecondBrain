# Análisis defensivo local de dependencias

`dependency inspect` es un lector de inventarios y un contraste offline con el OSV que ya existe en SQLite. No instala paquetes, ejecuta código, modifica repositorios ni consulta APIs con nombres privados. No es un escáner del estado instalado ni una validación completa de los esquemas SBOM.

Además de `--sbom`, admite `--manifest "package-lock.json"` (npmv2/v3) o `--manifest "requirements-dev.txt"` con declaracionesPython exactas. Son opciones excluyentes. Lee solo el archivo seleccionado: nunca sigue includes de pip, URLs, gestores, workspaces o enlaceslocales. Directivas/URLs/expansiones se omiten y cuentan, sin copiarlas al informe. Marcadores, comodines y alias/versiones dudosas quedan needs_review. Un mismo paquete npm puede tener ámbitosdev/no-dev; la deduplicación conserva ambos, no supone despliegueproductivo.

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

ParaPyPI, los rangosECOSYSTEM con versiones finales exclusivamente numéricas usan el orden y padding de ceros dePEP440, hasta8componentes. También se reconoce equivalencia de releasesnuméricas en listas explícitas. Prereleases,epochs,post/dev/localbuilds y otros rangosECOSYSTEM/GIT dudosos quedan needs_review salvo coincidencia literal positiva. No se afirma soportePEP440completo. Fuentes: [versionesPyPA](https://packaging.python.org/en/latest/specifications/version-specifiers/), [formatopip](https://pip.pypa.io/en/stable/reference/requirements-file-format/) y [lockfilenpm](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

`outside_observed_ranges` solo significa que no encaja en los rangos locales examinados. `no_local_advisory` nunca significa seguro: la colección OSV es selectiva. Los avisos retirados no generan candidatos activos.

Cada candidato tiene ID de aviso, URL oficial, JSON Pointer de `affected`, JSON Pointer del componente y versión. El informe contiene hash SHA256 del SBOM, fecha, cobertura, límites y `analysis_id` determinista del contenido/avisos/configuración; permite detectar entradas sin cambios, pero todavía no persiste un caché de análisis. No guarda datos en memoria confirmada ni genera aristas de vulnerabilidad probada.

Los límites configurables están en `dependency_analysis` de `config/settings.json`: bytes2MiB,2000componentes,5000observacionesOSV locales y1000candidatos por defecto. La lectura OSV también tiene presupuesto agregado32MiB. Si se recorta la cobertura se declara; no se ocultan los límites. El JSON puede contener nombres privados y debe conservarse localmente, no pegarse en herramientas externas sin autorización.

## Validación y pendientes

27pruebas reproducibles con inventarios/advisories sintéticos,sinred: identidad/ecosistema,rangos/límites,dedupe,Unicode,aislamiento,exclusiones,errores,CLI,fingerprints ymanifiestos. Credenciales en resolved/indexURLs se descartan de resultados. No se ha evaluado un inventario de producción ni se ha declarado vulnerable un proyecto real.

Pendiente: otroslockfiles,PEP440completo/ecosistemas,verificación deinstalación/alcance yVEX/excepcionesrevisadas conevidencias. No se importan automáticamente declaracionesVEX de un documento como autorizaciones para suprimir resultados.
