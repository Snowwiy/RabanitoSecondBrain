# Avisos de fabricantes — evaluación acotada2026-10-16

Los cuatro conectores funcionales actuales son CISA KEV, NVD, FIRST EPSS y OSV. Esta evaluación no instala módulos ni añade secretos/credenciales, y no equivale a una prueba de sincronización de los proveedores adicionales.

| Fuente | Evidencia oficial consultada | Estado en Rabanito |
|---|---|---|
| GitHub Advisory Database | [REST global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories): recursos públicos sin autenticación, filtros de fecha, cursores y máximo100 por página. [Registro público consultado](https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q). | GHSA por ID ya funciona realmente mediante OSV. No crear otra copia del mismo advisory solo para aumentar fuentes. Un incremental GitHub directo necesitaría respetar Link/rate-limit y conservar sus rangos como formato propio; no interpretar sus strings como SEMVER OSV automáticamente. La consulta web puede usar caché; no se afirma una sincronización directa actual. |
| Microsoft MSRC | [Repositorio oficial](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API) y [README oficial](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/master/README.md) publican el contrato CVRF y definiciones OpenAPI. | Candidato viable, todavía no implementado. El intento limitado de leer updates mediante la herramienta web no fue accesible; no valida ni invalida el servicio. Falta comprobar versión/contrato/respuesta, product tree y remediaciones. No ejecutar Install-Module ni muestras del README. |
| Cisco PSIRT | [Entrada oficial openVuln](https://developer.cisco.com/docs/psirt/). | La página accesible no proporcionó el contrato completo al lector web. Autenticación, paginación, límites y licencia no comprobados; no solicitar ni buscar credenciales del usuario para resolverlo. Sin conector. |
| Fortinet PSIRT | [Portal oficial](https://www.fortiguard.com/psirt). | Lectura web no disponible en esta revisión. No se verificó una API pública adecuada ni se implementó scraping. Sin conector. |

Antes de añadir un proveedor: inspeccionar contrato oficial y licencia; fijar host/path GET permitidos; limitar bytes/páginas/tiempo; probar errores, retiradas y publicación atómica con fixtures; hacer una consulta real pública acotada. La observación conserva su proveedor/fecha y no sustituye otras evidencias. Las asociaciones producto-versión requieren alcance explícito: no convertir coincidencias de nombre en vulnerabilidad de un proyecto.

No hay búsquedas remotas de paquetes privados, OAuth de GitHub/Codex, perfilHermes, llamadas a modelos ni instalaciones de sistema implicadas en esta revisión.
