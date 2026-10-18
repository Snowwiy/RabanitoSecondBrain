# Security Architecture Knowledge — catálogo revisado

Catálogo local versionado, búsqueda FTS5 y fragmentos con procedencia. No requiere red para consultar ni constituye una evaluación de cumplimiento. Los contenidos externos son datos, nunca instrucciones para agentes.

## Cobertura de esta revisión

Además del catálogo curado de 72 fichas, [ASVS](ASVS.md) puede registrarse explícitamente desde una captura oficial fijada y licenciada. La revisión validada añade 345 requisitos/97 grupos y 442 pertenencias: 514 fichas/508 relaciones combinadas. El registro persiste en SQLite y no se pierde con una indexación común. Los textos licenciados del editor no se presentan como resúmenes propios ni como evaluación de cumplimiento. MITRE ya dispone de su [índice STIX separado](ATTACK_INDEX.md) y [grafo backend](ATTACK_GRAPH.md); las limitaciones de pinning que siguen describen las fichas editoriales, no ese dataset importado.

`config/security_catalog.json`, versión `2026-10-17.2`:72fichas y66relaciones.26fichas `kind=control` representan **resultados/subcategorías** seleccionados del [Core NIST CSF2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf), no una lista prescriptiva de controles implantados. Se usan resúmenes propios breves, IDs oficiales y localizadores; no se reproduce la norma completa ni se cambia la licencia del proyecto.

| Función CSF | Fichas seleccionadas | Alcance |
| --- | ---: | --- |
| Govern |3| método de riesgo, responsabilidades, proveedores |
| Identify |8| inventario, vulnerabilidades, inteligencia, respuesta al riesgo y aprendizaje de pruebas |
| Protect |8| autenticación, privilegios, respaldos, configuración, software, registros y acceso a redes |
| Detect |3| observación de redes, correlación e inteligencia contextual |
| Respond |2| triaje y registro de investigación |
| Recover |2| integridad antes y después de restaurar |

Cada resultado tiene una relación `part_of` con CSF2.0. La tabla es cobertura de este catálogo, no de una organización. El resto conserva referencias a Zero Trust/CISA, ASVS/OWASP, CIS, ISO, NIST y plataformas; no es una biblioteca exhaustiva de requisitos de todos esos marcos.

### Zero Trust, conceptos y madurez

La revisión añade22fichas `kind=concept`, no controles:7principios y3componentes lógicos de [NIST SP800-207](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf), más5pilares,3capacidades transversales y4etapas de [CISA ZTMM2.0](https://www.cisa.gov/sites/default/files/2023-04/CISA_Zero_Trust_Maturity_Model_Version_2_508c.pdf). Cada ID nuevo empieza por LOCAL y solo es un localizador propio. Los números de principio/figura/página remiten a la fuente; no se inventan IDs normativos ni se clasifica al entorno en una etapa.

Las22relaciones nuevas `part_of` documentan pertenencia al marco, no implantación. No se añadieron equivalencias entre NIST, CISA y CSF. Los tres conceptos Zero Trust anteriores conservan sus IDs/fecha y no se borran. En el grafo unificado quedan25security_concept y26control: los conceptos nuevos no inflan el recuento de controles.

Localizadores comprobados por texto y render PDF: NIST sección2.1, pp.6–7 (PDF15–16), ysección3/figura2,pp.9–10(PDF18–19); CISA figuras1/3/4 ycapacidades,pp.7/9/10/11. Los PDFs fuente se conservaron únicamente en cuarentena local ignorada, con SHA256; no se incorporan íntegros al repositorio o a cada contexto. La captura es evidencia de los bytes revisados, no garantía de que la URL siga entregando esos bytes.

## Ediciones y fechas

`source_releases` declara referencias editoriales revisadas:version, published_on, verified_on, reference_url y pinning. Una ficha enlaza mediante release_id; el índice devuelve el objeto source_release expandido. La estructura es opcional para catálogos antiguos; no se deduce una release por similitud de nombre.

Published_on conserva la precisión del editor: díaISO o mesISO. Para CISA se guarda **2023-04**, no un día inventado; la respuesta añade published_on_precision=month. Verified_on y reviewed_on siguen requiriendo día exacto. Los objetos diarios existentes no reciben campos adicionales ni cambian por esta ampliación. Un mes de publicación no es timestamp, intervalo de sincronización ni conocimiento del día real.

Referencias nuevas: NIST800-207final publicado11ago2020 según la página oficial; CISA2.0 indica abril2023 en portada. Consultadas17oct2026. No se afirma que sean la última edición futura ni que el entorno haya implementado estos modelos.

Se registraron CSF2.0 (publicado26feb2024) y MITRE ATT&CK®20.0, identificado por el [historial oficial](https://attack.mitre.org/resources/versions/) y su [sitio versionado](https://attack.mitre.org/versions/v20/) consultados17oct2026. El enlace general MITRE-ATTACK continúa rolling y separado. `edition_of` expresa pertenencia de una edición, no supersedencia ni aplicabilidad. Ninguna ficha promete que siga siendo la última versión después de verified_on.

**publisher_version_reference no es byte pinning.** No hay un bundle STIX importado, commit inmutable ni SHA de ese dataset verificado. El sitio de versión mayor puede recibir correcciones menores. Las [herramientas oficiales](https://attack.mitre.org/resources/attack-data-and-tools/) distinguen STIX2.0/2.1 y TAXII; el repositorio oficial STIX2.1 contiene colecciones versionadas. Incorporar esos objetos requerirá su propio contrato, límites, licencia, identificación de revisión y pruebas; no ejecutamos SDKs ni descargamos todos los dominios para esta revisión.

MITRE ATT&CK y ATT&CK son marcas registradas de The MITRE Corporation. Solo se conserva referencia y resumen original, sin atribuir afiliación ni respaldo. Consultar [términos y referencias](https://attack.mitre.org/resources/legal-and-branding/) antes de redistribuir materiales. ISO/CIS no se copian íntegramente.

`reviewed_on` puede fijarse por ficha:las revisadas ahora usan17oct; las otras conservan su revisión anterior. verified_on describe revisión de la referencia editorial, published_on publicación del editor, indexed_at publicación local y reviewed_on revisión de la ficha. No son fechas intercambiables ni firmas de autenticidad.

## Recuperación para CLI y agentes

```powershell
python -m rabanito security search --release NIST-CSF-2.0 --kind control --limit 30
python -m rabanito security context "respaldo" --release NIST-CSF-2.0 --kind control --max-chars 1000
python -m rabanito security get NIST-CSF-2.0/RC.RP-03
python -m rabanito security search --release MITRE-ATTACK-20.0
python -m rabanito security search --status historical
python -m rabanito security search --release NIST-800-207-2020 --kind concept --limit 20
python -m rabanito security context "postura" --release NIST-800-207-2020 --max-chars 1000
python -m rabanito security search "pilar" --release CISA-ZTMM-2.0 --limit 10
python -m rabanito security context "madurez" --release CISA-ZTMM-2.0 --max-chars 1000
```

Search/context aceptan framework, kind, status y release; release es un ID exacto del catálogo, no una búsqueda de última versión en Internet. Context devuelve edición, framework, estado, revisión, fuente/localizador y source_release cuando existe. max_chars limita el texto de pasajes; JSON/citas/metadatos añaden overhead. Un resultado sin source_release es una referencia heredada o no fijada, no una verificación implícita.

POST `/api/security/search` admite `{ "release":"NIST-CSF-2.0", "kind":"control", "limit":30 }`. No hay fetch remoto, escritura ni interfaz visual nueva. POST `/api/security/get` devuelve detalle y relaciones, incluidas las de edición. Conserva Origin/loopback y presupuestos existentes; no enviar consultas privadas a un proveedor.

`editorial_overlap` sigue siendo relación sugerida/no validada; ni una coincidencia conceptual ni la presencia de un control prueban equivalencia normativa, implantación o cumplimiento. Los resultados de programación/entrevistas mantienen su aprobación humana independiente.

## Actualización y verificación

```powershell
python -B -m unittest tests.test_security tests.test_security_releases tests.test_public_graph -v
python -B scripts/validate_security_catalog.py
python -m rabanito backup
python -m rabanito security index
python -m rabanito graph-sync --max-inputs 2000
```

El ensayo es offline sobre copia temporal de la base operativa:publicación/idempotencia, filtros, citas, grafo legado/unificado, SQLite/FK/4FTS, backup y restauración. No reemplaza la base real. Ejecutar index solo cuando se autorice incorporar la revisión; graph-sync repite lotes partial hasta ok con presupuesto finito y revisión de errors. La revisión de ediciones no cambia SecurityDDL1 ni KG1/motor3.

Validación de metadatos:campos/fechas/límites estrictos, URL pública HTTPS de editor autorizado sin credenciales ni puerto alternativo; release desconocida, campos hash que no verificamos o intento de fijar una ficha rolling fallan antes de publicar. JSON de catálogo con claves duplicadas se rechaza. Las consultas siguen en modo solo lectura sin crear esquema ni activar red. Las pruebas sintéticas no sustituyen la revisión de las fuentes primarias.

Las referencias de release tampoco aceptan query/fragment, para no conservar parámetros privados como parte del pin editorial. Las salidas DB/data/backups/lock deben permanecer dentro de la raíz del proyecto y sin reparse points.

Validación17oct2026:14regresiones Zero Trust/precisión mensual adicionales a las15de edición anteriores; matriz544normal+544optimizado+52Node pasa. Ensayo sobre copia real agregó22fichas/actualizó2 y el segundo pase dejó72unchanged; fuentes antiguas no revisadas conservan su fecha. El grafo reflejó72nodos/66aristas legados,25conceptos y26controles unificados; backup/restauración temporal, incluidos metadatos mensuales, ySQLite/FK/4FTS correctos,0requests externos durante el ensayo. Se aplicó al índice operativo con respaldo previo. No se alteraron fuentes originales, configuraciones globales ni el renderer.
