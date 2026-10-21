# Estado técnico de publicación

Implementados: núcleo documental, búsqueda citada, proyectos incrementales, decisiones revisadas, cinco conectores públicos (MSRC por mes explícito), staging NVD, catálogo inicial de estándares, inspección offline de dependencias y dashboard/grafos existentes.

Validación del respaldo inicial: **290/290 Python normal, 290/290 Python optimizado y 52/52 JavaScript**, sin fallos ni omisiones (632 ejecuciones entre modos, no 632 pruebas diferentes). Incluye seis pruebas nuevas de protección de publicación. Runtime: Python 3.14.7 / SQLite 3.53.1, Windows nativo. La revisión acumulada posterior se describe debajo; no confundir sus cifras con las del primer commit.

Smoke de exportación limpia sin configuración/memoria privada: indexado vacío autorizado OK, catálogo público 28 entradas/17 relaciones y recuperación Zero Trust con citas y límite de 400 caracteres OK. Auditoría de candidatos: 84 archivos, sin incidencias pendientes; excepciones solo para nueve literales AST sintéticos exactos de regresión (diez coincidencias), nunca para carpetas enteras. La auditoría preparada y verificación remota se ejecutan después; este documento no las anticipa. No se incluyen métricas de conocimiento privado ni instantáneas de índices.

## Desarrollo local posterior al respaldo inicial (no publicado automáticamente)

El [inventario de Audit](AUDIT_INVENTORY.md) distingue archivos elegibles todavía
no indexados de documentos cuyo índice está desactualizado. Enumera metadatos
con presupuestos y cobertura explícitos, sin abrir notas nuevas ni registrar
proyectos. La muestra no es conocimiento incorporado y una cobertura parcial no
certifica limpieza. No cambia los contadores existentes ni la API del lector.

Las [vistas documentales](DOCUMENT_READERS.md) separan lecturas de la
inicialización SQLite: no backfills/DDL desde búsquedas, Audit, estadísticas,
decisiones, cambios o grafo. El primer resultado vacío puede usar RAM sin crear
un índice persistente. La convivencia WAL y el cierre seguro se prueban aparte;
no se usa immutable, se borran auxiliares manualmente o se relaja restore.
Las lecturas de origen de backup/pre-restore conservan metadatos, no los migran.
La matriz histórica inferior no acredita por sí sola esta corrección posterior.

Última validación del backend: 1.027 pruebas Python normales, 1.027 optimizadas,
1.027 desde copia limpia y 52 JavaScript; 3.133 ejecuciones / 1.079 pruebas
distintas, sin fallos, errores u omisiones finales. Pasan 32 procesos CLI
sintéticos de almacenamiento/recuperación, una CLI real y 21 HTTP locales.
La [autorización de origen](SOURCE_AUTHORIZATION.md) se aplica antes del recall
de caché; se probaron denegaciones con configuración solo en memoria sin alterar
la configuración real, los originales ni el índice. También se validan políticas
por archivo/contexto, caché de permisos del grafo y metadatos del historial.
Los lockfiles/SBOM mantienen su selección independiente de los documentos.
Seis consultas reales del grafo y cinco FTS en una restauración exclusivamente
temporal pasan; no se reconstruyó el índice ni se modificaron originales.
Las cifras inferiores describen cierres históricos, no una matriz más reciente.
No se publicó automáticamente este desarrollo posterior al respaldo autorizado.

La [consulta fría del grafo](GRAPH_SNAPSHOT.md) evita recalcular una validación
global ya completada en la misma transacción. En un ensayo real dejó de agotar
el presupuesto, sin aumentarlo y sin cambiar páginas/vecinos. Los casos con
inputs sucios o revocados conservan el filtrado por huellas y permisos.

Se corrigió un cuello de botella medido en la [publicación Cyber](CYBER_PUBLICATION.md):
la limpieza FTS agrupa identificadores afectados en vez de recorrer la tabla por
cada entidad. En el mismo replay aislado de 2.759 registros, publicar pasó de
57,041 s a 1,713 s; huellas lógicas, búsqueda, contexto e integridad coincidieron.
No cambia API/esquema/cobertura, ni sustituye los controles de rollback o de red.

Se verificó el mantenimiento público y la proyección incremental con el código
actual: dos ciclos completos en copia y en el índice operativo, segundo ciclo
idempotente; recuperación y APIs loopback reales, incluido el lector Markdown.
Son validaciones backend, no un rediseño, despliegue de UI o instalación de agentes.
Un grafo limpio no acredita cobertura completa de proveedores: revisar por
separado `cyber status`, especialmente `coverage.backlog` de NVD. EPSS/OSV y
MSRC mantienen sus ámbitos selectivo/mensual, sin inferir exposición local.

Se corrigió el [contexto Cyber por proveedor](CYBER_CONTEXT.md): el selector se
aplica a observaciones antes de gastar el presupuesto, conservando sus citas.
Antes, pedir KEV podía devolver solo NVD en un contexto corto. Selector CLI
opcional/aditivo; sin él no cambia la recuperación multisource ni la API HTTP.
Nueve regresiones nuevas y cuatro consultas CLI reales offline verifican citas,
fuentes y presupuestos. Cierre de esta revisión: 872 normal + 872 optimizadas +
52 JavaScript + 872 desde copia limpia de 187 candidatos, sin fallos finales
(2668 ejecuciones / 924 pruebas distintas). No se publicaron estos cambios
automáticamente. La frescura de los proveedores se consulta aparte en `cyber status`.

Nuevo [validador de transporte Hermes](HERMES_TERMINAL_VALIDATION.md): carga la
Skill y el handler de terminal completos reales en un home temporal y consulta
estadísticas, Obsidian, proyectos y experiencias documentadas con resultados
idénticos a la CLI directa. Verifica citas físicas y límites de evidencia sin
guardar fragmentos en logs. No es instalación, conversación de modelos o prueba
del perfil real; el audit hook no es un sandbox OS de procesos nativos.
15tests nuevos y cierre863normal+863optimizado+52JavaScript+863copia limpia de185
archivos pasan (2641ejecuciones/915tests distintos,0fallos/errores/omitidas finales).
32CLIfixtures conservanbackup/restore/contextoigual. Ensayo real separado:
4llamadas nativas y5baselinesCLI, sin modelos,instalaciones,captura de memorias
nuevas o edición de fuentes.

El [almacenamiento del indexador](INDEX_STORAGE.md) protege perfiles, bitácora y
apertura de SQLite frente a redirecciones. Conserva IDs, texto manual y bytes de
la versión anterior; una recuperación no sobrescribe trabajo concurrente. Los
perfiles sin cambios no se reescriben y los backups no se importan como notas.
No cambia el esquema ni las respuestas públicas; la rotación y SQLite no forman
una transacción conjunta. Fuentes ausentes mantienen `partial`/`error`.
24regresiones nuevas;834normal+834optimizado+52JavaScript+834copia limpia de181
archivos pasan:2554ejecuciones/886tests distintos,0fallos/errores/omitidas finales.
32CLI reproducen cinco escritores y sus backups/restauraciones. Esto no certifica
todos los openers de DB. El mkdir anterior al guard en el cargador se reprodujo
en dos pruebas rojas y se corrigió: se validan ambos roots antes de inicializarlos,
fijando padres nativos, sin abrir DB/lock.14regresiones nuevas conservan configuración
pública/relativa. Matriz más reciente:848normal+848optimizado+52JavaScript+848copia
limpia de182archivos:2596ejecuciones/900tests distintos,0fallos/errores/omitidas finales.
32CLI conbackup/restore por ensayo y dos denegaciones de startup sin escritura en
fuentes pasan. Dos indexaciones reales posteriores conservaron IDs/hash/status
y perfiles; backup restaurado solo a temporal,5FTS/contextoigual comprobados.
No es una nueva ingesta pública, instalación en clientes o publicación Git.

Se protegió la [publicación de informes](REPORT_STORAGE.md) frente a raíces
solapadas y sustitución del directorio después de comprobarlo.19regresiones nuevas
conservan las respuestas y nombres existentes. Cada formato se publica completo;
un fallo entre los dos se informa y conserva el artefacto recuperable, sin borrar
rutas publicadas que otro actor pudiera haber sustituido.
Matriz de este cierre:810/810normal,810/810optimizado,52/52JavaScript y810/810en
copia limpia177candidatos:2482ejecuciones/862tests distintos,0fallos/errores/skips
finales.23CLI reproducen los cuatro escritores con2FTS/restore porensayo. También
pasó una exportación real metadata-only superior a64KiB sin nuevas memorias.

La [captura de entrevistas](INTERVIEWS.md) corrige tres problemas reproducidos:
junction hacia fuente sintética, asignaciones sensibles detectables persistidas
y Markdown parcial ante UTF-8 inválido. Revisión del candidato exacto, límites y
publicación protegida conservan aprobación explícita y el contrato existente.
23regresiones nuevas y un ensayo de cinco CLI verifican el flujo sin conocimiento
de producción, llamadas de modelos o modificaciones a fuentes originales.
Revisión anterior de entrevistas:791/791normal,791/791optimizado,52/52JavaScript y791/791en
copia limpia de173candidatos sin datos privados:2425ejecuciones/843tests distintos,
0fallos/errores/skips finales.17CLI ejercitan los tres escritores, con2FTS/restore
porensayo ytemporaleslimpios. Los resultados no equivalen a sesiones de agentes.

Se corrigió un escape reproducido del escritor antiguo de decisiones a través de
una junction en `knowledge/decisions`. La [publicación protegida](DECISION_STORAGE.md)
reutiliza HANDLEs nativos/raíces propias/política/rename sin reemplazo, mantiene
el Markdown y no modifica fuentes importadas. Dieciocho regresiones nuevas y un
ensayo CLI sintético cubren rutas, concurrencia, recuperación y restauración;
no son registros confirmados de producción ni una instalación en clientes.
Revisión anterior de decisiones:768/768normal,768/768optimizado,52/52JavaScript y768/768en
copia limpia de169candidatos sin datos privados:2356ejecuciones/820tests distintos,
0fallos/errores/skips. DoceCLI reales ejercitan ambos escritores en la copia,
con restauración ytemporaleslimpios. La nueva protección sigue siendo local.

Se agregó un [validador opcional del cargador real de Hermes](HERMES_LOADER_VALIDATION.md).
Con las dependencias PM ya existentes importa `tools.skills_tool`, carga la Skill
en un home temporal sin/con preprocesado y comprueba tres rechazos de rutas.
No usa CLI/bootstrap, instala paquetes ni modifica perfiles. La prueba real pasa;
no demuestra conversaciones de Opus/Luna ni el transporte `terminal` del perfil.
Ocho regresiones sintéticas prueban el contrato sin requerir Hermes en la suite.
Revisión anterior del cargador:750/750Python normal,750/750optimizado y52/52JavaScript,
sin fallos/errores/omisiones;1552ejecuciones y802tests distintos. La copia portable
anterior validó742, no se presenta como una reproducción nueva de750. SQLite y
recuperación CLI citada se verificaron aparte de la prueba de biblioteca Hermes.

Corrección posterior de recuperación documentada: se reprodujo un reintento que
devolvía indexed=true con una fila FTS ausente y búsqueda vacía. Ahora el guardado
compara y verifica derivados acotados de la nota antes/después de escribir; repara
con el mismo ID y sin tocar la fuente. El indexador común elimina FTS de fragmentos
huérfanos solo del documento actualizado. Ocho regresiones nuevas y el ensayo CLI
de ocho procesos cubren este caso; no es certificación forense del índice completo.

El lector y el backend acumulado fueron publicados tras autorización específica
del estado auditado. El avance siguiente de [guardado documentado](DOCUMENTED_MEMORY.md)
vuelve a ser local: CLI explícita con digest del texto aprobado,32regresiones
focales, creación sin reemplazo, indexado individual y reintento tras fallo.
No hay autoaprobación, promoción histórica, escritor HTTP, instalación de clientes
ni publicación adicional. Matriz posterior:734/734Python normal,734/734optimizado,
52/52JavaScript y734/734en copia limpia de162candidatos sin datos privados;0fallos/
errores/skips. SeisCLI reales ybackup/restauración con2FTS en entorno sintético.
Después,8pruebas deSkills nativas/preflight/instaladoresTEMP pasan tras una edición
soloMarkdown de sus tres entrypoints. Validadorgenérico deSkills no disponible por
PyYAML ausente; no es dependencia del núcleo ni se instaló para esta comprobación.

Revisión del backend publicado: **702/702Python normal,702/702optimizado y52/52JS**,
0fallos/errores/skips. Copia de159archivos publicables sin configuración, DB o memoria
privadas: otras702/702pruebas aprobadas.2158ejecuciones de cierre/754tests distintos.
Estos resultados no equivalen a integración visual ni instalación de clientes.

- [Lector Markdown por ID](../FRONTEND_BACKEND_CONTRACT.md): backend real de solo
  lectura, contrato compatible con Frontend-Design, fuentes/proyectos actuales,
  rutas/handle seguros, presupuestos UTF-8, redacción detectable, errores y
  referencias explícitas.35regresiones y matriz694normal+694optimizado+52JS
  pasan. Recuperación HTTP real y parser UI en memoria validados; no implica
  merge/despliegue visual ni autorización de escritura a fuentes.
- [Preview de experiencias documentadas](DOCUMENTED_MEMORY.md): stdin JSON64KiB
  produce Markdown exacto/digest versionado para revisión humana;8regresiones
  nuevas. No persiste/aprueba/indexa ni verifica historia. El escritor separado
  local ya exige el digest del texto aprobado, sin promover evidencia histórica;
  ninguna memoria privada de producción se usa como fixture o se publica.

- [Experiencias documentadas de entorno](DOCUMENTED_MEMORY.md): consulta explícita CLI/APIRO para relatos humanos aprobados con evidencia parcial/pendiente;contextos lógicos sin registrar repositorios,hash/rutas/metadata/exclusiones/citas/límites yno promoción a soluciones verificadas.18regresiones nuevas;matriz659normal+659optimizado+52JavaScript=1370ejecuciones/711tests entrelenguajes,0fallos. Una experiencia real aprobada se conserva solo en memoria local privada, no en el repositorio.
- Reproducción de esa revisión:153candidatospublicables sinconfiguración/datos/conocimiento privado,659/659pruebas adicionales;indexvacío yconsulta documentada vacía correctos,temporal limpiado.2029ejecucionesmatriz+repro/711tests distintos. No se copia ni publica el registro humano como fixture;los tests usan datos sintéticos propios.

- Snapshots incrementales/VEX revisado implementados,25pruebas focales; sin registros de producción inventados ni supresión de hallazgos. Ver [memoria de dependencias](DEPENDENCY_MEMORY.md). Persiste informes idempotentes, no evita todavía todo el procesamiento.
- Historial observado Cyber con migraciónaditiva3, baseline perezoso, consultas metadata/cursor, CLI y POST local.15regresiones incluyen paginación, aliases, rollback, errores y recuperación. Ver [historial](CYBER_HISTORY.md). No modifica visualmente el dashboard.
- Grafo unificado backend con proyección incremental, consultas keyset, vecinos, filtros/permisos actuales y validación por epoch;34regresiones, CLI/POST y prueba en copia del índice operativo. Ver [contrato](KNOWLEDGE_GRAPH.md). No hay sustitución visual del renderer actual.
- [Reutilización de procesamiento de inventarios](DEPENDENCY_CACHE.md), motor6: consulta RO de snapshots explícitos, hashes de bytes, metadata OSV/cobertura/config/permisos, checksum de resultado y16regresiones iniciales. Invalida resultados anteriores sin borrarlos. No hay evaluaciones privadas de producción ni esquema adicional aplicado por esta lectura.
- [MSRC mensual](MSRC_CONTRACT.md): ledgerMSRC1 aditivo y backup, captura/normalización propia acotadas, resumen incremental, publicación/FTS/historia atómicos y retiros aislados por mes. Ingesta real de2026-Oct con2.135observaciones; segundo paseunchanged, ensayo en copia/restauración/HTTP reales. ADV no es CVE ni prioridad publicada, y explotación de fabricante no marcaCISAKEV. Grafo motor2 mantieneKG1 y renderer existentes.
- [Catálogo de seguridad revisado](SECURITY_CATALOG.md):72fichas/66relaciones,26resultados CSF2.0 de las seis funciones y25conceptos, con principios/componentes NIST y pilares/capacidades/etapas CISA. Metadatos de versión, publicación de precisión mensual cuando el editor no da día, filtros CLI/API y fragmentos acotados. Referencia MITRE ATT&CK20.0 separada del rolling, sin STIX/bytepin/cumplimiento.15regresiones de edición más14Zero Trust, ensayo/publicación incremental/restauración reales, sin migrar SecurityDDL1 ni rediseñar UI.
- [uv.lock defensivo](UV_LOCK.md): TOML estándar, versión1/revisiones0–5, límites de estructura y componentes, localizadores del árbol parseado sin líneas inventadas. URLs privadas, credenciales, rutas y marcadores no salen del lector; su identidad permanece no verificada.27regresiones y ensayo de un lock público real (96componentes) en copia con restauración, sin evaluación privada de producción. Grafo motor3 mantieneKG1 y diferencia fuentes/condiciones sin cambiar IDs anteriores.
- [Orden PEP440 acotado](PEP440.md): parser propio con biblioteca estándar, epochs/pre/post/dev/normalización/equivalencia pública y límites explícitos. Builds locales/legacy no se convierten en seguridad confirmada.22regresiones nuevas y ensayo de un aviso OSV real en copia temporal con151versiones enumeradas y6probes de límites diferenciados de releases publicadas; citas/reutilización/restauración/4FTS comprobados. Sin namespace nuevo ni cambios al grafo o dashboard.
- [Pylock portable](PYLOCK.md): lectura seleccionada de pylock1.0 y variantes con nombre, origen/artefactos/condiciones separados, loader TOML compartido acotado.24regresiones y ensayo de un fixture oficial de pip en copia real:3entradas locales/directas permanecen review, con caché/grafo/restauración y sin seguir artefactos. No es validación de una exportación de producción ni del instalador pip.
- [MITRE ATT&CK®](ATTACK_CAPTURE.md): captura de Enterprise20.0 a commit explícito, blob/tamaño/SHA256/licencia, lector STIX2.1 y recuperación citada. [ATTACK1](ATTACK_INDEX.md) enSQLite compartida, ediciones/revisiones/FTS y seisPOSTRO;27regresiones además de31de captura/parser. [Proyección KGmotor4](ATTACK_GRAPH.md) con tipos/IDs/SROs estables, flags históricos opt-in, head/memberships y watchers/checkers sin alterarKG1/ATTACK1;17regresiones adicionales y ensayo operativo de dos ciclos/restauración/paginación/performance. UIATTACK y exposición local no validadas por el grafo.
- [ASVS5.0.0](ASVS.md): importación oficial fijada/licenciada de345requisitos y97grupos, registroSQLite persistente que conserva indexación común, reemplazo explícito/backup, búsqueda porL exacto yprocedencia/licencia en contexto/KG4.22regresiones;ensayo copiaDBreal/publicación incremental/idempotencia/restore/HTTP reales. Los requisitos no son cumplimiento,CC-BY-SA4.0 de datos no licencia el código;sin nuevaDDL oUI.
- Matriz local posterior: **659/659Python normal,659/659optimizado y52/52JavaScript**,0fallos/errores/omitidas(1370ejecuciones de matriz/711tests entre lenguajes). MSRC tiene24regresiones deparseo/normalización+15decaptura+23desync. No confundir un mes con cobertura global ni pruebas standalone con clientes agentes instalados.
- Corregido localmente el filtro de exclusiones deltest de sintaxis para checkouts anidados; la copia original descargada deGitHub ya pasó290/290fuera delancestro.test-temp. La autorización de publicar el estado acumulado es específica: no habilita commits posteriores automáticos.

## Pendientes vigentes

Reproducción del estado local posterior:150candidatos publicables copiados sin configuración, índices ni conocimiento privado;641/641pruebas, indexvacío y catálogo curado72+recuperaciónZeroTrust pasan. Sumadas a matriz normal/optimizada/Node:1975ejecuciones de cierre aprobadas,693tests distintos entrelenguajes. La copia temporal se limpió; no es otro commit ni contiene ASVS sin su registro explícito.

Los siguientes son límites o evoluciones posibles, no una obligación de añadir fuentes/ecosistemas indefinidamente. No se identificó una nueva brecha backend requerida en la auditoría actual. El aporte de una experiencia real exige revisión humana; sesiones reales de clientes y activación global no se sustituyen por fixtures. La integración visual continúa fuera de esta etapa.

- Otras fuentes/lockfiles y aplicabilidad instalada. Caché de procesamiento yVEX/persistencia revisada ya funcionan enbackend, sin endpoint/vista nuevos; no constituyen evaluación de producción.
- Historia anterior al activar revisión individualCyber sigue desconocida; no reconstruirla artificialmente. La migración real3 y dos nuevas observaciones KEV se validaron con backup/restauración e integridad, sin historia inventada.
- Integración visual del grafo unificado y aplicabilidad verificada a proyectos. La API progresiva backend ya funciona; las vistas visuales actuales siguen separadas y acotadas por decisión de alcance.
- Controles oficiales/versiones adicionales y conectores de fabricantes con contratos verificables.
- QA visual/lector de pantalla y sesiones reales de todos los clientes/modelos. Formato/CLI no sustituyen esa prueba.
- Otros lockfiles/ecosistemas y aplicabilidad instalada. PEP440 ya tiene orden público acotado; no incluye specifiers/entornos de pip, versiones legacy ni verificación de parches downstream.

Retomar backend desde esos pendientes después del respaldo inicial. El rediseño visual va por separado; no integrar worktrees ni sobrescribir cambios concurrentes. Conservar checksums de DDL aplicadas; los cambios requieren nuevas migraciones.
