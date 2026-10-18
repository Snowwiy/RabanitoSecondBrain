# Estado técnico de publicación

Implementados: núcleo documental, búsqueda citada, proyectos incrementales, decisiones revisadas, cinco conectores públicos (MSRC por mes explícito), staging NVD, catálogo inicial de estándares, inspección offline de dependencias y dashboard/grafos existentes.

Validación del respaldo inicial: **290/290 Python normal, 290/290 Python optimizado y 52/52 JavaScript**, sin fallos ni omisiones (632 ejecuciones entre modos, no 632 pruebas diferentes). Incluye seis pruebas nuevas de protección de publicación. Runtime: Python 3.14.7 / SQLite 3.53.1, Windows nativo. La revisión acumulada posterior se describe debajo; no confundir sus cifras con las del primer commit.

Smoke de exportación limpia sin configuración/memoria privada: indexado vacío autorizado OK, catálogo público 28 entradas/17 relaciones y recuperación Zero Trust con citas y límite de 400 caracteres OK. Auditoría de candidatos: 84 archivos, sin incidencias pendientes; excepciones solo para nueve literales AST sintéticos exactos de regresión (diez coincidencias), nunca para carpetas enteras. La auditoría preparada y verificación remota se ejecutan después; este documento no las anticipa. No se incluyen métricas de conocimiento privado ni instantáneas de índices.

## Desarrollo local posterior al respaldo inicial (no publicado automáticamente)

Revisión conjunta más reciente: **702/702Python normal,702/702optimizado y52/52JS**,
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
  nuevas. No persiste/aprueba/indexa ni verifica historia. Escritura posterior
  segura y con aprobación exacta sigue pendiente; ninguna memoria privada de
  producción se usa como fixture o se publica con esta capacidad.

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
