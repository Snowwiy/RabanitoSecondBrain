# Grafo de conocimiento unificado — backend

La proyección KG1 relaciona documentos, proyectos, experiencias revisadas, observaciones públicas, vulnerabilidades, tecnologías, dependencias, análisis guardados, claims VEX y catálogo de seguridad. Comparte SQLite con los motores existentes; no sustituye sus fuentes ni los grafos del dashboard actual. No se ha integrado visualmente en el renderer.

El motor4 mantiene KG1 y los IDs anteriores, incorporando [ATT&CK](ATTACK_GRAPH.md)
desde los heads publicados de ATTACK1, con tipos/flags/citas propios y sin inferir
aplicabilidad local. Conserva security_advisory/explotación de fabricante delmotor2
y ámbito de procedencia/condiciones de inventarios delmotor3 (uv.lock/pylock), sin
afirmar CISAKEV o instalación. Un cambio de motor requiere un recorrido explícito
completo de graph-sync; repetir partial hastaok sin reconstruir fuentes. La pasada
completa siguiente debe ser idempotente, no basta con un solo lote sin cambios.

## Preparación y consultas

Requiere Python 3.11+ y SQLite **3.35+**, además de FTS5 para el núcleo. No añade paquetes, red, modelos ni servicios. Desde la raíz del checkout autorizado:

```powershell
python -m rabanito graph-sync --max-inputs 1000
python -m rabanito knowledge-graph page --kind project --limit 20
python -m rabanito knowledge-graph page --kind vulnerability --risk known_exploited --limit 50
python -m rabanito knowledge-graph page --project "<ACTIVE_PROJECT_ROOT>" --limit 50
python -m rabanito knowledge-graph neighbors "<ID_DEVUELTO_POR_PAGE>" --limit 50
```

`graph-sync` es escritura local explícita. No indexa fuentes documentales ni consulta proveedores. Si retorna `partial` (exit1), leer `errors`, `missing_or_stale_inputs` y `next_key`; repetir manualmente con el mismo presupuesto continúa el ciclo. Un cambio de generación de las fuentes reinicia el recorrido sin duplicar claims. No usar un bucle ilimitado: detenerse ante errores o falta de progreso. Máximo1–5000 entradas por llamada y 8–64MiB de payload de entrada (predeterminado32MiB); límite adicional por entrada/proyección. Los objetos Python y SQL añaden overhead de memoria.

Las lecturas nunca crean esquema, instalan contadores ni sincronizan. Antes de la primera sincronización devuelven `projection_available=false`. Cada nueva instalación crea un backup verificado previo al esquema. Las sincronizaciones comparten el bloqueo interproceso del indexador y publican cada lote en una transacción. No sobrescriben archivos originales.

## Contrato para frontend y agentes

Todas las rutas usan POST JSON, Host/Origin loopback y puerto exacto, sin CORS público; GET devuelve405. No poner consultas, rutas privadas ni cursores en URLs o logs.

| Ruta | Cuerpo |
| --- | --- |
| `/api/knowledge-graph` | filtros opcionales; `q`, `kind`, `project_id` o `project`, `source`, `category`, `risk`, `since`, `until`, `limit`, `cursor`, `suggestions` |
| `/api/knowledge-graph/neighbors` | mismos filtros más `id` obligatorio (ID del nodo) |
| `/api/knowledge-graph/sync` | `confirm_graph_sync:true`, `max_inputs` y `max_bytes` opcionales |

Consultar el handler para los campos exactos. Campos desconocidos, duplicados JSON, tipos incorrectos, límites o filtros inválidos se rechazan; no convertir `null`/errores en acceso global. Cuerpo de lectura hasta16KiB; sync hasta2KiB. No es autenticación multiusuario: cualquier proceso local autorizado al puerto puede acceder. No exponer por túneles.

`page` devuelve nodos raíz y `edges:[]`; `neighbors` expande **un salto**, con anchor y hasta200 aristas por página (puede devolver hasta201 nodos). Repetir con `next_cursor` mientras `has_more`; un cliente puede expandir vecinos para dos saltos manteniendo sus propios límites de nodos/peticiones. No intentar cargar todo el grafo para cada vista.

IDs estables por namespace: `document:<id>`, `project:<id>`, `vulnerability:<id>`, `observation:<provider>:<id>`, `security:<id>`, `solution:<document_id>` y hashes de identidad para paquetes, condiciones y claims. No son rutas ni autorizaciones de apertura. Abrir documentos únicamente mediante el `data.document_id` y el POST de apertura existente; no pasar nodos públicos a ese endpoint.

Filtros:

- `kind`: project, document, decision, solution, vulnerability, observation, weakness, package, security_concept, reference, product_condition, standard, control, dependency, dependency_declaration, technology, snapshot, review o all.
- `q` (CLI `--query`): subcadena literal Unicode, no lenguaje SQL/FTS; `%` y `_` no son comodines.
- Proyecto: ID positivo, raíz absoluta exacta autorizada o nombre único. Homónimos requieren raíz. Nunca se devuelve otro proyecto privado como vecino.
- `source`: origen de la afirmación; las métricas públicas fusionadas conservan atribución a sus proveedores. `category` permite prefijo.
- `risk`: known_exploited, high_prediction (EPSS>=0.1) o published: prioridad pública, **no** riesgo confirmado de un proyecto. En expansión se mantienen puentes no vulnerabilidad que cumplen los demás filtros.
- `since`/`until`: fecha UTC del nodo (`updated`), no garantía de cobertura de sincronización; fechas sin hora incluyen el día completo en `until`.
- `limit`:0–200, predeterminado50. `suggestions` predeterminadofalse, también en asociaciones de raíz de proyecto.
- `include_inactive` (CLI `--include-inactive`): booleano estricto, defaultfalse;
  permite nodos/SROs ATT&CK revoked/deprecated con sus flags. No revive miembros
  retirados del head ni documentos/proyectos excluidos. Nuevos kinds/origen/categorías
  y reglas de fechas/relaciones están en [ATTACK_GRAPH](ATTACK_GRAPH.md).

`total_candidates` cuenta candidatos antes de revalidar experiencias. Una página vacía puede aún tener cursor: continuar de forma acotada. Cursores keyset opacos ligados a filtros, permisos, generación, versión del motor y operación; si cambia el dataset se rechazan y el cliente debe reiniciar. No ofrecen snapshot durable entre peticiones ni autenticación.

## Evidencia y semántica

Cada nodo/arista conserva cita. Para fuentes privadas son relativas (`obsidian:...`, `projects:<id>:...`, `internal:...`); no se devuelven raíces absolutas ni cuerpos de notas. IDs de proyecto desambiguan documentos homónimos. Las citas públicas proceden de observaciones reales, no de enlaces fabricados para aparentar un registro existente.

- Wikilinks resueltos y citas exactas son explícitos. No se relajan las fronteras del resolvedor para unir bóvedas/proyectos por nombre.
- Una memoria revisada puede vincular evidencia Obsidian autorizada e indexada; no se infiere que toda nota relacionada sea una decisión confirmada.
- `detected_technology` es inferencia de metadatos. Una declaración de dependencia por nombre no acredita ecosistema, versión ni instalación.
- Aviso→identificador es referencia, no equivalencia entre todas sus CVE. Condición CPE o paquete publicado no demuestra aplicabilidad local.
- Inventarios y candidatos guardados se etiquetan como análisis previo no revalidado. Claims VEX conservan caducidad/revocación, no suprimen candidatos OSV ni acreditan mitigación.
- Las soluciones se revalidan contra hash/evidencia actuales al leer, hasta32 por respuesta; un presupuesto agotado se informa y permite seguir paginando. `passed_as_recorded_not_rerun` no significa una prueba ejecutada ahora.
- Mappings editoriales son sugerencias opt-in; citas a estándares no acreditan cumplimiento. Registros retirados no adquieren prioridad published por defecto.

## Consistencia y rendimiento

La [validación del snapshot](GRAPH_SNAPSHOT.md) se reutiliza dentro de una lectura
solo después de comprobar globalmente que no hay inputs sucios u obsoletos.
No relaja permisos, esquemas, presupuestos o validación entre peticiones; evita
recalcular la misma unión al construir páginas y vecinos de un índice limpio.

`kg_inputs` guarda huellas de metadatos y relaciones derivadas por origen. Entradas modificadas se reemplazan de forma transaccional; ausentes/inadmisibles se retiran solo al completar el recorrido. Lecturas ocultan claims obsoletos o excluidos antes de la próxima sincronización. Cambiar el motor exige incrementar `ENGINE_VERSION`; las identidades siguen estables. DDL aplicada y checksum son inmutables: cambios posteriores requieren otra migración.

El esquema instala triggers propios `kg_watch_*` que solo incrementan `kg_epoch` dentro de las transacciones de tablas fuente locales. No modifica sus filas ni archivos canónicos. Cada lectura verifica cobertura y definición de los triggers y los esquemas de origen. Una huella completa limpia permite memoizar **solo su digest**, máximo16, sin conexiones persistentes ni texto privado. Epoch, configuración/permisos, generación o archivos DB cambiados invalidan la prueba; rollback revierte el contador. Si falta un trigger o aparece otro dominio, se usa verificación completa y se informa `requires_sync`. Sync repone triggers ausentes; uno alterado se rechaza, no se sobrescribe silenciosamente. No es protección forense contra un administrador que manipule arbitrariamente toda la DB.

Cobertura: `requires_sync`, `missing_or_stale_inputs`, `obsolete_inputs`, `watcher_coverage_complete`, `source_validation`, `last_complete_at`, comprobaciones/omisiones de soluciones y presupuesto. Índice limpio no significa fuentes actuales: Audit sigue siendo necesario para deriva documental y Cyber status para cobertura pública.

SQL usa paginación por claves, índices de incidentes y CTE materializadas; presupuesto cooperativo de20M operaciones/5s por petición. Al excederlo retorna error seguro, no resultados aparentemente completos. Temporales SQL solo en memoria de la conexión; no escribe temporales fuera del proyecto. No es un benchmark de latencia garantizada ni una cota exacta de RAM.

## Validación reproducible

```powershell
python -B -m unittest tests.test_knowledge_graph -v
python -B scripts/validate_knowledge_graph.py
```

La segunda operación migra/proyecta una **copia temporal** de la DB real, consulta páginas/vecinos e integridad y elimina sus temporales. Nunca reemplaza el índice vivo; imprime solo agregados y guarda informe ignorado bajo `data/`. No valida el renderer, clientes de agentes ni proveedores remotos. Las pruebas focales incluyen aislamiento, Unicode, exclusiones, relaciones, rollback, restauración, concurrencia, cursores, namespaces nuevos, esquema y contadores ausentes/alterados, motor nuevo y corpus mayor que el límite visual.
