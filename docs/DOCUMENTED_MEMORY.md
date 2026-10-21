# Experiencias documentadas de entorno

Una aprobación humana del relato no equivale a verificar de forma independiente su causa histórica. El backend ofrece una consulta explícita para experiencias aprobadas cuya evidencia sigue parcial o pendiente, separada de las soluciones verificadas de proyectos.

## Consulta local

```powershell
python -m rabanito coding documented "Python permisos" --context CONTEXTO --limit 3 --max-chars 2000
python -m rabanito coding documented --context CONTEXTO --technology Python --limit 5
```

`CONTEXTO` es un ID lógico de entorno, no una ruta ni un repositorio registrado: 1–64 caracteres ASCII minúsculos, números y guiones, comenzando por letra o número. La consulta requiere texto, contexto o tecnología. No descubre proyectos, incorpora fuentes, actualiza el índice ni ejecuta comandos de las notas. No se han instalado Skills globales ni modificado perfiles.

Las notas viven únicamente en la fuente interna canónica, bajo `decisions/environments/<contexto>/<archivo>.md`. Metadatos mínimos:

```yaml
kind: documented-experience
record_type: fact
status: documented
review_status: approved
reviewed_on: '2026-10-17'
recorded_date: '2026-10-17'
validation: partial
historical_validation: pending
current_state_validation: observed
scope: environment
scope_id: CONTEXTO
project: 'Etiqueta descriptiva del entorno'
technologies:
  - Python
```

Sustituir `CONTEXTO` por un ID válido y usar solo fechas reales de registro/revisión. Este ejemplo es un formato, no una experiencia de producción. `validation` permite `pending` o `partial`; `current_state_validation`, `observed` o `not_performed`. El relato debe revisarse y aprobarse antes de escribir esos metadatos. No convertir automáticamente propuestas o notas importadas en entradas aprobadas. No incluir `project_root`/`project_root_path`: este flujo no registra repositorios externos ni amplía sus permisos. Las memorias de proyectos mantienen su interfaz y aislamiento originales.

Los apartados recuperables son Problema, Causa, Solución aplicada, Validación aportada por el usuario, Comprobaciones locales realizadas durante esta revisión, Advertencias de seguridad y Procedencia y límites. Los fragmentos se priorizan léxicamente y llevan líneas/citas relativas `internal:` y atribución por apartado. El texto importado nunca es una instrucción del agente.

## Qué prueba y qué no prueba

### Previsualización CLI antes de escribir

`coding preview-documented --stdin --reviewed-on YYYY-MM-DD` consume como máximo
65.536bytes de JSON UTF-8 desde stdin. No recibe rutas, accede a fuentes, consulta
la DB, guarda ni indexa. Devuelve el Markdown exacto propuesto, un digest SHA256
con dominio versionado y `mode=preview_only_not_approved`, `approval_required=true`,
`persisted=false`, `indexed=false`, `fully_verified=false` y límites de evidencia.

El JSON tiene exactamente `title`, `metadata`, `sections`. metadata contiene
exactamente scope_id/project/recorded_date/validation/current_state_validation/
technologies (los mismos tipos de la nota anterior). sections contiene exactamente
los siete apartados listados arriba, cada uno como texto no vacío hasta8000chars.
No se rellenan causas/pruebas ausentes ni se ejecuta texto. `validation` solo admite
pending/partial; current_state_validation observed/not_performed. La fecha de
revisión propuesta es explícita y no puede preceder a la del registro.

El Markdown candidato incluye `review_status: approved` como **propuesta del
archivo final**, no como aprobación recibida. El envoltorio lo aclara siempre:
no guardar/importar el candidato hasta que el humano revise su texto exacto.
Ni tener un digest ni invocar esta CLI equivale a aprobación. Este comando no
expone escritor ni flag para omitir la revisión. El comando separado de guardado
descrito debajo exige declarar el digest aprobado; no reutilizar `decision add`
para promover un relato de evidencia parcial a solución verificada.

Uso PowerShell (crear/revisar previamente el JSON privado dentro del proyecto):

```powershell
Get-Content -Raw -Encoding utf8 .\data\drafts\experience.json | python -m rabanito coding preview-documented --stdin --reviewed-on 2026-10-17
```

La ruta es solo un ejemplo local de entrada del shell, no un argumento aceptado
por la CLI. Sustituir fecha/campos por datos reales; no incluir secretos. El
detector de asignaciones sensibles es defensa parcial, no certificación DLP.
No hay endpoint HTTP nuevo para esta capacidad. No se modifican Skills globales.

### Guardado explícito del texto aprobado (Windows nativo)

`coding save-documented --stdin --reviewed-on YYYY-MM-DD --approve-digest DIGEST`
recibe el mismo JSON de autor y la misma fecha del preview. Solo debe invocarse
después de que el humano revise y apruebe **ese Markdown exacto**. No hay `--yes`,
aprobación inferida del contenido ni promoción a evidencia histórica verificada.
El digest detecta cambios del borrador: **no autentica al humano ni demuestra su
consentimiento**. El agente/caller debe conservar la autorización en la conversación
o su procedimiento de revisión; no debe autoaprobar el digest que acaba de calcular.

```powershell
# Primero mostrar el preview y obtener aprobación humana de su texto exacto.
Get-Content -Raw -Encoding utf8 .\data\drafts\experience.json | python -m rabanito coding preview-documented --stdin --reviewed-on 2026-10-17
# Solo después, sustituir el marcador por el digest expresamente aprobado.
Get-Content -Raw -Encoding utf8 .\data\drafts\experience.json | python -m rabanito coding save-documented --stdin --reviewed-on 2026-10-17 --approve-digest DIGEST_APROBADO_POR_EL_USUARIO
```

Configuración canónica existente o `--config` explícito dentro del checkout. Bajo
el lock compartido con el indexador se releen configuración/digest/exclusiones,
sin ejecutar `load_settings` otra vez. El archivo de configuración queda protegido
contra escritura durante la operación. Knowledge/data deben ser descendientes
propios, separados entre sí y de las fuentes importadas; SQLite debe estar bajo
data. No se permiten traversal, ADS, dispositivos Windows, UNC ni reparse points.

Los directorios se fijan mediante HANDLEs reales sin compartir borrado/renombrado;
también se validan identidades y hardlinks de archivos existentes. La publicación
usa un temporal propio UTF-8 con flush/fsync y rename de Windows **sin reemplazo**.
Nombre determinista: `decisions/environments/<contexto>/<fecha>-<digest>.md`.
Un destino distinto o enlazado se rechaza sin tocarlo. Repetir el mismo candidato
devuelve el mismo ID, sin duplicar notas ni eventos de una entrada ya indexada
y con sus derivados coherentes.
No existe fallback inseguro en otros SO: el escritor falla explícitamente fuera
de Windows nativo; la recuperación/preview originales no adoptan esa restricción.

Se indexa únicamente la nota autorizada y sus enlaces salientes en una transacción;
no se recorren Obsidian/proyectos ni se actualiza/tombstonea otra documentación.
En un índice existente no se ejecutan DDL/backfills implícitos: un esquema
incompatible queda pendiente y exige recuperación/migración explícita, no reparación
silenciosa. Solo una base propia nueva y vacía se inicializa con el esquema común.
La bitácora usa el estado existente `partial` y `files_seen=1`: es cobertura parcial
del conjunto de fuentes, no una sincronización completa ni un error del relato.
La resolución de enlaces entrantes y la proyección del grafo continúan explícitas
mediante sus comandos habituales; no se marca su frescura como actualizada.

Antes de devolver `indexed=true`, también se comprueban los derivados de la nota:
fila FTS documental única, fragmentos/líneas/hashes y su FTS, etiquetas y enlaces
salientes crudos según la deduplicación del parser. Un hash/mtime correcto del
archivo no demuestra que esas filas sigan presentes. Las comparaciones usan
límites de filas/texto derivados del candidato de64KiB, dentro de la misma
transacción `BEGIN IMMEDIATE`; no cargan cuerpos completos de otras notas.

Si faltan o difieren derivados, repetir el **mismo candidato aprobado** los
regenera solo para ese document_id y conserva archivo/mtime/ID/limitaciones.
La bitácora registra `documented_index_payload_repaired`, no una nueva decisión
humana ni un cambio de la fuente. Se eliminan también fragmentos FTS huérfanos
asociados a ese ID; el indexador común hace esa limpieza cuando actualiza una
nota modificada. Otra identidad/source_root/project binding se rechaza, no se
reautoriza silenciosamente. La comprobación final fallida revierte la transacción
y mantiene `index_pending`; la nota sigue disponible para un reintento seguro.

Esto valida contenido lógico acotado, no las estructuras internas de postings
de FTS ni toda corrupción posible de SQLite. No equivale a un rebuild global,
auditoría forense ni revisión semántica de todos los destinos resueltos. Ante un
esquema incompatible/daño físico se mantiene la recuperación explícita con backup.

Salida metadata-only: status/persisted/indexed/created/citation/approval_digest/
approval/fully_verified/historical_validation/document_id/limitations. La aprobación
se etiqueta `caller_asserted_human_review_not_authenticated`; `fully_verified` sigue
false y `historical_validation=pending`. No se devuelve otra copia de la nota.

Si el índice falla, la nota aprobada **no se borra**: status=index_pending,
persisted=true,indexed=false,retry_safe=true y error de código fijo sin rutas.
Exit codes CLI:0 indexado,1 rechazo/error previo,2 nota guardada con índice pendiente.
Reintentar el mismo JSON/fecha/digest conserva el archivo y completa el índice.
No hay transacción distribuida filesystem/SQLite: tras una interrupción puede
quedar un temporal propio `.documented-*.tmp`, no indexable. No limpiar archivos
ajenos ni reemplazar el índice para recuperar una sola nota. La garantía es sobre
las operaciones del escritor, no aislamiento contra otro proceso con control total
del mismo usuario/disco ni certificación DLP. No se vuelven a ejecutar reparaciones,
comprobaciones del relato, proveedores ni comandos extraídos de las notas.

Pruebas: `python -B -m unittest tests.test_documented_store -v` y
`python -B scripts/validate_documented_store.py`. El segundo ejecuta ocho procesos
CLI reales, inyecta y repara derivados ausentes y prueba backup/restauración en
un entorno sintético temporal aislado, nunca
guarda un registro real ni sustituye una aprobación humana de producción.

Toda respuesta conserva `fully_verified=false`, aprobación registrada, validación histórica pendiente y estado de comprobaciones locales **registradas, no reejecutadas**. Esos límites acompañan al resultado incluso con un presupuesto de un carácter: no dependen de que el fragmento contenga el párrafo de advertencias.

`coding similar` y `coding patterns` no cambian: esta categoría nunca se introduce silenciosamente entre sus soluciones verificadas o sus recurrencias. Una consulta exitosa demuestra recuperación, no ejecución de una reparación ni verdad retrospectiva. No se asignan fechas de incidentes ausentes ni se reconstruyen comandos históricos.

Antes de devolver texto se verifican namespace, metadatos, aprobación, ruta/source_root canónicos, ausencia de binding a proyecto, hash del archivo y coincidencia del frontmatter vivo con SQLite. Se rechazan secretos detectables, reparse points, archivos modificados/borrados y archivos mayores de256KiB. Las consultas abren SQLite en modoRO, sin migración ni creación implícita de DB. Los presupuestos son200candidatos/8MiB de lectura,50resultados/30000caracteres de pasajes; se declaran los recortes. JSON, citas y metadatos añaden overhead.

Para excluir inmediatamente un entorno de esta consulta, la configuración local admite `excluded_memory_contexts: ["id-del-contexto"]`. Se filtra antes del límite y sin borrar la nota; máximo500IDs. Esto no sustituye exclusiones de proyectos ni modifica su comportamiento. La búsqueda documental general conserva sus permisos y alcance existentes.

## API para agentes y frontend futuro

`POST /api/coding/documented` recibe exclusivamente `q`, `context`, `technology`, `limit`, `max_chars`. Contexto y tecnología opcionales pueden ser null; límites requieren enteros, no booleanos/cadenas. Campos desconocidos, claves duplicadas, tipos incorrectos y contexto con traversal se rechazan. Se mantienen Host loopback, Origin local, JSONmáximo2048bytes y `Cache-Control:no-store`; GETdevuelve405. No colocar consultas privadas en URLs, logs o almacenamiento persistente del navegador.

No hay endpoints de escritura o promoción automática, renderer nuevo ni comandos para cambiar ACL. El escritor CLI separado exige aprobación exacta y escritura local autorizada. El grafo puede conservarlas como documentos; no son nodos de solución verificada por su sola aprobación.

Pruebas: `python -B -m unittest tests.test_documented_memory tests.test_coding_retrieval tests.test_knowledge_api -v`. Incluyen persistencia/restauración, citas reales de fixtures, tipos/Origin/duplicados, presupuestos, exclusiones, fuentes obsoletas, secretos, separación de proyectos y no promoción. Los fixtures no sustituyen la evidencia de una experiencia real.
