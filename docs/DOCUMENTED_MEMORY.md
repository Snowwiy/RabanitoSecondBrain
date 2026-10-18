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

### Previsualización CLI antes de una futura escritura

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
expone escritor ni flag para omitir la revisión. La escritura segura/idempotente
con comprobación de aprobación sigue pendiente; no reutilizar `decision add`
para promover un relato de evidencia parcial a solución verificada.

Uso PowerShell (crear/revisar previamente el JSON privado dentro del proyecto):

```powershell
Get-Content -Raw -Encoding utf8 .\data\drafts\experience.json | python -m rabanito coding preview-documented --stdin --reviewed-on 2026-10-17
```

La ruta es solo un ejemplo local de entrada del shell, no un argumento aceptado
por la CLI. Sustituir fecha/campos por datos reales; no incluir secretos. El
detector de asignaciones sensibles es defensa parcial, no certificación DLP.
No hay endpoint HTTP nuevo para esta capacidad. No se modifican Skills globales.

Toda respuesta conserva `fully_verified=false`, aprobación registrada, validación histórica pendiente y estado de comprobaciones locales **registradas, no reejecutadas**. Esos límites acompañan al resultado incluso con un presupuesto de un carácter: no dependen de que el fragmento contenga el párrafo de advertencias.

`coding similar` y `coding patterns` no cambian: esta categoría nunca se introduce silenciosamente entre sus soluciones verificadas o sus recurrencias. Una consulta exitosa demuestra recuperación, no ejecución de una reparación ni verdad retrospectiva. No se asignan fechas de incidentes ausentes ni se reconstruyen comandos históricos.

Antes de devolver texto se verifican namespace, metadatos, aprobación, ruta/source_root canónicos, ausencia de binding a proyecto, hash del archivo y coincidencia del frontmatter vivo con SQLite. Se rechazan secretos detectables, reparse points, archivos modificados/borrados y archivos mayores de256KiB. Las consultas abren SQLite en modoRO, sin migración ni creación implícita de DB. Los presupuestos son200candidatos/8MiB de lectura,50resultados/30000caracteres de pasajes; se declaran los recortes. JSON, citas y metadatos añaden overhead.

Para excluir inmediatamente un entorno de esta consulta, la configuración local admite `excluded_memory_contexts: ["id-del-contexto"]`. Se filtra antes del límite y sin borrar la nota; máximo500IDs. Esto no sustituye exclusiones de proyectos ni modifica su comportamiento. La búsqueda documental general conserva sus permisos y alcance existentes.

## API para agentes y frontend futuro

`POST /api/coding/documented` recibe exclusivamente `q`, `context`, `technology`, `limit`, `max_chars`. Contexto y tecnología opcionales pueden ser null; límites requieren enteros, no booleanos/cadenas. Campos desconocidos, claves duplicadas, tipos incorrectos y contexto con traversal se rechazan. Se mantienen Host loopback, Origin local, JSONmáximo2048bytes y `Cache-Control:no-store`; GETdevuelve405. No colocar consultas privadas en URLs, logs o almacenamiento persistente del navegador.

No hay endpoints de escritura o promoción automática, renderer nuevo ni comandos para cambiar ACL. Guardar notas sigue requiriendo aprobación exacta y escritura local autorizada. El grafo puede conservarlas como documentos; no son nodos de solución verificada por su sola aprobación.

Pruebas: `python -B -m unittest tests.test_documented_memory tests.test_coding_retrieval tests.test_knowledge_api -v`. Incluyen persistencia/restauración, citas reales de fixtures, tipos/Origin/duplicados, presupuestos, exclusiones, fuentes obsoletas, secretos, separación de proyectos y no promoción. Los fixtures no sustituyen la evidencia de una experiencia real.
