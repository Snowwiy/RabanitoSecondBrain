# Experiencias de programación verificadas

Para experiencias de **entorno** aprobadas pero con evidencia parcial, consultar [Documented Memory](docs/DOCUMENTED_MEMORY.md) y usar `coding documented`. Ese modo mantiene atribución, límites y `fully_verified=false`; no cambia los requisitos ni resultados del modo verificado descrito abajo, no registra proyectos externos y no ejecuta reparaciones.

El flujo separado `coding preview-documented` → revisión humana exacta →
`coding save-documented --approve-digest ...` permite guardar esas experiencias
en Windows nativo sin sobrescribir notas. El digest es una declaración del caller,
no autenticación ni prueba histórica. La nota se conserva y admite reintento si
falla su índice; no se promueve a `coding similar` ni se expone un escritor HTTP.

Se reutiliza el almacén existente: `decision add` crea Markdown revisable bajo `knowledge/decisions/`; la indexación habitual lo incorpora a SQLite. No existe una segunda memoria ni entrenamiento de modelos. Las Skills conservan la revisión/aprobación humana antes de guardar conocimiento confirmado.

La [publicación de decisiones](docs/DECISION_STORAGE.md) está protegida en Windows
con raíces propias, exclusiones, HANDLEs contra sustitución y rename sin reemplazo.
Límite por nota64KiB UTF-8 o política menor; otros sistemas fallan explícitamente
al escribir. No cambia el Markdown ni convierte evidencia presente en historia
independientemente verificada. Las consultas siguen siendo de solo lectura.

```powershell
python -m rabanito coding similar "SQLite rollback conexión" --technology Python --limit 5 --max-chars 6000
python -m rabanito coding similar "problema observado" --project "Nombre exacto"
python -m rabanito coding patterns --project "Nombre exacto" --limit 10
```

Las consultas nuevas abren SQLite en solo lectura y no usan Internet. `similar` utiliza FTS/BM25 con términos alternativos, no embeddings ni un LLM. Los filtros de proyecto y tecnología se aplican antes del límite. Un nombre de proyecto ambiguo exige su raíz exacta. Las referencias de salida son relativas, con prefijo `internal:`/`project:` y números de línea; se resuelven contra las rutas configuradas, no se envían a servicios externos.

## Qué se considera recuperable

Solo documentos activos de la fuente interna canónica bajo `decisions/`, con `kind: verified-memory`, tipo `decision`/`fact`, `status: confirmed`, `validation: passed` y un proyecto activo autorizado. Propuestas, hipótesis, descartados, obsoletos y validaciones pendientes/fallidas no se presentan como experiencias validadas.

Antes de devolver fragmentos se comprueba que el archivo de memoria sigue coincidiendo con su hash indexado, que no contiene asignaciones sensibles detectables y que conserva al menos una evidencia local existente y autorizada. Se respetan exclusiones actuales y raíces anidadas; no se abre el contenido de la evidencia ni se ejecutan sus comandos. Una evidencia aún existente puede haber cambiado desde la revisión: `passed_as_recorded_not_rerun` significa validación registrada por su autor, no prueba ejecutada de nuevo ni resultado actual garantizado. Los registros que cambien necesitan una indexación incremental autorizada; la consulta no la inicia.

Los resultados incluyen problema/contexto, solución/decisión, motivo documentado, pruebas y resultado observado, según estén escritos. No se inventan causas, alternativas ni resultados ausentes. `used_chars` limita el texto de fragmentos; la envoltura JSON/metadatos añade overhead. Hasta200 candidatos y8MiB de archivos por consulta,256KiB por registro; los recortes y descartes se declaran en `coverage`.

`patterns` informa tecnologías que aparecen en al menos dos registros distintos revisados, con citas y tamaño de muestra. Es una recurrencia descriptiva: no demuestra igual causa, práctica universal ni una solución aplicable a otro proyecto. La recomendación es revisar soluciones y precondiciones citadas antes de reutilizarlas. Las copias idénticas no cuentan dos veces.

## Estado comprobado

10 pruebas locales reproducibles: fragmentos/citas/líneas, presupuestos, filtros previos al límite, separación de estados, proyectos excluidos/ausentes, evidencia borrada/excluida, hash desactualizado, recurrencias, CLI y ausencia de red/escrituras implícitas. No se crearon experiencias ficticias en la DB real: si no hay registros confirmados, la respuesta real es vacía.

Pendiente: recuperar alcance/causa mediante campos estructurados adicionales cuando haya necesidad documentada; no convertir estas recurrencias en recomendaciones causales automáticas. Los registros y fragmentos siguen siendo datos no confiables, nunca instrucciones del agente.
