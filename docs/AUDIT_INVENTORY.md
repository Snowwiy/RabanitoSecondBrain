# Inventario de fuentes en Audit (contrato aditivo)

`collect_audit`, la CLI `audit`, sus informes JSON/Markdown y la proyección del
dashboard añaden `source_inventory`. No cambia ningún contador anterior:
`documents_index_drift` sigue revisando documentos ya indexados. No se añaden
rutas HTTP, parámetros de búsqueda o campos al lector Markdown.

La sección distingue existencia de archivos elegibles y registro visible en el
índice. No indexa, registra proyectos, escribe fichas o confirma conocimiento.
No abre contenidos de notas, manifiestos, credenciales o código: solo enumera
entradas/atributos y consulta metadatos SQLite. La revisión de contenido de
documentos YA indexados permanece en `index_drift_summary` y otras revisiones.

## Campos de `source_inventory`

| Campo | Significado |
| --- | --- |
| `scope` | `metadata_only_eligible_files` |
| `performed` | Indica que se intentó la revisión; ausente en un informe antiguo no equivale a cobertura completa. |
| `roots_total`, `roots_started` | Fuentes activas configuradas y fuentes cuya enumeración comenzó. |
| `entries_examined` | Entradas recorridas, incluidas las excluidas. |
| `eligible_files`, `indexed_files`, `unindexed_files` | Archivos únicos elegibles observados; con o sin registro activo y visible. No son documentos incorporados. |
| `new_project_roots`, `inactive_project_roots` | Raíces observadas sin registro o con registro no activo. No son proyectos incorporados. |
| `excluded_entries`, `reparse_entries_skipped`, `oversized_files` | Exclusiones observadas por política, redirección o límites de tamaño. |
| `unverifiable_project_files` | Memoria de proyecto cuya autorización no puede probarse solo con metadatos; se omite y declara cobertura parcial. |
| `roots_unavailable`, `directory_errors`, `directories_changed`, `depth_limited_directories` | Problemas o cambios observados que impiden asegurar cobertura del recorrido. No contienen errores/rutas absolutos. |
| `budget_exhausted`, `coverage_complete` | Límite cooperativo alcanzado y cobertura del inventario elegible; independientes de la revisión de documentos indexados. |
| `findings_truncated`, `findings` | Muestra acotada de candidatos, no una lista necesariamente exhaustiva. |
| `limits` | Límites efectivos de entradas, raíces, profundidad, tiempo cooperativo y hallazgos. |
| `review_only` | Siempre `true`. |

Cada hallazgo contiene únicamente `source_kind`, `relative_path`, `status` y
`review_only`. Los estados son `not_indexed`, `not_visible_in_index`,
`project_not_registered` y `project_not_active`. No hay IDs ficticios, raíces
absolutas, títulos, hashes o contenido. Se aplica la redacción habitual de Audit.

## Límites configurables

Claves opcionales en la configuración local; valores inválidos usan el default,
fuera de rango se acotan. No se modifica automáticamente la configuración real.

| Clave | Default | Rango efectivo |
| --- | ---: | ---: |
| `audit_inventory_max_entries` | 20000 | 1–200000 |
| `audit_inventory_max_roots` | 64 | 1–1024 |
| `audit_inventory_max_depth` | 32 | 0–128 |
| `audit_inventory_max_findings` | 100 | 0–500 |
| `audit_inventory_max_seconds` | 5 | 0.01–30 |

Se reutilizan exclusiones y selección de documentos del indexador. Proyectos:
primer nivel y raíces VCS propias, no cada manifiesto de un monorepo. Directorios
excluidos/reparse no se recorren; fuentes deshabilitadas no se inspeccionan.
La memoria de proyecto interna requiere una asociación comprobable sin leer sus
notas. Si no puede verificarse, la omisión es explícita, no una cobertura limpia.
El recorrido conservador de `decisions/` también puede omitir una experiencia
de entorno sin asociación a proyecto, aunque ya esté indexada y sea recuperable
por Coding Memory. Se cuenta como `unverifiable_project_files`, sin divulgar su
nombre en hallazgos ni cambiar su aprobación/validación. Este contador no prueba
que falte un documento o que el usuario deba registrarlo de nuevo.

Los límites son cooperativos: una llamada bloqueada al sistema de archivos no
puede cancelarse con una comprobación de tiempo entre entradas; tampoco son un
timeout duro para operaciones SQLite. La enumeración
no congela el filesystem ni es una auditoría forense; cambios de directorio
observados invalidan su cobertura. Un recorrido completo no demuestra contenido
vigente ni seguridad de los documentos. Debe combinarse con las demás revisiones.

## Uso e interpretación

`python -m rabanito audit` devuelve la sección junto al resto de la auditoría.
`python -m rabanito audit --write` publica explícitamente informes locales
JSON/Markdown mediante el escritor protegido existente; no cambia las fuentes
ni incorpora los candidatos encontrados. Un índice ausente se consulta en RAM,
sin crear la base persistente. Un índice existente inválido no se repara u oculta.

`unindexed_files > 0` pide revisar las fuentes/políticas y decidir una
sincronización incremental por separado. No autoriza una sincronización
automática. `coverage_complete=false` impide afirmar que no quedan otras altas;
consultar los contadores de problemas y límites. Agotar la muestra de hallazgos
no cambia los contadores totales observados. `indexed_files` acredita una fila
activa/visible de ese origen, no igualdad del cuerpo: ver `index_drift_summary`.

Audit toma una copia de configuración y una transacción SQL de lectura común
para sus metadatos. No obtiene un snapshot global del filesystem. La identidad
de archivo es lexical y no sigue reparse; las comprobaciones entre operaciones
no son un sandbox frente a un administrador que cambie el árbol concurrentemente.

## Level Up (comportamiento aditivo)

Las recomendaciones deben advertir de archivos pendientes, proyectos nuevos/no
activos y cobertura parcial del inventario. Conservan el formato existente
`priority/action/why/command` y el resumen `based_on`; no añaden rutas HTTP o
campos al lector. El informe local completo ya incluye Audit y su inventario.
Estos avisos proponen revisar `python -m rabanito audit`, no ejecutar indexado,
registrar proyectos, forzar presupuestos o confirmar conocimiento. Una memoria
de entorno omitida conservadoramente no se presenta como nota perdida.
Level Up sigue siendo una operación explícita que escribe informes locales;
no se convierte en consulta pura por consumir un inventario de solo lectura.

Esta ampliación corrige la ausencia de aviso al crear un archivo autorizado tras
la última indexación. La implementación y sus pruebas se registran por separado;
el contrato por sí solo no acredita validación en una instalación determinada.
