# Contrato unificado Frontend ↔ backend — Rabanito Second Brain 3.0

## Base y procedencia de la integración (2026-10-21)

Esta rama de integración parte del backend estabilizado de `origin/main`
`c1f11ce12240caf2a085cc299ddf243676095da6` y combina el frontend publicado
`origin/Frontend-Design` `39b572f28dc6f60915d44bc8b6ad790f78d1c386`.
Este documento conserva el contrato de seguridad del lector y añade los
consumidores del Neural Command Center. `main` y `Frontend-Design` son fuentes
de referencia; el trabajo de resolución vive solo en `integration/rabanito-3.0`.

Las lecturas del API aplican una configuración de fuentes tomada como snapshot
por consulta. Los filtros de autorización, las exclusiones actuales y los
límites se evalúan antes de entregar datos o citas. Las consultas del grafo no
sincronizan fuentes; la sincronización del índice y de proyecciones derivadas
conserva sus controles explícitos.

## POST /api/doc/content

Petición JSON exacta, sin campos adicionales ni duplicados:

```json
{"document_id":123,"max_bytes":65536}
```

Ambos campos son obligatorios: ID entero positivo seguro para JavaScript
(hasta 9007199254740991); max_bytes entero 1–65536. No acepta rutas.
Host y Origin HTTP loopback con el puerto del servidor, Content-Type JSON,
cuerpo de hasta 2048 bytes; filtros privados nunca en la URL. GET devuelve405.

Respuesta200, exactamente el formato requerido por el lector existente:

```json
{
  "document_id":123,
  "content_markdown":"# …",
  "bytes_returned":5,
  "truncated":false,
  "references":[{
    "target_document_id":456,
    "title":"…",
    "target_raw":"…",
    "relative_path":"…",
    "status":"resolved"
  }]
}
```

El ejemplo ilustra tipos; bytes_returned debe coincidir con la codificación
UTF-8 real de content_markdown. Cache-Control:no-store; no rutas absolutas
ni metadatos del filesystem en envoltura, referencias o errores.

## Precisiones necesarias antes de implementar

No se encontró incompatibilidad de campos con el adaptador. Estas reglas
precisan comportamientos de seguridad no especificados en la rama UI:

- El cuerpo es una **vista de texto no confiable**, no una exportación exacta:
  se redactan patrones detectables de credenciales y rutas absolutas mediante
  marcadores visibles. No es un detector universal de información confidencial;
  mantener exclusiones de fuentes. No se añade un campo `redacted` no acordado.
  El servidor no interpreta HTML, ejecuta instrucciones ni carga recursos.
- Se leen como máximo max_bytes bytes del original. El texto devuelto también
  queda dentro de ese presupuesto UTF-8. Se normalizan BOM/saltos de línea;
  una última línea incompleta por truncamiento se omite para no revelar secretos
  parcialmente leídos. truncated refleja recorte del original o de la salida,
  no la redacción. Un presupuesto diminuto puede devolver texto vacío.
- Un documento cambiado desde su indexación devuelve409; no se sincroniza
  automáticamente. Para archivos completos se contrasta también el hash del
  índice. Para prefijos truncados solo se acredita identidad/tamaño/mtime
  estable; no se afirma haber verificado el hash de todo el original.
- Se revalidan estado activo, fuente actualmente habilitada, política de
  exclusiones, pertenencia a proyecto activo y rutas sin reparse/symlinks.
  La lectura usa un descriptor de solo lectura y verifica su identidad antes
  de consumir bytes. No abre aplicaciones ni escribe notas o base de datos.
- references contiene como máximo512 enlaces explícitos resueltos a documentos
  activos y actualmente autorizados; no sugerencias, ambiguos o rutas externas.
  Cada cadena tiene como máximo1000 caracteres. Se omiten referencias inseguras;
  su presencia no prueba frescura del contenido del destino.
- Las consultas seleccionan solo las columnas necesarias para autorización y
  frescura. No cargan frontmatter/tags/errores completos de cada destino; títulos
  y target_raw se acotan en SQL antes de materializar las referencias.
- Errores reutilizan el formato existente `{"error":"codigo_estable"}`:
  400 petición/UTF-8 inválidos, 403 origen/formato denegados, 404 documento
  ausente/no autorizado, 409 fuente cambiada/no disponible, 413 tamaño excedido,
  503 índice no disponible. Nunca se incluyen valores de entrada ni OS errors.

Esta precisión mantiene compatibles los estados400/404/409/413 y los errores5xx
que el lector ya contempla. La protección final de renderizado sigue siendo
responsabilidad del parser DOM seguro del frontend; no usar innerHTML.

## Validación

El backend del lector se publicó inicialmente en `main`; la combinación actual
se valida por separado en `UI_TEST_RESULTS.md`. El histórico de pruebas del
backend no sustituye la regresión del árbol combinado ni la QA del navegador.

### Adaptador del lector en el Neural Command Center

El Inspector solicita primero `GET /api/doc/{id}` y contexto citado mediante
`POST /api/context`. La acción explícita “Leer Markdown” envía únicamente el ID
indexado y el presupuesto a `POST /api/doc/content`. La interfaz no acepta rutas
del sistema de archivos. Los errores 400/403/404/409/413/503 conservan los
metadatos y citas ya disponibles, sin reindexar automáticamente.

El parser Markdown crea nodos DOM de un subconjunto acotado, trata HTML crudo
como texto, permite enlaces externos HTTP(S) y resuelve enlaces internos solo con
referencias autorizadas devueltas por el endpoint. Cuerpo y consultas no se
guardan en preferencias del navegador. El servidor y los assets se sirven desde
el mismo origen loopback; no se habilita CORS para unir worktrees.

## Contrato del Neural Command Center

### Estado de indexación expuesto al dashboard

`GET /api/stats` (`latest_scan`), `GET /api/scans` y `POST /api/index` reutilizan
la proyección compacta de `project_scan_summary()`: `status`, `errors`, marcas
de tiempo, contadores, `source_summary` acotado y los subconjuntos validados de
`scan_coverage` y `retirement_guard`. HTTP 200 solo confirma el transporte.

El dashboard considera completa una ejecución únicamente cuando `status=ok`,
`errors=0`, existe `finished_at`, la cobertura indica `complete=true` con todas
las fuentes esperadas/completadas y sin fallidas, sin procesar o incompletas, y
el guard informa estado `not_required` o `approved` sin retiros retenidos,
alcance incompleto, identidades cambiadas ni documentos preservados de fuentes
no configuradas. Un estado `approved` debe traer `approval_applied=true`. La UI
no crea ni envía aprobaciones y nunca recomienda un reintento con force.

`status=partial`, errores, fuentes inaccesibles, cobertura incompleta, retiros
retenidos, `review_required`/`approval_rejected`, campos faltantes o diagnósticos
malformados se muestran como parcial, fallo, revisión humana requerida o estado
no confirmado. Se presentan los contadores permitidos para cobertura y retiros;
los errores agregados de `source_summary` no se convierten en una explicación de
permisos ni exponen raíces privadas. No inferir estos estados de `removed`,
`skipped`, `errors` ni del código HTTP.

`GET /api/stats` y `GET /api/scans` devuelven `last_complete_scan`, una marca
confirmada y enlazada a su fila de bitácora/cobertura. El dashboard la conserva
como la última sincronización completa confirmada aunque el intento actual sea
parcial o falle; `null` se presenta como “sin registro confirmado”, no como
prueba de que nunca existió una ejecución. `/api/scans` puede devolver hasta 30
filas; la UI presenta diez. Los historiales `ok` antiguos sin diagnósticos no se
promueven retroactivamente a completos.

El contrato aditivo está descrito con sus invariantes y límites en
[`docs/SCAN_OUTCOMES.md`](docs/SCAN_OUTCOMES.md). La implementación del dashboard
está en `web/knowledge.js` y en el panel heredado de `web/index.html`; las pruebas
con datos sintéticos cubren retiros masivos retenidos, fuentes inaccesibles,
respuestas HTTP 200 parciales, estados heredados sin cobertura y la persistencia
de la última marca completa.

### Protección de respuestas asíncronas del Inspector y páginas del grafo

Cada selección del Inspector invalida el contexto de recuperación anterior y
usa una generación dedicada; respuestas, errores y `finally` tardíos solo pueden
actualizar el DOM si generación, ID y selección siguen vigentes. Fragmentos y
relaciones permanecen protegidos por la generación del inspector compartida.
La paginación tipada conserva los cursores de página separados de los cursores de
vecinos y no solicita una página si alcanzó 1,000 nodos, el cursor falta/se repite
o la respuesta anterior no añadió nodos ni relaciones. El cliente comunica
entidades cargadas frente a candidatos disponibles (estos últimos son el conteo
del backend antes de su verificación viva); los límites locales siguen en 1,000
nodos y 4,000 aristas.

| Vista/operación | Contrato | Comportamiento y límite |
|---|---|---|
| Dashboard y filtros | `GET /api/health`, `/api/stats`, `/api/projects`, `/api/categories`, `/api/tags`, `/api/sources`; `POST /api/search`, `/api/context` | Usa inventario y citas del índice. Consultas privadas van en JSON POST. Valores se renderizan como texto. |
| Inspector | `GET /api/doc/{id}`, `/api/related/{id}`; `POST /api/doc/content` | Solo IDs activos y autorizados; lectura Markdown hasta 65,536 bytes. No acepta rutas del caller. |
| Neural Orbit / Hex / Tree / Galaxy | `POST /api/graph` para documentos; `POST /api/knowledge-graph` y `/neighbors` para entidades tipadas | Página tipada hasta 200 registros, vecinos de un salto; el cliente limita el acumulado a 1,000 nodos y 4,000 aristas. Las vistas y filtros son de solo lectura. |
| Actualización del grafo tipado | `POST /api/knowledge-graph/sync` | Requiere `confirm_graph_sync: true` después de confirmar en un diálogo modal accesible. El cliente pide como máximo 1,000 entradas/32 MiB por lote. Un lote parcial no se repite automáticamente y no modifica Obsidian ni archivos de proyectos. |
| Cyber Threat / Zero Trust / Coding Memory | Rutas de `/api/attack/*`, `/api/cyber/*`, `/api/security/*` y `/api/coding/*`, descritas en `docs/API_CONTRACT.md` | Conserva autorización, límites, citas y estados de cobertura. Evidencia parcial, sugerida o histórica no se promueve a hecho confirmado. |

Las aristas distinguen `explicit`, `suggested`, `inferred` y `reviewed_claim`.
Las sugerencias requieren activación del usuario. Las comunidades visuales son
estimaciones topológicas sobre enlaces cargados, no clasificación semántica del
backend. Las 32 clases tipadas conservan IDs y procedencia; etiquetas localizadas
no sustituyen claves API.

Los cursores de Knowledge Graph quedan ligados a filtros y al tamaño de página.
El cliente reutiliza el tamaño de la primera página al continuar; las respuestas
de `/neighbors` amplían nodos/aristas sin reemplazar el cursor de paginación de
`/api/knowledge-graph`. Si cambia el alcance y el servidor rechaza el cursor,
la interfaz conserva el grafo visible y permite volver a solicitar la primera
página.

El modo de documentos de `/api/graph` sigue compatible con el dashboard; se
conservan también los dominios `cyber` y `security` del backend. El servidor
rechaza query string, parámetros y fragmentos en URLs del Knowledge Graph, y
rechaza claves JSON duplicadas en las rutas protegidas. Los cuerpos POST siguen
limitados: 16 KiB para páginas/vecinos del grafo y 2 KiB para operaciones
pequeñas, incluido el lector.

## Operación y degradación

Ejecutar el dashboard combinado desde este checkout con `python -m rabanito dashboard`.
Un proceso anterior debe reiniciarse de forma controlada para cargar
esta versión; la integración no termina procesos ajenos. Los fixtures siguen
siendo solo de prueba y se identifican como sintéticos. Un error de red o timeout
es recuperable y no repite escrituras ni refresca fuentes automáticamente.

La QA visual, los resultados de regresión y las limitaciones de zoom, lectores
de pantalla y frame-time se registran en `UI_TEST_RESULTS.md`.

Referencia de implementación Windows: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
y [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
Se usa lectura OPEN_EXISTING, sin compartir escritura/eliminación, y se comprueba
la ruta del handle antes de leer. No se elevan privilegios ni se cambian ACL.
