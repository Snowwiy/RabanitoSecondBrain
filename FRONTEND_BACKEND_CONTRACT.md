# Contrato de lectura Markdown — backend main

## Referencia revisada, sin merge

Revisión de solo lectura de `Frontend-Design`, commit
`4dd4a23f647a067cff862496a21fcecb502b8717` (2026-10-17).
El SHA256 de su `FRONTEND_BACKEND_CONTRACT.md` es
`026120a9772d69dfcd514cbc844fed876efa33856d204a5f05474d04f06a62d1`.
También se contrastaron UI_MASTER_SPEC, UI_INTEGRATION_PLAN y el adaptador
Markdown de web/knowledge.js. No se copian sus archivos ni se modifica su rama.

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

Implementado y validado en main; la revisión del frontend no hizo merge ni
modificó su checkout. El commit publicado se verifica mediante Git, no mediante
un estado de despliegue supuesto en esta documentación.35regresiones nuevas
incluyen junctions reales de Windows y reemplazo entre autorización/apertura.
La matriz del endpoint pasó694Python normal+694optimizado y52JavaScript; los
resultados posteriores del backend se documentan en TEST_RESULTS/NEXT_SESSION.
HTTP real recuperó Obsidian con2referencias resueltas, proyectos y memoria interna.
El parser real de Frontend-Design/cyber.js aceptó esas tres respuestas cargado
solo en memoria. Se comprobó backup/restauración, SQLite/FK/5FTS, originales
indexados y checkout UI intactos. No confundir esto con fixtures ni QA visual.

### Handoff a Frontend-Design (sin instalación ni merge)

El adaptador existente puede consumir este esquema sin cambiar campos. Usar un
servidor que ejecute el backend actualizado de main (`python -m rabanito dashboard`
desde ese checkout). Un servidor ya abierto con código anterior necesita reinicio
controlado; este desarrollo no mata ni reemplaza procesos ajenos.

Frontend y API deben servirse desde el mismo Origin. El servidor propio de la rama
UI antigua todavía no contiene este endpoint y el dashboard actual de main aún
no contiene sus nuevos assets/lector. La unión visual necesita una etapa posterior
autorizada; no copiar archivos entre worktrees, fusionar, usar el fixture como
API real ni abrir CORS para saltarse ese aislamiento. Un404 puede indicar backend
antiguo/servidor incorrecto, no inexistencia de documentos. Mantener409 como estado
de fuente cambiada y refrescar el índice solo mediante acción explícita autorizada.

No se modificó el worktree de Luna, se instaló una Skill ni se validó un navegador.

Referencia de implementación Windows: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
y [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
Se usa lectura OPEN_EXISTING, sin compartir escritura/eliminación, y se comprueba
la ruta del handle antes de leer. No se elevan privilegios ni se cambian ACL.
