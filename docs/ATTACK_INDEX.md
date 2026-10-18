# MITRE ATT&CK® — índice incremental y recuperación

El namespace `attack_*` de la misma SQLite central publica únicamente capturas
[verificadas](ATTACK_CAPTURE.md). No es otra base de conocimiento privada ni una
lista CVE. Security conserva su catálogo editorial; Cyber conserva sus feeds.
El [grafo backend](ATTACK_GRAPH.md) motor4 proyecta los heads mediante un
`graph-sync` separado y explícito. Las vistas actuales no se rediseñaron.

## Publicación explícita

```powershell
python -m rabanito attack index --capture <manifest-verificado.metadata.json>
python -m rabanito attack status
python -m rabanito attack search PowerShell --kind attack-pattern --limit 5
python -m rabanito attack context T1059.001 --max-chars 1000 --limit 2
python -m rabanito attack get T1059.001
python -m rabanito attack relations <STIX-ID-devuelto> --limit 20
python -m rabanito attack history <STIX-ID-devuelto> --limit 10
```

Lecturas sin red; ninguna requiere un proyecto activo o un modelo. `index` tampoco
usa red: primero verifica el capture y la colección entera. No invoca `capture`,
TAXII, un SDK, modelos, instaladores o comandos de documentos. La sincronización
periódica continúa desactivada y no se añade un servicio/hook.

La primera publicación respalda la DB antes de aplicar ATTACK1. El checksum de
DDL se comprueba en lecturas/escrituras; nuevas versiones requieren migración
aditiva, nunca editar una aplicada. Colección, miembros, revisiones, FTS y head
se publican en una sola transacción. Un fallo revierte esa publicación completa;
un fallo en DDL inicial revierte las tablas nuevas. Un esquema vacío recién creado
puede quedar tras un fallo posterior de publicación, pero no un head parcial.

Se utiliza el lock compartido del indexador y `BEGIN IMMEDIATE`; el timeout no
autoriza borrar locks, índices o staging ajenos. Restaurar el acceso/cerrar el
escritor que corresponda y repetir normalmente. Los originales nunca se modifican.

## Identidad, revisiones y ausencias

- La clave lógica actual es dominio+STIX ID. Un release ID deriva de dominio,
  edición, commit, SHA256 del cuerpo/licencia y versión del adaptador.
- Las colecciones publicadas son inmutables. Sus memberships conservan revisión
  y pointer específicos, aunque un objeto idéntico aparezca en otra posición.
  La licencia íntegra se almacena con cada edición; mantenerla al copiar la DB.
- Fingerprint del objeto fuente completo; campos no mostrados también invalidan
  la revisión. Las revisiones observadas se registran como `added`, `modified`,
  `retired` o `reactivated`, con fecha local y release de la observación.
- Una ausencia en una colección **completa** retira la identidad del head, sin
  inventar `revoked` ni `deprecated`. El histórico conserva última cita positiva
  y la edición donde se observó la ausencia por separado.
- Una reaparición conserva identidad/historial. No se pierde una edición anterior,
  ni se reconstruye retrospectivamente una cronología de MITRE.
- Se rechazan ediciones/fechas de colección menores, versiones de objetos con
  `modified` anterior y selección de un release ya sustituido como head. Un cambio
  de bytes a igual fecha de objeto puede ser una corrección documentada: queda
  registrado, no se finge un timestamp nuevo del editor. No hay rewind implícito.
- Un release nuevo de contenido igual agrega membresías/citas, **no reescribe FTS
  ni las revisiones**. Repetir el head exacto no escribe datos de este namespace;
  se vuelven a comprobar capture/colección. `checked_at` no renueva captured_at.

FTS contiene revisiones positivas, no eventos de ausencia. Por eso una consulta
histórica sigue encontrando su texto aunque el head ya lo haya retirado. Las
consultas seleccionan memberships para no devolver revisiones duplicadas.

## Recuperación y desambiguación

`--domain` selecciona Enterprise (default), Mobile o ICS solo si se publicó ese
dominio. `--release` acepta una edición publicada o un release ID exacto; una
edición con varias capturas selecciona la última **publicada localmente**, no una
suposición sobre el commit más reciente de GitHub. Sin selector se usa el head.

`search` usa FTS5/BM25, términos AND literales y prioridad de ID exacto. Admite
`--kind`, `--include-inactive`, `--limit`1–100 y `--offset`0–100000. Por defecto
busca objetos semánticos, no descripciones de procedimientos; `--kind relationship`
permite estas últimas. La búsqueda no interpreta operadores FTS arbitrarios.
Los estados revoked/deprecated se excluyen por defecto, no se borran del histórico.

`get` acepta STIX ID o external ID y devuelve `matches`, `total`, `ambiguous` y
`truncated` (hasta20). **Nunca elige automáticamente un homónimo.** `--kind` ayuda
a distinguir técnicas/mitigaciones antiguas. Una consulta explícita por ID muestra
flags históricos aunque estén inactivos. Una ausencia en el head devuelve vacío;
consultar la edición previa o `history`, no asumir inexistencia histórica.

`context` usa ese FTS y limita únicamente el texto de fragmentos a1–12000caracteres,
con hasta50resultados. Citas/JSON tienen overhead. Preserva fuente fijada, commit,
SHA256, edición, fechas distintas, pointer JSON, flags, revisión y licencia.
`text_truncated` es recorte de texto; `truncated` indica resultados omitidos.
`context --capture <manifest>` conserva el scan de cuarentena anterior, sin DB;
no se combina con filtros de dominio/edición publicados.

`relations` requiere STIX ID ya desambiguado, `--direction both|incoming|outgoing`
y paginación hasta100. Conserva dirección/tipo/ID/flags/cita del SRO original.
Por defecto excluye también aristas con endpoints inactivos; `--include-inactive`
devuelve sus flags. `source_documented` no demuestra explotación de un proyecto,
eficacia de una mitigación, cobertura defensiva completa ni una relación transitiva.

`history` usa cursor exclusivo `--before <revision_id>`, hasta50. Devuelve metadata
de cambios observados, no cuerpos completos; distingue `citation` de
`observed_in_release`, en especial en retiros. Su fecha local no reemplaza modified.

## API local para el frontend futuro

Solo POST JSON same-origin a127.0.0.1, sin queries en URL. Seis operaciones RO:

| Ruta | Campos permitidos (todos opcionales salvo q/id indicados) |
|---|---|
| `/api/attack/status` | domain |
| `/api/attack/search` | q, domain, release, kind, include_inactive, limit, offset |
| `/api/attack/get` | **id**, domain, release, kind |
| `/api/attack/context` | **q**, domain, release, kind, include_inactive, limit, max_chars |
| `/api/attack/relations` | **id** STIX, domain, release, direction, include_inactive, limit, offset |
| `/api/attack/history` | **id** STIX, domain, limit, before |

Campos desconocidos/duplicados y tipos/límites incorrectos fallan400. Get sin
matches devuelve404; ambigüedad devuelve200 con bandera, sin selección silenciosa.
GET devuelve405. Input hasta2048bytes, Host/Origin y JSON exigidos; resultados
acotados y no cacheables, sin raíces privadas ni contenido estático exportado.
No hay endpoints de captura/publicación/lectura de rutas ni UI nueva. Un servidor
ya en marcha debe reiniciarse por el operador para cargar código nuevo; no se
detienen procesos del usuario automáticamente.

## Ensayo y recuperación

```powershell
python scripts/validate_attack_index.py <manifest-verificado.metadata.json>
python -m unittest tests.test_attack_store -v
```

El ensayo copia la DB a un directorio temporal autorizado, reutiliza el capture,
publica/repite/consulta y restaura realmente un backup en otra ruta temporal.
Nunca reemplaza la DB viva, no hace requests ni crea inventarios privados falsos.
Comprueba SQLite, FK, cinco FTS y checksums. La licencia/capturas se mantienen
bajo data ignorada por Git; no son archivos publicables del código.

Para recuperar producción se usa el procedimiento existente de backup/restore
con todos los escritores cerrados, primero ensayado sobre una copia. No modificar
a mano heads, checksums o historial para esconder un error. ATTACK1 es separado
de Cyber1/2/3, MSRC1, Security1, KG1 y Dependency1; estos siguen intactos.
