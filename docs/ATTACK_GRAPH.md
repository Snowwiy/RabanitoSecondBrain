# MITRE ATT&CK® en el grafo backend

El motor4 añade al KG1 existente los **heads publicados** del namespaceATTACK1.
No migra sus DDL aplicadas, descarga datos, toca notas/proyectos ni modifica el
renderer. `attack index` publica una colección; `graph-sync` es otra operación
explícita. Las lecturas no realizan ninguna de esas escrituras automáticamente.

## Tipos e identidad

Un objeto STIX de cada dominio tiene ID estable `attack:<domain>:<stix_id>`.
Dos objetos con el mismo external ID o STIX ID en dominios diferentes no se
fusionan. La colección vigente usa `attack:<domain>:collection`; su edición,
STIX ID original y revisión fijada permanecen en metadata, no en la identidad.

| STIX | kind de nodo |
|---|---|
| attack-pattern | attack_technique |
| campaign | attack_campaign |
| course-of-action | attack_mitigation |
| intrusion-set | threat_group |
| malware / tool | attack_software |
| x-mitre-tactic / matrix | attack_tactic / attack_matrix |
| x-mitre-analytic | attack_analytic |
| x-mitre-data-component / data-source | attack_data_component / attack_data_source |
| x-mitre-detection-strategy / asset | attack_detection_strategy / attack_asset |
| head de colección | attack_collection |

`source=attack`, `category=<domain>` (enterprise-attack/mobile-attack/ics-attack).
El título incluye external IDs y nombre para buscar `T1059.001` sin conocer su
UUID. Se acota la etiqueta; IDs completos quedan en metadata.

Los SRO no se convierten en nodos ficticios: producen aristas con dirección,
tipo, STIX ID, pointer, modified y flags originales. Sus IDs derivan de
dominio+STIX ID del SRO y permanecen estables ante un nuevo commit. La pertenencia
de un objeto a la colección completa genera `member_of_attack_collection`, con
identidad estable propia. Es pertenencia documentada, no un control implantado.

No se crean enlaces por palabras coincidentes hacia CVE, proyectos, paquetes,
tecnologías, controles o personas. No se añaden aristas transitivas, custom-property
edges ni crosswalks normativos. Un proyecto sin evidencia explícita no adquiere
asociaciones ATT&CK por estar en la misma memoria.

## Fechas, procedencia y estados

Cada nodo/arista conserva cita al blob fijado, commit/SHA256, edición/release ID,
captured_at y published_at separados, localizador e información de licencia.
`updated` de objetos usa STIX modified; la colección usa su collection_modified.
Esto no acredita cobertura actual de un proveedor ni un ataque observado local.

Se almacenan los miembros del head, incluidos flags históricos, para permitir
consultarlos sin reproyectar. **Por defecto se ocultan revoked/deprecated**:

- Un endpoint inactivo no aparece como ancla/vecino ni permite ver su arista.
- Un SRO inactivo se oculta aunque sus dos endpoints sigan activos.
- `include_inactive=true` permite consultarlos conservando sus flags, no vuelve
  actuales las afirmaciones históricas.
- Una ausencia/retired en el head no se revive con esa opción. Para consultar
  colecciones previas se usa `attack get/search --release` o `attack history`, no
  una proyección histórica falsa en este grafo de head.
- El parámetro no permite recuperar documentos excluidos, proyectos ajenos o
  memorias sin revisión; las fronteras de privacidad existentes siguen activas.

`validation=source_documented` / `kind=explicit` significa relación publicada,
no explotación local, severidad CVSS, cobertura defensiva completa o parche
aplicado. ATT&CK no obtiene prioridad KEV/EPSS por pertenecer a este grafo.

## CLI y API existentes

```powershell
python -m rabanito graph-sync --max-inputs 2000
python -m rabanito knowledge-graph page --kind attack_technique --source attack --query T1059.001 --limit 10
python -m rabanito knowledge-graph page --source attack --category enterprise-attack --include-inactive --limit 50
python -m rabanito knowledge-graph neighbors "attack:enterprise-attack:attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736" --source attack --limit 20
```

Repetir lotes `partial` hasta `ok`, sin force ni recreación del índice. Un cambio
de motor requiere un recorrido completo; un segundo ciclo completo comprueba
idempotencia, no basta con un solo lote sin cambios.

Los POST JSON same-origin `/api/knowledge-graph` y `/api/knowledge-graph/neighbors`
admiten los nuevos kinds y booleano estricto `include_inactive` (defaultfalse).
Permanecen los filtros de proyecto, fuente, categoría, fecha, riesgo y sugerencias,
el límite200 y los cursores opacos. Cambiar flags/filtros/dataset invalida un
cursor anterior. El renderer de `/api/graph` no se sustituye ni acepta un dominio
ATT&CK nuevo por el mero hecho de existir esta API backend.

Vecinos es un salto paginado. El cliente puede expandir dos saltos con sus propios
límites de nodos/peticiones; no debe cargar toda la colección ni dibujar nombres
simultáneamente. Los IDs públicos no autorizan abrir archivos mediante `/api/open`.

## Incrementalidad y coherencia

Descriptores separados para colección, objetos y SROs. Huella compartida del head
materializada una vez; fingerprints de SRO incluyen sus endpoints, no solo su
texto. Así un cambio de estado del endpoint invalida también la representación
de la arista. Las lecturas ocultan contribuciones antiguas antes de sincronizar.
Retirados se desactivan al completar el recorrido, no durante un lote parcial.

Se comprueba ATTACK1 en el validador de esquemas fuente. Sync agrega triggers
`kg_watch_*` a sus seis tablas de migración/heads/releases/members/revisions/records;
solo incrementan epoch, no cambian sus filas. Una nueva tabla sin cobertura o un
trigger ausente desactiva memoización; un trigger alterado se rechaza sin borrarlo.
Rollback del índice fuente también revierte el contador. La prueba no es integridad
forense frente a un administrador que manipule toda la DB.

Se conservan presupuestos cooperativos SQL20Moperaciones/5s,200nodos por petición
y lotes/input bytes de sincronización. No se ampliaron para aparentar rendimiento.
`requires_sync` describe proyección, no frescura documental o de feeds públicos.

## Verificación

```powershell
python -m unittest tests.test_attack_graph tests.test_knowledge_graph -v
python scripts/validate_knowledge_graph.py
```

El helper reutiliza la DB publicada y ensaya dos ciclos completos, páginas/vecinos,
flags, rendimiento, watchers/checksums y restauración en una copia temporal dentro
del proyecto. No hace requests, no sustituye la DB viva ni instala clientes/Skills.
Los fixtures sintéticos son pruebas reproducibles, no eventos de producción.
