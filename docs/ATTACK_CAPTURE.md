# MITRE ATT&CK® — captura fijada y recuperación offline

Rabanito puede capturar **un dominio y una edición explícitos** del repositorio
oficial [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
Esta etapa verifica bytes, normaliza un subconjunto STIX 2.1 y recupera fragmentos
locales. Capturar/inspeccionar **no publica automáticamente** enSQLite.
La publicación explícita/FTS/API se describe en [índice ATT&CK](ATTACK_INDEX.md);
la [proyección al grafo backend](ATTACK_GRAPH.md) es otra operación explícita y
el renderer del dashboard permanece sin cambios.
La ficha editorial `MITRE-ATTACK-20.0` del catálogo Security sigue siendo una
referencia independiente, no el dataset importado.

## Contrato de origen

- El [editor](https://attack.mitre.org/resources/attack-data-and-tools/) enlaza el
  repositorio STIX 2.1 y ofrece TAXII como alternativa. Aquí no se instala un SDK,
  ejecuta código remoto ni consulta TAXII.
- El [índice oficial](https://github.com/mitre-attack/attack-stix-data/blob/master/index.json)
  enumera ediciones por dominio. Un nombre de versión bajo `master` **no fija los
  bytes**: primero se revisa un commit de 40 hex y el metadata oficial del archivo
  a ese commit (Git blob SHA y tamaño), después se captura esa ruta exacta.
- Una captura conserva SHA256 propio, Git blob SHA1 comprobado, commit, tamaño,
  fecha de consulta y licencia de la misma revisión. Son evidencias de integridad
  y procedencia inspeccionada, no una firma del editor ni prueba de última edición.
- Primera evidencia real: Enterprise 20.0, commit
  `c2494b29dd268c46a5d0ea0990553e4327cd2253`, 55.271.014 bytes,
  blob `b39ce73c609d0f028841546e042ec16ffd7fe63f`, SHA256
  `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`.
  Colección modificada `2026-10-13T17:53:10.145Z`; esto no es fecha de consulta
  ni frescura global de vulnerabilidades.

## Operación

Desde el checkout y con un Python validado (3.11+, biblioteca estándar):

```powershell
python -m rabanito attack capture --domain enterprise-attack --release 20.0 --commit c2494b29dd268c46a5d0ea0990553e4327cd2253 --blob b39ce73c609d0f028841546e042ec16ffd7fe63f --bytes 55271014
python -m rabanito attack inspect --capture <nombre-devuelto.metadata.json>
python -m rabanito attack context T1059.001 --capture <nombre-devuelto.metadata.json> --kind attack-pattern --max-chars 1000 --limit 3
```

No repetir `capture` si la captura ya verificada existe: `inspect` y `context`
reutilizan sus archivos offline. El nombre incluye UUID; la CLI no acepta una
ruta arbitraria, `master`, `latest`, otra organización o una URL del usuario.
Para otra revisión, inspeccionar nuevamente su metadata; no reutilizar a ciegas
el blob/tamaño de este ejemplo. No hay descubrimiento, polling o instalación
programada automáticos. La misión autoriza estas consultas públicas explícitas,
no el envío de conocimiento privado.

## Límites, fallos y privacidad

- GET públicos fijos, sin auth/cookies/proxies/redirecciones; no se envían notas,
  nombres de proyectos, consultas privadas ni paquetes locales.
- Cuerpo hasta64MiB, licencia hasta16KiB, timeout de socket hasta25s y deadline
  cooperativo total120s (configurable hasta300s programáticamente). Se rechazan
  HTML/gzip inesperado, tamaño incorrecto, truncamiento y blob distinto.
- Los dos archivos se capturan bajo `data/attack-captures/`, dentro de la raíz,
  sin reparse points. El manifest se publica atómicamente **al final**, solo con
  las dos transferencias verificadas. Un fallo normal limpia únicamente archivos
  nuevos de esa captura. Una interrupción dura puede dejar un archivo sin manifest:
  no es publicable ni reproducible mediante la interfaz; revisarlo localmente,
  sin borrar otros archivos ni rehacer la DB.
- HTTP429 devuelve `status` y `retry_after`; no hay reintentos implícitos.
  Respetar ese plazo antes de otro intento autorizado. No avanza ningún watermark.
- El replay vuelve a comprobar hash/tamaño/stat del cuerpo y licencia antes del
  parser. No sustituye un índice, una memoria privada o los originales.
- JSON estricto: sin claves duplicadas/no-finitos, hasta100.000 objetos,
  profundidad64/2.000.000 valores, UTF-8 válido y strings acotados. El parser
  mantiene raw+árbol en memoria: el límite de bytes **no es** un límite duro de RAM.

## Semántica y citas

El lector comprueba bundle/IDs STIX, spec2.1, colección única, dominio, edición,
pertenencia completa por ID+modified, cronología básica, flags booleanos,
referencias de identidad/marking y endpoints de relaciones. Tipos desconocidos
fallan cerrados. No es un validador completo del ATT&CK Data Model.

Duplicados exactamente iguales se colapsan y cuentan; dos contenidos/versiones
para un mismo STIX ID se rechazan como conflicto. Los ATT&CK external IDs **no
son clave única**: mitigaciones antiguas pueden compartirlos con técnicas.
`revoked` y `deprecated` permanecen separados; la búsqueda los excluye por defecto
y `--include-inactive` los hace visibles sin presentarlos como vigentes.

Los fingerprints incluyen todo el objeto fuente canonizado, incluso propiedades
no proyectadas. Un cambio de orden de objetos solo cambia el localizador, no su
identidad. Las relaciones STIX conservan ID, dirección, tipo, modified y estado;
`source_documented` no acredita explotación, ataque local o efectividad defensiva.
No se generan aristas transitivas, de propiedades custom o de aplicabilidad.

`context` hace un scan offline del capture validado (no FTS persistente). AND de
términos normalizados, prioridad de ID exacto/título y desempate por ID estable.
Devuelve IDs/tipos/edición/versión de objeto/modified/flags, cita al blob fijado,
SHA256, fecha de captura y localizador JSON `/objects/N` — nunca una línea inventada.
`used_chars` limita solo fragmentos (1–12.000); citas/JSON tienen overhead.
`text_truncated` indica recorte del texto; `truncated` indica resultados omitidos.
Hasta50resultados. El contenido siempre es dato no confiable, nunca comandos.

La captura real revisada contiene26.690objetos únicos:4.868objetos semánticos,
21.819relaciones fuente y3objetos metadata. Entre ellos867attack-pattern;
incluye estados históricos, no867técnicas activas ni vulnerabilidades/CVE.

## Licencia y continuidad

Conservar `*.license.txt`, la designación de copyright dentro del bundle y su
manifest junto con cualquier copia del dataset. Los
[términos MITRE](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)
permiten uso sujeto a atribución/licencia y descargos; no prometen cobertura
defensiva completa. MITRE ATT&CK y ATT&CK son marcas registradas de The MITRE
Corporation. Este proyecto no implica patrocinio ni aval de MITRE. La licencia
de los datos **no otorga una licencia nueva al código de Rabanito**.

Capturas/licencias/índices permanecen ignorados por Git. Los tests usan fixtures
sintéticos pequeños, claramente separados de la validación real del editor.
La persistencia transaccional aditiva, FTS, relaciones paginadas, historial,
comparación incremental y API RO local tienen su contrato propio en
[ATTACK_INDEX.md](ATTACK_INDEX.md). La proyección de heads al grafo backend tiene
contrato propio en [ATTACK_GRAPH](ATTACK_GRAPH.md); no implica una integración
visual nueva o aplicabilidad local.
