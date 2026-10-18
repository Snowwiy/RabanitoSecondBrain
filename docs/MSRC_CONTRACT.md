# MSRC CVRF — contrato y fundamento de normalización

Estado: conector mensual explícito implementado en CLI/API, registro compartido de proveedores y ledger MSRC1 aditivo. La evidencia operativa y sus fechas se conservan en el checkpoint vigente; fixtures, captura, ensayo en copia e ingesta real son comprobaciones distintas. No cambia la interfaz visual ni el acceso de solo lectura a fuentes privadas.

## Evidencia oficial y alcance

Se revisaron el [OpenAPI oficial](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/docs/swagger.json), la [configuración del módulo](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/MsrcSecurityUpdates/Private/Set-GlobalVariables.ps1) y la [consulta CVRF oficial](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfDocument.ps1), sin instalar ni ejecutar código del proveedor. OpenAPI3.0.1, contrato v3; SHA256 del documento observado: `1632aa08008963cead7902c0051fb2ac09ac67c75a27f973f3d7238755d3ef3f`.

El SDK indica base `https://api.msrc.microsoft.com/cvrf/v3.0`, parámetro `api-version=2023-11-01` y consulta sin APIkey. La API comprobada admite GET `/updates/<yyyy-Mmm>` y `/cvrf/<yyyy-Mmm>`. No se siguen URLs arbitrarias de las respuestas, no se envían paquetes privados, notas ni credenciales. No se encontró una cuota numérica en los archivos examinados: eso no significa solicitudes ilimitadas. Un futuro conector debe aplicar límites, backoff/cooldown y respetar429/Retry-After.

El repositorio de ejemplos usa [MIT](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/LICENSE). No se incorpora su código, instala su módulo ni añade una licencia a Rabanito. Esa licencia de software no se presenta como licencia de redistribución de todo el catálogo. La implementación es propia; artefactos de investigación permanecen ignorados en data/, con procedencia. No publicar copias masivas de documentos del proveedor.

## Comprobación real

GET del resumen `2026-Oct` respondió200: publicación inicial13oct y modificación16oct. La forma real usa `value` y propiedades PascalCase, distinta de algunos nombres camelCase del OpenAPI. HEAD respondió405. El CVRF mensual excedió los límites de lectura JSON completa de8/16MiB: no se aumentaron los límites globales de los conectores existentes.

El lector incremental completó **26.697.560bytes**, 2.091 entradas y344productos. Son2.090CVE más `ADV260001`, aviso de hardening que no es una CVE. No son2.090vulnerabilidades nuevas deoctubre: el documento puede referenciar identificadores publicados anteriormente. La primera métrica del probe llamó incorrectamente invalid_cve_ids a esa entrada no-CVE; el código actual la clasifica por separado, no como error del proveedor.

La normalización completa y la integración transaccional son gates distintos. Los primeros intentos detectaron CWE como lista y declaraciones redundantes; se corrigieron con fixtures. Los plazos posteriores se diagnosticaron separando etapas: la transferencia real necesitó163,493s, mientras la normalización offline completa tardó2,337s (9,086s con perfilador). El gate de normalización **ya pasa con el documento real**, sin publicar registros. No confundirlo con un conector instalado o un índice actualizado.

## Lector incremental

`rabanito/cyber/cvrf_stream.py` separa headers y elementos de Vulnerability sin retener todo el array original. Acepta orden de propiedades distinto, UTF8/BOM, fragmentos cortos y Unicode. Rechaza duplicados, JSON inválido/incompleto/trailing, no-finitos y tipos incorrectos.

Presupuestos:64MiB de entrada, hasta5.000entradas,2MiB por entrada,8MiB agregados de headers y120s cooperativos. No son una cota exacta deRAM: los objetos decodificados añaden overhead. Cuando existe read1, se usa una lectura de buffer por paso para revisar el plazo entre fragmentos; un timeout de socket sigue siendo necesario. No es un deadline absoluto de todo DNS/TLS/apertura de transporte.

Los callbacks son **provisionales**. No deben escribir/persistir ni actualizar FTS/caché/watermark hasta validar el envelope completo y su identidad. Un error tardío no convierte los elementos anteriores en una importación parcial autorizada. El módulo no realiza red, escritura ni ejecución de datos.

## Normalización

`rabanito/cyber/msrc.py` es una base independiente de transporte/publicación:

- Identidad nativa por documento e identificador oficial: `MSRC-<mes>-<id>`, alias CVE solo cuando existe. ADV conserva tipo security_advisory y estado advisory; nunca genera una CVE inventada.
- Referencia al documento y JSONPointer de la entrada. Fechas de documento, consulta y revisión de CVE son distintas. Un sentinel0001 o fecha no especificada no se transforma en publicación de la vulnerabilidad.
- Resuelve ProductID usando FullProductName. Solo KnownAffected (código3) entra como afectación declarada; otros códigos permanecen opacos. Producto desconocido queda sin etiqueta y con contador de cobertura, no se adivina.
- Etiquetas de producto no son versiones instaladas, CPE validados ni evidencia de vulnerabilidad del proyecto. No se realiza matching con repositorios por palabras de producto.
- CVSS conserva score/vector y ámbitos de producto; no calcula scores. Si el vector no declara versión reconocible, la versión queda unversioned. CWE admite las formas verificadas sin inventar nombres.
- VendorFix (tipo2) se conserva en fixes; otras remediaciones, incluidas desconocidas, mantienen su código/evidencia sin llamarse parches. El [ejemplo oficial de remediaciones](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/README.md) documenta workaround0, mitigation1 y vendorfix2.
- Explotación reportada solo por afirmación explícita Exploited:Yes del campo de explotación; una predicción More Likely no equivale a explotación observada. No marca KEV por ser aviso de Microsoft. Se preservan los ámbitos de producto de amenazas.
- HTML se convierte a texto sin ejecutar scripts/estilos ni abrir enlaces. Las URLs son referencias, nunca instrucciones de fetch o del agente.

Declaraciones idénticas de métricas, amenazas y remediaciones unen sus ProductID sin perder ámbitos. Fixes y otras remediaciones no se duplican; referencias repetidas se consolidan. Se limita a32MiB normalizados, incluidos nombres de producto resueltos, y2MiB por registro. Un límite excedido falla cerrado, no recorta información fingiendo cobertura completa.

## Pruebas y uso de investigación

```powershell
python -B -m unittest tests.test_cvrf_stream tests.test_msrc -v
python -B scripts/validate_msrc_contract.py 2026-Oct
python -B scripts/validate_msrc_contract.py 2026-Oct --normalize
```

Los dos últimos hacen una petición pública explícita y acotada y guardan evidencia agregada en data/; no importan registros ni actualizan la DB. No ejecutarlos en un bucle. Los fixtures cubren fragmentación/Unicode, límites, errores tardíos, separación ADV/CVE, explotación, productos, métricas, CWE, tipos desconocidos y deduplicación conservando scope. Una prueba offline no valida por sí sola el proveedor real.

## Captura reutilizable y diagnóstico por etapas

```powershell
python -B scripts/capture_msrc.py capture 2026-Oct --max-seconds 300
python -B scripts/capture_msrc.py normalize '<manifest_devuelto.metadata.json>' --save-records --profile
python -B scripts/capture_msrc.py normalize '<mismo_manifest.metadata.json>'
```

Reutilizar una captura existente para ajustes offline; no descargar por cada cambio. `capture` guarda un cuerpo público en cuarentena bajo `data/msrc-captures`, hash SHA256 y manifest UUID. `transport_complete` no implica JSON válido. `normalize` comprueba tamaño/hash/origen/mes, estabilidad y límites antes de aceptar resultados; no realiza red ni escribe SQLite. Un archivo que crece durante verificación no permite un bucle de hashing ilimitado. No admite rutas arbitrarias ni reparse points.

La transferencia sigue limitada a64MiB; el plazo explícito puede ser de hasta300s porque las mediciones mostraron4MiB/26s y8MiB/79s. El parser mantiene sus120s y demás límites. Socket/DNS/TLS no constituyen un deadline absoluto; los informes separan apertura, transferencia, hashing y CPU/tiempo de normalización. Fallos limpian únicamente el parcial UUID recién creado. `Retry-After` se registra para impedir otra solicitud durante el cooldown.

Gzip es opt-in (`--gzip`), requiere esa codificación sin fallback a identity, máximo16MiB por cable/64MiB descomprimidos, bloques acotados, EOF/CRC y rechazo de trailing/truncamiento. Se usa la [descompresión incremental de zlib](https://docs.python.org/3.14/library/zlib.html); los fixtures comprueban bombas y errores. El intento real gzip terminó con error de transporte: no se afirma compatibilidad real del proveedor con esta opción.

Captura real del17oct02:53:09UTC:26.697.560bytes, SHA256 `71d4cf6591766fa405ce9eb415df515cf444b799c904826b5963aceed0bd3e73`. Normalizó2.091IDs únicos:2.090CVE y un aviso,344productos/0sin resolver,1.986métricas numéricas,2.078registros conVendorFix y una afirmación de explotación. No son parches aplicados ni ataques en proyectos locales. No se encontraron avisos etiquetados como CVE, citas inválidas o fechas0001; el registro mayor serializado midió33.372bytes. El JSON normalizado, los perfiles sin argumentos/contenidos y los informes permanecen ignorados en data/.

## Sincronización mensual y publicación

```powershell
python -m rabanito cyber sync --source msrc --month 2026-Oct
python -m rabanito cyber sync --source msrc --month 2026-Oct --capture '<manifest_devuelto.metadata.json>'
python -m rabanito cyber search --source msrc --limit 10
python -m rabanito cyber history '<CVE_real_o_ID_nativo>' --source msrc --limit 10
python -B scripts/validate_msrc_sync.py '<manifest_devuelto.metadata.json>'
```

`month` es obligatorio y debe coincidir exactamente con `20xx-Jan` a `20xx-Dec`; no se permite `all`, URLs libres ni consultas privadas. GET público pequeño de updates/mes valida ID, URL oficial y CurrentReleaseDate. Un resumen idéntico, misma versión del adaptador y prueba de cantidad/huellas de registros permite omitir descarga y normalización. Solo checked_at y la consulta del resumen avanzan: las fechas de captura, observaciones y sus revisiones no se renuevan artificialmente. No prueba frescura mundial ni confirma una captura de proveedor inmutable.

Si necesita un cuerpo, se captura una sola vez en cuarentena (identity, hasta64MiB/300s configurables mediante cyber.msrc_capture_seconds; parser120s/32MiB normalizados) y se vuelve a comprobar el resumen después. `--capture` solo acepta un basename UUID de esa cuarentena, verifica SHA/tamaño/mes y normaliza el cuerpo original, no un JSON normalizado sin verificar. La fecha CurrentReleaseDate del cuerpo debe coincidir con el resumen oficial actual. Una captura antigua puede rechazarse aunque sus bytes sigan íntegros; no editar el manifest ni relajar la comparación para reutilizarla. Primero comprobar cambio real del proveedor, luego capturar su revisión una sola vez.

MSRC1 tiene checksum/backup previo y guarda mes, versiones declaradas, adaptador, captura SHA/fecha, publicación, comprobación y prueba agregada de registros. CyberDDL1/2/3 yKG1 no se modifican. Los registros, aliases, entidades, FTS, revisiones observadas, ledger y estado de éxito se publican en la misma transacción. Retiros limitados al prefijo nativo del mes completo; nunca snapshot global ni otros meses. Documento vacío, versión discordante, corrupción, interrupción o excepción SQL no publica cambios parciales. El writer lock es compartido con el resto del motor. Los fallos conservan código seguro, metadatos de ejecución y cooldown por Retry-After; no incluyen cuerpo/secretos en logs. No hay bucle de reintentos de cuerpos grandes.

La caché SQL guarda solo el resumen, no los26MB del CVRF. El límite de100respuestas continúa vigente. `requests` cuenta invocaciones lógicas del cliente/captura, no necesariamente intentos físicos de transporte. `status.coverage.months` muestra documentos seleccionados; checked_at no sustituye captured_at. La cadencia MSRC es manual: si se añade a cyber.cadence.sources se rechaza explícitamente, sin escoger meses o iniciar servicios por cuenta propia.

API: POST `/api/cyber/sync` con `{"source":"msrc","month":"2026-Oct","confirm_public_sync":true}`; no acepta capture/capture_manifest ni rutas locales. Conserva controles de Origin/loopback. La CLI es la única interfaz de replay. El dashboard existente sigue compatible; no hay selector visual nuevo de meses.

ADV permanece security_advisory/advisory, sin prioridad published ni alias CVE inventado. Explotación reportada por Microsoft puede elevar prioridad pública sin marcar kev=true. El grafo usa motor de proyección2 con el mismo esquemaKG1; hay que ejecutar graph-sync explícitamente después de actualizar el motor. Un riesgo público nunca demuestra aplicabilidad o ataque a un proyecto.

23regresiones de sync cubren publicación, incrementalidad sin red grande, historial, aislamiento mensual, vacío/corrupción/rollback, concurrencia, 429, interrupción, migración, CLI/API, avisos, prioridad y grafo. El ensayo copia únicamente DB y cuerpo/manifest públicos a un temporal del proyecto, comprueba dos resúmenes oficiales pequeños, idempotencia, citas, proyección e integridad/FTS y restaura el respaldo en otro temporal. Nunca reemplaza la base operativa ni descarga otra vez el cuerpo.

Validación real17oct2026: la captura previa (CurrentReleaseDate16oct) se rechazó al cambiar el resumen oficial. Una consulta acotada del prefijo confirmó que el cuerpo también había cambiado; se capturó una revisión nueva una sola vez (26.818.242bytes, fecha de documento17oct01:49:02UTC, capturada10:33:09UTC). Normalización:2.135registros,2.134CVE+1aviso,351productos/0sin resolver,2.029métricas numéricas,2.122registros conVendorFix y1afirmación de explotación. No representan CVE todas nuevas, parches aplicados ni ataques locales.

Ensayo en copia: publicación29,809s, segundo pase2.135unchanged sin nuevo cuerpo, citas e historial, proyección16lotes/34,647s y restauración/SQLite/FK/4FTS correctos. Después, ingesta operativa real y segundo pase idénticos (runs74/75), con backup previo aMSRC1; grafo motor2 reproyectado y recorrido completo adicional30.072entradas sin cambios/errores/retiros. HTTP real en loopback confirmó búsqueda, detalle, historial, aviso y compatibilidad del grafo legado. Sin rediseño ni instalación de agentes.

Mantener todas las DDL aplicadas inmutables, incluida MSRC1 una vez aplicada. No anunciar frescura global de MSRC por sincronizar un mes, ni cambiar Hermes/Jev/OAuth/Skills instaladas o la interfaz visual en esta etapa.
