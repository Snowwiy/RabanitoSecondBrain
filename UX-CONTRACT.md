# UX Contract — Rabanito local Neural Command Center

## Product context

Persona operadora local en Windows; consulta memoria técnica y datos públicos de vulnerabilidades. UI es-MX, fechas de proveedor en ISO con su zona UTC explícita cuando se conoce. Fechas de calendario no se convierten a otra zona. Objetivo de accesibilidad WCAG2.2AA; la verificación automatizada no certifica lectores de pantalla.

## Business-context sources

| Dominio | Fuente | Revisión |
|---|---|---|
| Permisos y privacidad | AGENTS.md, ADR-127, validación Host/Origin en rabanito/server.py |2026-10-16|
| Procedencia y transacciones | rabanito/cyber/model.py, store.py, sync.py |2026-10-16|
| Retención | ADR-127: observaciones retiradas conservadas, ninguna edición a fuentes |2026-10-16|
| Datos/afirmaciones de seguridad | Misión3.0: distinguir publicación, predicción y explotación |2026-10-16|
| Billing/legal | Sin pagos ni operaciones legales en esta interfaz; fuentes públicas citadas |2026-10-16|

## Visual contract

DESIGN.md refleja las variables canónicas de web/index.html (modeloB). Tema oscuro y controles nativos. No nuevo framework ni biblioteca. La auditoría de drift se ejecuta con pruebas Node de contraste y revisión del CSS.

## Canonical UI Map

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Select/Listbox | select nativo + CSS compartido | DESIGN.md/web/index.html | popup del SO aceptado | teclado/browser |
| Form | etiquetas nativas + novalidate | RabanitoHandler/UX-CONTRACT | búsqueda / sincronización | Node + HTTP |
| Scrollbar | CSS global de web/index.html | DESIGN.md | tabla/detalle con gutter estable | computed style/browser |
| Toast | role=status, aria-live del panel dueño | UX-CONTRACT | feedback inline persistente (sin notificaciones efímeras) | Node + browser |
| Tabs | roving tabindex, flechas/Home/End | web/knowledge.js | cuatro vistas mutuamente excluyentes | Node + browser |
| Splitter | separador ARIA, ratón/teclado | web/knowledge.js | anchos acotados y persistidos localmente | browser |
| Graph | canvas 2D local y canvas 3D existente | `/api/graph` | nodos/edges reales, filtros y selección | fixtures + browser |
| CRUD | RabanitoHandler y web/cyber.js | ADR-127 | consulta/publicación atómica de conector | HTTP + backend |

Selección masiva, calendario, edición/borrado de CVE y modal no aplican a Cyber.

## Dataset navigation

Frescura de conectores: mostrar last_success como consulta, no cobertura. NVD conserva el fin de la última ventana global y backlog aunque después se consulte una CVE puntual; sin ventanas no hay frescura global demostrada. Permiso de cadencia en configuración no equivale a servicio/proceso activo.

Security Architecture/Coding Memory reutiliza panel y controles nativos, estados inline y requests POST sin filtros privados enURL. Catálogo20fichas/página, experiencias hasta5/6000caracteres, recurrencias hasta10. Proyecto/tecnología solo se envían cuando aplican; cambiar biblioteca invalida respuestas anteriores. No hay escrituras/instalaciones desde este panel. Ficha de estándar con fuente/revisión/edición y advertencia editorial; experiencias con citas relativas y validación registrada, no repetida.

La consulta es lazy al abrir el panel. Fallos conservan resultados con advertencia de frescura; cero resultados no genera ejemplos. Una búsqueda nueva invalida detalle pendiente. Los nombres/fragmentos importados se presentan como texto, nunca HTML. Node/HTTP comprueban estos comportamientos; la QA visual existente cubre el navegador de prueba con fixtures. La certificación con lector de pantalla sigue pendiente.

Tabla de20 filas, offset/total reales del servidor, Anterior/Siguiente con límites, filtros reinician página. Orden seleccionable por evidencia/predicción o fecha. Rangos nulos nunca se presentan como cero. Carga, cero coincidencias y fallo tienen estado persistente; un fallo conserva filas anteriores identificadas como potencialmente desactualizadas.

Excepción de URLs: filtros y consultas permanecen en memoria porque la página comparte el contexto documental privado. Se envían con POST JSON; no localStorage ni querystring. Solo las preferencias visuales no sensibles se persisten localmente. Búsqueda explícita/IME y debounce comparten el mismo flujo. La búsqueda global ofrece un botón accesible para limpiar; al activarlo cancela el debounce pendiente, invalida respuestas anteriores, refresca la vista sin consulta y devuelve el foco al campo.

## Neural Command Center

- Neural Orbit consume `/api/graph` (`domain=documents`) y `/api/search`; el límite inicial es 180 nodos, ampliable por carga progresiva hasta 1000. Las búsquedas se envían por POST, nunca en query strings.
- Orbit resalta el nodo bajo el cursor y muestra una vista de texto con título, categoría, fuente, proyecto, grado y una ruta relativa validada. Las flechas muestran la misma vista y anuncian el título seleccionado; pasar el cursor no selecciona ni inspecciona el documento.
- Proyecto, fuente, categoría, grado mínimo y profundidad visible filtran la vista. Los edges sugeridos aparecen solo mediante checkbox, como trazos naranjas; quedan separados de los enlaces explícitos confirmados.
- El resumen del grafo distingue entidades encontradas de relaciones cargadas; no afirma que todo el payload esté visible después de aplicar filtros locales de grado o profundidad.
- Hex agrupa por categoría, fuente, proyecto o componentes conexos derivados únicamente de edges explícitos. Seleccionar un grupo enfoca Orbit y no crea relaciones.
- Tree agrupa por `project_name` como metadato y muestra enlaces explícitos aparte. No presupone arquitectura ni componentes.
- Galaxy mueve el renderer y los controles 3D existentes al panel central; no migra el renderer ni escribe en el índice.
- Inspector usa `/api/doc/{id}` para metadatos, `/api/context` para fragmentos citados acotados y el control explícito “Leer Markdown” para consultar `/api/doc/content` con ID indexado y presupuesto de hasta 65,536 bytes. La respuesta es vista de solo lectura, puede ocultar rutas/credenciales detectables y no modifica ni reindexa la fuente. La UI conserva metadatos/citas ante error y distingue documento ausente/no autorizado (404), fuente obsoleta/no disponible (409), tamaño (413), índice no disponible (503) y fallos de mismo origen (403). Actualizar el índice requiere una acción explícita separada.
- La apertura autorizada anuncia estado pendiente, resultado exitoso o error recuperable en `operationStatus` (`role="status"`, `aria-live="polite"`); no usa diálogos nativos del navegador.
- El inspector del Neural Command Center solo anuncia éxito al abrir una fuente cuando `/api/open/{id}` responde `opened: true`; un HTTP 200 sin esa confirmación no significa que el sistema operativo haya abierto el archivo.
- No está disponible en esta rama el endpoint tipado más nuevo de Knowledge Graph del checkout backend concurrente. La interfaz lo marca pendiente y no llama operaciones de sincronización.
- El servidor de fixtures para QA usa datos sintéticos y muestra un banner persistente. La verificación real del lector de 2026-10-20 usó otro servidor loopback con rutas de solo lectura y el endpoint de contenido autorizado; no habilitó indexado ni sincronización.

## Flow ledger

| Operación | Pending | Éxito | Fallo/foco | Fuente |
|---|---|---|---|---|
| Buscar vulnerabilidades | aria-busy lista; paging bloqueado | misma lista y rango | texto inline/reintentar; mantener entrada | server/store |
| Abrir identificador | estado local de detalle | detalle citado; foco en panel | estado inline y selección repetible | cyber/get |
| Leer Markdown | estado local “Leyendo…”; botón deshabilitado; generación asociada al ID seleccionado | Markdown seguro, referencias autorizadas y contador de bytes | respuesta obsoleta ignorada; 400/403/404/409/413/503 con texto local; no reindexar ni ocultar los metadatos existentes | contrato `/api/doc/content` |
| Actualizar fuente pública | botón bloqueado y aria-busy | contadores tras respuesta y recarga local | consultar estado antes de reintentar si resultado incierto | ADR-127/sync |

## Async and resilience

Generaciones independientes para lista, detalle, conectores, búsqueda, grafo e inspector/lector Markdown. Debounce de 280ms y composición IME, sin retry automático de mutaciones. Lecturas con límite15s, sync180s; abortar HTTP no garantiza que el servidor haya cancelado la actualización. No afirmar fallo definitivo tras timeout; el estado persistente del conector resuelve la incertidumbre. El servidor usa lock compartido de escritura; no se presenta como bloqueo de lectura.

## Validation and permissions

Solo orígenes loopback del mismo puerto y JSON pasan a endpoints POST. El lector acepta solo IDs de documentos activos y no rutas arbitrarias; el servidor revalida fuente, exclusiones y proyecto al leer. La UI exige identificadores públicos CVE/GHSA válidos; el servidor vuelve a validar. KEV no acepta identificador; OSV sí lo requiere en UI. Sin claves ni campos secretos. La nueva funcionalidad no edita proyectos.

## Verification

Backend: suite de `tests`; Node: `tests/test_cyber_ui.mjs`, `tests/test_graph_filter.mjs` y `tests/test_neural_command_center.mjs`. La QA visual del centro usa un servidor de fixtures sintéticas aislado; nunca se conecta a Obsidian ni a SQLite. Browser: búsqueda, selección, citas, alternancia de vistas, controles del canvas y pantalla de fixture. Anotar si el viewport exacto 1080p/1440p o el índice real no se probó. No ejecutar sincronizaciones desde browser para validar botones ya cubiertos por HTTP/fixtures. Audit premium se registra aparte y no sustituye estas pruebas.
