# Autorización de fuentes durante recuperación

La caché no concede permiso de consulta. Cada conexión de lectura documental
compara el par `(source_kind, source_root)` registrado con las fuentes activas
de su configuración. Cambiar la bóveda o la carpeta de conocimiento, retirar
una fuente adicional o cambiar su tipo debe ocultar sus filas anteriores sin
esperar una indexación. Una fuente deshabilitada también permanece oculta.

Las filas de proyectos necesitan una raíz de proyecto permitida bajo la
colección actual y un `source_root` coherente con esa raíz. Se conservan las
exclusiones de proyecto y las restricciones existentes sobre memoria heredada.
Las consultas internas de tres argumentos que solo comprueban asociación de
proyecto no autorizan por sí mismas un documento: su consulta necesita además
el origen configurado. El predicado documental de cuatro argumentos realiza
ambas comprobaciones.

El filtro se aplica en SQL antes del ranking, los límites y la selección de
fragmentos. Afecta búsquedas, contexto, detalle, relaciones, estadísticas y
auditoría que reutilizan el predicado común. No añade campos, rutas HTTP,
estados, IDs o migraciones. El lector Markdown por ID mantiene sus controles
adicionales de ruta y archivo nativo. El grafo tipado ya comprueba las raíces
en sus descriptores; no se sustituye esa comprobación.

Revocar una fuente no borra su índice, sus originales o el historial. Si vuelve
a autorizarse exactamente el mismo origen, sus filas pueden recuperarse otra
vez; Audit sigue comprobando frescura por separado. Una raíz autorizada pero
temporalmente inaccesible no se trata como permiso revocado: la recuperación
offline de caché permanece disponible. Esto no prueba que el archivo aún exista
o conserve el mismo contenido.

La configuración se evalúa al abrir la conexión, no se relee un archivo JSON
por cada resultado. No es un sistema de usuarios/ACL del servidor ni una
garantía frente a quien pueda alterar SQLite o la configuración local. No se
modifica automáticamente la configuración real ni se sincroniza por consultar.

## Elegibilidad por documento (ampliación44)

El predicado común añade comprobación metadata-only de `relative_path`:
directorios/nombres/extensiones excluidos, extensiones permitidas y excepciones
explícitas `metadata_names`, además de contextos de entorno excluidos. Reutiliza
las reglas del indexador, sin leer cuerpos ni sincronizar. `exclude_extensions`
prevalece sobre `metadata_names`; los metadatos permitidos por nombre no se
confunden con formatos rechazados solo por una allowlist de extensiones.
Se rechazan rutas relativas inseguras. Los tamaños de procesamiento no se
convierten en afirmaciones sobre confidencialidad ni frescura del contenido.

El filtro se aplica antes de recuperar texto, metadatos y relaciones. Decisiones
y Coding Memory también comprueban elegibilidad; no se promueve ni elimina una
memoria al cambiar la configuración. Revertir la exclusión permite recuperar la
misma fila sin una reconstrucción. Configuración inválida no autoriza datos.

El grafo conserva sus restricciones previas y añade la allowlist completa y los
contextos de entorno. Su prueba cacheada/cursor incluye exclusiones de contexto
y usa una copia de configuración por consulta: una mutación concurrente no puede
mezclar permisos antiguos con una firma de configuración nueva. No cambian DDL,
versiones de esquema/motor, IDs o campos HTTP; un cambio efectivo de permisos
puede invalidar un cursor anterior como los demás cambios de configuración.

La implementación y sus pruebas se registran por separado: esta ampliación no
se considera validada solo por este contrato. No basta con coincidir en raíz
para demostrar elegibilidad por documento.

La selección de documentos no se aplica a los inventarios de dependencias:
SBOM y lockfiles autorizados pueden tener formatos excluidos del indexado de
cuerpos documentales. El grafo separa ambos predicados y mantiene las
exclusiones de rutas/nombres/extensiones de inventarios y revisiones. Esto no
incorpora sus archivos como notas ni amplía los permisos de un proyecto.

El historial documental (`/api/changes`) también aplica estos predicados antes
de limitar eventos: una exclusión no debe dejar títulos o rutas visibles a
través del diario. Las filas y los eventos de eliminación se conservan; pueden
volver a consultarse si se restaura la autorización. No se exige reindexar.
