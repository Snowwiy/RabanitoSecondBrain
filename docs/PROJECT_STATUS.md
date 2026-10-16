# Estado técnico de publicación

Implementados: núcleo documental, búsqueda citada, proyectos incrementales, decisiones revisadas, cuatro conectores públicos, staging NVD, catálogo inicial de estándares, inspección offline de dependencias y dashboard/grafos existentes.

Validación de publicación: **290/290 Python normal, 290/290 Python optimizado y 52/52 JavaScript**, sin fallos ni omisiones (632 ejecuciones entre modos, no 632 pruebas diferentes). Incluye seis pruebas nuevas de protección de publicación. Runtime: Python 3.14.7 / SQLite 3.53.1, Windows nativo.

Smoke de exportación limpia sin configuración/memoria privada: indexado vacío autorizado OK, catálogo público 28 entradas/17 relaciones y recuperación Zero Trust con citas y límite de 400 caracteres OK. Auditoría de candidatos: 84 archivos, sin incidencias pendientes; excepciones solo para nueve literales AST sintéticos exactos de regresión (diez coincidencias), nunca para carpetas enteras. La auditoría preparada y verificación remota se ejecutan después; este documento no las anticipa. No se incluyen métricas de conocimiento privado ni instantáneas de índices.

## Pendientes

- VEX/excepciones revisadas con alcance, caducidad y evidencia; persistencia incremental de análisis por proyecto.
- Revisiones individuales Cyber: hoy se conserva la observación más reciente por proveedor; no existe una historia retroactiva inventada.
- Grafo unificado/progresivo y aplicabilidad verificada a proyectos. Las vistas públicas actuales son separadas y acotadas.
- Controles oficiales/versiones adicionales y conectores de fabricantes con contratos verificables.
- QA visual/lector de pantalla y sesiones reales de todos los clientes/modelos. Formato/CLI no sustituyen esa prueba.
- PEP 440 completo y otros lockfiles: el lector actual declara su subconjunto y ambigüedades.

Retomar backend desde esos pendientes después del respaldo inicial. El rediseño visual va por separado; no integrar worktrees ni sobrescribir cambios concurrentes. Conservar checksums de DDL aplicadas; los cambios requieren nuevas migraciones.
