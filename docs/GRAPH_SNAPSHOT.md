# Reutilización de la validación dentro de una lectura del grafo

Una consulta fría verifica esquemas, permisos, huellas de todas las familias e
inputs ausentes/obsoletos dentro de una transacción SQLite de solo lectura. El
filtro visual solicitado no reduce el ámbito de esa validación global.

Si no hay inputs ausentes, modificados u obsoletos, todos los `kg_inputs` activos
ya coinciden con la unión de fuentes `U` en ese snapshot. Las selecciones de
nodos y vecinos pueden reutilizar esa equivalencia sin volver a calcular `U`.
No se confía en un marcador persistido ni se omite la primera validación.

Cuando hay inputs sucios u obsoletos se conserva el join por huella, que oculta
claims desfasados o revocados. Ausencia de watchers sigue informando
`requires_sync=true` y obliga a validar otra vez en la siguiente petición. La
memoización por epoch entre peticiones no cambia. Una lectura fría conserva
`source_validation=live_fingerprint_scan`, no se presenta como lectura de caché.

No cambia el esquema, motor, IDs, cursores, filtros o campos HTTP. Los controles
de permisos y la canonicalización permanecen. Tampoco aumentan los presupuestos
cooperativos de 20 millones de operaciones y cinco segundos; un exceso sigue
devolviendo un error seguro, no un resultado aparentemente completo.

```powershell
python -B -m unittest tests.test_graph_snapshot_reuse tests.test_knowledge_graph tests.test_attack_graph -v
```

Las pruebas cuentan evaluaciones de huellas, no tiempos frágiles. Cubren páginas,
vecinos, validación de otros dominios, watchers ausentes, claims modificados,
retirados, exclusiones de proyectos, esquemas alterados y diferencias entre
lecturas frías y memoizadas.

En una copia real, una página fría de 50 vulnerabilidades agotaba el presupuesto
al repetir la unión de fuentes. Tras reutilizar la prueba de ese snapshot necesitó
14.472.000 operaciones y 2,265 s. Su contenido coincide con la lectura anterior
en caliente, al igual que paginación, vecinos, proyectos y ATT&CK. Son mediciones
de ese host/dataset, no un SLA ni garantía para grafos de cualquier tamaño o carga.
La cobertura de proveedores y el estado de proyección se consultan por separado.
