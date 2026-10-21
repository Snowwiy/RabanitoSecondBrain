# Contexto público por proveedor

La recuperación es local y citada; no sincroniza proveedores ni envía consultas
a Internet. El texto devuelto sigue siendo dato no confiable, no instrucciones.

```powershell
python -m rabanito cyber context "CVE-2021-44228" --source kev --limit 1 --max-chars 500
```

API Python existente: `vulnerability_context(settings, query, source="kev",
limit=1, max_chars=500)`. Proveedores: kev/nvd/epss/osv/msrc. `--source` es un
selector CLI opcional/aditivo; sin él se conserva la recuperación multisource.
No se añade endpoint HTTP ni campos a `/api/doc/content` u otras respuestas.

El filtro de búsqueda selecciona entidades que tienen una observación de ese
proveedor. El contexto aplica además el filtro a sus observaciones **antes** de
consumir el presupuesto y emitir citas. Así una descripción NVD no ocupa los
caracteres solicitados para KEV. Conserva cita/fecha/localizador de la observación
real; no presenta una descripción agregada como si la hubiera publicado otra
fuente. `kev_only` sigue siendo un predicado de entidad, no un selector de fuente.

Si desaparece o falta la observación seleccionada, no rellena el espacio con
otro proveedor ni inventa texto. `total_matches` es el conteo de candidatos de
búsqueda, no número de fragmentos. Fuente desconocida se rechaza incluso con
presupuesto cero; presupuesto cero válido conserva el sobre vacío anterior.
Ranking por entidad y límites por fragmento permanecen sin cambios. El filtro
no verifica aplicabilidad instalada, frescura mundial o explotación local.

Se corrigió una regresión reproducida: `source=kev` devolvía NVD con presupuesto
corto, y `source=osv` devolvía todas las observaciones. Las pruebas usan fixtures
locales, no son validación de proveedores. La comprobación con registros reales
se registra por separado en los archivos de continuidad.
