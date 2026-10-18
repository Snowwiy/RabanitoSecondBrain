# Inventarios portables pylock.toml

El motor6 lee un archivo PyPA pylock1.0 seleccionado explícitamente, con `tomllib` de Python estándar. Acepta `pylock.toml` y `pylock.<nombre>.toml`, también en rutas Unicode. No es un gestor, instalador, escáner del entorno instalado ni validador completo del esquema.

```powershell
python -m rabanito dependency inspect --project '<PROYECTO_AUTORIZADO>' --manifest 'pylock.toml'
python -m rabanito dependency inspect --project '<PROYECTO_AUTORIZADO>' --manifest 'docs/pylock.ci.toml'
```

Reutiliza autorización de proyecto activo, exclusiones, lectura estable, restricciones de rutas/reparse y presupuestos existentes:2MiB por defecto/16MiB máximo,2000componentes por defecto/10000máximo. El loader TOML común con uv limita estructura a100000valores/profundidad64, rechaza nonfinite y oculta líneas de error potencialmente privadas.

## Qué se conserva

Cada componente declara nombre/versión, clasificación del origen y `/packages/N`: localizador lógico del árbol TOML, no número de línea inventado. El informe incorpora hashes de ámbito de origen/artefactos y condiciones. Los metadatos de creador, índices, URLs, rutas, markers, grupos, herramientas y attestations no se copian al resultado ni se ejecutan. Las referencias originales siguen en el archivo autorizado, sin duplicarlo.

El formato admite fuentes y condiciones variadas. Referencias oficiales: [especificación PyPA](https://packaging.python.org/en/latest/specifications/pylock-toml/) y [pip lock](https://pip.pypa.io/en/stable/cli/pip_lock/). El lector admite únicamente lock-version="1.0"; versiones futuras y claves semánticas desconocidas fallan cerradas. Grupos/extras/environments/requires-python se acotan y resumen por hash, sin evaluarlos. `packages.dependencies` es informativo: no se fabrican aristas confirmadas a partir de ese campo.

## Identidad y límites de evidencia

| Origen declarado | Tratamiento local |
| --- | --- |
| Wheels/sdist con URLs HTTPS de files.pythonhosted.org/packages, sin credenciales/query/fragment/puerto alternativo, y sin índice o con PyPI público explícito | Coordenadas PyPI declaradas; candidatas contra OSV local |
| Índice privado o artefacto de otro origen, incluso con nombre coincidente | Identidad no verificada; needs_review |
| Path de artefacto, incluso si también hay URL pública | No se sigue; needs_review |
| VCS, directorio, archivo directo, fuentes contradictorias o ausentes | No se asumen PyPI; needs_review |
| Metadata de artefactos inválida o forma no soportada | No habilita comparación automática |

`artifact_integrity=declared_hashes_not_verified` no prueba bytes, firma, attestation, autoría o autenticidad. No se descargan ni abren wheels/sdist/archives, ni se verifican sus hashes. Se comprueba forma de metadatos y longitud de algoritmos conocidos, no conformidad criptográfica completa. Un hash débil tampoco es garantía de integridad. VCS/directorios siguen opacos; el lector no valida commits ni dependencias de builds.

Se conservan por separado variantes de fuente/artefactos/condiciones; solo entradas públicas equivalentes pueden deduplicarse, con hasta5localizadores adicionales. El lock puede describir múltiples alternativas: `environment_selection=pylock_entry_conditions_not_evaluated` y `coverage.selection` dejan explícito que no se seleccionaron markers, extras, grupos, Python ni compatibilidad de wheels. Contraste de versiones: [PEP440 acotado](PEP440.md). No_local_advisory/outside_observed_ranges nunca significa seguro.

## Persistencia e interfaces

Consultar no escribe caché ni crea esquemas. Motor6 invalida reutilización de motores anteriores sin borrar snapshots. Guardar uno mantiene autorización explícita independiente; VEX/decisiones confirmadas exigen revisión humana. KG3/DDL1 ya conserva las identidades de ámbito: no necesita migración ni reproyección global por este lector. No hay nuevo endpoint HTTP que acepte rutas de manifiestos; el dashboard actual permanece compatible.

## Evidencia

24regresiones cubren parser/versión/estructura/límites, origen público/privado/local y contradicciones, privacidad, Unicode/paths/permisos, deduplicación/condiciones, CLI, caché, snapshot, grafo y restauración. Las regresiones previas de uv/PEP440 permanecen.

Se capturó del repositorio oficial pypa/pip un **fixture upstream**, no una exportación de producción:747bytes, Gitblob194817b4404f15b96d2dbc8d05b752f617271e11 y SHA256e0b65af8c139d22df5f641b3e86e91d4114a86ac185011a3a054ba4fedfe9754. [Archivo upstream](https://github.com/pypa/pip/blob/main/tests/data/lockfiles/pylock.toml), [prueba oficial que lo usa](https://github.com/pypa/pip/blob/main/tests/functional/test_lock.py). Sus3componentes usan rutas/archivo directo: los3correctamente requieren revisión, sin asumir identidad PyPI. Ensayo offline en copia real de SQLite: reutilización,3nodos del proyecto temporal,4FTS/FK/integridad,backup/restauración y limpieza comprobados. No se ejecutó pip ni se siguieron sus rutas. Esto no demuestra un proyecto real vulnerable ni compatibilidad end-to-end con el instalador.
