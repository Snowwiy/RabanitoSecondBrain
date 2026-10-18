# OWASP ASVS: requisitos versionados y recuperación local

Importación explícita en Security1, sin nueva migración. No evalúa aplicaciones ni demuestra cumplimiento. Los textos del editor son datos no confiables, nunca instrucciones para agentes.

## Fuente y licencia

[OWASP ASVS](https://owasp.org/projects/asvs) y su [repositorio oficial](https://github.com/OWASP/ASVS) identifican la edición estable 5.0.0 como publicada en **mayo de 2025**: se conserva precisión mensual, sin inventar día. El snapshot revisado procede de la rama `v5.0.0`, no de un tag inmutable. `master` no sustituye esta edición.

- Commit fijado: `3383877f732ce89a458a1af43288f2f1b1d7db0c`, fechado 14 de octubre de 2026. Es fecha de revisión, no de publicación original.
- JSON: `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json`, 149407 bytes; Git blob SHA1 `16a314527781b79f2e499ac8f1e33eaf76234d22`; SHA256 `bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`.
- `LICENSE.md`: 20138 bytes; Git blob SHA1 `2d58298e6eda10e7204abb52722efbc840db2390`; SHA256 `28a9529c7d0bb4dc51f4bf5c116a3d16ef247a052f7591466768ddf563fd1cf5`.
- Atribución: OWASP ASVS Project and contributors. Datos bajo [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); licencia íntegra conservada con la captura y una vez en el registro SQLite. Esto **no asigna una licencia al código** de Rabanito.

Los requisitos conservan el texto original; navegación y resúmenes de grupos son normalización local. Cada entrada declara atribución, cambios y derechos. Una redistribución de ese contenido requiere cumplir atribución/ShareAlike; no presentarlo como resumen propio libre de derechos. Dataset y licencia descargados permanecen en `data/`, excluido de Git.

## Captura y registro explícitos

```powershell
python -m rabanito asvs capture --commit 3383877f732ce89a458a1af43288f2f1b1d7db0c --blob 16a314527781b79f2e499ac8f1e33eaf76234d22 --bytes 149407 --license-blob 2d58298e6eda10e7204abb52722efbc840db2390 --license-bytes 20138
python -m rabanito asvs inspect --capture NOMBRE.metadata.json
python -m rabanito security index --asvs-capture NOMBRE.metadata.json
python -m rabanito security imports
```

Capturar realiza dos GET públicos acotados, JSON y licencia, exclusivamente en rutas oficiales fijadas por commit. Sin host arbitrario, query, autenticación, proxy o redirección. Verifica tamaño, Git blob y SHA256; límites de 2 MiB para JSON y 64 KiB para licencia, con deadline. No transmite notas, consultas ni código privado. Inspeccionar/registrar una captura existente no usa red.

Se validan UTF-8, campos, IDs, ordinales, niveles y jerarquía; se rechazan duplicados, campos desconocidos y rutas traversal/reparse. El manifiesto se publica al final; un fallo no incorpora un catálogo parcial.

`meta.security_registered_imports` conserva la importación normalizada y su licencia. El índice combina catálogo curado y registro; `security index` normal **preserva ASVS**, incluso sin la captura disponible. Una revisión diferente de la misma edición requiere `--replace-asvs` junto a `--asvs-capture`, con respaldo previo. Repetir la misma revisión es idempotente.

Entradas, FTS, relaciones y registro usan lock/transacción compartidos. Un registro corrupto se rechaza, no se elimina silenciosamente. Recuperar mediante respaldo verificado y restauración existente, nunca editando checksums de esquemas aplicados.

## Identidad y significado

El snapshot contiene 17 capítulos, 80 secciones y **345 requisitos**: 442 fichas y 442 pertenencias `part_of`, sin duplicar la raíz `OWASP-ASVS-5.0.0`. Catálogo combinado: 514 fichas/508 relaciones.

- Requisito oficial `v5.0.0-1.2.5`: `kind=control`, `knowledge_type=licensed_publisher_requirement`, `asvs.assessment=not_performed`.
- IDs locales de navegación: `ASVS-5.0.0/chapter/1`, `ASVS-5.0.0/section/1.2`, `kind=concept`. No son controles oficiales nuevos.
- Cita con URL fijada, commit, SHA y JSON Pointer real. Pointer no es número de línea. El ejemplo corresponde a `/Requirements/0/Items/1/Items/4` en este snapshot.
- Campo `L` del editor: 70 nivel 1, 183 nivel 2 y 92 nivel 3. El filtro selecciona **L exacto**, no un perfil acumulativo ni una evaluación local.

No se inventan crosswalks, enlaces a CVE o aplicabilidad a proyectos. Las pertenencias describen jerarquía documental.

## Consulta offline y contrato backend

```powershell
python -m rabanito security search --framework OWASP-ASVS-5.0.0 --kind control --level 1 --limit 20
python -m rabanito security get v5.0.0-1.2.5
python -m rabanito security context "authentication" --framework OWASP-ASVS-5.0.0 --level 2 --max-chars 1000
```

`POST /api/security/search` añade `level` entero 1–3, rechazando cadenas/booleanos. Detalle y contexto preservan `asvs`, `source_dataset`, `source_license`, `rights` y `knowledge_type`. Citas/metadatos añaden overhead al presupuesto de pasajes. Sin endpoints nuevos de captura/registro ni rediseño visual.

El grafo backend proyecta los mismos controles, conceptos y pertenencias con licencia/estado. `category=OWASP-ASVS-5.0.0` los aísla. Completar los lotes de proyección y repetir un ciclo antes de afirmar idempotencia. Renderer anterior intacto.

## Pruebas

```powershell
python -B -m unittest tests.test_asvs tests.test_security tests.test_security_releases tests.test_zero_trust tests.test_attack_capture -v
python -B scripts/validate_security_catalog.py --asvs-capture NOMBRE.metadata.json
```

El ensayo trabaja offline sobre copia temporal de DB real: registro, repetición, filtros, citas, derechos, grafo, backup/restauración; no reemplaza la base operativa. Fixtures sintéticos prueban errores y rollback, no sustituyen bytes reales del proveedor. Consultar checkpoint local para última matriz y publicación.
