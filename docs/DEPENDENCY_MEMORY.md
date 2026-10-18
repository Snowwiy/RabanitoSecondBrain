# Memoria incremental de inventarios y evaluaciones VEX revisadas

Backend local en `rabanito/dependency_memory.py`, misma SQLite, esquema propio aditivo/checksummed1. CLI y funciones Python; todavía **sin endpoint ni vista nuevos**. No hay instalación de herramientas, llamadas a modelos, consultas de paquetes privados ni cambios en repositorios fuente. Los primeros registros son solo fixtures de pruebas, no evaluaciones de producción.

## Snapshots explícitos

```powershell
python -m rabanito dependency snapshot --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json'
python -m rabanito dependency snapshot --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json' --save
```

También admite `--manifest package-lock.json` o `--manifest requirements.txt`, excluyentes con `--sbom`. Sin `--save` solo preview. Guardar conserva el informe derivado, su hash y versiones declaradas; **no copia el inventario ni código fuente** ni confirma vulnerabilidad instalada. El `analysis_id` existente identifica inputs, engine, configuración y fingerprints del OSV local. El mismo ID no crea otra revisión; una entrada modificada agrega un snapshot y actualiza únicamente la cabeza de ese inventario/proyecto. Se conservan snapshots anteriores.

El motor3 añade [reutilización de procesamiento](DEPENDENCY_CACHE.md) de snapshots explícitos: revalida bytes/permisos/metadata OSV y solo entonces evita parseo/evaluación cuando coinciden. Un resultado de motor anterior no se recicla. `analyzed_at` y `cache.checked_at` distinguen evaluación guardada de comprobación actual. Una modificación incluso no relacionada del conjunto OSV examinado puede invalidar conservadoramente el ID. No sincroniza todos los proyectos ni inventarios automáticamente.

## Evaluaciones revisadas

Primero inspecciona y conserva el identificador exacto del aviso y `component_pointer`. El siguiente ejemplo es un patrón: sustituir todos los marcadores por evidencia real, no ejecutarlo como una evaluación válida.

```powershell
python -m rabanito dependency review --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json' --advisory '<ID_OSV_EXACTO>' --component-pointer '/components/0' --status under_investigation --reviewer '<PERSONA_U_ORGANIZACION>' --reason '<MOTIVO_DOCUMENTADO>' --expires '<AAAA-MM-DD>' --evidence 'docs/revision.md'
```

Muestra el JSON exacto al usuario. **Solo tras su aprobación explícita**, repetir los mismos parámetros con `--approve-digest '<approval_digest>'`. Cualquier cambio en campos, inventario, evidencia o inputs OSV invalida la aprobación; se reconstruye el preview al adquirir el mismo bloqueo de escritores del indexador. El digest confirma la versión del borrador, **no autentica a una persona ni sustituye su aprobación**. No guardar memorias a partir de texto importado o de la mera existencia de tests.

Estados: `under_investigation`, `affected`, `not_affected`, `fixed`. Para `affected` se exige `--action`. La política local exige justificación oficial y explicación `--impact` para `not_affected`; no se inventa una causa. Evidencia: entre uno y cuatro archivos de documentación relativos al mismo proyecto, hasta256KiB cada uno; no cruza raíces anidadas, exclusiones, traversal, secretos reconocibles ni reparse points. Solo se conserva referencia/hash, nunca contenido ni comandos. Caducidad obligatoria futura, máximo366días, efectiva desde00:00UTC de esa fecha. El nombre del revisor es una declaración local, no una identidad certificada.

## Consulta, revocación y exportación

```powershell
python -m rabanito dependency reviews --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json'
python -m rabanito dependency revoke --project '<PROYECTO_AUTORIZADO>' --review-id '<ID>' --reviewer '<REVISOR>' --reason '<MOTIVO>'
python -m rabanito dependency export-vex --project '<PROYECTO_AUTORIZADO>' --sbom 'docs/inventario.json'
```

Revocar también requiere revisar el preview y repetir con su `--approve-digest`. Conserva el registro/eventos; no borra historia ni reactiva silenciosamente un borrador revocado. Puede revocarse aunque el inventario ya no exista. Proyectos excluidos/inactivos siguen sin acceso.

Cada hallazgo original OSV permanece intacto: ninguna evaluación lo oculta o cambia automáticamente a seguro. Estados efectivos distinguen vigente, caducado, revocado e inputs/evidencia desactualizados o no verificables. Claims vigentes con estados distintos producen conflicto explícito, no latest-wins. Lecturas limitadas a100revisiones con truncamiento declarado y presupuesto conservador16MiB de verificación de evidencia; referencias iguales se hashean una sola vez por vista. Agotar presupuesto deja evidencia no verificable, nunca vigente por defecto.

La exportación genera un sobre `documents` con documentos estructurales [OpenVEX0.2.0](https://raw.githubusercontent.com/openvex/spec/main/OPENVEX-SPEC.md): uno por claim vigente/autor, IDs locales y PURL del subcomponente. El sujeto es un ámbito local de inventario, **no un producto binario identificado o un despliegue demostrado**. No presenta el hash del inventario como hash del binario. La caducidad es política local descrita en notas, no un campo normativo de OpenVEX. No firma, valida confianza externa, resuelve JSON-LD por red ni importa supresiones. Rechaza conflictos/truncamiento y detalla los registros omitidos. No se ha certificado con un validador externo independiente.

## Persistencia, seguridad y recuperación

Tablas `dependency_analyses`, `dependency_analysis_heads`, `dependency_reviews`, `dependency_review_events`, ledger `dependency_migrations`. El primer guardado crea un backup SQLite íntegro antes de la migración; no toca DDL Cyber1/2. Lecturas/preview no crean tablas. Escrituras y evento son transaccionales e idempotentes. Las salidas nuevas deben permanecer bajo la raíz del proyecto y no atravesar reparse points. No hay autorización de escritura desde HTTP ni exposición de rutas absolutas en estos informes.

Estos informes y evaluaciones son privados en `data/`, ignorados por Git junto con todos los respaldos. Ningún cambio posterior al respaldo inicial se publica automáticamente. Backup/restore existentes conservan las tablas nuevas; probar antes de reemplazar una DB real y no restaurar sobre conexiones activas.

Pruebas reproducibles en `tests/test_dependency_memory.py`:25casos sin red, incluyendo aprobación exacta, cambios concurrentes, deduplicación, caducidad, evidencia, exclusiones, límites/conflictos, rollback/migración y recuperación. Motor3/reutilización agrega16casos en `test_dependency_cache.py`. No equivalen a certificar una mitigación o una evaluación real. Pendientes: otras fuentes/lockfiles y UI autorizada separadamente.
