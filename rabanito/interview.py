from __future__ import annotations

from datetime import datetime
from typing import Callable

from .config import Settings
from .utils import slugify


QUESTIONS = [
    "¿Cuál es el objetivo o resultado que quieres conseguir con este tema?",
    "¿Qué hechos consideras confirmados y qué fuente los respalda?",
    "¿Qué decisiones ya tomaste y por qué, si está documentado?",
    "¿Qué alternativas descartaste o riesgos identificaste?",
    "¿Qué pasos, pruebas o evidencias existen actualmente?",
    "¿Qué problemas siguen abiertos y qué información falta?",
    "¿Qué debería recordar Rabanito para ayudarte en una sesión futura?",
]


def conduct_interview(settings: Settings, topic: str, input_fn: Callable[[str], str] = input, output_fn: Callable[[str], None] = print) -> dict[str, object]:
    if any(not char.isprintable() for char in topic):
        raise ValueError("El tema debe contener entre 1 y 160 caracteres imprimibles en una sola línea.")
    topic = topic.strip()
    if not topic or len(topic) > 160:
        raise ValueError("El tema debe contener entre 1 y 160 caracteres imprimibles en una sola línea.")

    answers: list[tuple[str, str]] = []
    output_fn(f"Entrevista guiada: {topic}")
    output_fn("Nada se guardará hasta que revises y apruebes el resumen final.")
    for question in QUESTIONS:
        answer = input_fn(f"\n{question}\n> ").strip()
        answers.append((question, answer))
    topic_yaml = "'" + topic.replace("'", "''") + "'"
    lines = ["---", "kind: approved-interview", "status: draft", f"topic: {topic_yaml}", "---", "", f"# Entrevista — {topic}", "", "> Borrador pendiente de revisión y aprobación.", ""]
    for number, (question, answer) in enumerate(answers, 1):
        lines.extend([f"## {number}. {question}", "", answer or "(sin respuesta)", ""])
    preview = "\n".join(lines)
    output_fn("\n=== VISTA PREVIA ===\n" + preview)
    approved = input_fn("\nEscribe APROBAR para guardar esta entrevista, o cualquier otra cosa para descartarla: ").strip().casefold() == "aprobar"
    if not approved:
        output_fn("Entrevista descartada; no se escribió ningún archivo.")
        return {"approved": False, "topic": topic, "questions": len(answers)}
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = settings.knowledge_root / "personal" / "interviews"
    directory.mkdir(parents=True, exist_ok=True)
    approved_text = preview.replace("status: draft", "status: approved", 1)
    approved_text = approved_text.replace("> Borrador pendiente de revisión y aprobación.", "> Aprobada explícitamente por el usuario después de revisar la vista previa.", 1)
    stem = f"{stamp}-{slugify(topic)}"
    path = None
    for suffix in range(1000):
        suffix_text = "" if suffix == 0 else f"-{suffix + 1:02d}"
        candidate = directory / f"{stem}{suffix_text}.md"
        try:
            with candidate.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(approved_text)
            path = candidate
            break
        except FileExistsError:
            continue
    if path is None:
        raise FileExistsError("No se encontró un nombre libre para guardar la entrevista sin sobrescribir archivos existentes.")
    output_fn(f"Entrevista aprobada y guardada en: {path}")
    return {"approved": True, "topic": topic, "questions": len(answers), "path": str(path)}
