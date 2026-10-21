from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import Settings
from .interview_storage import MAX_NOTE_BYTES, save_reviewed_interview
from .utils import redact_sensitive_lines, slugify


QUESTIONS = [
    "¿Cuál es el objetivo o resultado que quieres conseguir con este tema?",
    "¿Qué hechos consideras confirmados y qué fuente los respalda?",
    "¿Qué decisiones ya tomaste y por qué, si está documentado?",
    "¿Qué alternativas descartaste o riesgos identificaste?",
    "¿Qué pasos, pruebas o evidencias existen actualmente?",
    "¿Qué problemas siguen abiertos y qué información falta?",
    "¿Qué debería recordar Rabanito para ayudarte en una sesión futura?",
]


def _text(value, maximum, *, single=False):
    if (not isinstance(value, str) or len(value) > maximum
            or any(ord(c) < 32 and c not in '\n\r\t' or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
            or single and any(not c.isprintable() for c in value)):
        raise ValueError('invalid_interview_text')
    if redact_sensitive_lines(value).splitlines() != value.splitlines():
        raise ValueError('interview_sensitive_content')
    return value.replace('\r\n', '\n').replace('\r', '\n').strip()


def conduct_interview(settings: Settings, topic: str, input_fn: Callable[[str], str] = input, output_fn: Callable[[str], None] = print, *, config_path: Path | None = None) -> dict[str, object]:
    settings = Settings(settings.root, copy.deepcopy(settings.raw))
    topic = _text(topic, 160, single=True)
    if any(not char.isprintable() for char in topic):
        raise ValueError("El tema debe contener entre 1 y 160 caracteres imprimibles en una sola línea.")
    topic = topic.strip()
    if not topic or len(topic) > 160:
        raise ValueError("El tema debe contener entre 1 y 160 caracteres imprimibles en una sola línea.")

    answers: list[tuple[str, str]] = []
    output_fn(f"Entrevista guiada: {topic}")
    output_fn("Nada se guardará hasta que revises y apruebes el resumen final.")
    for question in QUESTIONS:
        answer = _text(input_fn(f"\n{question}\n> "), 8000)
        answers.append((question, answer))
    topic_yaml = "'" + topic.replace("'", "''") + "'"
    lines = ["---", "kind: approved-interview", "status: approved", f"topic: {topic_yaml}", "---", "", f"# Entrevista — {topic}", "", "> Aprobada explícitamente por el usuario después de revisar la vista previa.",
             "> La aprobación revisa el texto; no verifica de forma independiente los hechos ni ejecuta sus instrucciones.", ""]
    for number, (question, answer) in enumerate(answers, 1):
        lines.extend([f"## {number}. {question}", "", answer or "(sin respuesta)", ""])
    preview = "\n".join(lines)
    if len(preview.encode('utf-8')) > MAX_NOTE_BYTES:
        raise ValueError('interview_size_limit')
    if redact_sensitive_lines(preview).splitlines() != preview.splitlines():
        raise ValueError('interview_sensitive_content')
    output_fn("\n=== VISTA PREVIA CANDIDATA; TODAVÍA NO APROBADA NI GUARDADA ===\n"
              "Los metadatos approved describen el estado propuesto solo si apruebas este texto exacto.\n" + preview)
    approval = input_fn("\nEscribe APROBAR para guardar esta entrevista, o cualquier otra cosa para descartarla: ")
    approved = isinstance(approval, str) and len(approval) <= 128 and approval.strip().casefold() == 'aprobar'
    if not approved:
        output_fn("Entrevista descartada; no se escribió ningún archivo.")
        return {"approved": False, "topic": topic, "questions": len(answers)}
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"{stamp}-{slugify(topic)}"
    path = save_reviewed_interview(settings, stem, preview, config_path=config_path)
    output_fn(f"Entrevista aprobada y guardada en: {path}")
    return {"approved": True, "topic": topic, "questions": len(answers), "path": str(path)}
