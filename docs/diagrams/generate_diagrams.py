#!/usr/bin/env python3
"""Generate the README diagrams as editable draw.io sources (English and German).

    python3 docs/diagrams/generate_diagrams.py            # writes concept.{en,de}.drawio, workflow.{en,de}.drawio
    python3 docs/diagrams/generate_diagrams.py --pin-svg  # after exporting: keep the SVGs light in dark mode

Export each source with draw.io (desktop CLI), for example

    drawio --export --format svg --embed-diagram --border 16 --scale 2 concept.en.drawio
    drawio --export --format png --embed-diagram --border 16 --scale 2 concept.en.drawio

then run ``--pin-svg``. draw.io writes adaptive ``light-dark()`` colours into SVGs by
default; GitHub shows an SVG as an image whose colour scheme follows the viewer's
system, so the diagrams pin their light palette and sit on their own white panel.

Standard library only. Labels are plain SVG text (no HTML labels), so the SVGs
need no fonts or links from the internet. Coordinates are explicit on purpose.
"""

from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
FONT = "Arial,Helvetica,sans-serif"

# Palette: one meaning per colour, the same in both diagrams.
INK, MUTED, LINE, BORDER = "#172033", "#475569", "#64748B", "#CBD5E1"
AGENT = ("#F1F5F9", "#64748B")      # agents: neutral slate
TOOL = ("#DCEBFF", "#2563EB")       # toolkit: blue
PERSON = ("#F3E8FF", "#7C3AED")     # responsible person: violet
TRAIL = ("#1E3A8A", "#1E3A8A")      # the one audit trail: dark blue, white text
STOP_RED, STOP_EDGE = "#DC2626", "#991B1B"
GO_GREEN, MANUAL_AMBER = "#15803D", "#B45309"
CONFIG = ("#FEF3C7", "#D97706")     # configurable step
OCTAGON = "shape=mxgraph.basic.polygon;polyCoords=[[0.29,0],[0.71,0],[1,0.29],[1,0.71],[0.71,1],[0.29,1],[0,0.71],[0,0.29]];polyline=0"


def style(**parts: object) -> str:
    return "".join(f"{key}={value};" for key, value in parts.items() if value is not None)


def text_style(size: int = 14, color: str = INK, bold: bool = False, align: str = "left", valign: str = "top") -> str:
    return style(text=1, strokeColor="none", fillColor="none", align=align, verticalAlign=valign, fontFamily=FONT,
                 fontSize=size, fontColor=color, fontStyle=1 if bold else 0, spacing=0)


def box_style(fill: str, stroke: str, *, size: int = 15, color: str = INK, bold: bool = False, valign: str = "middle",
              align: str = "center", dashed: bool = False, width: int = 2, radius: int = 10, top: int = 0) -> str:
    return style(rounded=1, absoluteArcSize=1, arcSize=radius, fillColor=fill, strokeColor=stroke, strokeWidth=width,
                 dashed=1 if dashed else None, fontFamily=FONT, fontSize=size, fontColor=color,
                 fontStyle=1 if bold else 0, align=align, verticalAlign=valign, spacingTop=top or None, spacing=6)


class Diagram:
    """One draw.io page. Everything sits on a white panel at (0, 0) whose label is the title."""

    def __init__(self, name: str, width: int, height: int, title: str) -> None:
        self.width, self.height = width, height
        self.mxfile = ET.Element("mxfile", {"host": "Electron", "agent": "agent-quality-toolkit generate_diagrams.py",
                                            "version": "31.4.2", "compressed": "false"})
        diagram = ET.SubElement(self.mxfile, "diagram", {"id": "page-1", "name": name})
        model = ET.SubElement(diagram, "mxGraphModel", {
            "dx": str(width), "dy": str(height), "grid": "1", "gridSize": "10", "guides": "1", "tooltips": "1",
            "connect": "1", "arrows": "1", "fold": "1", "page": "1", "pageScale": "1", "pageWidth": str(width),
            "pageHeight": str(height), "math": "0", "shadow": "0", "adaptiveColors": "none"})
        self.root = ET.SubElement(model, "root")
        ET.SubElement(self.root, "mxCell", {"id": "0"})
        ET.SubElement(self.root, "mxCell", {"id": "1", "parent": "0"})
        self.origin: dict[str, tuple[float, float]] = {"1": (0, 0)}
        self.count = 0
        self.vertex(title, 0, 0, width, height, style(
            rounded=1, absoluteArcSize=1, arcSize=18, container=1, collapsible=0, fillColor="#FFFFFF",
            strokeColor=BORDER, strokeWidth=1.5, fontFamily=FONT, fontSize=24, fontStyle=1, fontColor=INK,
            align="left", verticalAlign="top", spacingLeft=28, spacingTop=18), parent="1", cell_id="panel")

    def _id(self, prefix: str) -> str:
        self.count += 1
        return f"{prefix}-{self.count}"

    def vertex(self, label: str, x: float, y: float, w: float, h: float, cell_style: str, *, parent: str = "panel",
               cell_id: str | None = None) -> str:
        """Place a vertex at absolute page coordinates (converted to the parent's frame)."""
        cell_id = cell_id or self._id("v")
        px, py = self.origin[parent]
        cell = ET.SubElement(self.root, "mxCell", {"id": cell_id, "value": label, "style": cell_style,
                                                   "vertex": "1", "parent": parent})
        ET.SubElement(cell, "mxGeometry", {"x": str(x - px), "y": str(y - py), "width": str(w), "height": str(h),
                                           "as": "geometry"})
        self.origin[cell_id] = (x, y)
        return cell_id

    def text(self, label: str, x: float, y: float, w: float, h: float, *, parent: str = "panel", **kw) -> str:
        return self.vertex(label, x, y, w, h, text_style(**kw), parent=parent)

    def card(self, name: str, sub: str | None, x: float, y: float, w: float, h: float, colours: tuple[str, str], *,
             parent: str = "panel", name_color: str = INK, sub_color: str = INK, size: int = 15,
             sub_top: int = 31) -> str:
        """A rounded card: bold name on top, optional plain sub-text below it."""
        fill, stroke = colours
        valign = "top" if sub else "middle"
        card = self.vertex(name, x, y, w, h, box_style(fill, stroke, size=size, bold=True, valign=valign,
                                                       color=name_color, top=4 if sub else 0), parent=parent)
        if sub:
            self.text(sub, x + 8, y + sub_top, w - 16, h - sub_top - 6, parent=card, size=14, color=sub_color,
                      align="center")
        return card

    def octagon(self, label: str, x: float, y: float, size: float = 56, *, parent: str = "panel", font: int = 13) -> str:
        return self.vertex(label, x, y, size, size, OCTAGON + ";" + style(
            fillColor=STOP_RED, strokeColor=STOP_EDGE, strokeWidth=1.5, fontFamily=FONT, fontSize=font, fontStyle=1,
            fontColor="#FFFFFF", align="center", verticalAlign="middle"), parent=parent)

    def badge(self, number: str, x: float, y: float, *, parent: str = "panel") -> str:
        return self.vertex(number, x, y, 24, 24, style(
            shape="ellipse", perimeter="ellipsePerimeter", fillColor="#334155", strokeColor="#334155", fontFamily=FONT, fontSize=13, fontStyle=1,
            fontColor="#FFFFFF", align="center", verticalAlign="middle"), parent=parent)

    def edge(self, source: str, target: str, *, points: list[tuple[float, float]] | None = None, color: str = LINE,
             dashed: bool = False, width: float = 2, arrow: str = "block", **constraints: float) -> str:
        cell_id = self._id("e")
        cell_style = style(edgeStyle="orthogonalEdgeStyle", rounded=1, orthogonalLoop=1, jettySize="auto",
                           endArrow=arrow, endFill=1, endSize=7, strokeColor=color, strokeWidth=width,
                           dashed=1 if dashed else None, **{k: v for k, v in constraints.items()})
        cell = ET.SubElement(self.root, "mxCell", {"id": cell_id, "value": "", "style": cell_style, "edge": "1",
                                                   "parent": "panel", "source": source, "target": target})
        geometry = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        if points:
            array = ET.SubElement(geometry, "Array", {"as": "points"})
            for px, py in points:
                ET.SubElement(array, "mxPoint", {"x": str(px), "y": str(py)})
        return cell_id

    def write(self, path: Path) -> Path:
        ET.indent(self.mxfile, space="  ")
        ET.ElementTree(self.mxfile).write(path, encoding="utf-8", xml_declaration=True)
        return path


# --------------------------------------------------------------------------------------------- texts
CONCEPT = {
    "en": {
        "title": "How the toolkit fits around any agent harness",
        "subtitle": "Agents work in their own programs. The toolkit is a control layer beside them. People decide.",
        "zones": ("Agents work", "Control layer", "People decide"),
        "agents": ("Claude Code", "Codex", "pi", "Agent Unity", "any other agent"),
        "agents_note": "Each agent runs in its\nown program. The toolkit\nis not a session view\nand not a harness.",
        "tools": (("aqt-quarantine", "holds untrusted input"), ("aqt-validate", "qualifies AI controls"),
                  ("aqt-change", "tests, receipts, gate"), ("aqt-signoff", "signatures with meaning"),
                  ("aqt-sensei", "read-only advisor relay"), ("aqt-capa", "deviations and CAPA")),
        "spec": "aqt-spec · one record format for every tool",
        "trail": ("aqt-trail · ONE audit trail", "hash-chained; the Linux kernel\nreports who sent each record"),
        "person": ("Responsible person", "developer or\nquality manager"),
        "ui": ("aqt-ui", "local quality desk"),
        "terminal": ("Terminal", "every command"),
        "decides": "Decides with a\npassphrase: release,\nsign, approve, review",
        "outputs": ("For auditors", "verify\nALCOA++ report\nsigned trail review\nsignature manifests"),
        "mechanisms": ("Hooks\nClaude Code only", "Commands\nany agent", "Terminal relay\ntmux or Herdr",
                       "Observation\nand import"),
        "right": ("needs a\ndecision", "signed\ndecision", "reports"),
        "notes": (
            ("Hooks · Claude Code only",
             "Called automatically.\naqt-quarantine checks web, search\nand MCP results before the model\n"
             "sees them. aqt-change blocks\n“done” without fresh passing\nreceipts. aqt-trail logs each step."),
            ("Commands · any agent",
             "Any agent with a shell runs the\nsame tools, for example\naqt-change run (the tool runs\n"
             "the tests) and aqt-signoff\nprepare (an action that waits\nfor approval)."),
            ("Terminal relay",
             "aqt-sensei passes advice between\ntwo agent terminals (tmux or\nHerdr). In the default mode the\n"
             "owner approves each message."),
            ("Observation and import",
             "The trail writer asks the Linux\nkernel which program sent each\nrecord. aqt-trail imports Claude\n"
             "Code, Codex and pi session logs."),
        ),
    },
    "de": {
        "title": "Wie das Toolkit um beliebige Agenten-Programme greift",
        "subtitle": "Agenten arbeiten in ihren eigenen Programmen. Das Toolkit ist eine Kontrollschicht daneben. "
                    "Menschen entscheiden.",
        "zones": ("Agenten arbeiten", "Kontrollschicht", "Menschen entscheiden"),
        "agents": ("Claude Code", "Codex", "pi", "Agent Unity", "jeder andere Agent"),
        "agents_note": "Jeder Agent läuft in\nseinem eigenen\nProgramm. Das Toolkit\nist keine Sitzungs-\n"
                       "ansicht und kein\nAgenten-Programm.",
        "tools": (("aqt-quarantine", "hält Verdächtiges zurück"), ("aqt-validate", "qualifiziert KI-Prüfer"),
                  ("aqt-change", "Tests, Belege, Prüfpunkt"), ("aqt-signoff", "signiert mit Bedeutung"),
                  ("aqt-sensei", "Berater, nur lesend"), ("aqt-capa", "Abweichungen und CAPA")),
        "spec": "aqt-spec · ein Datensatzformat für alle Werkzeuge",
        "trail": ("aqt-trail · EIN Audit Trail", "hash-verkettet; der Linux-Kernel\nmeldet den Absender jedes Eintrags"),
        "person": ("Verantwortliche\nPerson", "Entwicklung oder\nQualitätsmanagement"),
        "ui": ("aqt-ui", "lokaler QS-Arbeitsplatz"),
        "terminal": ("Terminal", "alle Befehle"),
        "decides": "Entscheidet mit\nPassphrase: freigeben,\nunterschreiben,\ngenehmigen, prüfen",
        "outputs": ("Für Auditoren", "verify\nALCOA++-Bericht\nsigniertes Trail-Review\nUnterschriftsmanifeste"),
        "mechanisms": ("Hooks\nnur Claude Code", "Befehle\njeder Agent", "Terminal-Relais\ntmux oder Herdr",
                       "Beobachtung\nund Import"),
        "right": ("braucht\nEntscheidung", "signierte\nEntscheidung", "Berichte"),
        "notes": (
            ("Hooks · nur Claude Code",
             "Laufen automatisch. aqt-quarantine\nprüft Web-, Such- und MCP-\nErgebnisse, bevor das Modell sie\n"
             "sieht. aqt-change blockiert\n„fertig“ ohne frische bestandene\nBelege. aqt-trail protokolliert."),
            ("Befehle · jeder Agent",
             "Jeder Agent mit Shell nutzt\ndieselben Werkzeuge, etwa\naqt-change run (das Werkzeug\n"
             "führt die Tests aus) und\naqt-signoff prepare (eine Aktion\nwartet auf Genehmigung)."),
            ("Terminal-Relais",
             "aqt-sensei leitet Rat zwischen\nzwei Agenten-Terminals weiter\n(tmux oder Herdr). Im Standard-\n"
             "modus gibt ein Mensch jede\nNachricht frei."),
            ("Beobachtung und Import",
             "Das Schreibprogramm des Audit\nTrails fragt den Linux-Kernel,\nwelches Programm jeden Eintrag\n"
             "sandte. aqt-trail importiert\nSitzungsprotokolle von Claude\nCode, Codex und pi."),
        ),
    },
}

WORKFLOW = {
    "en": {
        "title": "One change from start to release",
        "subtitle": "Who acts in each step. A red STOP waits for a person or for evidence; "
                    "every step becomes a record in the one audit trail.",
        "lanes": ("Agent", "Toolkit", "Responsible person"),
        "step": "Step",
        "steps": ("1  Untrusted\n    input", "2  Plan", "3  Tests and\n    review", "4  “Done”\n    gate",
                  "5  Release", "6  Approved\n    action"),
        "a_read": "Reads web pages, search\nresults or MCP output",
        "a_refused": "Releasing it itself:\nrefused and recorded",
        "t_score": "aqt-quarantine scores it:\npass · warn · hold",
        "go_caption": "pass, warn:\nmarked untrusted",
        "hold_caption": "hold: STOP until a\nperson decides",
        "p_release": "Releases it or declares\na threat (passphrase)",
        "a_plan": "Writes the plan: tasks,\nchecks, allowed paths",
        "t_plan": "Records the accepted plan\nversion (baseline hash)",
        "p_plan": "Signs this plan version\n“approved”. Needed for\nGO in step 4.",
        "a_tests": "Changes the code; asks\nthe tool to run checks",
        "t_tests": "aqt-change run: runs the\ndeclared checks, keeps receipts",
        "p_review": "Review by a person or an\nagent of another model.\nNeeded for GO in step 4.",
        "configurable": "configurable",
        "a_done": "Says “done”:\naqt-change finish",
        "a_done_caption": "The Claude Code hook and\nfinish refuse “done”\nwithout fresh passing\nreceipts.",
        "gate": "Gate",
        "nogo": "NO-GO: a receipt is\nmissing, failing or stale",
        "manual": "MANUAL_VERIFY_REQUIRED:\na person must check",
        "go": "GO: fresh passing\nreceipts for every check",
        "gate_caption": "stale: the code changed after\nthe tests. Waivers stay visible\nand never give GO.",
        "release_caption": "STOP until a person signs\n“released”. Changed content\nvoids the signature.",
        "p_signs": "Signs “released”\n(passphrase)",
        "a_action": "Prepares an action, e.g.\na deployment (prepare)",
        "action_caption": "STOP until approved for the exact hash.",
        "p_approve": "Approves the exact\nhash (passphrase)",
        "t_run": "Runs it once. “unknown” is never\nretried; a person resolves it.",
        "legend": "Legend",
        "legend_items": ("STOP: waits for a person", "Gate: decided from records", "GO: may continue",
                         "set per project", "refused and recorded"),
        "capa": "7  Side loop:\n    deviation and CAPA",
        "capa_steps": ("Refused attempts, failed\nreceipts → candidates", "Person accepts a\ndeviation (or dismisses)",
                       "Root cause recorded", "Corrective action,\napproved by a person",
                       "Effectiveness check\nfrom later evidence"),
        "capa_stop": "Closure only\nwhen effective",
        "periodic": "8  Periodic",
        "periodic_items": ("Qualification of a\ndetector or AI reviewer\nholds until its date.\nExpiry or a change:\n"
                           "requalify before relying.",
                           "Audit-trail review,\nsigned by a person who\ndid not act in that\nperiod.",
                           "ALCOA++ report on\nthe trail."),
        "trail": "aqt-trail · ONE audit trail",
        "trail_sub": "Every step above becomes a record: who, what, when, why and on which exact content. "
                     "Hash-chained; the Linux kernel reports the sender.",
    },
    "de": {
        "title": "Eine Änderung vom Start bis zur Freigabe",
        "subtitle": "Wer in jedem Schritt handelt. Ein rotes STOP wartet auf einen Menschen oder auf Nachweise; "
                    "jeder Schritt wird ein Eintrag im einen Audit Trail.",
        "lanes": ("Agent", "Toolkit", "Verantwortliche Person"),
        "step": "Schritt",
        "steps": ("1  Fremde\n    Eingabe", "2  Plan", "3  Tests und\n    Review", "4  Prüfpunkt\n    „fertig“",
                  "5  Freigabe", "6  Genehmigte\n    Aktion"),
        "a_read": "Liest Webseite, Such-\nergebnis, MCP-Ausgabe",
        "a_refused": "Gibt sie selbst frei:\nabgelehnt, protokolliert",
        "t_score": "aqt-quarantine bewertet:\npass · warn · hold",
        "go_caption": "pass, warn: als\nfremd markiert",
        "hold_caption": "hold: STOP, bis ein\nMensch entscheidet",
        "p_release": "Gibt frei oder erklärt\neine Bedrohung\n(Passphrase)",
        "a_plan": "Schreibt den Plan: Auf-\ngaben, Prüfungen, Pfade",
        "t_plan": "Hält die angenommene Plan-\nversion fest (Basis-Hash)",
        "p_plan": "Unterschreibt diese Plan-\nversion „genehmigt“; nötig\nfür GO in Schritt 4.",
        "a_tests": "Ändert den Code; lässt\ndas Werkzeug prüfen",
        "t_tests": "aqt-change run: führt die Prü-\nfungen selbst aus, hebt Belege auf",
        "p_review": "Review: ein Mensch oder\nein anderes Modell;\nnötig für GO in Schritt 4.",
        "configurable": "einstellbar",
        "a_done": "Meldet „fertig“:\naqt-change finish",
        "a_done_caption": "Claude-Code-Hook und\nfinish lehnen „fertig“\nohne frische bestandene\nBelege ab.",
        "gate": "Prüf-\npunkt",
        "nogo": "NO-GO: ein Beleg fehlt,\nist rot oder veraltet",
        "manual": "MANUAL_VERIFY_REQUIRED:\nein Mensch muss prüfen",
        "go": "GO: frische bestandene\nBelege für jede Prüfung",
        "gate_caption": "veraltet: Code nach den Tests\ngeändert. Ausnahmen (Waiver)\nbleiben sichtbar, nie GO.",
        "release_caption": "STOP, bis ein Mensch\n„freigegeben“ unterschreibt.\nNeuer Inhalt: ungültig.",
        "p_signs": "Unterschreibt\n„freigegeben“",
        "a_action": "Bereitet eine Aktion vor,\netwa ein Deployment\n(prepare)",
        "action_caption": "STOP bis zur Genehmigung dieses Hashs.",
        "p_approve": "Genehmigt genau\ndiesen Hash",
        "t_run": "Läuft genau einmal. „unknown“ wird nie\nwiederholt; ein Mensch klärt es.",
        "legend": "Legende",
        "legend_items": ("STOP: wartet auf Menschen", "Prüfpunkt: aus Einträgen", "GO: darf weiter",
                         "je Projekt", "abgelehnt, protokolliert"),
        "capa": "7  Nebenschleife:\n    Abweichung und CAPA",
        "capa_steps": ("Abgelehnte Versuche, rote\nBelege → Kandidaten", "Mensch nimmt Abweichung\nan (oder verwirft)",
                       "Ursache festgehalten", "Korrekturmaßnahme, von\neinem Menschen genehmigt",
                       "Wirksamkeitsprüfung\naus späteren Nachweisen"),
        "capa_stop": "Abschluss erst\nwenn wirksam",
        "periodic": "8  Periodisch",
        "periodic_items": ("Qualifizierung eines\nDetektors oder KI-Gut-\nachters gilt bis zu ihrem\n"
                           "Datum. Ablauf, Änderung:\nerst requalifizieren.",
                           "Audit-Trail-Review, unter-\nschrieben von jemandem,\nder im Zeitraum nicht\ngehandelt hat.",
                           "ALCOA++-Bericht über\nden Audit Trail."),
        "trail": "aqt-trail · EIN Audit Trail",
        "trail_sub": "Jeder Schritt oben wird ein Eintrag: wer, was, wann, warum und an welchem genauen Inhalt. "
                     "Hash-verkettet; der Linux-Kernel meldet den Absender.",
    },
}


# --------------------------------------------------------------------------------------------- concept
def concept(lang: str) -> Diagram:
    t = CONCEPT[lang]
    top, bottom = 100, 620                      # the three zones
    d = Diagram(t["title"], 1146, 826, t["title"])
    d.text(t["subtitle"], 28, 58, 1090, 24, size=15, color=MUTED)

    def zone(label: str, x: int, w: int, colours: tuple[str, str], tint: str) -> str:
        return d.vertex(label, x, top, w, bottom - top, style(
            rounded=1, absoluteArcSize=1, arcSize=14, container=1, collapsible=0, fillColor=tint,
            strokeColor=colours[1], strokeWidth=1.5, fontFamily=FONT, fontSize=16, fontStyle=1, fontColor=INK,
            align="left", verticalAlign="top", spacingLeft=14, spacingTop=10))

    left = zone(t["zones"][0], 28, 200, AGENT, "#F8FAFC")
    middle = zone(t["zones"][1], 392, 420, TOOL, "#F5F9FF")
    right = zone(t["zones"][2], 912, 206, PERSON, "#FBF8FF")

    # left: the agents, each in its own program
    chips = [d.card(name, None, 44, 150 + 50 * i, 168, 40, ("#FFFFFF", AGENT[1]), parent=left)
             for i, name in enumerate(t["agents"])]
    d.text(t["agents_note"], 44, 410, 172, 120, parent=left, size=14, color=MUTED)

    # middle: six tools, the shared record format, the one trail
    tools = {}
    for index, (name, sub) in enumerate(t["tools"]):
        row, col = divmod(index, 2)
        tools[name] = d.card(name, sub, 408 + 200 * col, 146 + 74 * row, 188, 62, TOOL, parent=middle)
    spec = d.vertex(t["spec"], 408, 380, 388, 40, box_style("#FFFFFF", TOOL[1], size=15), parent=middle)
    trail_box = (408, 446, 388, 158)
    trail = d.vertex(t["trail"][0], *trail_box, style(
        shape="cylinder3", boundedLbl=1, size=12, fillColor=TRAIL[0], strokeColor=TRAIL[1], strokeWidth=2,
        fontFamily=FONT, fontSize=17, fontStyle=1, fontColor="#FFFFFF", align="center", verticalAlign="top",
        spacingTop=12), parent=middle)
    d.text(t["trail"][1], 424, 528, 356, 44, parent=trail, size=14, color="#FFFFFF", align="center")
    d.edge(spec, trail, color=TOOL[1], exitX=0.5, exitY=1, entryX=0.5, entryY=0)

    # right: the responsible person, two ways in, the decision, the outputs
    person_h = 96 if "\n" in t["person"][0] else 78
    person = d.card(t["person"][0], t["person"][1], 926, 146, 178, person_h, PERSON, parent=right,
                    sub_top=person_h - 46)
    ui_top = 146 + person_h + 12
    d.card(t["ui"][0], t["ui"][1], 926, ui_top, 178, 58, PERSON, parent=right)
    d.card(t["terminal"][0], t["terminal"][1], 926, ui_top + 64, 178, 58, PERSON, parent=right)
    decide_top, decide_h = ui_top + 134, t["decides"].count("\n") * 17 + 34
    decide = d.vertex(t["decides"], 926, decide_top, 178, decide_h,
                      box_style("#FFFFFF", PERSON[1], size=14, width=2.5), parent=right)
    out_top = decide_top + decide_h + 14
    out_h = bottom - 14 - out_top
    outputs = d.vertex(t["outputs"][0], 926, out_top, 178, out_h, style(
        shape="document", boundedLbl=1, size=0.1, fillColor="#FFFFFF", strokeColor=LINE, strokeWidth=1.5,
        fontFamily=FONT, fontSize=15, fontStyle=1, fontColor=INK, align="center", verticalAlign="top",
        spacingTop=4), parent=right)
    d.text(t["outputs"][1], 934, out_top + 27, 162, out_h - 42, parent=outputs, size=14, align="center",
           valign="middle")

    # integration mechanisms: numbered arrows from the agents into the control layer
    lanes = [(chips[0], tools["aqt-quarantine"], 170), (left, tools["aqt-change"], 251),
             (left, tools["aqt-sensei"], 325), (left, trail, trail_box[1] + trail_box[3] // 2)]
    for number, ((source, target, y), label) in enumerate(zip(lanes, t["mechanisms"]), 1):
        exit_y = 0.5 if source != left else (y - top) / (bottom - top)
        target_top, target_h = (trail_box[1], trail_box[3]) if target == trail else (d.origin[target][1], 62)
        d.edge(source, target, exitX=1, exitY=round(exit_y, 4), entryX=0,
               entryY=round((y - target_top) / target_h, 4), color="#334155")
        d.badge(str(number), 240, y - 38)
        d.text(label, 270, y - 40, 118, 36, size=14)

    # people: what needs them, what they send back, what auditors get
    d.edge(middle, person, exitX=1, exitY=round((185 - top) / (bottom - top), 4), entryX=0,
           entryY=round(39 / person_h, 4))
    d.text(t["right"][0], 818, 146, 90, 36, size=14, align="center")
    decide_y = decide_top + decide_h / 2
    d.edge(decide, middle, exitX=0, exitY=0.5, entryX=1, entryY=round((decide_y - top) / (bottom - top), 4),
           color=PERSON[1])
    d.text(t["right"][1], 818, decide_y - 46, 90, 36, size=14, align="center")
    out_y = out_top + out_h / 2
    d.edge(trail, outputs, exitX=1, exitY=round((out_y - trail_box[1]) / trail_box[3], 4), entryX=0, entryY=0.5)
    d.text(t["right"][2], 818, out_y - 24, 90, 20, size=14, align="center")

    # notes, one per mechanism
    for index, (head, body) in enumerate(t["notes"]):
        x = 28 + index * 276
        note = d.vertex(head, x, bottom + 20, 262, 158, style(
            rounded=1, absoluteArcSize=1, arcSize=10, fillColor="#F8FAFC", strokeColor=BORDER, strokeWidth=1.5,
            fontFamily=FONT, fontSize=15, fontStyle=1, fontColor=INK, align="left", verticalAlign="top",
            spacingLeft=44, spacingTop=12))
        d.badge(str(index + 1), x + 12, bottom + 29, parent=note)
        d.text(body, x + 14, bottom + 58, 240, 112, parent=note, size=14)
    return d


# --------------------------------------------------------------------------------------------- workflow
def workflow(lang: str) -> Diagram:
    t = WORKFLOW[lang]
    d = Diagram(t["title"], 1180, 1154, t["title"])
    d.text(t["subtitle"], 28, 58, 1120, 24, size=15, color=MUTED)

    rows = [(140, 340), (340, 440), (440, 540), (540, 790), (790, 880), (880, 1050)]
    for index, ((top, bottom), step) in enumerate(zip(rows, t["steps"])):
        d.vertex(step, 32, top, 850, bottom - top, style(
            rounded=0, fillColor="#FFFFFF" if index % 2 else "#F8FAFC", strokeColor="none", fontFamily=FONT,
            fontSize=15, fontStyle=1, fontColor=INK, align="left", verticalAlign="top", spacingLeft=10,
            spacingTop=14))
    d.vertex(t["step"], 32, 100, 118, 40, style(rounded=0, fillColor="#F1F5F9", strokeColor=BORDER, strokeWidth=1.5,
                                                fontFamily=FONT, fontSize=16, fontStyle=1, fontColor=INK))

    def lane(label: str, x: int, w: int, colours: tuple[str, str]) -> str:
        return d.vertex(label, x, 100, w, 950, style(
            shape="swimlane", horizontal=1, startSize=40, rounded=0, fillColor=colours[0],
            swimlaneFillColor="none", strokeColor=BORDER, strokeWidth=1.5, fontFamily=FONT, fontSize=16,
            fontStyle=1, fontColor=INK, collapsible=0))

    agent = lane(t["lanes"][0], 150, 192, AGENT)
    tool = lane(t["lanes"][1], 342, 330, TOOL)
    person = lane(t["lanes"][2], 672, 210, PERSON)

    def a(label, x, y, w=178, h=56, parent=agent, **kw):
        return d.vertex(label, x, y, w, h, box_style(AGENT[0], AGENT[1], size=14, **kw), parent=parent)

    def k(label, x, y, w=302, h=56, parent=tool):
        return d.vertex(label, x, y, w, h, box_style(TOOL[0], TOOL[1], size=14), parent=parent)

    def p(label, x, y, w=182, h=56, parent=person):
        return d.vertex(label, x, y, w, h, box_style(PERSON[0], PERSON[1], size=14), parent=parent)

    def status(label, x, y, w, h, fill, parent=tool, size=14):
        return d.vertex(label, x, y, w, h, box_style(fill, fill, size=size, color="#FFFFFF", bold=True, radius=22)
                        + "spacing=3;", parent=parent)

    def tag(x, y, parent):
        return d.vertex(t["configurable"], x, y, 100, 22, box_style(CONFIG[0], CONFIG[1], size=13, bold=True,
                                                                    width=1.5, radius=11), parent=parent)

    # 1 untrusted input
    read = a(t["a_read"], 157, 152)
    refused = d.vertex(t["a_refused"], 157, 236, 178, 56, box_style("#FEF2F2", STOP_RED, size=14, dashed=True),
                       parent=agent)
    score = k(t["t_score"], 356, 152, 200)
    go1 = status("GO", 584, 165, 60, 30, GO_GREEN)
    d.text(t["go_caption"], 558, 202, 112, 38, parent=tool, size=14, align="center")
    hold = d.octagon("STOP", 428, 236, parent=tool)
    d.text(t["hold_caption"], 356, 298, 200, 38, parent=tool, size=14, align="center")
    release = p(t["p_release"], 686, 232, h=64)
    d.edge(read, score, exitX=1, exitY=0.5, entryX=0, entryY=0.5)
    d.edge(score, go1, exitX=1, exitY=0.5, entryX=0, entryY=0.5, color=GO_GREEN)
    d.edge(score, hold, exitX=0.5, exitY=1, entryX=0.5, entryY=0, color=STOP_RED)
    d.edge(refused, hold, exitX=1, exitY=0.5, entryX=0, entryY=0.5, color=STOP_RED, dashed=True)
    d.edge(hold, release, exitX=1, exitY=0.5, entryX=0, entryY=0.5, color=STOP_RED)

    # 2 plan
    plan_a = a(t["a_plan"], 157, 356)
    plan_t = k(t["t_plan"], 356, 356)
    plan_p = p(t["p_plan"], 686, 356, h=70)
    tag(778, 343, plan_p)
    d.edge(plan_a, plan_t, exitX=1, exitY=0.5, entryX=0, entryY=0.5)
    d.edge(plan_t, plan_p, exitX=1, exitY=0.5, entryX=0, entryY=0.4, color=CONFIG[1], dashed=True)

    # 3 tests and review
    tests_a = a(t["a_tests"], 157, 456)
    tests_t = k(t["t_tests"], 356, 456)
    review = p(t["p_review"], 686, 456, h=70)
    tag(778, 443, review)
    d.edge(tests_a, tests_t, exitX=1, exitY=0.5, entryX=0, entryY=0.5)

    # 4 the "done" gate
    done = a(t["a_done"], 157, 580)
    d.text(t["a_done_caption"], 157, 646, 178, 76, parent=agent, size=14, color=MUTED, align="center")
    gate = d.vertex(t["gate"], 356, 566, 74, 84, style(
        shape="rhombus", fillColor="#FEE2E2", strokeColor=STOP_RED, strokeWidth=2.5, fontFamily=FONT,
        fontSize=15 if lang == "en" else 13, fontStyle=1, fontColor=INK, align="center", verticalAlign="middle"),
        parent=tool)
    nogo = status(t["nogo"], 454, 556, 204, 46, STOP_RED, size=13)
    manual = status(t["manual"], 454, 610, 204, 46, MANUAL_AMBER, size=13)
    go = status(t["go"], 454, 664, 204, 46, GO_GREEN, size=13)
    d.text(t["gate_caption"], 356, 722, 220, 56, parent=tool, size=14, color=MUTED)
    d.edge(done, gate, exitX=1, exitY=0.5, entryX=0, entryY=0.5)
    d.edge(tests_t, gate, exitX=round(37 / 302, 4), exitY=1, entryX=0.5, entryY=0)
    for target, y in ((nogo, 579), (manual, 633), (go, 687)):
        d.edge(gate, target, exitX=1, exitY=0.5, entryX=0, entryY=0.5, points=[(442, 608), (442, y)])

    # 5 release
    signed = d.octagon("STOP", 584, 806, parent=tool)
    d.text(t["release_caption"], 356, 808, 222, 56, parent=tool, size=14)
    signs = p(t["p_signs"], 686, 806)
    d.edge(go, signed, exitX=round(158 / 204, 4), exitY=1, entryX=0.5, entryY=0, color=GO_GREEN)
    d.edge(signed, signs, exitX=1, exitY=0.5, entryX=0, entryY=0.5, color=STOP_RED)

    # 6 approved action
    action = a(t["a_action"], 157, 894, h=60)
    approval = d.octagon("STOP", 356, 896, parent=tool)
    d.text(t["action_caption"], 356, 960, 302, 22, parent=tool, size=14)
    approve = p(t["p_approve"], 686, 896)
    run = k(t["t_run"], 356, 990, h=48)
    d.edge(action, approval, exitX=1, exitY=0.5, entryX=0, entryY=0.5)
    d.edge(approval, approve, exitX=1, exitY=0.5, entryX=0, entryY=0.5, color=STOP_RED)
    d.edge(approve, run, exitX=0.5, exitY=1, entryX=1, entryY=0.5, color=PERSON[1])

    # legend
    legend = d.vertex(t["legend"], 906, 100, 242, 196, style(
        rounded=1, absoluteArcSize=1, arcSize=10, container=1, collapsible=0, fillColor="#FFFFFF",
        strokeColor=BORDER, strokeWidth=1.5, fontFamily=FONT, fontSize=15, fontStyle=1, fontColor=INK,
        align="left", verticalAlign="top", spacingLeft=14, spacingTop=10))
    d.octagon("!", 920, 136, 28, parent=legend, font=14)
    d.vertex("?", 920, 168, 28, 28, style(shape="rhombus", fillColor="#FEE2E2", strokeColor=STOP_RED, strokeWidth=2,
                                          fontFamily=FONT, fontSize=13, fontStyle=1, fontColor=INK), parent=legend)
    status("GO", 916, 203, 36, 22, GO_GREEN, parent=legend, size=12)
    tag(916, 233, legend)
    d.vertex("×", 918, 265, 32, 22, box_style("#FEF2F2", STOP_RED, size=14, color=STOP_RED, bold=True, dashed=True,
                                              width=1.5, radius=4), parent=legend)
    for y, label, x in zip((137, 169, 201, 231, 263), t["legend_items"], (960, 960, 960, 1024, 960)):
        d.text(label, x, y, 1142 - x, 26, parent=legend, size=14, valign="middle")

    # 7 side loop: deviation and CAPA
    capa = d.vertex(t["capa"], 906, 312, 242, 410, style(
        rounded=1, absoluteArcSize=1, arcSize=10, container=1, collapsible=0, fillColor="#FFFFFF",
        strokeColor=BORDER, strokeWidth=1.5, fontFamily=FONT, fontSize=15, fontStyle=1, fontColor=INK,
        align="left", verticalAlign="top", spacingLeft=14, spacingTop=10))
    owners = (TOOL, PERSON, PERSON, PERSON, TOOL)
    previous = None
    for index, (label, colours) in enumerate(zip(t["capa_steps"], owners)):
        cell = d.vertex(label, 922, 368 + 58 * index, 210, 40, box_style(*colours, size=14), parent=capa)
        if previous:
            d.edge(previous, cell, exitX=0.5, exitY=1, entryX=0.5, entryY=0)
        previous = cell
    stop7 = d.octagon("STOP", 922, 656, parent=capa)
    d.text(t["capa_stop"], 988, 658, 150, 52, parent=capa, size=14, valign="middle")
    d.edge(previous, stop7, exitX=0.12, exitY=1, entryX=0.5, entryY=0)

    # 8 periodic
    periodic = d.vertex(t["periodic"], 906, 738, 242, 312, style(
        rounded=1, absoluteArcSize=1, arcSize=10, container=1, collapsible=0, fillColor="#FFFFFF",
        strokeColor=BORDER, strokeWidth=1.5, fontFamily=FONT, fontSize=15, fontStyle=1, fontColor=INK,
        align="left", verticalAlign="top", spacingLeft=14, spacingTop=10))
    d.octagon("!", 920, 778, 28, parent=periodic, font=14)
    d.text(t["periodic_items"][0], 954, 776, 188, 92, parent=periodic, size=14)
    d.vertex("✓", 922, 882, 26, 26, box_style(PERSON[0], PERSON[1], size=14, color=PERSON[1], bold=True, width=1.5,
                                              radius=4), parent=periodic)
    d.text(t["periodic_items"][1], 954, 880, 188, 76, parent=periodic, size=14)
    d.vertex("A", 922, 970, 26, 26, box_style(TOOL[0], TOOL[1], size=13, color=TOOL[1], bold=True, width=1.5,
                                              radius=4), parent=periodic)
    d.text(t["periodic_items"][2], 954, 968, 188, 40, parent=periodic, size=14)

    # the one audit trail, along the bottom
    band = d.vertex(t["trail"], 32, 1070, 1116, 56, style(
        rounded=1, absoluteArcSize=1, arcSize=10, fillColor=TRAIL[0], strokeColor=TRAIL[1], fontFamily=FONT,
        fontSize=16, fontStyle=1, fontColor="#FFFFFF", align="left", verticalAlign="top", spacingLeft=16,
        spacingTop=7))
    d.text(t["trail_sub"], 48, 1098, 1090, 22, parent=band, size=14, color="#FFFFFF")
    for source in (agent, tool, person, periodic):
        d.edge(source, band, exitX=0.5, exitY=1, entryX=round((d.origin[source][0] + (
            {agent: 96, tool: 165, person: 105, periodic: 121}[source]) - 32) / 1116, 4), entryY=0, color=TRAIL[0])
    return d


# --------------------------------------------------------------------------------------------- SVG pinning
LIGHT_DARK = re.compile(r"light-dark\(\s*((?:rgba?\([^()]*\)|[^,()]+))\s*,\s*(?:rgba?\([^()]*\)|[^,()]+)\s*\)")


def pin_svg(path: Path) -> None:
    """Replace adaptive light-dark() colours with their light value."""
    svg = path.read_text(encoding="utf-8")
    svg = LIGHT_DARK.sub(lambda m: m.group(1).strip(), svg)
    svg = svg.replace("color-scheme: light dark;", "color-scheme: light;")
    path.write_text(svg, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pin-svg", action="store_true", help="pin the light palette in the exported SVGs")
    args = parser.parse_args()
    if args.pin_svg:
        for path in sorted(HERE.glob("*.svg")):
            pin_svg(path)
            print(f"pinned {path.name}")
        return 0
    for lang in ("en", "de"):
        print(concept(lang).write(HERE / f"concept.{lang}.drawio").name)
        print(workflow(lang).write(HERE / f"workflow.{lang}.drawio").name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
