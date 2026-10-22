# Validierungsbeispiel: Manipulationserkennung des Audit Trails in aqt-trail

> **Übungsbeispiel – keine Freigabe für den GMP-Einsatz.** Der Autor hat dieses Dokument als Demonstration einer CSV-Dokumentation für sein eigenes Open-Source-Werkzeug geschrieben; es ersetzt nicht die Validierung durch ein reguliertes Unternehmen für dessen Zweckbestimmung.

| | |
|---|---|
| Dokument | AQT-VAL-TRAIL-01 (Übung), Version 0.2 (Wiederholung auf `eb920b1`) |
| Prüfgegenstand | aqt-trail 0.1.0 mit aqt-spec 0.1.0 (Bibliothek `aqt_evidence`), Git-Commit `eb920b1` (`eb920b161c7efa1138b1a11410484750fbd793bb`) |
| Autor | Benedikt Neumayer |
| Durchführung | KI-Agent im Auftrag des Autors; Review: Benedikt Neumayer, ausstehend |
| Aufbau | Validierungsplan, URS, Risikoanalyse, Testspezifikation, Testprotokoll und Bericht wären real getrennte, einzeln freigegebene Dokumente; hier sind sie zusammengefasst. |
| Protokollstand | Kapitel 1–6 festgelegt am 2026-10-22, 19:52 MESZ, vor der Erstdurchführung auf `917db6e`; danach nur redaktionell gekürzt. Für die Wiederholung auf `eb920b1` (Kapitel 7) inhaltlich unverändert übernommen; angepasst wurden nur die Commit-Angaben. |

## 1. Zweck und Geltungsbereich

**Zweck:** an einer Funktion zeigen, wie eine risikobasierte Validierung nach GAMP 5 (2. Ausgabe, 2022) dokumentiert wird.

**Prüfgegenstand:** die Manipulationserkennung (tamper evidence) des Audit Trails in aqt-trail, Commit `eb920b1`: separater Writer mit Writer-Zeit, laufender Nummer, beobachtetem Absender, Spool und Lückenmarkern (`server.py`, `writer.py`, `observe.py`, `client.py`); Hash-Kette und Ed25519-Signatur (`chain.py`, `crypto.py` in aqt-spec); signierte Checkpoints, Kopfkopien und RFC-3161-Zeitstempel (`anchors.py`, `tsa.py`, `der.py`); `aqt-trail verify` und Export-Bundle (`verify.py`, `export.py`).

**Nicht Gegenstand:** die übrigen sechs Pakete; in aqt-trail Importer, Hook, Audit-Trail-Review, ALCOA++-Bericht und Ansichten; der Betrieb unter separatem Systembenutzer (`aqt-trail/scripts/setup-system-user.sh`, von der Testsuite nie ausgeführt); RFC 3161 mit einem echten Zeitstempeldienst (TSA; getestet wird nur die eingebaute TEST-ONLY-Instanz `test:`); andere Betriebssysteme, Last, Archivierung, Backup/Restore, IQ einer Produktivinstallation, Code-Review.

## 2. Systembeschreibung und GAMP-5-Kategorisierung

**Systembeschreibung.** aqt-trail ist ein Kommandozeilenwerkzeug in Python (≥ 3.11) für Linux. Clients senden Datensätze (*AQT Evidence Records 0.1*, `aqt-spec/spec/evidence-records-0.1.md`) über einen Unix-Socket (0600) an den Writer `aqt-trail serve`; er prüft, setzt Zeit, `observed` und Kette, signiert, hängt eine kanonische JSON-Zeile an und ruft `fsync` auf. Ist er nicht erreichbar, spoolen Clients; der Writer schreibt später `trail.gap` und die Datensätze mit `via: spool`. `checkpoint [--anchor]` signiert den Kettenkopf (optional mit RFC-3161-Token), `head --export` gibt ihn zur Ablage außerhalb aus. `verify` meldet „intact“ (Exit 0) oder „broken from seq N“ bzw. ein Problem (Exit 1); `export` schreibt ein Bundle, das `verify --bundle` anderswo prüft. Im Standard-Benutzermodus gehören Writer, Log und Schlüssel demselben Benutzer wie die Agenten: Manipulation wird nur erkannt, nicht verhindert, und nur mit gepinntem Schlüssel und Kopfkopien außerhalb der Reichweite der Agenten (`aqt-trail/README.md`, *Threat model and limits*).

**Kategorisierung.** aqt-trail und `aqt_evidence` sind **Kategorie 5 (kundenspezifische Software)**: eigener Code ohne Markthistorie und Anwenderbasis; die Funktion entsteht durch Code (Writer, Kettenprüfung, eigener DER-Parser für Token), nicht durch Konfiguration (`trail.toml` ändert nur Pfade und Schwellen). Daher voller Lebenszyklus mit Spezifikation, Code-Review und Tests; die Testtiefe je Funktion folgt der Risikoanalyse. Python, Linux (`SO_PEERCRED`, `/proc`, `flock`, `fsync`) und die Bibliothek `cryptography` sind Kategorie 1 (Infrastruktur): Versionen festhalten, indirekt mitgeprüft.

**GxP-Relevanz.** Im GMP-Einsatz hielte der Trail: Handlungen von KI-Coding-Agenten an GxP-relevanter Software (`trail.import`, Hash und kurzer Auszug); menschliche Entscheidungen mit Bedeutung und Begründung, auch von anderen AQT-Werkzeugen (z. B. `signoff.signature`); abgewiesene Versuche (`trail.refused`); Start, Stopp, Zeitsprünge, Lücken; Zeitanker und Audit-Trail-Reviews (Annex 11 (2011) §9, 21 CFR 11.10(e), EU-GMP Kap. 4 (Entwurf 2025) 4.24). Bewertung: GxP-relevant; hohe Auswirkung auf die Datenintegrität, indirekte auf die Produktqualität (eine unerkannte Fälschung könnte eine nicht autorisierte Änderung an GxP-Software verdecken).

**Zweckbestimmung.** aqt-trail zeichnet auf einem Linux-Arbeitsplatzrechner die Arbeit von KI-Coding-Agenten und zugehörige menschliche Entscheidungen manipulationserkennend auf; ein unbeteiligter Prüfer stellt mit `verify` fest, ob die Aufzeichnungen unverändert und vollständig sind, und kann eine prüfbare Kopie weitergeben. Nicht Zweck: Schutz vor Eigentümer oder root, Authentifizierung von Personen, Erfassung von Ereignissen, die den Writer nie erreichen.

## 3. Anforderungen (URS)

Begründung mit Katalog-IDs aus `aqt-spec/crosswalk.md`.

| ID | Anforderung | Begründung |
|---|---|---|
| URS-01 | Der Writer setzt Zeit und laufende Nummer (`chain.seq`) selbst; die Client-Zeit bleibt als `observed.client_time` erhalten. Rückwärtssprünge der Uhr und Abweichungen der Wanduhr von der monotonen Uhr über 2 s werden als `clock.jump` aufgezeichnet. | `alcoa:contemporaneous`, `alcoa:consistent`, `annex11-2025d:12.2`, `annex11-2025d:12.3`, `part11:11.10(e)` |
| URS-02 | Der Writer erfasst den beobachteten Absender (pid, uid, gid aus `SO_PEERCRED`, Prozesskette, Agentenumgebung) getrennt von der behaupteten Identität (`actor`) und speichert beides. | `alcoa:attributable`, `annex11-2011:12.4`, `part11:11.10(h)` |
| URS-03 | Abgewiesen und als `trail.refused` aufgezeichnet werden: writer-eigene Felder (`sig`, `chain`, `observed`), ungültige Datensätze, menschliche Entscheidungen ohne Begründung, nicht zugelassene uids, abweichender Inhalt unter bekannter ID. Identische Wiederholung erzeugt kein Duplikat. | `annex11-2025d:12.3`, `annex11-2025d:12.2`, `annex11-2011:12.1`, `part11:11.10(g)` |
| URS-04 | Jeder Datensatz wird verkettet (SHA-256), mit dem Ed25519-Schlüssel des Writers signiert, als kanonische Zeile angehängt und mit `fsync` gesichert; nur ein Writer je Trail. Eine beim Absturz unvollständige letzte Zeile wird beim Start entfernt und als `log.repaired` aufgezeichnet; ein nicht mehr verkettetes Log wird nicht fortgeschrieben. | `alcoa:original`, `annex11-2011:9`, `annex11-2025d:12.3`, `part11:11.10(e)` |
| URS-05 | `verify` erkennt Änderung, Einfügen, Löschen, Umordnen und gefälschte Signaturen, nennt den ersten betroffenen Datensatz („broken from seq N“) und endet mit Exit 1. | `part11:11.10(a)`, `alcoa:accurate`, `alcoa:original`, `annex11-2011:7.1` |
| URS-06 | Signierte Checkpoints werden gespeichert und können außerhalb abgelegt werden (`head --export`); `verify` erkennt damit Abschneiden und Rollback. | `alcoa:complete`, `part11:11.10(c)`, `annex11-2025d:12.3` |
| URS-07 | Eine vollständige Neuschreibung wird mit unabhängig aufbewahrtem öffentlichem Schlüssel (`--pin-key`) oder externen Kopfkopien erkannt; ohne Pinning warnt `verify`. | `alcoa:enduring`, `annex11-2025d:12.3`, `part11:11.10(c)` |
| URS-08 | Ein RFC-3161-Zeitstempel über den Kopf wird als `trail.anchor` gespeichert; `verify` prüft Imprint, Signatur, `timeStamping`-Verwendung und Kette zur konfigurierten CA und lehnt abweichende oder nicht vertrauenswürdige Token ab. | `annex11-2025d:13.2`, `part11:11.30`, `alcoa:enduring` |
| URS-09 | Bei Ausfall spoolen Clients; der Writer schreibt danach `trail.gap` und die Datensätze mit `via: spool` ohne beobachteten Absender. Start und Stopp werden aufgezeichnet. | `alcoa:complete`, `alcoa:contemporaneous`, `part11:11.10(e)` |
| URS-10 | `export` erzeugt ein vollständiges Bundle (Log, Checkpoints, öffentliche Schlüssel, TSA-CA, `MANIFEST.json` mit SHA-256 je Datei, Prüfanleitung), das `verify --bundle` anderswo prüft; Änderungen werden erkannt. | `annex11-2025d:12.9`, `annex11-2025d:16`, `annex11-2011:17`, `part11:11.10(b)`, `alcoa:available` |

## 4. Risikoanalyse (FMEA)

### 4.1 Skalen

| Wert | S – Schwere | O – Auftreten | D – Entdeckung |
|---|---|---|---|
| 1 | keine Auswirkung auf Datenintegrität | praktisch ausgeschlossen (nur mit root) | `verify` erkennt automatisch und sicher |
| 2 | nur Metadaten betroffen | unwahrscheinlich (gezielter Angriff mit Systemkenntnis) | automatisch, wenn eine Voraussetzung erfüllt ist (gepinnter Schlüssel, externe Kopfkopie, CA) |
| 3 | Zuordnung oder Zeit unsicher, im Review erkennbar | möglich (Agent mit Benutzerrechten, z. B. nach Prompt-Injection) | nur im Review oder durch manuellen Vergleich |
| 4 | GMP-Aufzeichnung unvollständig oder falsch zugeordnet | wahrscheinlich (Bedien- oder Konfigurationsfehler) | nur mit Aufzeichnungen außerhalb, die oft fehlen |
| 5 | GMP-Aufzeichnung unerkannt verfälscht oder verloren | häufig | nicht erkennbar |

RPZ = S × O × D; **hoch** ≥ 40, **mittel** 16–39, **niedrig** ≤ 15. Ein D-Wert, der auf einer Kontrolle von aqt-trail beruht, gilt erst nach bestandenem Testfall.

### 4.2 Fehlermodi, Kontrollen und Restrisiken

| ID | Fehlermodus · Ursache · Auswirkung | S·O·D = RPZ | Technische Kontrolle (Test) | Restrisiko · verfahrensbezogene Maßnahme |
|---|---|---|---|---|
| R-01 | Datensatz geändert, eingefügt, gelöscht, umgeordnet, Signatur gefälscht · Agent bearbeitet `trail.jsonl` (im Benutzermodus beschreibbar) · verfälschte Entscheidungsgrundlage | 5·3·1 = 15 niedrig | Kette, Signatur, erste betroffene seq (TC-07, TC-08) | unbemerkt bis zur nächsten Prüfung · `verify` in festem Intervall; separater Benutzer |
| R-02 | Log abgeschnitten oder zurückgesetzt · wie R-01, alte Kopie zurückgespielt · jüngste Datensätze fehlen | 5·3·2 = 30 mittel | Checkpoints, `head --export`, `--heads` (TC-05, TC-06, TC-09) | ohne Kopie außerhalb keine Erkennung · Kopfkopien regelmäßig auf ein anderes Gerät |
| R-03 | Log unter neuem Schlüssel neu geschrieben · Log und öffentliche Schlüssel ersetzt · gefälschte Historie | 5·2·2 = 20 mittel | `--pin-key`, externe Köpfe (TC-10) | ohne Pinning nur Warnung · öffentlichen Schlüssel unabhängig (QMS) ablegen, stets pinnen |
| R-04 | Log mit echtem Service-Schlüssel neu geschrieben (Schlüsselverwahrung) · `keys/service.key` unverschlüsselt (unbeaufsichtigter Start) und im Benutzermodus lesbar, Anker mit entfernt · Fälschung besteht die gepinnte Prüfung | 5·2·4 = 40 hoch | nur Kopien außerhalb (TC-11, Grenztest) | **akzeptiert:** stimmige Fälschung möglich; Token liegen nur im Trail · separater Benutzer; Kopien außerhalb; Schlüsselverwahrung regeln (Schlüsselwechsel in 0.1 nicht implementiert) |
| R-05 | Falsche Writer-Zeit · Uhr verstellt oder nicht synchronisiert, Vorstellen bei gestopptem Writer, Drift unter Schwelle · falsche Zeit und Reihenfolge | 4·2·3 = 24 mittel | `clock.jump` (TC-04); genTime der TSA | **akzeptiert:** Vorstellen bei gestopptem Writer, Drift, falsche Zeit schon beim Start · NTP überwachen; regelmäßige Anker; Review auf Zeitanomalien |
| R-06 | Writer-eigene Felder gesetzt oder fremde Identität behauptet · präparierte Datensätze, z. B. `actor: human:…` · gefälschte Zuordnung | 4·3·3 = 36 mittel | Abweisung mit `trail.refused` (TC-02); Behauptung und Beobachtung gespeichert (TC-01) | keine Personen-Authentifizierung · Audit-Trail-Review (`attribution_mismatch`, eigene Validierung); persönliche Kennungen |
| R-07 | Gespoolte Datensätze unbeobachtet, Spool fälschbar · Writer gestoppt, Agent schreibt in den Spool · untergeschobene Datensätze | 4·3·3 = 36 mittel | `trail.gap`, `via: spool`, Start/Stopp (TC-03) | **akzeptiert:** Herkunft nicht prüfbar · Writer als Dienst mit Neustart; Spool-Datensätze im Review klären |
| R-08 | Ereignis erreicht den Writer nie · Hook deaktiviert, `AQT_SINK` fehlt, Writer umgangen · Lücke ohne Hinweis | 5·3·5 = 75 hoch | keine | **akzeptiert:** mit dem Trail allein nicht erkennbar · Hook-/Sink-Konfiguration unter Änderungskontrolle; Abgleich mit Sitzungsimporten; periodische Überprüfung |
| R-09 | Token ungültig, verändert, fremde TSA, widerrufenes Zertifikat · falscher Digest, falsche CA, keine Sperrprüfung · falscher Zeitnachweis | 4·2·2 = 16 mittel | Imprint, Signatur, EKU, CA-Kette, Nonce (TC-05) | **akzeptiert:** keine Sperrprüfung, echte TSA ungetestet · TSA auswählen (ggf. qualifiziert); CA kontrolliert ablegen |
| R-10 | Exportkopie verändert oder unvollständig · Übertragung, Manipulation des Archivs · Kopie nicht vertrauenswürdig | 4·2·1 = 8 niedrig | `MANIFEST.json`, `verify --bundle` (TC-12) | neu erzeugtes Bundle nur mit Pinning/Kopfkopie erkennbar · Bundles gepinnt prüfen; Wiederherstellungstest |
| R-11 | Fehler in Writer oder Prüflogik („intact“ trotz Manipulation, Absturz zerstört Log) · kundenspezifischer Code ohne unabhängiges Code- und Security-Review (`SECURITY.md`) · Kontrolle versagt unbemerkt | 5·2·3 = 30 mittel | Tests, Spezifikations-Testvektoren, OpenSSL- und `aqt-evidence`-Gegenprüfung (TC-03, TC-05–TC-12) | kein unabhängiges Code-Review · Code-Review bzw. Lieferantenbewertung; Regressionstests |

R-06 ist nach dem ungünstigeren Teil bewertet: Writer-Felder werden abgewiesen (D = 1), eine falsche Identität wird nur gespeichert und im Review sichtbar (D = 3).

## 5. Teststrategie und Akzeptanzkriterien

### 5.1 Testtiefe und Testarten

**Testtiefe (risikobasiert):** Klasse hoch mit technischer Kontrolle sowie S = 5 mit D aus aqt-trail (R-01–R-04, R-11): automatisiert **und** manuell am laufenden Writer, positiv und negativ, jede Manipulationsart einzeln, mit unabhängiger Gegenprüfung. Mittel (R-05, R-06, R-07, R-09): automatisiert plus manueller Hauptpfad. Niedrig (R-10): automatisiert plus manuelle Bestätigung. Ohne technische Kontrolle (R-08): kein Test. Es handelt sich um funktionale Prüfungen auf OQ-Ebene; IQ und PQ sind nicht Teil der Übung.

- **Automatisiert:** pytest-Suiten von aqt-trail und (Kette, Testvektoren) aqt-spec. Eignung (Annex 11 §4.7): alle referenzierten Tests gelesen; jeder prüft das Ergebnis direkt (`first_bad_seq`, Fehlercode, Record-Typ). Ersetzt werden nur Uhr, Peer-Credentials, `/proc` und TSA-Transport in den jeweils dafür gebauten Tests, nie die Prüflogik.
- **Manuell:** Kommandozeile gegen einen echten Writer mit echtem Unix-Socket; Manipulationen mit einem Hilfsskript (Anhang A), stets an **Kopien**.
- **Unabhängig:** `openssl ts -verify`; `aqt-evidence verify/conform` (nur aqt-spec); 57 Testvektoren der Spezifikation.

### 5.2 Testumgebung

Linux-Arbeitsplatz des Autors (Ubuntu 24.04.5 LTS, Kernel 7.0.0-31-generic, OpenSSL 3.0.13); Python 3.13 in `aqt-trail/.venv` bzw. `aqt-spec/.venv` (editierbare Installation aus dem Repository); Commit `eb920b1`, Arbeitsverzeichnis ohne lokale Änderungen; TSA nur `test:` (offline). Ausführender ist ein KI-Agent (Claude Code), alle Clients laufen also unterhalb eines Agentenprozesses; für TC-01 ist das beabsichtigt. Isolation (echte `~/.config/aqt` und `~/.local/state/aqt` werden vorher und nachher geprüft):

```sh
export R=<Repository> V=/tmp/aqtval          # kurzer Pfad: AF_UNIX erlaubt etwa 104 Byte
export HOME=$V/home XDG_STATE_HOME=$V/state XDG_CONFIG_HOME=$V/config XDG_RUNTIME_DIR=$V/run TMPDIR=$V/tmp
unset AQT_SINK AQT_TRAIL_STATE AQT_EVIDENCE AQT_ACTOR AQT_SIGNERS AQT_KEYS_DIR
export PATH=$R/aqt-trail/.venv/bin:$PATH S=$XDG_STATE_HOME/aqt/trail     # S: Zustand des Trails
P=$V/ext/pinned.pub H=$V/ext/heads.jsonl M="python $V/manip.py"          # $V/ext: "anderes Gerät"
```

### 5.3 Akzeptanzkriterien (vor der Durchführung festgelegt)

| ID | Kriterium |
|---|---|
| AK-1 | Jeder referenzierte automatisierte Test endet mit „passed“ („skipped“ gilt ohne bewertete Abweichung als nicht erfüllt). |
| AK-2 | Jeder manuelle Schritt liefert das erwartete Ergebnis, einschließlich Exit-Code und gemeldeter seq bzw. Problemmeldung. |
| AK-3 | Jede Manipulation im Geltungsbereich wird erkannt, wenn die genannten Voraussetzungen (Pinning, Kopfkopie, CA) erfüllt sind; TC-11 ist bestanden, wenn sich genau die dokumentierte Grenze zeigt. |
| AK-4 | `~/.config/aqt` und `~/.local/state/aqt` existieren nach der Durchführung weiterhin nicht. |
| AK-5 | Erfolgreich, wenn AK-1 bis AK-4 erfüllt sind oder jede Abweichung bewertet ist und keine URS beeinträchtigt. |

## 6. Testfälle

Die Testfälle bauen nacheinander einen Trail auf; TC-07 bis TC-12 arbeiten an Kopien. Vorbedingung ist jeweils der vorige Testfall, sofern nicht anders angegeben. `N` ist die seq von `val.record-b`; „Spez.“ meint `aqt-spec/spec/evidence-records-0.1.md`.

### 6.1 Ziel, Schritte, erwartetes Ergebnis, Akzeptanz

| TC (Bezug) | Ziel · Vorbedingung · Schritte | Erwartetes Ergebnis · Akzeptanz |
|---|---|---|
| **TC-01** Writer-Felder und beobachteter Absender (URS-01, URS-02; R-06) | Writer setzt Zeit und seq, bewahrt die Client-Zeit, erfasst den Absender getrennt. Vorbed.: `aqt-trail init --log-id trail_val`; `aqt-trail serve &`. 1. `stat -c %a $S/keys/service.key $XDG_RUNTIME_DIR/aqt/trail.sock` 2. `$M record old-time \| aqt-trail append -` (behauptet `human:val-tester`, Client-Zeit 2020-01-01) 3. `aqt-trail show 1` | 1: `600`, `600`. 2: „stored 1“. 3: seq 1; `time` = Writer-Zeit; `client_time` 2020-01-01T00:00:00.000000Z; uid/gid des Ausführenden, pid gesetzt, `via` socket, `process_chain` nicht leer; `harness` nennt den ausführenden Agenten, `actor.id` bleibt `human:val-tester`. **AK-1, AK-2** |
| **TC-02** Abweisung und Aufzeichnung (URS-03; R-06) | Writer-Felder, Entscheidung ohne Begründung und fremder Inhalt unter bekannter ID werden abgewiesen und aufgezeichnet; Wiederholung erzeugt kein Duplikat. 1. `$M record chain \| aqt-trail append -`, ebenso `observed`, `sig $V/w/client.key`, `no-reason` 2. `$M record base > $V/w/r.json`; zweimal `aqt-trail append $V/w/r.json`; `$M record changed $V/w/r.json \| aqt-trail append -` 3. `aqt-trail list --type trail.refused` | 1: je Exit 1, „invalid_record“ mit Feldname bzw. „needs a reason“. 2: zweimal Exit 0, ein `val.base` im Trail; dann Exit 1, `duplicate_id`. 3: fünf `trail.refused` mit `reason_code`, Akteur `human:val-tester`. **AK-1, AK-2** |
| **TC-03** Ausfall, Spool, Lückenmarker, Absturz (URS-04, URS-09; R-07, R-11) | Ausfall, gespoolte Datensätze und eine unvollständige letzte Zeile werden sichtbar; das Log bleibt prüfbar. 1. Writer mit SIGTERM stoppen 2. `aqt-trail event --action val.while-down --actor human:val-tester --reason "TC-03"` 3. `printf '{"partial": ' >> $S/trail.jsonl` (simulierter Absturz) 4. Writer starten; `aqt-trail list`; `aqt-trail show <seq>` 5. `aqt-trail drain`; `aqt-trail verify` | 2: „… spooled“. 4: `service.stop`, `log.repaired` (`removed_bytes` 12), `service.start`, `trail.gap` (`count` 1), `val.while-down` mit `via` spool ohne pid/uid/gid. 5: „spool is empty“; „intact“, Exit 0. **AK-1, AK-2** |
| **TC-04** Zeitsprünge (URS-01; R-05) | Rückwärts- und Vorwärtssprünge erzeugen `clock.jump`. Vorbed.: eigenes Zustandsverzeichnis; die Systemuhr bleibt unverändert, beide Uhren werden über die Python-API simuliert (Anhang A). 1. `python $V/clock.py $V/w/clock` (Wanduhr +1 h, monotone Uhr +1 s vor dem dritten Datensatz) 2. `aqt-trail --state $V/w/clock verify` | 1: `val.a`, `val.b`, `clock.jump` (forward, `wall_elapsed_ms` 3600000, `monotonic_elapsed_ms` 1000), `val.c`. 2: „intact: 4 records“, Exit 0. **AK-1, AK-2** |
| **TC-05** Checkpoint und RFC-3161-Anker, TEST-TSA (URS-06, URS-08; R-02, R-09) | Kopf wird signiert und verankert; `verify` und OpenSSL prüfen das Token; falsche Token werden abgelehnt. Vorbed.: TC-03 plus Ereignisse `val.record-a`, `-b`, `-c` (`aqt-trail event …`). 1. `aqt-trail checkpoint --anchor --tsa test:` 2. `aqt-trail --json verify --test-tsa` 3. `aqt-trail verify` (ohne CA) 4. Token aus `trail.anchor` extrahieren (wie `aqt-trail/docs/usage.md`); `openssl ts -verify -digest <Kopf-Hash> -in token.der -token_in -CAfile $S/test-tsa/ca.pem` 5. wie 4 mit fremdem Digest | 1: Checkpoint und Anker mit genTime. 2: `ok` true, `anchors` 1, `anchors_verified` 1, Exit 0. 3: „intact“ mit Warnung „TSA certificate chain not checked (no --tsa-ca)“. 4: „Verification: OK“. 5: „Verification: FAILED“. **AK-1, AK-2** |
| **TC-06** Intakter Trail, Kopfkopie, Konformität L3 (URS-04, URS-06, URS-07; R-01, R-02, R-11) | Unveränderter Trail ist intakt; Kopfkopie und öffentlicher Schlüssel liegen außerhalb; aqt-spec allein bestätigt L3. 1. `aqt-trail head --export > $H`; `cp $S/keys/service.key.pub $P` 2. `aqt-trail verify --pin-key $P --heads $H --test-tsa` 3. `aqt-evidence conform $S/trail.jsonl --level 3 --key $P --checkpoint $H` 4. `aqt-evidence vectors` | 2: „intact“, keine Probleme, Exit 0. 3: „L3 reached (target L3)“. 4: „57 of 57 vectors agree“. **AK-1, AK-2** |
| **TC-07** Geänderter Datensatz, gefälschte Signatur (URS-05; R-01) | Änderung und gefälschte Signatur werden am betroffenen Datensatz erkannt. 1. `$M edit $S/trail.jsonl $V/w/edit.jsonl N`; `aqt-trail verify --trail $V/w/edit.jsonl --pin-key $P` 2. `aqt-evidence verify $V/w/edit.jsonl` (nur Kette) 3. `$M sig $S/trail.jsonl $V/w/sig.jsonl N`; verify wie 1 | 1: „broken from seq N: invalid signature“, Exit 1. 2: „broken from seq N+1: prev does not match …“ (die Kette allein erkennt die Änderung erst am Folgedatensatz, Spez. §7). 3: wie 1. **AK-1 bis AK-3** |
| **TC-08** Löschen, Einfügen, Umordnen (URS-05; R-01) | Jede Manipulation wird mit der ersten betroffenen seq gemeldet. Vorbed.: TC-06. `$M delete\|insert\|swap $S/trail.jsonl $V/w/<op>.jsonl N`; je `aqt-trail verify --trail $V/w/<op>.jsonl --pin-key $P` | delete: „broken from seq N: expected seq N, found N+1“; insert (Kopie von N-1 vor N): „… found N-1“; swap (N, N+1): „… found N+1“; je Exit 1. **AK-1 bis AK-3** |
| **TC-09** Abschneiden und Rollback (URS-06; R-02) | Abschneiden wird mit Checkpoints und Kopfkopie erkannt; ohne sie zeigt sich die Grenze der Kette. Vorbed.: TC-06. 1. `cp -a $S $V/w/s-trunc`; `$M truncate $S/trail.jsonl $V/w/s-trunc/trail.jsonl N`; `rm $V/w/s-trunc/checkpoints.jsonl` 2. `aqt-trail --state $V/w/s-trunc verify --pin-key $P` 3. wie 2 mit `--heads $H` 4. `aqt-trail verify --trail $V/w/s-trunc/trail.jsonl --pin-key $P` (Checkpoints des Originals) | 2: „intact: N records“, Exit 0 (Grenze, Spez. §7). 3: „external head at seq … is beyond the head: the trail was truncated“, Exit 1. 4: „checkpoint at seq … is beyond the head …“, Exit 1. **AK-1 bis AK-3** |
| **TC-10** Neuschreibung unter neuem Schlüssel (URS-07; R-03) | Neuschreibung mit eigenem Schlüssel wird mit Pinning und Kopfkopie erkannt. Vorbed.: TC-06; Kopie `$V/w/s-newkey`; `aqt-evidence keygen $V/w/evil.key`. 1. `$M rewrite $S/trail.jsonl $V/w/s-newkey/trail.jsonl $V/w/evil.key N`; öffentliche Schlüssel der Kopie durch `evil.key.pub` ersetzen, `checkpoints.jsonl` löschen 2. `aqt-trail --state $V/w/s-newkey verify` 3. wie 2 mit `--pin-key $P` 4. wie 2 mit `--heads $H` | 2: „intact“ mit Warnung „service key not pinned …“, Exit 0 (Grenze). 3: „broken from seq 0: no valid signature from a known key“, Exit 1. 4: Problem „external head at seq …“, Exit 1. **AK-1 bis AK-3** |
| **TC-11** Grenztest: Neuschreibung mit dem echten Service-Schlüssel (URS-07; R-04) | Nachweis der Grenze aus R-04: Mit lesbarem Service-Schlüssel entsteht eine Fälschung, die die gepinnte Prüfung besteht; nur Aufzeichnungen außerhalb erkennen sie. Vorbed.: TC-06; Kopien `$V/w/s-samekey`, `$V/w/s-keep` ohne `checkpoints.jsonl`. 1. `$M rewrite $S/trail.jsonl $V/w/s-samekey/trail.jsonl $S/keys/service.key N` 2. `aqt-trail --state $V/w/s-samekey verify --pin-key $P --test-tsa` 3. wie 2 mit `--heads $H` 4. Variante mit belassenen Ankern (`$M rewrite-keep` nach `$V/w/s-keep`), verify wie 2 | 2: „intact“, Exit 0 – **Fälschung nicht erkannt** (erwartete Grenze). 3: Problem „external head at seq …“, Exit 1. 4: „anchor checkpoint at seq … does not match the record: the trail was rewritten“, Exit 1. **Genau diese Ergebnisse (AK-2, AK-3)** |
| **TC-12** Export-Bundle (URS-10; R-10) | Bundle ist vollständig, anderswo prüfbar, Änderungen werden erkannt. Vorbed.: TC-06. 1. `aqt-trail export --out $V/ext/bundle`; `cp -a $V/ext/bundle $V/w/bundle-copy` 2. `aqt-trail --json verify --bundle $V/w/bundle-copy --pin-key $P --heads $H` 3. `aqt-evidence verify $V/w/bundle-copy/trail.jsonl --key $P --require-signature` (nur aqt-spec, wie `VERIFY.md`) 4. `$M edit` an der Bundle-Kopie (seq N); `aqt-trail verify --bundle $V/w/bundle-copy` | 1: `trail.jsonl`, `checkpoints.jsonl`, `keys/service.key.pub`, `tsa-ca.TEST-ONLY.pem`, `VERIFY.md`, `MANIFEST.json`. 2: `ok` true, `anchors_verified` 1, Exit 0. 3: „intact“. 4: „trail.jsonl does not match MANIFEST.json“, Exit 1. **AK-1 bis AK-3** |

### 6.2 Grundlage: automatisierte Tests

Pfade relativ zu `aqt-trail/tests/`, sofern nicht `aqt-spec/tests/` genannt ist; Vektoren in `aqt-spec/vectors/`.

| TC | Bestehende automatisierte Tests |
|---|---|
| TC-01 | `test_writer.py::test_append_sets_writer_fields`; `test_server.py::test_socket_append_observes_the_peer`, `::test_process_chain_and_harness_from_fake_proc`, `::test_attribution_mismatch_is_recorded_not_blocked`, `::test_aqt_evidence_socket_sink_is_compatible` |
| TC-02 | `test_writer.py::test_writer_fields_are_refused_and_logged` (2 Parameter), `::test_client_signature_is_refused`, `::test_human_decision_needs_reason`, `::test_idempotent_by_id_and_duplicate_id`; `test_server.py::test_refusal_codes_over_the_socket`, `::test_unauthorized_uid` (fremde uid nur automatisiert) |
| TC-03 | `test_server.py::test_client_spools_when_writer_is_down_then_drain_on_start`, `::test_drain_op_over_socket`, `::test_resent_record_after_spool_is_not_duplicated`, `::test_second_server_on_same_socket_is_refused`; `test_writer.py::test_drain_writes_gap_then_spooled_records`, `::test_torn_last_line_is_repaired_and_recorded`, `::test_writer_refuses_to_continue_a_broken_log`, `::test_single_writer_lock` |
| TC-04 | `test_writer.py::test_clock_jump_backwards_is_recorded` (nur rückwärts; vorwärts nur manuell) |
| TC-05 | `test_tsa.py::test_token_verifies`, `::test_wrong_digest_untrusted_ca_and_tampering`, `::test_certificate_without_timestamping_usage_is_rejected`, `::test_nonce_mismatch_is_rejected`, `::test_refused_status`, `::test_openssl_accepts_our_tokens`, `::test_anchor_record_in_trail_verifies` |
| TC-06 | `test_tamper.py::test_intact`; `test_writer.py::test_stored_records_are_canonical_lines`; `test_cli.py::test_end_to_end` (mit L3-Prüfung); `aqt-spec/tests/test_vectors.py::test_library_agrees` (57 Vektoren); `aqt-spec/tests/test_evidence.py::test_chain_detects_edit_insert_delete_reorder`, `::test_checkpoint_detects_truncation_and_rewrite` |
| TC-07 | `test_tamper.py::test_edit_is_detected`, `::test_forged_signature_is_detected`, `::test_wrong_key_is_detected`, `::test_garbage_line_is_reported_with_position`; Vektoren `tampered/edited-signed.json`, `tampered/edited-unsigned.json` |
| TC-08 | `test_tamper.py::test_delete_is_detected`, `::test_insert_is_detected`, `::test_reorder_is_detected`; Vektoren `tampered/deleted.json`, `tampered/inserted.json`, `tampered/reordered.json` |
| TC-09 | `test_tamper.py::test_truncation_is_detected_by_checkpoint_and_heads`; `test_server.py::test_head_and_checkpoint_ops`; Vektoren `tampered/truncated.json`, `signed/checkpoint-truncated.json` |
| TC-10 | `test_tamper.py::test_full_rewrite_is_detected_by_pinned_key_and_external_heads`; Vektor `tampered/rewritten-fresh-key.json` |
| TC-11 | keiner; nur manuell |
| TC-12 | `test_alcoa_export.py::test_export_bundle_verifies_and_detects_tampering`; `test_cli.py::test_end_to_end` |

## 7. Testdurchführung und Ergebnisse

### 7.1 Angaben

| | |
|---|---|
| Datum, Zeit | 2026-10-22, 21:00–21:02 MESZ |
| Durchführung | KI-Agent im Auftrag des Autors; Review: Benedikt Neumayer, ausstehend |
| Umgebung | Ubuntu 24.04.5 LTS, Kernel 7.0.0-31-generic; Python 3.13.13; pytest 9.1.1; cryptography 50.0.2; OpenSSL 3.0.13 |
| Software-Stand | Commit `eb920b1`; gesamtes Arbeitsverzeichnis vorher und nachher ohne lokale Änderungen (`git status` leer) |
| Änderung gegenüber `917db6e` | `aqt-trail/src/`: 9 Dateien, zusammen 12 geänderte Zeilen, nur Kommentare und Docstrings; `aqt-trail/tests/`, `aqt-spec/src/`, `aqt-spec/vectors/`, `spec/`, `schemas/` unverändert; Katalogtexte überarbeitet, drei Annex-22-Einträge ergänzt (`annex22-2025d:3`, `:4`, `:7`; nicht zitiert); interne Entwurfsdateien aus dem Repository entfernt (hier nie zitiert). Alle Referenzen dieses Dokuments wurden erneut geprüft. |
| Isolation | wie 5.2; `~/.config/aqt` und `~/.local/state/aqt` fehlten vorher und nachher (**AK-4 erfüllt**) |
| Rohdaten | `/tmp/aqtval/log/TC-xx.txt` (Konsole), `/tmp/aqtval/results/` (pytest, JUnit-XML); Erstdurchführung auf `917db6e` in `/tmp/aqtval/run-917db6e/`; temporär (O-4) |

### 7.2 Automatisierte Tests

| Suite | Ergebnis |
|---|---|
| aqt-trail, vollständig: `python -m pytest -p no:cacheprovider -v -rA` (21:00:52) | **70 passed**, 0 failed, 0 skipped |
| aqt-spec: `test_vectors.py::test_library_agrees` und die zwei `test_evidence.py`-Tests aus TC-06 (21:00:54) | **59 passed** (57 Vektoren + 2) |

Kapitel 6 referenziert 44 Testfunktionen (41 aqt-trail, 3 aqt-spec) mit 101 Instanzen; ein Skript hat jede Referenz gegen die pytest-Ausgabe abgeglichen: alle vorhanden, alle „passed“ (**AK-1 erfüllt**). Präzisierung zu 5.1: `test_writer.py` und `test_tamper.py` übergeben ein festes `observed` (`observed_stub`); die echte Beobachtung prüfen die Server-Tests und TC-01. `test_cli.py::test_end_to_end` ersetzt zusätzlich Agentenprüfung und Passphrase, nur für das Signieren des Reviews (nicht Prüfgegenstand).

### 7.3 Ergebnisse je Testfall auf `eb920b1` (N = 14; Ausgaben wörtlich, Hashes gekürzt)

| TC | Zeit | Ist-Ergebnis | Bewertung |
|---|---|---|---|
| 01 | 21:01:00 | `600`, `600`; „stored 1, spooled 0, refused 0“; seq 1: `time` 2026-10-22T19:01:00.771776Z, `client_time` 2020-01-01T00:00:00.000000Z, uid/gid 1000, `via` socket, `process_chain` aqt-trail ← bash ← claude ← … ← systemd, `harness` claude-code, `actor.id` human:val-tester | bestanden |
| 02 | 21:01:05 | „invalid_record: writer-owned field(s) set by the client: chain“ (ebenso observed, sig); „… a human decision (meaning set) needs a reason“; je Exit 1. `val.base` zweimal Exit 0, einmal im Trail (seq 6); dann „duplicate_id: a different record with id … is already stored“, Exit 1. Fünf `trail.refused` (seq 2–5, 7), Akteur human:val-tester | bestanden |
| 03 | 21:01:13 | „rec_… spooled“; seq 8 `service.stop`, 9 `log.repaired` (`removed_bytes` 12), 10 `service.start`, 11 `trail.gap` (`count` 1), 12 `val.while-down` mit `observed` {`via` spool, `process_chain` [], `harness` null, `client_time`}; „spool is empty“; „intact: 13 records“, Exit 0 | bestanden |
| 04 | 21:01:22 | `val.a`, `val.b`, `clock.jump` {forward, 3600000 ms Wanduhr, 1000 ms monoton}, `val.c`; „intact: 4 records“, Exit 0 | bestanden |
| 05 | 21:01:22 | „checkpoint seq 15 …“, „anchor rec_… (RFC 3161 2026-10-22T19:01:22.878801Z)“; `ok` true, `anchors` 1, `anchors_verified` 1, Exit 0; ohne CA Warnung „anchor seq 16: TSA certificate chain not checked (no --tsa-ca)“; OpenSSL „Verification: OK“; fremder Digest „message imprint mismatch … Verification: FAILED“ | bestanden |
| 06 | 21:01:28 | Kopf seq 16 exportiert; „intact: 18 records, head seq 17“, `checkpoints` 2, `heads` 1, `anchors_verified` 1, keine Probleme, Exit 0; „L3 reached (target L3), 18 records“; „57 of 57 vectors agree“ | bestanden |
| 07 | 21:01:35 | „broken from seq 14: invalid signature“, Exit 1; nur Kette „broken from seq 15: prev does not match the previous record hash“; Signatur „broken from seq 14: invalid signature“, Exit 1; Original weiter „intact“ | bestanden |
| 08 | 21:01:35 | „broken from seq 14: expected seq 14, found 15“ / „… found 13“ / „… found 15“; je Exit 1 | bestanden |
| 09 | 21:01:35 | ohne Checkpoints „intact: 14 records“, Exit 0; `--heads` „external head at seq 16 is beyond the head: the trail was truncated“, Exit 1; Original-Checkpoints „checkpoint at seq 15 …“, „… seq 16 … truncated“, Exit 1 | bestanden |
| 10 | 21:01:45 | ohne Pinning „intact: 16 records“ + „warning: service key not pinned …“, Exit 0; `--pin-key` „broken from seq 0: no valid signature from a known key“, Exit 1; `--heads` „external head at seq 16: signature invalid or key unknown“, Exit 1 | bestanden |
| 11 | 21:01:46 | `--pin-key --test-tsa` „intact: 16 records“, Exit 0, seq 14 mit „nachträglich geändert“ – **nicht erkannt**, wie erwartet; `--heads` „external head at seq 16 is beyond the head: the trail was truncated“, Exit 1; mit Ankern „anchor checkpoint at seq 15 does not match the record: the trail was rewritten“, Exit 1 | bestanden (Grenze bestätigt) |
| 12 | 21:01:46 | sechs erwartete Dateien (`head_seq` 17); `ok` true, `heads` 1, `anchors_verified` 1, Exit 0; `aqt-evidence` „intact: 18 records“; nach Änderung „broken from seq 14: invalid signature“, „trail.jsonl does not match MANIFEST.json“, „the trail head differs from MANIFEST.json“, Exit 1 | bestanden |

Abschluss 21:01:50: Writer beendet (`service.stop`, seq 18); Original-Trail mit Pinning, Kopfkopie und TEST-CA „intact: 19 records“. **AK-2 und AK-3 erfüllt.** Die Erstdurchführung auf `917db6e` (19:54–19:57 MESZ) ergab in allen 12 Testfällen dieselben Meldungen, Exit-Codes und seq-Nummern; abweichend waren nur Zeiten, Schlüssel-IDs und Hashes.

### 7.4 Abweichungen

| Nr. | Beschreibung | Bewertung | Entscheidung |
|---|---|---|---|
| A-01 | Kapitel 1–6 wurden vor der Erstdurchführung festgelegt, aber weder vor ihr noch vor der Wiederholung geprüft und freigegeben. | formal; real sind freigegebene Pläne vor der Durchführung nötig (`annex11-2025d:9.4`); Ergebnisse unberührt | für die Übung akzeptiert; Review nachholen (O-1) |
| A-02 | Bei der Erstdurchführung auf `917db6e` enthielt `aqt-spec/` nicht committete, fremde Textänderungen (`catalogues/`, `crosswalk.md`), obwohl 5.2 ein unverändertes Arbeitsverzeichnis forderte. | damals bewertet ohne Auswirkung (aqt-trail liest die Kataloge nicht). Die Änderungen sind in `eb920b1` committet; die Wiederholung lief auf sauberem Arbeitsverzeichnis. | **geschlossen** durch die Wiederholung auf `eb920b1` |

### 7.5 Beobachtungen und nicht Getestetes

| Nr. | Beobachtung | Empfehlung |
|---|---|---|
| B-01 | RFC-3161-Token liegen nur im Trail. Mit echtem Schlüssel und entfernten Ankern meldet `verify --pin-key` „intact“ (TC-11). Die README-Aussage, Zeitstempel machten Neuschreibungen erkennbar, gilt nur, wenn Token, Bundles oder Kopfkopien auch außerhalb liegen (so `docs/technical-documentation.md` §8.2). | README präzisieren; Ablage außerhalb in die SOP (O-2) |
| B-02 | TC-11 meldet „… truncated“, obwohl neu geschrieben wurde (zwei Datensätze entfernt); Erkennung korrekt, Ursache vereinfacht. | als „Kopf stimmt nicht“ lesen |
| B-03 | Kein automatisierter Test für den Vorwärtssprung der Uhr. | Test ergänzen (O-3) |
| B-04 | Wegen der Ausführung durch einen KI-Agenten tragen alle `human:val-tester`-Datensätze `harness` claude-code; ein Review würde `attribution_mismatch` melden. | keine; beabsichtigt |

**Nicht getestet:** separater Systembenutzer (Skript nie ausgeführt); echte TSA und Sperrprüfung (ausgeschlossen bzw. nicht implementiert); fremde uid am Socket manuell (bräuchte einen zweiten Systembenutzer; nur automatisiert); Verstellen der echten Systemuhr (Systemeinstellung; in TC-04 simuliert); Ereignisse, die den Writer nie erreichen (R-08).

## 8. Rückverfolgbarkeitsmatrix

| URS | Risiko | Testfall | Ergebnis auf `eb920b1` |
|---|---|---|---|
| URS-01 Writer-Zeit, seq, Zeitsprünge | R-05 | TC-01, TC-04 | bestanden |
| URS-02 beobachteter Absender | R-06 | TC-01 | bestanden |
| URS-03 Abweisung, `trail.refused` | R-06 | TC-02 | bestanden |
| URS-04 Kette, Signatur, ein Writer, Absturz | R-01, R-11 | TC-03, TC-06 | bestanden |
| URS-05 einzelne Manipulationen | R-01, R-11 | TC-07, TC-08 | bestanden |
| URS-06 Checkpoints, Abschneiden | R-02 | TC-05, TC-06, TC-09 | bestanden |
| URS-07 Neuschreibung | R-03, R-04 | TC-06, TC-10, TC-11 | bestanden; Restrisiko R-04 bestätigt |
| URS-08 RFC-3161-Anker | R-09 | TC-05 | bestanden (nur TEST-TSA) |
| URS-09 Spool, Lückenmarker | R-07 | TC-03 | bestanden |
| URS-10 Export-Bundle | R-10 | TC-12 | bestanden |
| – | R-08 | – | kein Test; akzeptiertes Restrisiko |

## 9. Validierungsbericht (Zusammenfassung)

**Gesamtbewertung.** Im Geltungsbereich aus Kapitel 1 sind alle 12 Testfälle, alle 101 referenzierten Testinstanzen und die vollständige Suite von aqt-trail (70/70) bestanden; AK-1 bis AK-4 sind erfüllt; A-01 ist bewertet ohne Auswirkung auf eine URS, A-02 ist geschlossen (AK-5). Für Commit `eb920b1` ist gezeigt (Wiederholung mit gleichem Ergebnis wie die Erstdurchführung auf `917db6e`): `verify` erkennt Änderung, Einfügen, Löschen und Umordnen mit der ersten betroffenen seq, Abschneiden und Neuschreiben unter neuem Schlüssel bei gepinntem Schlüssel bzw. externer Kopfkopie; Token werden geprüft (nur TEST-TSA); Bundles sind anderswo prüfbar. Ebenso gezeigt ist die Grenze: Eine Neuschreibung mit dem echten Schlüssel erkennen nur Aufzeichnungen außerhalb.

**Offene Punkte:** O-1 Review und Freigabe dieses Dokuments (Autor); O-2 README zu Zeitstempeln präzisieren (Entwickler); O-3 Test für den Vorwärtssprung der Uhr (Entwickler); O-4 Rohdaten und Hilfsskripte aus `/tmp/aqtval` kontrolliert ablegen (Autor); O-5 unabhängiges Code- und Security-Review der Signatur- und Prüflogik (offen). Erledigt: O-6 aus der Erstdurchführung (Wiederholung nach den Kommentaränderungen in `aqt-trail/src/`) durch diese Durchführung auf `eb920b1`; jede weitere Änderung von aqt-trail oder aqt-spec erfordert eine erneute Durchführung (Änderungskontrolle).

**Akzeptierte Restrisiken** (Maßnahmen in 4.2): R-04 Schlüsselverwahrung und Neuschreibung mit echtem Schlüssel, R-05 Uhrzeit, R-07 Spool, R-08 Ereignisse ohne Writer, R-09 fehlende Sperrprüfung und ungetestete echte TSA.

**Voraussetzungen für einen echten GMP-Einsatz:**

1. **Separater Benutzer** für Writer, Log und Schlüssel, Installation außerhalb von `/home`; Qualifizierung dieser hier ungetesteten Betriebsart.
2. **Schlüsselverwahrung:** Service-Schlüssel nur für den Dienstbenutzer lesbar; öffentlicher Schlüssel bei Inbetriebnahme unabhängig hinterlegt und stets gepinnt; Vorgehen bei Verlust oder Kompromittierung.
3. **Echte TSA**, bei Bedarf eIDAS-qualifiziert; Token-Prüfung mit deren CA testen; fehlende Sperrprüfung bewerten.
4. **Kopien außerhalb:** Kopfkopien und Bundles regelmäßig außerhalb der Reichweite der Agenten; Prüfung immer mit `--pin-key` und `--heads`.
5. **Verfahren:** SOPs für Audit-Trail-Review (Funktion separat validieren), periodische Überprüfung, Änderungskontrolle (aqt-trail, Hooks, Sink), Zeitsynchronisation, Backup und Archiv mit Wiederherstellungstest, Schulung.
6. **IQ und Lieferant:** IQ mit fixierten Versionen; Lieferantenbewertung bzw. Übernahme der Verantwortung für den Open-Source-Code einschließlich Code-Review.
7. **Umfang:** weitere genutzte Funktionen validieren; Tests auf dem freigegebenen Release-Stand wiederholen.

**Schlussfolgerung:** Im definierten Umfang wurden die Akzeptanzkriterien erfüllt; dies ist keine Freigabe für den GMP-Einsatz.

## 10. Unterschriften

| Rolle | Name | Funktion | Datum | Unterschrift |
|---|---|---|---|---|
| Erstellt | | | | |
| Geprüft | | | | |
| Freigegeben | | | | |

In einem echten Projekt würden die Unterschriften elektronisch mit aqt-signoff geleistet, je mit Bedeutung und Begründung und an den SHA-256-Hash dieser Datei gebunden: Erstellt = `authored`, Geprüft = `reviewed`, Freigegeben = `approved`, z. B. `aqt-signoff sign docs/de/validierungsbeispiel.md --meaning reviewed --reason "Validierungsbeispiel geprüft" --signer human:<id>`. Jede spätere Änderung der Datei macht die Unterschriften sichtbar ungültig.

## Anhang A – Hilfsskripte

Beide Skripte lagen nur in der Testumgebung (SHA-256 `manip.py` `abeb3a1a…5144`, `clock.py` `6c95d707…7877`; Ablage O-4) und nutzen nur die öffentliche API von `aqt_evidence` bzw. `aqt_trail`. `manip.py record VARIANTE` erzeugt Client-Datensätze (`trail.event`, `human:val-tester`): mit Client-Zeit 2020-01-01 (`old-time`), mit gesetztem `chain` oder `observed`, mit eigenem Client-Schlüssel signiert (`sig KEY`), mit `meaning` ohne `reason` (`no-reason`), unverändert (`base`) oder mit gleicher ID und anderer `action` (`changed FILE`). `manip.py OP SRC DST N` schreibt eine Kopie mit geänderter Begründung von N (`edit`), umgedrehtem Signaturwert (`sig`), gelöschtem N (`delete`), Kopie von N-1 vor N (`insert`), vertauschtem N und N+1 (`swap`) bzw. nur den ersten N Datensätzen (`truncate`); `rewrite`/`rewrite-keep SRC DST KEY N` ändert N, entfernt bei `rewrite` alle `trail.anchor` und verkettet und signiert alles mit KEY neu. `clock.py STATE` legt einen Trail an, ersetzt `writer.clock` und `writer.monotonic` durch feste Folgen (10:00:00, 10:00:01, 11:00:01 bzw. 100, 101, 102 s) und schreibt drei Datensätze.
