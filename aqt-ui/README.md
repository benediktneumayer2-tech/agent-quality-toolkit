# aqt-ui — one local page for the person who supervises the agents

Part of the **Agent Quality Toolkit (AQT)**. The toolkit's command-line tools are many; the person who has to act on their results is usually not the agent but you: a quality manager or a developer who supervises AI coding agents. `aqt-ui` gives you one web page on your own machine that answers **"Is everything in order, and what needs me?"** and lets you deal with each item.

It is optional. It reads the same files and calls the same package functions as the command-line tools, which keep working exactly as before, with or without it. It adds no record types and no new authority: every decision is signed with your passphrase-protected key and written by the owning package into the one audit trail, exactly as the command line would.

![Overview in read-only mode, with the "Needs you" queue](docs/screenshots/overview-read-only.png)

## Start

```bash
uv venv .venv && uv pip install --python .venv/bin/python \
    -e ../aqt-spec -e ../aqt-trail -e ../aqt-quarantine -e ../aqt-signoff \
    -e ../aqt-change -e ../aqt-capa -e ../aqt-validate -e .
.venv/bin/aqt-ui
```

`aqt-ui` prints a login link that works once and opens it in your browser. Press Enter in its terminal for a fresh link; Ctrl+C stops the server and ends every session. Only `aqt-spec` and `aqt-trail` are required; a view whose package is missing says "not installed" and shows the install command.

| Option | Meaning |
|---|---|
| `--port N` | TCP port on 127.0.0.1 (default: a free port) |
| `--read-only` | never allow decisions from this server |
| `--no-browser` | only print the link |
| `--config PATH` | settings file (default `~/.config/aqt/ui.toml`) |

Optional settings in `~/.config/aqt/ui.toml`:

```toml
port = 0                      # 0 = a free port at each start
open_browser = true
review_due_days = 7           # "Needs you": no signed trail review for this long
qualification_warn_days = 30  # "Needs you": a qualification expires within this many days

[changes]
projects = ["~/code/my-project"]   # repositories whose aqt-change gates to show
```

Everything else (trail location, evidence sink, signer registry) comes from the other tools' own settings and environment variables, so the page sees what the command line sees.

## What the page shows

| View | What you see | What you can decide here |
|---|---|---|
| Overview | The **Needs you** queue sorted by urgency first, then trail status (intact or broken from which record), writer and spool, ALCOA++ per attribute, tool health, refused attempts of the last 24 hours | – |
| Trail | Records page by page (100 at a time, newest first) with filters kept in the address, claimed actor next to the observed process chain, the stored record as text, verification on demand | **Sign the audit-trail review** (prepare the worksheet, set a disposition per finding, sign); **download a verification bundle** (no passphrase, records nothing) |
| Quarantine | Held and warned cases with the suspicious passages highlighted and hidden characters made visible; trusted sources | **Release** or **declare a threat**; **trust a source** until a date, or revoke that trust |
| Changes | Release gates (GO, NO-GO, MANUAL) with every reason in words, receipts with their test counts, approval state; prepared actions | **Approve the plan version** shown; **approve** or **reject** a prepared action |
| Signatures | Verify a file, record or hash, with the signature manifest to download; the signer registry | – |
| CAPA | Candidates first when there are any, deviations with their timeline, effectiveness results, trend summary | **Accept** or **dismiss** a candidate, **approve** an implemented corrective action, **close** a deviation |
| Qualifications | Qualified detectors and AI reviewers, valid until when, recorded requalification triggers, the thresholds file in use | – |

How each decision is recorded, as the command line does it:

- **Trust a source** is `aqt-quarantine trust-source`: a signed `quarantine.source.trusted` record. Trust only lowers the band for content that arrives later from that domain; it releases no held case, and the page says so.
- **Approve the plan version** is `aqt-signoff sign --record <approval target> --meaning approved` over the plan version the gate shows. The project folder comes from `ui.toml` and is passed explicitly.
- **CAPA:** aqt-capa records accept, dismiss and close without a signature, under the identity it is given. The page first unlocks the chosen signer's key with your passphrase (a failed unlock is recorded as `signoff.auth.failed`) and then lets aqt-capa record the decision under that signer. A corrective action is approved as aqt-capa recommends: an aqt-signoff signature with the meaning "approved" over its implementation record, which aqt-capa then reports as `signed-verified`. Closing needs a recorded investigation and, with actions, a passed effectiveness check; a deviation without actions can be closed with a justification.
- **Audit-trail review** is `aqt-trail review run` and `review sign`. The independence rule holds: a person who acted in the reviewed period cannot sign its review, and a refused attempt is recorded as `trail.refused`.

**Language.** The switch in the top bar shows English (the default) or German labels, with German quality terms (Freigabe, Abweichung, Wirksamkeitsprüfung, Audit Trail, Prüfpunkt, Bedeutung der Unterschrift). The choice stays in the browser's `localStorage`. Evidence, record content and the tools' own messages are never translated.

![Overview in German](docs/screenshots/overview-de.png)

Opening or refreshing a page never writes evidence. Two tools keep working state of their own when they are read, as their command lines do: aqt-capa refreshes its candidate index, and `aqt-change gate` may note that a plan's history moved on.

![A held case and the decision panel](docs/screenshots/quarantine-decision.png)

## Security model

The threat picture is the toolkit's own: one person on one Linux machine, AI agents running as the same user next to the page and possibly steered by injected content, and quarantined text that is hostile by definition.

- **Local only.** The server listens on `127.0.0.1` and answers only requests whose `Host` is `127.0.0.1:<port>` or `localhost:<port>`. For use from another device, forward the port over SSH; there is no option to listen elsewhere.
- **One-time login.** The printed link carries a random token that is exchanged once for a session cookie (`HttpOnly`, `SameSite=Strict`, gone when the server stops). A copy of the link in terminal scrollback is useless afterwards.
- **Every change is checked.** Each request that changes something must carry the session's CSRF token in a header and the server's own `Origin`.
- **Untrusted text stays text.** A strict Content-Security-Policy allows only the page's own script and style; evidence is put into the page as text, never as markup, so a quarantined page cannot run code or fake a passphrase prompt.
- **The passphrase is asked for every decision.** It travels once in the body of that one request over loopback, unlocks the key, and is dropped. It is never written to disk, a log, a cookie, browser storage or an address. The request log holds method, path, status and duration only.
- **You sign what you see.** Each decision carries the hash or version shown on screen (case content, action, plan version, implementation record, worksheet head, deviation state, trust entry). If it changed in the meantime, nothing is signed and the page says so.
- **Agents cannot decide through the page.** At start, `aqt-ui` runs the toolkit's agent check (agent environment markers, agent processes among its parents, an interactive terminal). Started inside an agent session it still runs, but read-only, with a ribbon that names the markers it found; an agent can show you the state, as the command line allows. In addition, for every decision request the server finds the process on the other end of the connection and checks its parents the same way: a request sent by `curl` under an agent is refused. Each refusal is recorded by the owning package (`quarantine.refused`, `signoff.refused`, `capa.refused`, `trail.refused`) and shows up in the trail and on the Overview.

What this does not protect against, as for the rest of the toolkit: an agent that learns your passphrase; an agent that drives your own browser and gets you to type the passphrase into a decision it prepared (the decision panel therefore shows plainly who signs, with which meaning, over which content); and a same-user process that deliberately works around the checks. The agent checks are a guard, not a boundary. The passphrase is the real control.

## Limits of version 0.1

- Linux only (the agent check and the connection lookup read `/proc`). A light design; a quiet dark variant follows the system setting.
- Signing a file or record, resolving an action whose outcome is unknown, the CAPA steps of the person handling a deviation (investigation, action plan, implementation, extending a window) and qualifying a detector stay in the terminal for now.
- Large trails: the Trail list is paged on the server, and the Overview reuses what it derived from the trail until the trail grows. With 50,000 records the first request reads the trail once (about 0.6 s); after that the Overview and any page answer in a few milliseconds (measured by the test suite). The full verification still reads the whole trail, at start and on demand; records added since are shown as "not yet verified".
- Gate evaluation runs `aqt-change gate` for each configured plan and is cached for a minute.
- aqt-sensei's owner decisions stay in the terminal by design.

![Narrow screen: the inspector becomes a sheet](docs/screenshots/phone-quarantine.png)

The screenshots come from the integration demo's throw-away environment, seeded and captured by a script running inside an AI agent session. That is why ALCOA++ "attributable" fails and the first picture shows the read-only ribbon: the toolkit noticed the agent, as it should. The pictures with decisions on were taken with the same test set-up the test suite uses.

## Tests

```bash
scripts/test_all.sh aqt-ui      # from the repository root
```

The tests start the server and a real aqt-trail writer in throw-away directories and cover login, cookies, the Host, CSRF and Origin checks, read-only mode, the peer check, stale views and a wrong passphrase for every decision; each decision end to end (release, threat, action approval, trust and revoke, plan approval, CAPA accept, dismiss, approval and close, review signing with the independence rule, export), including that the passphrase appears in no response, log line or file; the German labels; and paging and response times with a generated 50,000-record trail.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
