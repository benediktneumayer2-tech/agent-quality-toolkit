# aqt-ui — one local page for the person who supervises the agents

Part of the **Agent Quality Toolkit (AQT)**. The toolkit's command-line tools are many; the person who has to act on their results is usually not the agent but you: a quality manager or a developer who supervises AI coding agents. `aqt-ui` gives you one web page on your own machine that answers **"Is everything in order, and what needs me?"** and lets you deal with each item.

It is optional. It reads the same files and calls the same package functions as the command-line tools, which keep working exactly as before, with or without it. It adds no record types and no new authority: every decision is signed with your passphrase-protected key and written by the owning package into the one audit trail, exactly as the command line would.

![Home: the "Needs you" queue, one line per case, most urgent first](docs/screenshots/home-queue.png)

## Start

```bash
uv venv .venv && uv pip install --python .venv/bin/python \
    -e ../aqt-spec -e ../aqt-trail -e ../aqt-quarantine -e ../aqt-signoff \
    -e ../aqt-change -e ../aqt-capa -e ../aqt-validate -e .
.venv/bin/aqt-ui
```

`aqt-ui` prints a login link that works once and opens it in your browser. Press Enter in its terminal for a fresh link (older unused links stop working); Ctrl+C stops the server and ends every session. Each browser tab needs its own login link. Only `aqt-spec` and `aqt-trail` are required; a view whose package is missing says "not installed" and shows the install command.

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

The page is one flow: the queue of what needs you, one page per case, and one page per change.

**Home is the queue (*Needs you*).** One line per case, most urgent first: what it is, why it needs you and how long it has been waiting. A plan of a configured project has one line, for the step it stops at: its version to approve, a gate that is not GO, or a finished GO change to sign as released (*Release to sign*). An empty queue says "Everything in order" with the trail status line. Keys: `j` and `k` move through the queue, `Enter` opens a case, `n` opens the next case, `Escape` closes a sheet; letters never act while you type in a field.

**One page per case** (`/case/<id>`, so reload and back work). At the top the subject and its STOP point: what waits for whom (a red STOP when it waits for you). In the middle the evidence: the highlighted passages and the content (quarantine), the reasons and failing or stale receipts (gate), the action's specification and hash, the candidate's source (CAPA), the review parameters and worksheet (trail review), the refused attempts. At the bottom the allowed decisions, each with one sentence on its consequence, in the decision panel that asks for your passphrase; after a decision the page shows the record ID and time and offers **Next case** (`n`). Cases without a decision on the page (writer down, spool, trail changed, unanchored head, review parameters, overdue deviations, an expiring qualification, an action whose outcome is unknown) show the evidence and the exact command to run in your terminal. A read-only server hides the decisions and says why in a ribbon; when the trail writer is down, a banner on every page gives the command to start it.

![A case page: a held page, its STOP point, the evidence and the decision](docs/screenshots/case-quarantine.png)

**One page per change** (`/change/<project>/<plan>`): the plan's timeline **Plan → Checks → Review → Gate → Release**, each step with its state (done, waits for you, waits for evidence) and its evidence, the current STOP marked. When the gate is GO and the change is finished, the page offers **Sign released** and shows whether the change is released, with the signatures and the manifest to download. A prepared action is not shown on the change page: nothing in its specification names the change it belongs to.

![The change page: the timeline with the STOP at Release](docs/screenshots/change-release.png)

**Health and the tool views** stay reachable for a closer look; auditors use them read-only:

| View | What you see | What you can decide here |
|---|---|---|
| Health | Trail status (intact or broken from which record), writer and spool, test mode and the review parameters (both from `trail.toml`, which any process of your user can edit: test mode and parameters that differ from aqt-trail's built-in defaults are also cases in the queue), ALCOA++ per attribute, tool health, refused attempts of the last 24 hours | – |
| Trail | Records page by page (100 at a time, newest first) with filters kept in the address, claimed actor next to the observed process chain and its chain status (a human claim the writer could not confirm is marked "unconfirmed", as in the review), detached signatures with their verification status, the stored record as text, verification on demand | **Sign the audit-trail review** (prepare the worksheet, which shows the profile's parameters and, prominently, those that differ from the built-in defaults and test mode; set a disposition per finding, sign); **download a verification bundle** (no passphrase, records nothing) |
| Quarantine | Held and warned cases with the suspicious passages highlighted and hidden characters made visible, the full content in pages of 200,000 characters; trusted sources | **Release** (once the whole content was on screen) or **declare a threat** (the highlights are enough, because a threat keeps the content withheld); **trust a source** until a date, or revoke that trust |
| Changes | Release gates (GO, NO-GO, MANUAL) with every reason in words, receipts with their test counts, approval state, a link to each change page; prepared actions | **Approve the plan version** shown; **approve** or **reject** a prepared action |
| Signatures | Verify a file, record or hash, with the signature manifest to download; the signer registry | – |
| CAPA | Candidates first when there are any, deviations with their timeline, effectiveness results, trend summary | **Accept** or **dismiss** a candidate, **approve** an implemented corrective action, **close** a deviation |
| Qualifications | Qualified detectors and AI reviewers, valid until when, recorded requalification triggers, the thresholds file in use | – |

The case pages use the same panels and the same server checks as these views.

How each decision is recorded, as the command line does it:

- **Trust a source** is `aqt-quarantine trust-source`: a signed `quarantine.source.trusted` record. Trust only lowers the band for content that arrives later from that domain; it releases no held case, and the page says so.
- **Approve the plan version** is `aqt-signoff sign --record <approval target> --meaning approved` over the plan version the gate shows. The project folder comes from `ui.toml` and is passed explicitly.
- **Sign released** is `aqt-signoff sign --record <change.finish record> --meaning released`, as in step 11 of the change workflow. In this order: the agent check, before the signer is even looked up (a refusal is recorded as `signoff.refused`); the plan by its registered id and the file shown; a fresh gate evaluation, not the one-minute cache, which must be GO (NO-GO and MANUAL are refused, nothing is signed); the `change.finish` record must be this change's: aqt-change's local copy names it, but that copy can be written by the agent's user, so the record signed is the copy in the evidence aqt-signoff reads, and it must be a `change.finish` record of this plan and file, the same as the local copy, in the trail when a trail is in use (as aqt-change confirms receipts), with a commit (or recorded head) in this repository's history that carries the `AQT-Finish` trailer, and the plan's latest finish; and it must be a finish of what the fresh gate evaluated: the plan version accepted now, the receipts the gate counts now and, when finish committed, HEAD or a commit with HEAD's files (after `finish --no-commit` the record names only the head before the change, shown as such; receipts and plan version bind it). After later commits, checks or plan versions the page says the change moved on and asks to finish it again; the page shows the finished commit next to HEAD, the record's own author next to the sender the trail writer observed, and names the commit (and HEAD when it differs) in the signature subject; otherwise the page shows the discrepancy instead of a release state, the queue lists it, and nothing can be signed; that record and its hash must be the ones shown; a valid "released" signature by the same signer refuses a second one; then aqt-signoff's own rules of `[policy.released]` in `signoff.toml` (roles, distinct from the author), which the page shows, and the unlock of your key. Whether a change is released is verified as `aqt-signoff verify --record <change.finish record> --require released` does, without recording anything.
- **CAPA:** aqt-capa records accept, dismiss and close without a signature, under the identity it is given. The page first unlocks the chosen signer's key with your passphrase (a failed unlock is recorded as `signoff.auth.failed`) and then lets aqt-capa record the decision under that signer. The record names the signer but carries no signature, so the record alone does not prove who decided. A corrective action is approved as aqt-capa recommends: an aqt-signoff signature with the meaning "approved" over its implementation record, which aqt-capa then reports as `signed-verified`. Closing needs a recorded investigation and, with actions, a passed effectiveness check; a deviation without actions can be closed with a justification.
- **Audit-trail review** is `aqt-trail review run` and `review sign`. The independence rule holds: a person who acted in the reviewed period cannot sign its review, and a refused attempt is recorded as `trail.refused`. The page signs the worksheet that this server prepared and showed you, not the `worksheet.json` file, which any process of your user could edit in between.

**Language.** The switch in the top bar shows English (the default) or German labels, with German quality terms (Freigabe, Abweichung, Wirksamkeitsprüfung, Audit Trail, Prüfpunkt, Bedeutung der Unterschrift). The choice stays in the browser's `localStorage`. Evidence, record content and the tools' own messages are never translated.

![The queue in German](docs/screenshots/home-de.png)

Opening or refreshing a page never writes evidence. Two tools keep working state of their own when they are read, as their command lines do: aqt-capa refreshes its candidate index, and `aqt-change gate` may note that a plan's history moved on.

## Security model

The threat picture is the toolkit's own: one person on one Linux machine, AI agents running as the same user next to the page and possibly steered by injected content, and quarantined text that is hostile by definition.

- **Local only.** The server listens on `127.0.0.1` and answers only requests whose `Host` is `127.0.0.1:<port>` or `localhost:<port>`. For use from another device, forward the port over SSH; there is no option to listen elsewhere.
- **One-time login.** The printed link carries a random token that is exchanged once for a session (gone when the server stops). The browser is not started with the link, because every local user can read a command line: it is started with a private page (a `0600` file in a `0700` folder `~/aqt-ui-login-*`) that forwards to the link and is deleted once a link was used and when the server stops. The folder is in your home directory because snap-packaged browsers (Ubuntu's default Firefox and Chromium) cannot read `$XDG_RUNTIME_DIR` or the host's `/tmp`; a hidden folder would not work either. If the browser still cannot open the page (for example a Flatpak browser), use the printed link. After a crash a folder with a dead link may remain; delete it. A fresh link makes older unused links invalid, and every use of a link is printed in the terminal, so a session that someone else started shows up there. A copy of a used link in terminal scrollback is useless.
- **Cookie plus session key.** Browsers send cookies for `127.0.0.1` to every port, so any other local web server you open in the same browser receives the session cookie (`HttpOnly`, `SameSite=Strict`). The cookie alone is therefore no session: every API request must also carry the session key in a header. The page receives the key once, with the login, and keeps it in the tab's `sessionStorage`, which is separate per port; no answer to a request with only the cookie contains it. A cookie set by another local page, even a malformed one, does not lock you out.
- **Every change is checked.** Each request that changes something must also carry the server's own `Origin` and a JSON body.
- **Untrusted text stays text.** A strict Content-Security-Policy allows only the page's own script and style; evidence is put into the page as text, never as markup, so a quarantined page cannot run code or fake a passphrase prompt. Hidden characters (bidi overrides and isolates, zero-width and other invisible format characters, control characters) are shown as `<U+XXXX>` in every text on the page, including the command of a prepared action, so text cannot read differently from what is stored.
- **The passphrase is asked for every decision.** It travels once in the body of that one request over loopback, unlocks the key, and is dropped. It is never written to disk, a log, a cookie, browser storage or an address. The request log holds method, path, status and duration only.
- **You sign what you see.** Each decision carries the hash or version shown on screen (case content, action, plan version, change.finish record, implementation record, worksheet, deviation state, trust entry). If it changed in the meantime, nothing is signed and the page says so. Held content is shown, and can be released, only while the stored text has the hash recorded when the case was opened, the hash the release signs. A release is offered, and accepted by the server, only after this browser session was shown every page of that text; the highlighted passages alone are not enough. Declaring a threat keeps the content withheld, so it may rest on the highlights. A later `quarantine.held` line for an existing case cannot change the case or its highlights (aqt-quarantine keeps the first and lists the ignored line on the case). A prepared action is shown as decidable only while its stored specification hashes to the action hash that is signed. The review signed is the worksheet shown, bound by a digest from display to signing.
- **A green trail means the current file.** "Intact" holds only while the trail file still starts with exactly the bytes the last check verified. If the file is replaced, truncated or those bytes change, the page shows "changed since the last check" (critical in "Needs you") until you verify again; records appended later count as not yet verified.
- **Agents cannot decide through the page.** At start, `aqt-ui` runs the toolkit's agent check (agent environment markers, agent processes among its parents, an interactive terminal). Started inside an agent session it still runs, but read-only, with a ribbon that names the markers it found; an agent can show you the state, as the command line allows. In addition, for every decision request the server finds the process on the other end of the connection and checks its parents and the agent markers in its environment: a request sent by `curl` under an agent, or by a process that carries an agent's environment variables, is refused, and so is a request from another user's process or one that cannot be identified. Each refusal is recorded by the owning package (`quarantine.refused`, `signoff.refused`, `capa.refused`, `trail.refused`) and shows up in the trail and on the Overview. The terminal log names the process (pid, uid, parents) behind every decision request; the decision record itself describes the aqt-ui server process, which is what the trail writer observes.
- **Bounded requests.** Each connection has a 20-second read and write timeout, at most 32 connections are handled at once, request bodies are limited to 64 KiB (a negative or malformed `Content-Length` is refused), and file verification reads only regular files up to 64 MiB.

A detached signature in the record inspector is shown with its status against the signer registry, its keys checked against the trail's enrolment records (`valid`, `invalid`, `revoked`, `unknown-key`), not as signed because the record carries one.

**Limits of Sign released.** In user mode the agent runs as the same user as aqt-change, so aqt-change's local ledger (`.git/aqt-change/`: the record mirror and the plan state) can be written by the agent. The page does not rely on it alone: the record signed is the copy in the evidence aqt-signoff reads (with a trail in use, confirmed by the trail as aqt-change confirms receipts), and it must be this project's own finish of what the fresh gate evaluated: recorded in the plan state's history with one of its plan versions, the plan completed, the accepted plan version, the receipts the gate counts, run on this repository's history since the plan's base commit, and HEAD's files. What it cannot rule out: an agent that edits the plan state file and writes its own finish record through the writer can produce a record that passes these checks. Such a record still names exactly the receipts, plan version and files the gate evaluated, so the signature covers the tested state, but aqt-change finish's own steps are skipped (the open-task acknowledgement; open tasks are therefore shown on the Release step). Receipts and finish records name no repository: when two projects share the plan id, the base commit and the tested files, a receipt of one cannot be told from the other's. Without a trail, nothing confirms the records beyond the evidence files, which the agent's user can also write. The trail under a separate user (manual 3.8) and the gate in CI are the stronger setup.

What this does not protect against, as for the rest of the toolkit: an agent that learns your passphrase; an agent that drives your own browser and gets you to type the passphrase into a decision it prepared (the decision panel therefore shows plainly who signs, with which meaning, over which content); and a same-user process that deliberately works around the checks, for example one that detaches from the agent and clears its environment, reads the private login page before the browser does, or swaps the trail file exactly while it is being verified. A same-user process can read the files the page shows anyway. The agent checks are a guard, not a boundary. The passphrase is the real control.

## Limits of version 0.1

- Linux only (the agent check and the connection lookup read `/proc`). A light design; a quiet dark variant follows the system setting.
- Signing a file or a record other than a plan version or a finished change, resolving an action whose outcome is unknown, the CAPA steps of the person handling a deviation (investigation, action plan, implementation, extending a window) and qualifying a detector stay in the terminal for now.
- Large trails: the Trail list is paged on the server, and the Overview reuses what it derived from the trail until the trail grows. With 50,000 records the first request reads the trail once (about 0.6 s); after that the Overview and any page answer in a few milliseconds (measured by the test suite). The full verification still reads the whole trail, at start and on demand; records added since are shown as "not yet verified". After the file changed, the status hashes the verified part once more to see that it is unchanged.
- Gate evaluation runs `aqt-change gate` for each configured plan and is cached for a minute.
- aqt-sensei's owner decisions stay in the terminal by design.

![Phone: a case page in one column](docs/screenshots/phone-case.png)

The screenshots come from a throw-away demo environment (synthetic projects, demo signers, `example` domains), seeded and captured by a script running inside an AI agent session. That is why ALCOA++ "attributable" fails in the queue: the toolkit noticed the agent, as it should ("enduring" fails because an offline demo has no RFC 3161 anchor). Started inside an agent session the real `aqt-ui` is read-only; the pictures with decisions on were taken with the same test set-up the test suite uses.

## Tests

```bash
scripts/test_all.sh aqt-ui      # from the repository root
```

The tests start the server and a real aqt-trail writer in throw-away directories and cover login (no token in the browser's command line), cookies and the session key, the Host, CSRF and Origin checks, request limits, read-only mode, the peer check, stale views and a wrong passphrase for every decision; substituted quarantine content, worksheets and action specifications, release only after every content page was shown, journal lines that try to reopen a case, the record inspector's attribution and signature status, and a trail changed after a good check; each decision end to end (release, threat, action approval, trust and revoke, plan approval, release of a finished change, CAPA accept, dismiss, approval and close, review signing with the independence rule, export), including that the passphrase appears in no response, log line or file; Sign released only on a fresh GO gate, over the record shown, once per signer and under `[policy.released]`; one queue entry per plan; the case and change pages served as the page shell; the German labels; and paging and response times with a generated 50,000-record trail.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
