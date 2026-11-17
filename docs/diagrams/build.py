#!/usr/bin/env python3
"""Generate keygent architecture diagrams as .excalidraw files.

Run:  python3 docs/diagrams/build.py
Open: https://excalidraw.com (File → Open) or the VS Code "Excalidraw" extension.
Edit this script and re-run instead of hand-editing the JSON, so diagrams stay consistent with the spec.
"""
import json
import os
import random

OUT = os.path.dirname(os.path.abspath(__file__))
random.seed(20261115)  # deterministic output → clean diffs

C = {
    "agent": "#ffc9c9",    # untrusted: AI agent side (same OS user)
    "client": "#a5d8ff",   # untrusted relay / thin client
    "trusted": "#b2f2bb",  # trusted core (broker)
    "secret": "#ff8787",   # plaintext present
    "human": "#d0bfff",    # human factors the agent cannot fake
    "store": "#ffec99",    # storage on disk
    "plain": "#ffffff",
    "neutral": "#e9ecef",
}
INK = "#1e1e1e"
RED_INK = "#c92a2a"


class Diagram:
    def __init__(self, name, title, subtitle=""):
        self.name, self.els, self.n = name, [], 0
        self.text(40, 20, title, size=28)
        if subtitle:
            self.text(40, 58, subtitle, size=16, color="#495057")

    # ── primitives ────────────────────────────────────────────────────────────
    def _id(self):
        self.n += 1
        return f"{self.name}-{self.n}"

    def _base(self, typ, x, y, w, h, stroke=INK, bg="transparent", style="solid",
              roundness=None, sw=2, opacity=100):
        e = {
            "id": self._id(), "type": typ, "x": x, "y": y, "width": w, "height": h,
            "angle": 0, "strokeColor": stroke, "backgroundColor": bg, "fillStyle": "solid",
            "strokeWidth": sw, "strokeStyle": style, "roughness": 1, "opacity": opacity,
            "groupIds": [], "frameId": None, "roundness": roundness,
            "seed": random.randint(1, 2**31 - 1), "version": 1,
            "versionNonce": random.randint(1, 2**31 - 1), "isDeleted": False,
            "boundElements": [], "updated": 1763164800000, "link": None, "locked": False,
        }
        self.els.append(e)
        return e

    @staticmethod
    def _measure(s, size):
        lines = s.split("\n")
        return max(len(l) for l in lines) * size * 0.6, len(lines) * size * 1.25

    def text(self, x, y, s, size=16, color=INK, font=1):
        w, h = self._measure(s, size)
        t = self._base("text", x, y, w, h, stroke=color)
        t.update(text=s, originalText=s, fontSize=size, fontFamily=font, textAlign="left",
                 verticalAlign="top", containerId=None, autoResize=True, lineHeight=1.25)
        return t

    def box(self, x, y, w, h, label="", bg=C["neutral"], size=16, style="solid",
            stroke=INK, font=1, shape="rectangle"):
        e = self._base(shape, x, y, w, h, stroke=stroke, bg=bg, style=style,
                       roundness={"type": 3} if shape == "rectangle" else {"type": 2})
        if label:
            lines = label.split("\n")
            size = min(size, (w - 16) / (0.6 * max(len(l) for l in lines)),
                       (h - 8) / (1.25 * len(lines)))
            size = max(10, round(size))
            tw, th = self._measure(label, size)
            t = self._base("text", x + (w - tw) / 2, y + (h - th) / 2, tw, th)
            t.update(text=label, originalText=label, fontSize=size, fontFamily=font,
                     textAlign="center", verticalAlign="middle", containerId=e["id"],
                     autoResize=True, lineHeight=1.25)
            e["boundElements"].append({"type": "text", "id": t["id"]})
        return e

    def zone(self, x, y, w, h, title, bg):
        z = self._base("rectangle", x, y, w, h, stroke="#868e96", bg=bg, style="dashed",
                       roundness={"type": 3}, opacity=60)
        self.text(x + 14, y + 10, title, size=18, color="#343a40")
        return z

    @staticmethod
    def anchor(e, side, f=0.5):
        x, y, w, h = e["x"], e["y"], e["width"], e["height"]
        return {"l": (x, y + h * f), "r": (x + w, y + h * f),
                "t": (x + w * f, y), "b": (x + w * f, y + h)}[side]

    def arrow(self, a, b, sa="r", sb="l", fa=0.5, fb=0.5, label="", style="solid",
              color=INK, both=False, via=None, size=14):
        p1 = self.anchor(a, sa, fa) if isinstance(a, dict) else a
        p2 = self.anchor(b, sb, fb) if isinstance(b, dict) else b
        pts = [p1] + (via or []) + [p2]
        rel = [[px - p1[0], py - p1[1]] for px, py in pts]
        xs, ys = [p[0] for p in rel], [p[1] for p in rel]
        e = self._base("arrow", p1[0], p1[1], max(xs) - min(xs), max(ys) - min(ys),
                       stroke=color, style=style, roundness=None if via else {"type": 2})
        e.update(points=rel, lastCommittedPoint=None, elbowed=False,
                 startArrowhead="arrow" if both else None, endArrowhead="arrow",
                 startBinding={"elementId": a["id"], "focus": 0, "gap": 4} if isinstance(a, dict) else None,
                 endBinding={"elementId": b["id"], "focus": 0, "gap": 4} if isinstance(b, dict) else None)
        for t in (a, b):
            if isinstance(t, dict):
                t["boundElements"].append({"type": "arrow", "id": e["id"]})
        if label:
            mid = len(pts) // 2
            (ax, ay), (bx, by) = pts[mid - 1], pts[mid]
            tw, th = self._measure(label, size)
            t = self._base("text", (ax + bx) / 2 - tw / 2, (ay + by) / 2 - th / 2, tw, th, stroke=color)
            t.update(text=label, originalText=label, fontSize=size, fontFamily=1,
                     textAlign="center", verticalAlign="middle", containerId=e["id"],
                     autoResize=True, lineHeight=1.25)
            e["boundElements"].append({"type": "text", "id": t["id"]})
        return e

    def line(self, x1, y1, x2, y2, style="dashed", color="#adb5bd"):
        e = self._base("line", x1, y1, abs(x2 - x1), abs(y2 - y1), stroke=color, style=style, sw=1)
        e.update(points=[[0, 0], [x2 - x1, y2 - y1]], lastCommittedPoint=None,
                 startArrowhead=None, endArrowhead=None, startBinding=None, endBinding=None)
        return e

    def legend(self, x, y, items):
        for i, (bg, label) in enumerate(items):
            self.box(x, y + i * 34, 26, 22, bg=bg)
            self.text(x + 38, y + i * 34 + 1, label, size=15)

    def sequence(self, actors, steps, x0=40, y0=110, gap=230, step_h=54, head_w=190):
        cx, heads = {}, {}
        for i, (key, label, bg) in enumerate(actors):
            heads[key] = self.box(x0 + i * gap, y0, head_w, 64, label, bg=bg, size=16)
            cx[key] = x0 + i * gap + head_w / 2
        top = y0 + 64
        bottom = top + 40 + len(steps) * step_h
        for key in cx:
            self.line(cx[key], top, cx[key], bottom)
        for i, step in enumerate(steps):
            src, dst, label = step[:3]
            color = step[3] if len(step) > 3 else INK
            y = top + 40 + i * step_h
            if src == dst:
                w, _ = self._measure(label, 14)
                self.box(cx[src] + 12, y - 16, w + 24, 32, label, bg=C["neutral"], size=14, stroke=color)
            else:
                self.arrow((cx[src], y), (cx[dst], y), label="", color=color)
                self.text(min(cx[src], cx[dst]) + 14, y - 22, label, size=14, color=color)
        for i, (key, label, bg) in enumerate(actors):
            self.box(x0 + i * gap, bottom, head_w, 44, label.split("\n")[0], bg=bg, size=14)

    def save(self):
        ids = {e["id"] for e in self.els}
        assert len(ids) == len(self.els), "duplicate element ids"
        for e in self.els:
            refs = [e.get("containerId")] + [b["id"] for b in e["boundElements"]]
            refs += [e[k]["elementId"] for k in ("startBinding", "endBinding") if e.get(k)]
            assert all(r in ids for r in refs if r), f"dangling reference in {e['id']}"
        doc ={"type": "excalidraw", "version": 2, "source": "https://excalidraw.com",
               "elements": self.els,
               "appState": {"gridSize": 20, "viewBackgroundColor": "#ffffff"}, "files": {}}
        path = os.path.join(OUT, f"{self.name}.excalidraw")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"wrote {os.path.relpath(path)}  ({len(self.els)} elements)")


# ── 01 System architecture ───────────────────────────────────────────────────
def system_architecture():
    d = Diagram("01-system-architecture", "keygent — system architecture",
                "One broker per OS user is the only process that holds plaintext. Everything else is untrusted.")
    d.zone(40, 100, 500, 560, "AI agent side — same OS user (UNTRUSTED)", C["agent"])
    cc = d.box(80, 150, 420, 70, "Claude Code (model + tools)", bg=C["plain"])
    hooks = d.box(80, 270, 420, 70, "Hooks: prompt · pre · post\n(UX + defense in depth)", bg=C["agent"])
    shell = d.box(80, 390, 420, 60, "Agent shell (bash / PowerShell)", bg=C["agent"])
    run = d.box(80, 500, 420, 70, "keygent run -- <cmd>\nthin client · never sees values", bg=C["client"])
    d.text(80, 600, "Sees handles {{keygent:stripe/live}} and\nredacted output ‹keygent:stripe/live› only", size=14)
    d.arrow(cc, hooks, "b", "t", label="hook JSON (stdin)")
    d.arrow(cc, shell, "l", "l", via=[(62, 185), (62, 420)], label="Bash tool")
    d.arrow(shell, run, "b", "t", label="exec")

    d.zone(40, 700, 500, 220, "Human — factors the agent cannot fake", C["human"])
    cli = d.box(70, 750, 210, 120, "keygent CLI\nadd · approve · trust\npassphrase (mutual auth,\nnever sent)", bg=C["human"])
    browser = d.box(300, 750, 210, 120, "Browser + passkey\nOS UV prompt\nTouch ID · Windows Hello", bg=C["human"])

    ui = d.box(620, 780, 220, 90, "keygent-ui\nlaunched by broker\norigin bound to child", bg=C["client"])

    d.zone(900, 100, 660, 500, "Trusted core — keygent broker (one per OS user)", C["trusted"])
    ipc = d.box(930, 150, 110, 400, "IPC\n\nUnix socket\n(0700 dir)\n\nNamed pipe\n(user-SID\nDACL)\n\npeer check", bg=C["plain"], size=14)
    d.box(1070, 150, 220, 110, "Auth & policy\npinned allow rules\ngrants + approvals\nmanifest trust", bg=C["plain"])
    d.box(1070, 280, 220, 120, "Audit writer\nHMAC chain + anchor", bg=C["plain"])
    keys = d.box(1070, 420, 220, 130, "Key material\nDEK + HKDF subkeys\nlocked arena\nnon-dumpable", bg=C["secret"])
    d.box(1310, 150, 220, 110, "Redactor\nall encodings\nstreaming", bg=C["plain"])
    d.box(1310, 280, 220, 120, "Passkey verifier\nWebAuthn ES256\nUV + origin pin", bg=C["plain"])
    spawner = d.box(1310, 420, 220, 130, "Spawner\nJob Object (Windows)\nsubreaper (Linux)\nprocess group", bg=C["plain"])
    d.text(930, 562, "Plaintext exists only in here — and in the authorized child's env", size=14, color=RED_INK)

    child = d.box(1310, 680, 220, 120, "Child process\nKEYGENT_STRIPE_LIVE=•••\nenv only, never argv", bg=C["secret"])
    store = d.box(1070, 680, 220, 120, "Per-user storage\nvault.kgt (AEAD)\naudit.jsonl (HMAC)\nowner-only ACL", bg=C["store"])

    d.arrow(hooks, ipc, "r", "l", fb=0.15, label="Redact · MatchPrompt · Grant")
    d.arrow(run, ipc, "r", "l", fb=0.55, both=True, label="Run ⇄ redacted output")
    d.arrow(cli, ipc, "r", "l", fa=0.3, fb=0.8, label="mutual auth")
    d.arrow(browser, ui, "r", "l", both=True, label="WebAuthn")
    d.arrow(ui, ipc, "r", "l", fb=0.95, both=True, label="spawn · assertions")
    d.arrow(spawner, child, "b", "t", both=True, label="spawn + env / output", color=RED_INK)
    d.arrow(keys, store, "b", "t", label="AEAD r/w")

    d.legend(620, 120, [(C["agent"], "untrusted: AI agent side"),
                        (C["client"], "untrusted relay / thin client"),
                        (C["trusted"], "trusted core (broker)"),
                        (C["secret"], "plaintext present"),
                        (C["human"], "human-only factors"),
                        (C["store"], "storage on disk")])
    d.save()


# ── 02 Trust boundaries ──────────────────────────────────────────────────────
def trust_boundaries():
    d = Diagram("02-trust-boundaries", "Trust model — the agent is the same OS user",
                "Every security claim names the tier it holds against (ADR 0003).")
    d.box(40, 110, 380, 130, "T1 · Accidental\nhelpful agent reads .env,\nprints env, echoes a key\n→ PREVENT", bg=C["trusted"])
    d.box(450, 110, 380, 130, "T2 · Generic prompt injection\nenv dumps, curl exfil,\npython os.environ\n→ PREVENT or ASK THE HUMAN", bg=C["store"])
    d.box(860, 110, 380, 130, "T3 · Adaptive attack on keygent\nreads child env, forges hooks\n→ out of scope v1 · detect\n→ Phase 6 egress proxy", bg=C["agent"])

    d.zone(40, 280, 580, 400, "Agent CAN (same uid)", C["agent"])
    d.text(70, 330, "• connect to the broker socket / pipe\n"
                    "• run any keygent subcommand, forge hook JSON\n"
                    "• fake a TTY, unset CLAUDECODE\n"
                    "• edit .keygent.toml, agent settings, shell rc\n"
                    "• replace binaries in user-writable dirs\n"
                    "• read a child's env while it runs (T3)\n"
                    "• act as a software WebAuthn client\n"
                    "• copy vault.kgt for offline guessing\n"
                    "• drive the browser / UI", size=17)
    d.zone(660, 280, 580, 400, "Agent CANNOT", C["trusted"])
    d.text(690, 330, "• know your passphrase\n"
                     "• pass Touch ID / Windows Hello / FIDO2 PIN\n"
                     "• read broker memory (locked, non-dumpable,\n"
                     "  hardened runtime / mitigation policies)\n"
                     "• get plaintext from any broker request\n"
                     "  (Reveal: CLI + passphrase proof only)\n"
                     "• approve a grant (broker observes UV,\n"
                     "  passphrase or passkey itself)\n"
                     "• swap a pinned binary (hash mismatch)\n"
                     "• impersonate the broker to the CLI", size=17)
    d.box(40, 720, 1200, 110,
          "Therefore every decision that matters is made in the broker, gated by: passphrase (challenge-response)\n"
          "· native UV with broker text · console passkey · trusted-manifest hash · pinned allow rules.\n"
          "Hooks, TTY checks, env markers and Claude's own dialog are UX / T1 only.", bg=C["neutral"], size=18)
    d.save()


# ── 03 run sequence ──────────────────────────────────────────────────────────
def run_sequence():
    d = Diagram("03-run-sequence", "Using a secret — keygent run with the default 'approve' policy",
                "The broker itself observes the approval. Plaintext steps in red. The agent only sees handles and redacted output.")
    actors = [("human", "Human", C["human"]), ("agent", "Claude Code\n(agent)", C["agent"]),
              ("hook", "hook pre", C["agent"]), ("run", "keygent run", C["client"]),
              ("broker", "Broker", C["trusted"]), ("child", "Child process", C["secret"])]
    steps = [
        ("agent", "hook", "1  Bash: STRIPE_API_KEY={{keygent:stripe/live}} stripe customers list"),
        ("hook", "broker", "2  GrantCreate{cmd, dialect, cwd}"),
        ("broker", "hook", "3  grant g1 (single use, grant key = cmd·cwd·program·scripts)"),
        ("hook", "agent", "4  updatedInput: keygent run --grant g1  (no command text)"),
        ("broker", "human", "5  Touch ID / Hello prompt: “stripe customers list · stripe/live”"),
        ("human", "broker", "6  approve (or 'keygent approve' / console passkey)"),
        ("agent", "run", "7  exec rewritten command"),
        ("run", "broker", "8  Run{cmd, dialect, cwd, g1} — client env ignored"),
        ("broker", "broker", "9  trust · policy · re-hash scripts · consume grant"),
        ("broker", "child", "10  spawn contained · env KEYGENT_STRIPE_LIVE", RED_INK),
        ("child", "broker", "11  stdout / stderr bytes", RED_INK),
        ("broker", "broker", "12  redact (all encodings) · audit"),
        ("broker", "run", "13  redacted stream + exit code"),
        ("run", "agent", "14  output shows ‹keygent:stripe/live›"),
        ("agent", "broker", "15  PostToolUse → Redact (second pass)"),
    ]
    d.sequence(actors, steps, gap=250, step_h=56)
    d.save()


# ── 04 Key hierarchy & vault format ──────────────────────────────────────────
def key_hierarchy():
    d = Diagram("04-key-hierarchy", "Key hierarchy and vault format",
                "Envelope encryption: unlock factors wrap one random DEK; HKDF separates every purpose.")
    f1 = d.box(40, 110, 260, 70, "Passphrase", bg=C["human"])
    f2 = d.box(340, 110, 260, 70, "Passkey PRF\n(WebAuthn hmac-secret)", bg=C["human"])
    f3 = d.box(640, 110, 260, 70, "Windows Hello · Touch ID\nFIDO2 (user presence)", bg=C["human"])
    k1 = d.box(40, 230, 260, 80, "Argon2id\nm=64 MiB · t=3 · p=4\nparams capped · salt", bg=C["neutral"])
    k2 = d.box(340, 230, 260, 80, "HKDF(PRF output)", bg=C["neutral"])
    k3 = d.box(640, 230, 260, 80, "platform key unwrap\n(TPM / Secure Enclave)", bg=C["neutral"])
    s1 = d.box(40, 360, 260, 60, "KEK slot · passphrase", bg=C["store"])
    s2 = d.box(340, 360, 260, 60, "KEK slot · passkey", bg=C["store"])
    s3 = d.box(640, 360, 260, 60, "KEK slot · hardware", bg=C["store"])
    for f, k, s in ((f1, k1, s1), (f2, k2, s2), (f3, k3, s3)):
        d.arrow(f, k, "b", "t")
        d.arrow(k, s, "b", "t")
    dek = d.box(340, 480, 260, 90, "DEK · 256-bit random\nnever encrypts data directly", bg=C["secret"])
    for s in (s1, s2, s3):
        d.arrow(s, dek, "b", "t", label="unwrap (AAD = header hash)" if s is s2 else "")
    hk = d.box(340, 620, 260, 60, "HKDF-SHA256(DEK, info)", bg=C["neutral"])
    d.arrow(dek, hk, "b", "t")
    subs = [("K_entry", "entries\nXChaCha20-Poly1305\nAAD = uuid‖handle‖ver"),
            ("K_index", "encrypted index\nhandles · policy\ntrust · passkeys"),
            ("K_hdr", "header MAC\n+ generation\n(rollback check)"),
            ("K_audit", "audit log\nHMAC chain"),
            ("K_auth", "CLI → broker\nre-auth proof"),
            ("K_broker", "broker → CLI\nidentity proof")]
    for i, (k, use) in enumerate(subs):
        x = 40 + i * 175
        b = d.box(x, 740, 155, 50, k, bg=C["trusted"], font=3)
        d.arrow(hk, b, "b", "t")
        d.box(x, 820, 155, 90, use, bg=C["plain"], size=14)

    d.zone(1000, 100, 420, 470, "vault.kgt layout", C["neutral"])
    rows = ["magic KGNT · format version", "vault UUID · generation counter",
            "KDF id + capped params + salt", "KEK slots (wrapped DEK) × n", "header MAC (K_hdr)",
            "encrypted index (K_index)", "entries × n (K_entry)"]
    for i, r in enumerate(rows):
        d.box(1030, 150 + i * 56, 360, 46, r, bg=C["store"] if i < 5 else C["secret"], size=15)
    d.text(1030, 548, "atomic replace · file lock · owner-only ACL\nrekey = new DEK · keystore rollback tripwire", size=14)
    d.save()


# ── 05 Unseal & mutual authentication ────────────────────────────────────────
def unseal_auth():
    d = Diagram("05-unseal-and-auth", "Unseal handoff and mutual re-authentication",
                "The passphrase never leaves the process that read it. The broker is the unseal's own child, so it can't be squatted.")
    actors = [("human", "Human", C["human"]), ("cli", "keygent unseal / CLI", C["human"]),
              ("broker", "Broker", C["trusted"]), ("ipc", "IPC endpoint", C["neutral"])]
    steps = [
        ("human", "cli", "1  passphrase (console, echo off)"),
        ("cli", "cli", "2  Argon2id → KEK → unwrap DEK locally"),
        ("cli", "broker", "3  spawn `keygent broker`: cleared env + inherited pipe"),
        ("cli", "broker", "4  DEK over the inherited pipe, then zeroize", RED_INK),
        ("broker", "broker", "5  harden: locked allocator · no dumps · mitigations"),
        ("broker", "ipc", "6  bind exclusively at fixed per-user path (not from env)"),
        ("ipc", "broker", "7  already bound? → refuse to start (anti-squat)"),
        ("human", "cli", "8  later: keygent rotate x  + passphrase"),
        ("cli", "cli", "9  derive K_auth, K_broker locally from vault"),
        ("cli", "broker", "10  hello(nc)"),
        ("broker", "cli", "11  nb, HMAC(K_broker, nc‖nb)"),
        ("cli", "cli", "12  verify broker proof — else abort: fake broker"),
        ("cli", "broker", "13  HMAC(K_auth, nb‖nc‖req) + value (session key)", RED_INK),
        ("broker", "broker", "14  verify (1 s delay on failure) · apply · audit"),
    ]
    d.sequence(actors, steps, gap=380, step_h=56, head_w=220)
    d.save()


# ── 06 Web console with passkeys ─────────────────────────────────────────────
def web_console():
    d = Diagram("06-web-console-passkey", "Web console — passkey login and per-action confirmation",
                "The broker launches the UI and trusts only its origin while that child lives. No reveal, no value entry.")
    actors = [("human", "Human", C["human"]), ("browser", "Browser", C["human"]),
              ("ui", "keygent-ui\n(broker's child)", C["client"]), ("broker", "Broker", C["trusted"])]
    steps = [
        ("human", "broker", "1  keygent ui → UiLaunch"),
        ("broker", "ui", "2  verify UI binary · spawn · bind origin to this child + port"),
        ("ui", "browser", "3  open http://localhost:<port>/#<one-time token>"),
        ("browser", "ui", "4  login"),
        ("ui", "broker", "5  request challenge"),
        ("broker", "ui", "6  c1 (60 s, single use)"),
        ("ui", "browser", "7  credentials.get(c1, UV required)"),
        ("browser", "human", "8  Touch ID / Windows Hello / key PIN"),
        ("browser", "ui", "9  assertion (origin, UV flag, counter, sig)"),
        ("ui", "broker", "10  verify"),
        ("broker", "broker", "11  ES256 · origin == live child's port · UV · counter"),
        ("broker", "ui", "12  session token (header, not cookie) · metadata only"),
        ("human", "browser", "13  click “Approve: stripe customers list”"),
        ("ui", "broker", "14  request action challenge"),
        ("broker", "ui", "15  c2 = H(nonce‖approve‖grant‖cmd hash)"),
        ("browser", "human", "16  UV prompt for this action"),
        ("ui", "broker", "17  assertion over c2 → grant approved · audit"),
    ]
    d.sequence(actors, steps, gap=380, step_h=52, head_w=220)
    d.save()


# ── 07 Platform abstraction ──────────────────────────────────────────────────
def platforms():
    d = Diagram("07-platform-matrix", "Cross-platform security primitives",
                "One `Platform` trait in src/platform/; each OS implements it with its strongest native mechanism.")
    d.box(230, 100, 1240, 120,
          "trait Platform: ipc_listen · ipc_connect · peer_identity · lock_memory · harden_process\n"
          "spawn_contained · forward_signal · kill_tree · secure_dir · secure_file · atomic_replace\n"
          "read_secret_line · canonical_path · user_presence (Phase 6) · clipboard_concealed",
          bg=C["trusted"], font=3, size=16)
    cols = [("Linux", 230), ("macOS", 650), ("Windows", 1070)]
    for name, x in cols:
        d.box(x, 250, 400, 50, name, bg=C["client"], size=20)
    rows = [
        ("IPC", ["Unix socket, $XDG_RUNTIME_DIR/keygent\n0700 dir · SO_PEERCRED",
                 "Unix socket, $TMPDIR/keygent\n0700 dir · getpeereid",
                 "Named pipe keygent-<user SID>\nSID-only DACL · FIRST_PIPE_INSTANCE\nreject remote clients"]),
        ("Memory", ["secret arena (mlock) + mlockall\nzero-on-free allocator",
                    "secret arena (mlock)\nzero-on-free allocator",
                    "secret arena (VirtualLock)\nzero-on-free allocator"]),
        ("Anti-dump /\ninjection", ["PR_SET_DUMPABLE=0 · RLIMIT_CORE=0\nstatic musl (no LD_PRELOAD)",
                                    "PT_DENY_ATTACH · RLIMIT_CORE=0\nhardened runtime (no DYLD_*)",
                                    "OWNER RIGHTS DACL · WER off\nbroker-only mitigations\nSetDefaultDllDirectories"]),
        ("Child\ncontainment", ["process group +\nPR_SET_CHILD_SUBREAPER",
                                "process group + run-id\nsweep (best effort)",
                                "Job Object · KILL_ON_JOB_CLOSE\nno breakaway"]),
        ("Approval\nprompt", ["keygent approve\n(passphrase) · console",
                              "Touch ID (LocalAuthentication)\nwith broker text",
                              "Windows Hello (UserConsent-\nVerifier) with broker text"]),
        ("Files", ["0600 / 0700 · O_NOFOLLOW\nrename + fsync(dir)",
                   "0600 / 0700 · O_NOFOLLOW\nrename + F_FULLFSYNC",
                   "protected owner-only DACL\nno reparse points · ReplaceFileW"]),
        ("Paths", ["realpath · case-sensitive",
                   "realpath · case-insensitive",
                   "final path · case-insensitive\n8.3 names · no ADS · strip \\\\?\\"]),
        ("User presence", ["FIDO2 key · passkey in browser",
                           "Touch ID · passkey (iCloud)",
                           "Windows Hello · passkey"]),
        ("Release signing", ["cosign + provenance",
                             "Developer ID + notarization",
                             "Authenticode"]),
    ]
    for i, (label, cells) in enumerate(rows):
        y = 320 + i * 100
        d.box(40, y, 170, 86, label, bg=C["neutral"], size=16)
        for (name, x), cell in zip(cols, cells):
            d.box(x, y, 400, 86, cell, bg=C["plain"], size=15)
    d.save()


# ── 09 Hook composition (chain composer) ─────────────────────────────────────
def hook_composition():
    d = Diagram("09-hook-composition", "Hook composition — keygent always goes first (ADR 0002)",
                "Claude Code runs matching hooks in parallel, so other tools' hooks are chained behind keygent.")
    d.zone(40, 110, 600, 330, "Before: parallel (unsafe)", C["agent"])
    ev = d.box(70, 170, 160, 70, "Hook event\nprompt / pre / post", bg=C["plain"])
    k1 = d.box(380, 150, 230, 70, "keygent hook\nblock / rewrite / redact", bg=C["trusted"])
    o1 = d.box(380, 260, 230, 70, "lean-ctx hook\nsees RAW data", bg=C["secret"])
    d.arrow(ev, k1, "r", "l")
    d.arrow(ev, o1, "r", "l", color=RED_INK, label="same payload")
    d.text(70, 360, "• observer may store a pasted secret / raw output\n• two updatedInput results: undefined winner", size=15, color=RED_INK)

    d.zone(700, 110, 760, 330, "After: chain composer", C["trusted"])
    ev2 = d.box(730, 170, 160, 70, "Hook event", bg=C["plain"])
    k2 = d.box(940, 160, 230, 90, "keygent hook --chain\n① block / rewrite\n② redact", bg=C["trusted"])
    o2 = d.box(1210, 160, 220, 90, "lean-ctx hook\nonly blocked-out or\nredacted data", bg=C["client"])
    d.arrow(ev2, k2, "r", "l")
    d.arrow(k2, o2, "r", "l", label="cleaned payload")
    d.text(730, 290, "prompt: keygent blocks → lean-ctx never called\n"
                     "pre: lean-ctx -c 'keygent run --grant g1'  (keygent innermost)\n"
                     "decision = most restrictive (deny > ask > allow)\n"
                     "post: lean-ctx observes the redacted output", size=15)
    d.save()


# ── 08 Release pipeline ──────────────────────────────────────────────────────
def release_pipeline():
    d = Diagram("08-release-pipeline", "Release pipeline (runs only when a GitHub release is published)",
                "Run scripts/preflight.sh locally before publishing. Actions are pinned to commit SHAs.")
    a = d.box(40, 140, 220, 100, "GitHub release\npublished", bg=C["human"])
    b = d.box(320, 110, 240, 160, "check × 3 OS\nfmt · clippy · test\n+ cargo-deny\n(Linux · macOS · Windows)", bg=C["neutral"])
    c = d.box(620, 80, 280, 220, "build matrix\nlinux musl x64 · arm64\nmacOS x64 · arm64\nwindows x64 · arm64\nsize budget per target", bg=C["client"])
    e = d.box(960, 110, 240, 160, "SHA256SUMS\ncosign (keyless)\nbuild provenance", bg=C["trusted"])
    f = d.box(1260, 140, 220, 100, "assets attached\nto the release", bg=C["store"])
    d.arrow(a, b)
    d.arrow(b, c)
    d.arrow(c, e)
    d.arrow(e, f)
    d.box(620, 340, 580, 70, "Deferred: macOS notarization · Windows Authenticode  |  install.sh / install.ps1 verify cosign + SHA256",
          bg=C["plain"], style="dashed", size=16)
    d.save()


if __name__ == "__main__":
    for fn in (system_architecture, trust_boundaries, run_sequence, key_hierarchy,
               unseal_auth, web_console, platforms, release_pipeline, hook_composition):
        fn()
