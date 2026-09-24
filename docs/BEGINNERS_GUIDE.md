# SentinelGraph — Beginner's Guide

> Read this top to bottom, slowly. It assumes **zero** prior knowledge about databases,
> Docker, or the command line. Every section explains *what* something is, *why* we do
> it, and *what you should see* when you run it.
>
> Last updated: 25 Sep 2026 — the databases now run **natively on this Mac** (no Docker
> needed for day-to-day work; Docker remains an option for the lab/demo machines).

---

## 1. The one-paragraph version

SentinelGraph is a project that stores cyber-threat information ("which hacker groups
exist, which malware they use, which software vulnerabilities they exploit") in **two
databases that are good at different jobs**, and lets you **ask questions in plain English**
and get answers with **links to the source reports** it based the answer on.

The project = **3 programs running on your computer at the same time**:

| Program | What it is | What it does |
|---|---|---|
| **MongoDB** | A "document" database | Stores long text (reports, descriptions), numbers, logs. Good at storing and aggregating evidence. |
| **Neo4j** | A "graph" database | Stores *things* and *arrows between things* (group → uses → technique). Good at finding paths and connections. |
| **Node.js app** (our code) | The middleman | Lets you talk to both databases through a website + web "API" (a set of URLs the app understands). |

You don't touch the databases directly most of the time — you use the app, and the app
talks to both databases. When you first load the databases with data, we use **script**
commands, and those need the databases to be running.

---

## 2. The "explain like I'm five" version of the whole flow

Think of a **restaurant**:

- **Neo4j (graph DB)** = the kitchen's *ingredient map*: "Flour → used in → Bread → served in → Breakfast". It's about *connections*. Ask it "how does an attacker reach a company that runs Log4j?" and it walks the map: Software → Vulnerability → Malware → Hacker group.
- **MongoDB (document DB)** = the *recipe book*: long texts ("this report says group X exploited Log4j on this date…"). Ask it "show me the actual text that proves this" and it returns paragraphs with sources.
- **The app (Node.js)** = the waiter. You tell the waiter "Which adversary groups exploit Log4j, and how?" The waiter asks the kitchen's map for the route, then asks the recipe book for the evidence, then hands you a written answer with the recipe names (citations) attached.

The whole project = automating this restaurant: loading the map and recipe book from
real public sources (MITRE ATT&CK = a real catalog of hacker groups/malware/techniques;
NVD = the official US government catalog of software vulnerabilities; CISA KEV = "which
of those are known to be actively exploited in the wild").

---

## 3. Why two databases, why not one?

Because the two kinds of questions need two different "shapes" of storage:

- "**How are things connected, over multiple steps?**" (find a path from Log4j to a hacker
  group) → a **graph** does this in milliseconds by following pointers between nodes. A
  document DB would have to search through everything repeatedly.
- "**What does the evidence text say?**" (long reports, similarity search over paragraphs)
  → a **document** store keeps text + numbers naturally and can run "statistical summaries"
  (aggregations) easily.

They share the same IDs (`mitreId` for hacker stuff like `G0016` = APT29, `cveId` for
vulnerabilities like `CVE-2021-44228` = Log4Shell), so the app can bounce between them.

---

## 4. Why are there so many `npm run …` commands?

`npm` is the tool that manages the JavaScript libraries ("packages") the app needs.
`npm run <name>` just runs a pre-defined command from the `package.json` file — you can
open that file and read the "scripts" section; each line is a shortcut.

The commands are **one machine per job on a factory line**. You run them in order once
(after setting up a machine / after wiping a machine). After that you rarely need them.

| Order | Command | What happens (what you'll see) | Needed when |
|---|---|---|---|
| 0 | `npm install` | Downloads the libraries (first time only, ~1–2 min, lots of text) | Once per machine/clone |
| 1 | `npm run ensure-indexes` | Creates "catalogues" (indexes) + "uniqueness rules" (constraints) in both DBs. Output: a list of created index names. | Once per empty database |
| 2 | `npm run ingest:attack` | Loads the MITRE ATT&CK catalog: 1,835 hacker groups/malware/techniques/tactics/mitigations into **both** DBs. Output: "Node counts by label" table. | Once (safe to re-run) |
| 3 | `npm run ingest:nvd` | Loads 4,007 real vulnerabilities (CVEs) + 19,000 software products + 44,000 "Affects" links. Output: counts. | Once (safe to re-run) |
| 4 | `npm run ingest:cisa` | Marks the 183 "known exploited in the wild" vulnerabilities. Output: "marked knownExploited". | Once (safe to re-run) |
| 5 | `npm run seed:software` | Adds industry sectors (Government, Energy…) + links hacker groups → sectors. Output: counts. | Once (safe to re-run) |
| 6 | `npm run seed:users` | Creates the 2 login accounts. Output: "user roles". | Once |
| 7 | `npm run seed:reports` | The slowest (~2–3 min): creates 3,800+ text reports, cuts them into ~500-word "chunks", computes a number-vector for each (embedding). Output: totals JSON. | Once (safe to re-run) |
| 8 | `npm start` | **Starts the actual app** (the thing you demo). Output: "SentinelGraph API listening on http://localhost:3000". | Every time you want to use the app |
| 9 | `npm run demo` | Runs the *entire demo automatically*: counts, CRUD, Q&A, algorithms, aggregations — prints ✔ for every step. | Any time you want a proof run |
| 10 | `npm test` | Runs 24 automated tests (a checklist the app must pass). Output: "24 passed". | After any code change |

**Why so many?** It's the "one job per command" principle: each step is small, safe to
re-run, and if one step fails you fix/re-run only that step instead of everything. The
steps also deliberately match the graded rubric (data loaded, indexes, CRUD, advanced
features), so the demo can *show* each piece working.

**Important:** steps 2–7 are **idempotent** (a fancy word meaning *re-running them creates
no duplicates*). This is a safety feature: if a step fails halfway, just run it again.

---

## 5. Services up or down? (the question you keep asking 😄)

The two databases are **services** — background programs. They only need to be running
*while you are working*:

| Situation | Do this |
|---|---|
| About to run any `ingest/seed` command, `npm start`, `npm test`, `npm run demo` | Make sure services are **UP** |
| Finished working for now | **DOWN** them to save battery/heat |
| First thing in the morning | `brew services start neo4j mongodb/brew/mongodb-community` |
| End of the day | `brew services stop neo4j mongodb/brew/mongodb-community` |

To check what's running at any time:

```bash
brew services list            # shows started/stopped
```

**Does stopping delete anything? No.** Databases keep their data on disk (in
`/opt/homebrew/var/mongodb` and `/opt/homebrew/var/neo4j`). Stopping just pauses them.
Starting takes ~10–20 seconds.

> ⚠️ Note: `brew services start` also makes them auto-start when you log in to the Mac.
> If you'd rather they *never* auto-start, tell me and I'll switch them to manual mode.

---

## 6. Why does my laptop heat up? (the honest answer)

On this Mac, until yesterday, the databases ran inside **Docker = a hidden Linux
computer inside a virtual machine** on top of macOS. That's double work: macOS powers a
virtual Linux machine, and inside it two real database engines churn. That was the main
heat source (and the cause of the freeze before we capped their memory).

**We just switched to native installs** — MongoDB and Neo4j are now installed directly on
macOS like normal Mac apps (via Homebrew). No Linux-in-the-middle, so less CPU and RAM.

Heat still happens when:
- the services are up (Neo4j is a Java program — Java is memory-hungry even idle), and
- you run the heavy steps (ingest + embed) or leave the Neo4j **browser tab** open (a web
  app that constantly redraws a graph).

So the heat-reduction routine is: **services down when idle, close the Neo4j browser tab,
don't run heavy steps while doing other work, plug in + Low Power Mode while working.**

---

## 7. Wait — what about Docker then?

Nothing is lost. Docker was one *way* to run the databases (the way the project plan
originally chose, because it's easy to reproduce on any computer — including the lab
machines where the demo may run). Your data is still saved in Docker volumes on disk.

- **For daily work on your Mac** → native services (what we set up today). Faster, cooler.
- **For the review/lab machine** → `docker compose up -d` still works (the
  `docker-compose.yml` is still in the repo and untouched).
- **Switching between them:** never run both at once (they fight over the same ports).
  To switch to Docker: stop native services, then `docker compose up -d` (that machine's
  volumes still hold the full dataset from before). To switch back: `docker compose down`,
  then start the native services.

---

## 8. Day-by-day workflow (the only commands you'll really use)

```bash
# Start the day
brew services start neo4j mongodb/brew/mongodb-community

# Use the app (dashboard on http://localhost:3000)
npm start

# Prove everything works, anytime
npm run demo          # the 10-minute review demo, automated
npm test              # 24 automated checks

# End of the day
brew services stop neo4j mongodb/brew/mongodb-community
```

Logins for the dashboard: `analyst@vitstudent.ac.in` / `Analyst@123` (analyst) ·
`admin@sentinelgraph.local` / `Admin@123` (admin).

---

## 9. What should you see when you demo (Review 2)

1. `brew services list` → both databases `started`.
2. `npm start` → app on http://localhost:3000 → health check green.
3. Log in (analyst). Go to **Ask** and type:
   `Which adversary groups exploit Log4j, and how?`
   → you get a written answer that names `CVE-2021-44228`, shows the traversal chain, and
   lists **cited sources with links** (CISA/NIST advisory, Microsoft blog, NVD page).
4. **Graph** tab: search `APT29` → a graph appears; click a node → it expands.
5. **Reports** tab: 4 charts (vulnerability severity over months, most-cited sources, …).
6. For the *proving* part (marks), run `npm run demo` and scroll the green ✔s:
   volumes (25,096 nodes, 63,534 relationships), idempotency, CRUD + roles, shortest path
   `Software:log4j → CVE-2021-44228 → Cobalt Strike → PowerShell → APT29`, 5 aggregations,
   Q&A with citations.

The full narrated script lives in `docs/demo-notes.md`.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `npm run …` says it can't connect to a database | Services are down → `brew services list`, then start them. |
| `EADDRINUSE` / "port already in use" when running `npm start` | The app is already running (or a stray process). Stop it (Ctrl+C or `pkill -f "node src/server.js"`). |
| Docker containers AND native services both running → health endpoint flaky | Port conflict: they share 27017/7687/7474. Stop one side. |
| `npm test` shows a random timeout | Services were starting up — wait ~10 s and re-run. |
| You broke the data and want a clean slate | `brew services stop neo4j mongodb/brew/mongodb-community` → delete the data folders → start → run steps 1–7 again. (I can write a `reset` script on request.) |
| Neo4j browser at http://localhost:7474 asks for a password | `neo4j` / `sentinelgraph` |

---

## 11. Glossary (words you'll keep seeing)

| Word | Meaning (plain English) |
|---|---|
| **Database** | A program that stores data on disk and answers questions about it. |
| **MongoDB** | A database that stores "documents" (JSON-like records). It calls a record a *document* and a group of them a *collection*. |
| **Neo4j** | A database that stores *nodes* (things) and *relationships* (arrows between things). It calls queries *Cypher*. |
| **Node / relationship** | In Neo4j: a thing (e.g. `APT29`) and an arrow (e.g. `USES_TECHNIQUE`). |
| **Collection / document** | In MongoDB: a folder of records and one record. |
| **STIX** | A standard file format (JSON) that MITRE publishes its ATT&CK knowledge base in. We parse it and pour it into both DBs. |
| **CVE** | The official ID of a vulnerability: `CVE-2021-44228` (Log4Shell). |
| **KEV (CISA)** | The US government list of vulnerabilities *known to be actively exploited*. |
| **mitreId / cveId** | The shared "passport numbers" that let the two databases talk about the same entity. |
| **API / REST** | A set of URLs the app exposes so other programs (or the dashboard) can talk to it: `POST /api/qa/ask`. |
| **CRUD** | Create, Read, Update, Delete — the four basic operations on any record. |
| **JWT / token** | A small "login pass" the app hands you after signing in; you send it with every request so it knows who you are. |
| **bcrypt** | A way of storing passwords so they're never saved in readable form. |
| **Role (analyst/admin)** | What you're allowed to do: admin can create/delete things; analyst can only read and ask questions. |
| **Index** | A catalogue the database keeps to find records fast (like a book's index). |
| **Constraint** | A rule the database enforces, e.g. "two nodes may not share the same mitreId". |
| **Aggregation** | A multi-step statistical summary query in MongoDB (e.g. "count vulnerabilities per month"). |
| **Chunk** | A ~500-word slice of a long report, stored separately so it can be searched. |
| **Embedding** | Turning text into a long list of numbers (a vector) so the computer can measure "how similar is this text to the question?". |
| **Vector search** | Finding the most similar texts by comparing these number-lists (cosine similarity). |
| **Traversal** | Walking the graph: "from Log4j, who can reach me in ≤ 2 steps?" |
| **Shortest path** | The algorithm that finds the fewest-step route between two nodes. |
| **PageRank / centrality** | Algorithms that rank "how important" a node is by how many others connect to it. |
| **Jaccard similarity** | A simple similarity score: share of common items (here: techniques two hacker groups both use). |
| **Idempotent** | Re-running a command produces the same result — no duplicates, no breakage. |
| **NFR** | "Non-functional requirement" — a performance rule, e.g. NFR1 = traversal under 500 ms. |
| **Docker** | A tool that runs programs in small virtual computers ("containers") so they behave identically on any machine. We used it originally; now native on this Mac, still available for lab machines. |
| **Homebrew / brew** | The Mac app-store for developer tools. `brew install X` installs X. |

---

## 12. Where everything lives (orientation)

```
sentinelgraph/
├── docker-compose.yml      # the Docker description (for lab machines)
├── .env                    # settings: ports, passwords (NEVER share/commit this)
├── package.json            # the list of commands ("scripts") + libraries
├── README.md               # technical documentation (for the team/reviewer)
├── docs/
│   ├── BEGINNERS_GUIDE.md  # ← you are here
│   └── demo-notes.md       # the narration for the Review 2 demo
├── TEAM_RUNDOWN.md         # one-page status for your teammate
├── src/
│   ├── server.js           # the app's front door (the waiter!)
│   ├── routes/             # the URLs the app understands, one file per topic
│   ├── services/           # the brains: ingestion, Q&A, embeddings, algorithms
│   └── scripts/            # the npm run … commands live here
├── tests/                  # the 24 automated tests
└── public/                 # the website (dashboard) you see in the browser
```