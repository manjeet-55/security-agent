# Demo: the guided scan

What you show: run `secagent` in a project folder, answer a few questions, watch the scan, open the PDF report.

## Before the demo (once)

```bash
cd secagent
npm install
npm run build
npm link                      # puts the `secagent` command on your PATH
npm run demo:setup -- ~/demo-shop     # a sample project that leaks in four ways
```

If you skip `npm link`, use `node /path/to/secagent/dist/cli.js` wherever the steps below say `secagent`.

## On stage

Terminal 1, the weak website to scan:

```bash
npm run demo:server           # http://127.0.0.1:8080
```

Terminal 2, the guided scan:

```bash
cd ~/demo-shop
secagent
```

Answer the questions:

| Question | Answer |
|---|---|
| Project name | Enter |
| What should I check? | arrows + space to tick **Deployed websites or APIs** (code is already ticked), Enter |
| Address of the deployed website | `http://127.0.0.1:8080` |
| ... is an internal address. Scan it anyway? | `y` (it is your own machine) |
| Website or API? / Environment | Enter / pick **Development** |
| Add another website or API? | Enter (no) |
| Where are you scanning from? | Enter (office) |
| I own these systems or have written permission to test them | `y` |

Then it scans (20 checks, one line each), shows the verdict, the three things to fix first and where the reports are, and offers **Open the PDF report**.

What to point out:

- It asked for what it needs; nothing was typed into a config file.
- Nothing was probed before the "I have permission" question.
- Findings read in plain words: what we found, why it matters, how to fix it.
- Secrets never appear, only file, line and a fingerprint. Open `src/config.js` in the demo project to see the real (fake) key next to the report.
- `?` lines are checks that could not run (here: TLS on a plain-HTTP site). They are listed under "Could not verify", never counted as passed.

Run `secagent` again in the same folder: it offers **Scan again**, **Change the settings** or **Start over**.

Reports are in `.secagent/reports/latest.md` and `latest.pdf` inside the project folder.
