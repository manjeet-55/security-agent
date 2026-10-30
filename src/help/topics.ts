/** Step-by-step guides for jobs that take more than one command: `secagent help <guide>` and the home screen's "How secagent works". */
export interface Guide {
  name: string;
  title: string;
  /** Paragraphs and numbered steps, as printed. */
  body: string;
}

export const GUIDES: readonly Guide[] = [
  {
    name: 'first-scan',
    title: 'Your first scan',
    body: `1. Open a terminal in your project folder and run:  secagent
2. Answer the questions: the project name, what to check (code, websites, servers), the addresses, where you are scanning from.
3. Confirm that you own the systems or have written permission to test them. Nothing on the network is touched before this.
4. Watch the checks run: ✓ passed, ✗ failed, ? could not check.
5. Read the verdict and "Fix first". The full report is in .secagent/reports/ as PDF, HTML and Markdown.
6. Fix the top item, run secagent again and choose "Scan again". The report then says what was fixed, what is new and what regressed.

Every later run of secagent opens the home screen: where the project stands and the step I suggest next.`,
  },
  {
    name: 'servers',
    title: 'Checking a server',
    body: `I never log in to your servers. You run a read-only script on each one and bring its output back.

1. List the server: run secagent, choose "Settings and setup" → "Change what is checked", tick Servers, enter its name and address.
2. Get the script: home screen → "Add a server's collector output", or  secagent collector --host web-1 --out collect.sh
3. Read the script, copy it to the server and run it there:  sudo sh collect.sh > web-1.json
4. Bring web-1.json back and add it: home screen → "Add a server's collector output", or  secagent snapshot add --host web-1 web-1.json
5. Scan again. I check SSH and nginx settings, reachable admin and database ports, pending security updates and packages with advisories.

Collector output older than 7 days is stale: run the script again.
To check a scanner's CVE claim against the server's real packages:  secagent verify --host web-1 --cve CVE-2024-6387`,
  },
  {
    name: 'ai',
    title: 'Using secagent with an AI assistant',
    body: `An AI assistant (Claude Code, Cursor, any MCP client) can run the scan, explain the findings and help fix them. I still decide every status; the assistant cannot change what is probed or accept a risk.

1. Set the project up once: run secagent in the folder and confirm the websites and servers.
2. Print the connect command:  secagent mcp setup   (or home screen → "Connect an AI assistant")
3. Run what it prints, e.g.  claude mcp add secagent -- secagent mcp --dir /path/to/project
4. Ask your assistant: "Run a security review of this project". In Claude Code with the secagent plugin:  /security-review
5. For what the scan cannot see, the assistant works through the review checklist with your code and labels its answers as its own review.`,
  },
  {
    name: 'ci',
    title: 'Running secagent in CI',
    body: `The code checks need nothing from your websites or servers, so they suit every pull request.

1. Commit .secagent/project.yaml (run secagent once on your machine, or  secagent init  in the pipeline).
2. Check out the full git history (the secrets-in-history check needs it) and run:
     secagent scan --only code --fail-on high
   It exits 1 when an open finding is high or critical, and writes the report to .secagent/reports/.
3. Keep .secagent/reports/latest.pdf as a build artifact.

docs/usage.md (Recipes, "CI gate on every pull request") has a complete GitHub Actions workflow.`,
  },
  {
    name: 'safety',
    title: 'What secagent touches, and what it never does',
    body: `• Scope: I only probe the websites and servers listed in .secagent/project.yaml, and refuse any other address, including one a page redirects to.
• Permission: nothing on the network is touched until you confirm you own the systems or have written permission to test them. Your yes is stored outside the project (~/.config/secagent/consent.json).
• Read-only: GET and HEAD requests, TLS handshakes and TCP connection tests. No logins, no form posts, no guessing passwords.
• Private addresses need an extra yes; cloud metadata addresses (169.254.169.254) are never probed.
• Your data: code and files stay on your machine. Only package names and versions go to public advisory databases (OSV, Ubuntu Security, CISA).
• Secrets: output shows the file, line and a short fingerprint, never the value.
• Servers: I never log in. You run a read-only script there and bring its output back.`,
  },
];
