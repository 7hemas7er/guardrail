# Masking reserved terms

Keeps terms that must not leave the machine (host, people, place and client
names) away from the model, wherever they come from: command output, a document
read, a search result, an MCP server reply. `nas-warehouse.lan` becomes
`nas-site1.lan`. It is turned on by creating `~/.config/guardrail/mask.tsv`,
outside any repo, **never** in `.guardrail.json`, which is tracked in projects:

```
# real-term   placeholder
warehouse     site1
```

One pair per line, separated by spaces or a TAB. The term is replaced only as a
whole word (`nas-warehouse` yes, `warehouses` no), regardless of case, and the
placeholder keeps its shape (`WAREHOUSE` → `SITE1`, `Warehouse` → `Site1`). The
placeholder must be a word that appears nowhere else. Without the file, nothing
changes.

To be set at the same time, once per machine, in `~/.claude/settings.json`:

```json
{ "includeGitInstructions": false }
```

Without it, Claude Code puts the git status and recent commits in the context
before any hook runs, and a file name or a commit message reaches the model in
clear. As long as it is missing, guardrail reports it at every session.

Masking is independent of per-project activation: it applies in every folder
where the map exists.

## Turning it on

It requires guardrail 0.9.0 or later (see [Updating](../README.md#updating)).

1. Create the map, one pair per line (here with `warehouse` as the example):

   ```
   mkdir -p ~/.config/guardrail
   printf 'warehouse\tsite1\n' >> ~/.config/guardrail/mask.tsv
   ```

   Pick a placeholder that is not a word already present in your files:
   everything the model writes with that placeholder will be converted to the
   real term.

2. In `~/.claude/settings.json` add `"includeGitInstructions": false`.

3. Open a **new session**: the map is read at every tool call, but the notice that
   explains the placeholders to the model enters only at startup.

To verify, type the real term in the prompt: the prompt must be blocked, with the
placeholder suggested. Then ask the agent to read with `cat` a file that contains
the term: the placeholder must appear in the answer.

Adding a term takes one line in the map, without restarting; masking is switched
off by removing the file. A malformed line stops every tool until you fix it:
that is deliberate, otherwise results would pass through in clear.

⚠️ Commands you run yourself with `!` in the prompt don't go through the hooks,
and their output enters the conversation as is. With masking on, whatever must
not reach the model must not be run with `!`.

## How it works

**Towards the model.** The result of every tool goes through the PostToolUse hook
(`mask.py output`, field `updatedToolOutput`): every string comes out with the
placeholders. The transcript stores the rewritten version, so even a resumed
session does not see the original again. Bash additionally goes through the
`mask.py run` runner, which masks on the way out: it is the only way to cover a
failing command, because a tool error (PostToolUseFailure) cannot be rewritten.

**Towards the machine.** The model writes placeholders and the tools receive real
terms, through the PreToolUse `updatedInput`, which the model doesn't see
(verified: the hook's stdout stays in the local transcript and doesn't enter the
context).

| Tool | Input: placeholder → real term | Result |
|---|---|---|
| Bash | yes, by the runner at execution time: the rewritten command contains only the model's text, because the confirmation and the auto mode classifier (a model) see the rewritten input | masked, even if the command fails |
| Read | the path, if the real file exists | masked. PDF, Office and archives **denied**: the text isn't in the bytes; via Bash `pdftotext file -` / `unzip -p` it comes out masked |
| Grep, Glob | the pattern; the path if it exists | masked |
| Write | the content | masked |
| Edit | **no**: Claude Code checks `old_string` against the file before the hooks run, so an Edit with the placeholder fails on its own. Edit with `sed` via Bash instead; the session notice tells the model | masked |
| MCP | no: a server error may quote the input | masked |
| WebFetch | **denied** towards a masked address: a model reads the page before any hook. For a private resource, `curl` via Bash | masked |
| Agent, WebSearch | no: the input goes to another model or to a search engine | masked |

With the map active, commands that show transformed text (`od`, `xxd`,
`hexdump`, `base64`, `rev`…) are denied too: the filter works on words and
doesn't recognize them there. In the first real trial an agent, trying to
understand a failed Edit, looked at the file's bytes with `od -c` and read the
term letter by letter.

A prompt containing a real term is blocked by the `UserPromptSubmit` hook: a hook
cannot rewrite it, only stop it.

**What it doesn't cover, and no hook can:** the content of images (screenshots,
photos); the context Claude Code injects by itself (CLAUDE.md, files mentioned
with `@`, the output of commands run with `!`, the git status if
`includeGitInstructions` stays on); a text transformation made on purpose to
evade the filter. It protects against accidental exposure, not against an agent
looking for it.

The `guard.py` rules evaluate the input with the real terms, so a
`prod_patterns` entry written on the real name keeps working; reasons and logs
come out masked. Masking does **not** follow `GUARDRAIL_DISABLE`: it is switched
off by removing the map. A map that exists but is unreadable or inconsistent
blocks **every** tool, instead of letting its result through in clear.

Costs: the Bash command runs in a separate `bash -c`, so a `cd` doesn't survive
to the next command and Claude Code's shell functions are not there; the
prefix-based `allow` rules in the settings no longer match the rewritten command,
so confirmations increase. The hooks run on every tool call: with no map they
exit immediately.
