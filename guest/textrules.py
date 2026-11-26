"""Text rules shared by the static checks (claude_checks.py), the MCP probe (mcp_probe.py) and the runtime analysis
(analyze_dynamic.py): instructions aimed at an AI, and invisible characters. Stdlib only, no side effects on import.
Importers put this folder on sys.path themselves: python3 -I leaves it off."""
import re

R = lambda s: re.compile(s, re.I)

# (severity, category, regex, detail): text an AI will read (agent instructions, MCP tool descriptions)
AI_TEXT_RULES = [
    ('high', 'prompt-injection', R(r'ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts)'), 'instruction override'),
    ('high', 'prompt-injection', R(r"(do not|don't|never) (tell|inform|mention|show|reveal|alert)[^\n]{0,30}(the )?user"), 'asks the AI to hide something from the user'),
    ('high', 'prompt-injection', R(r'without (asking|prompting|confirmation|telling)'), 'asks the AI to act without confirmation'),
    ('high', 'prompt-injection', R(r'(this|the) (skill|plugin|repo|repository|code|tool|package) (is|has been) (safe|verified|audited|trusted|approved)'), 'self-declared safety (aimed at reviewers)'),
    ('high', 'prompt-injection', R(r'(security )?(reviewer|auditor|scanner|ai model|language model|assistant)s?[,:]? (should|must|please)'), 'text addressed to an AI reviewer'),
    ('medium', 'prompt-injection', R(r'you are now|new instructions|system prompt|<\s*/?\s*(system|instructions?)\s*>'), 'role/system-prompt manipulation'),
]

# Extra rules for what an MCP server tells the client at runtime (tool/prompt/resource text, server instructions).
# Kept apart from AI_TEXT_RULES: phrases like "always call X first" are normal in a SKILL.md but are the classic
# tool-poisoning pattern in a tool description, which should only describe that one tool.
MCP_TEXT_RULES = [
    ('high', 'mcp-tool-poisoning', R(r'<\s*/?\s*(important|critical|secret|hidden)\s*>'), 'tag used to smuggle instructions into a tool description'),
    ('high', 'mcp-tool-poisoning', R(r'~/?\.ssh|id_(rsa|ed25519|ecdsa)|\.aws/|\.netrc|\.npmrc|\.git-credentials|\.env\b|mcp\.json|\.claude(/|\.json)|claude_desktop_config|keychain'), 'mentions credential or agent-config files'),
    ('medium', 'mcp-tool-poisoning', R(r'before (using|calling|you (use|call|run)|running|any)\b[^\n]{0,40}\b(tool|other|this|any)\b'), 'tells the AI what to do before using a tool (cross-tool instruction)'),
    ('medium', 'mcp-tool-poisoning', R(r'\b(always|must|first)\b[^\n]{0,20}\b(call|use|run|read|send|pass|include)\b[^\n]{0,40}\b(tool|file|contents?|conversation|history|token|key|password)'), 'orders the AI to call, read or send something'),
    ('medium', 'mcp-tool-poisoning', R(r'\b(send|forward|include|append|pass)\b[^\n]{0,40}\b(conversation|chat history|previous messages|system prompt|api key|token|password|credentials?)\b'), 'asks for conversation or secrets to be sent along'),
]

# Invisible or text-hiding characters: ANSI escape (ESC starts terminal sequences that hide or overwrite text),
# Unicode tags, bidi controls, zero-width characters. Written as escapes: this file must stay ASCII (CI checks).
HIDDEN_UNI = re.compile('[\x1b\U000E0000-\U000E007F\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\u180E]')


def hidden_severity(ch):
    """Tag characters (invisible ASCII copies) > bidi overrides and ANSI escape > zero-width characters."""
    o = ord(ch)
    return 'critical' if 0xE0000 <= o <= 0xE007F else ('high' if 0x202A <= o <= 0x2069 or o == 0x1B else 'medium')
