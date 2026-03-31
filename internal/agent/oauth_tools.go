package agent

// Anthropic's API blocks specific lowercase tool names (bash, read, write,
// edit) when requests use OAuth bearer tokens. This file wraps tools with
// the capitalized names that the Claude Code client uses so that requests
// are accepted.
//
// Source: https://cchistory.mariozechner.at/data/prompts-2.1.11.md

import (
	"strings"

	"charm.land/fantasy"
)

// claudeCodeToolNames maps crush tool names to their Claude Code equivalents.
var claudeCodeToolNames = map[string]string{
	"bash":  "Bash",
	"read":  "Read",
	"write": "Write",
	"edit":  "Edit",
	"grep":  "Grep",
	"glob":  "Glob",
	"view":  "View",
}

var reverseToolNames = func() map[string]string {
	m := make(map[string]string, len(claudeCodeToolNames))
	for k, v := range claudeCodeToolNames {
		m[strings.ToLower(v)] = k
	}
	return m
}()

// ToClaudeCodeName returns the Claude Code–compatible name for a tool, or the
// original name if no mapping exists.
func ToClaudeCodeName(name string) string {
	if cc, ok := claudeCodeToolNames[strings.ToLower(name)]; ok {
		return cc
	}
	return name
}

// FromClaudeCodeName is the inverse of ToClaudeCodeName.
func FromClaudeCodeName(name string) string {
	if orig, ok := reverseToolNames[strings.ToLower(name)]; ok {
		return orig
	}
	return name
}

// oauthToolWrapper presents a tool under its Claude Code–compatible name.
type oauthToolWrapper struct {
	fantasy.AgentTool
	renamedName string
}

func (w *oauthToolWrapper) Info() fantasy.ToolInfo {
	info := w.AgentTool.Info()
	return fantasy.ToolInfo{
		Name:        w.renamedName,
		Description: info.Description,
		Parameters:  info.Parameters,
	}
}

// WrapToolsForOAuth returns a copy of tools with Claude Code–compatible names
// applied where needed. Call this before passing tools to the agent when using
// an Anthropic OAuth bearer token.
func WrapToolsForOAuth(tools []fantasy.AgentTool) []fantasy.AgentTool {
	out := make([]fantasy.AgentTool, len(tools))
	for i, t := range tools {
		orig := t.Info().Name
		renamed := ToClaudeCodeName(orig)
		if renamed != orig {
			out[i] = &oauthToolWrapper{AgentTool: t, renamedName: renamed}
		} else {
			out[i] = t
		}
	}
	return out
}
