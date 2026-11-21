#!/bin/bash
# PreToolUse hook: keep Read/Grep/Glob out of build output. Done here, not as
# Read() deny rules, because those are merged into the sandbox and break make.
in=$(cat)
if [ "$(jq -r .tool_name <<<"$in")" = Glob ]; then
	paths=$(jq -r '.tool_input | (.path // ""), (.pattern // "")' <<<"$in")
else
	paths=$(jq -r '.tool_input | .file_path // .path // ""' <<<"$in")
fi
while IFS= read -r p; do
	[ -n "$p" ] || continue
	p=/${p#"$CLAUDE_PROJECT_DIR"/}/
	case "$p" in
	/build/build/) continue ;;
	/build/*|*/CMakeFiles/*|*/.cache/*|*/.lto/*|*/Testing/*|\
	*/autom4te.cache/*|*/bak/*|*.pch/|*.gch/)
		echo "blocked: $p is build output (see CLAUDE.md)" >&2
		exit 2 ;;
	esac
done <<<"$paths"
exit 0
