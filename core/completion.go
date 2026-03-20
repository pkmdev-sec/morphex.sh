package synapse

import (
	"fmt"
	"io"
)

// GenerateBashCompletion writes a bash completion script for the MORPHEX CLI
// to w. The script supports all subcommands and their flags.
func GenerateBashCompletion(w io.Writer, binaryName string) error {
	script := `# bash completion for %[1]s                              -*- shell-script -*-

_%[1]s_completions()
{
    local cur prev words cword
    _init_completion || return

    local -r subcommands="version scan scan-git stdin"
    local -r global_flags="--no-color --log-level"

    local -r scan_flags="--json --sarif --threshold --workers --verify --dry-run --raw --model-dir --policy --deep --fail --baseline --create-baseline --redact --include --exclude"
    local -r scan_git_flags="--json --threshold --since --max-commits --workers --branch"
    local -r stdin_flags="--json --threshold"

    # Determine the active subcommand by scanning previous words.
    local subcmd=""
    local i
    for (( i=1; i < cword; i++ )); do
        case "${words[i]}" in
            scan-git|scan|stdin|version)
                subcmd="${words[i]}"
                break
                ;;
        esac
    done

    # Complete flag values that take arguments.
    case "${prev}" in
        --log-level)
            COMPREPLY=( $(compgen -W "error warn info debug trace" -- "${cur}") )
            return
            ;;
        --threshold|--workers|--max-commits|--redact)
            # Numeric - no completions.
            return
            ;;
        --model-dir|--policy|--baseline)
            _filedir
            return
            ;;
        --since)
            # Date - no completions.
            return
            ;;
        --branch)
            # Branch name - no completions.
            return
            ;;
        --include|--exclude)
            # Glob patterns - no completions.
            return
            ;;
    esac

    # If no subcommand yet, complete subcommands and global flags.
    if [[ -z "${subcmd}" ]]; then
        COMPREPLY=( $(compgen -W "${subcommands} ${global_flags}" -- "${cur}") )
        return
    fi

    # Complete flags for the active subcommand.
    case "${subcmd}" in
        scan)
            COMPREPLY=( $(compgen -W "${scan_flags} ${global_flags}" -- "${cur}") )
            [[ ${#COMPREPLY[@]} -eq 0 ]] && _filedir
            ;;
        scan-git)
            COMPREPLY=( $(compgen -W "${scan_git_flags} ${global_flags}" -- "${cur}") )
            [[ ${#COMPREPLY[@]} -eq 0 ]] && _filedir
            ;;
        stdin)
            COMPREPLY=( $(compgen -W "${stdin_flags} ${global_flags}" -- "${cur}") )
            ;;
        version)
            # No flags for version.
            ;;
    esac
}

complete -F _%[1]s_completions %[1]s
`
	_, err := fmt.Fprintf(w, script, binaryName)
	return err
}

// GenerateZshCompletion writes a zsh completion script for the MORPHEX CLI
// to w. The script supports all subcommands and their flags.
func GenerateZshCompletion(w io.Writer, binaryName string) error {
	script := `#compdef %[1]s

__%[1]s_scan_flags() {
    local -a flags=(
        '''--json[Output benchmark-compatible JSON]'''
        '''--sarif[Output in SARIF v2.1.0 format]'''
        '''--threshold[Confidence threshold (default: 0.7)]:threshold:'''
        '''--workers[Concurrent workers (0=auto)]:workers:'''
        '''--verify[Enable AI-powered credential verification]'''
        '''--dry-run[Plan verification but do not execute]'''
        '''--raw[Include unverified findings (debug mode)]'''
        '''--model-dir[Path to DistilBERT ONNX model directory]:directory:_directories'''
        '''--policy[Path to scan policy JSON file]:file:_files'''
        '''--deep[Enable deep scanning]'''
        '''--fail[Exit with code 1 if secrets are found]'''
        '''--baseline[Path to baseline file]:file:_files'''
        '''--create-baseline[Create baseline from current findings]'''
        '''--redact[Redaction percentage 0-100]:redact:'''
        '''--include[Comma-separated glob patterns to include]:patterns:'''
        '''--exclude[Comma-separated glob patterns to exclude]:patterns:'''
    )
    _arguments -s "${flags[@]}" '''*:path:_files'''
}

__%[1]s_scan_git_flags() {
    local -a flags=(
        '''--json[Output JSON]'''
        '''--threshold[Confidence threshold (default: 0.7)]:threshold:'''
        '''--since[Only scan commits after this date]:date:'''
        '''--max-commits[Limit number of commits (0=all)]:count:'''
        '''--workers[Concurrent workers (0=auto)]:workers:'''
        '''--branch[Specific branch to scan]:branch:'''
    )
    _arguments -s "${flags[@]}" '''*:repo:_directories'''
}

__%[1]s_stdin_flags() {
    local -a flags=(
        '''--json[Output JSON]'''
        '''--threshold[Confidence threshold (default: 0.7)]:threshold:'''
    )
    _arguments -s "${flags[@]}"
}

_%[1]s() {
    local -a commands=(
        '''version:Show version info'''
        '''scan:Scan a file or directory for secrets'''
        '''scan-git:Scan git history for secrets'''
        '''stdin:Scan content from standard input'''
    )

    local -a global_flags=(
        '''--no-color[Disable colorized output]'''
        '''--log-level[Logging verbosity]:level:(error warn info debug trace)'''
    )

    _arguments -C \
        "${global_flags[@]}" \
        '''1:command:->command''' \
        '''*::arg:->args'''

    case "${state}" in
        command)
            _describe -t commands '''morphex command''' commands
            ;;
        args)
            case "${words[1]}" in
                scan)
                    __%[1]s_scan_flags
                    ;;
                scan-git)
                    __%[1]s_scan_git_flags
                    ;;
                stdin)
                    __%[1]s_stdin_flags
                    ;;
                version)
                    ;;
            esac
            ;;
    esac
}

_%[1]s "$@"
`
	_, err := fmt.Fprintf(w, script, binaryName)
	return err
}

// GenerateFishCompletion writes a fish completion script for the MORPHEX CLI
// to w. The script supports all subcommands and their flags.
func GenerateFishCompletion(w io.Writer, binaryName string) error {
	script := `# fish completion for %[1]s

# Disable file completions by default; re-enable where needed.
complete -c %[1]s -f

# Helper: true when no subcommand has been given yet.
function __%[1]s_no_subcommand
    set -l cmd (commandline -opc)
    for word in $cmd[2..-1]
        switch $word
            case version scan scan-git stdin
                return 1
        end
    end
    return 0
end

# Helper: true when the given subcommand is active.
function __%[1]s_using_subcommand
    set -l cmd (commandline -opc)
    for word in $cmd[2..-1]
        if test "$word" = "$argv[1]"
            return 0
        end
    end
    return 1
end

# --- Global flags ---
complete -c %[1]s -l no-color -d '''Disable colorized output'''
complete -c %[1]s -l log-level -x -a '''error warn info debug trace''' -d '''Logging verbosity'''

# --- Subcommands ---
complete -c %[1]s -n '''__%[1]s_no_subcommand''' -a version -d '''Show version info'''
complete -c %[1]s -n '''__%[1]s_no_subcommand''' -a scan -d '''Scan a file or directory'''
complete -c %[1]s -n '''__%[1]s_no_subcommand''' -a scan-git -d '''Scan git history'''
complete -c %[1]s -n '''__%[1]s_no_subcommand''' -a stdin -d '''Scan from standard input'''

# --- scan flags ---
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l json -d '''Output benchmark-compatible JSON'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l sarif -d '''Output SARIF v2.1.0 format'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l threshold -x -d '''Confidence threshold (default: 0.7)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l workers -x -d '''Concurrent workers (0=auto)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l verify -d '''Enable AI-powered credential verification'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l dry-run -d '''Plan verification but do not execute'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l raw -d '''Include unverified findings (debug mode)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l model-dir -r -F -d '''Path to ONNX model directory'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l policy -r -F -d '''Path to scan policy JSON file'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l deep -d '''Enable deep scanning'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l fail -d '''Exit with code 1 if secrets found'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l baseline -r -F -d '''Path to baseline file'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l create-baseline -d '''Create baseline from current findings'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l redact -x -d '''Redaction percentage 0-100'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l include -x -d '''Comma-separated include patterns'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -l exclude -x -d '''Comma-separated exclude patterns'''
# Allow file/dir completion for the positional path argument.
complete -c %[1]s -n '''__%[1]s_using_subcommand scan''' -F

# --- scan-git flags ---
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l json -d '''Output JSON'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l threshold -x -d '''Confidence threshold (default: 0.7)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l since -x -d '''Only scan commits after this date'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l max-commits -x -d '''Limit number of commits (0=all)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l workers -x -d '''Concurrent workers (0=auto)'''
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -l branch -x -d '''Specific branch to scan'''
# Allow dir completion for the repo-path argument.
complete -c %[1]s -n '''__%[1]s_using_subcommand scan-git''' -F

# --- stdin flags ---
complete -c %[1]s -n '''__%[1]s_using_subcommand stdin''' -l json -d '''Output JSON'''
complete -c %[1]s -n '''__%[1]s_using_subcommand stdin''' -l threshold -x -d '''Confidence threshold (default: 0.7)'''
`
	_, err := fmt.Fprintf(w, script, binaryName)
	return err
}
