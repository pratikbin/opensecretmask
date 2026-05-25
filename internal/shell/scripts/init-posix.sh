# opensecretmask shell integration — managed by `osm shell install`.
# Re-run `osm shell install` after editing wrapped-tool list.
# Remove with `osm shell uninstall`.

claude() { _osm_wrap claude "$@"; }
codex()  { _osm_wrap codex  "$@"; }
pi()     { _osm_wrap pi     "$@"; }

_osm_wrap() {
  local cmd="$1"; shift
  if ! command -v "$cmd" >/dev/null 2>&1; then
    command "$cmd" "$@"
    return $?
  fi
  if ! command -v osm >/dev/null 2>&1; then
    printf "\033[43;30mWarning:\033[0m osm not on PATH; %s runs unmasked.\n" "$cmd" >&2
    command "$cmd" "$@"
    return $?
  fi
  if [ -z "${OSM_QUIET:-}" ] && [ -t 2 ]; then
    printf "\033[36mosm:\033[0m wrapping '%s' via osm run (set OSM_QUIET=1 to silence)\n" "$cmd" >&2
  fi
  osm run -- "$cmd" "$@"
}
