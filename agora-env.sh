#!/usr/bin/env bash
# agora-env.sh — load simple KEY=value defaults for local Agora helper scripts

resolve_agora_env_file() {
    local workdir="${1:-$(pwd)}"
    printf '%s' "${AGORA_ENV_FILE:-$workdir/.agora-env}"
}

load_agora_env_defaults() {
    local workdir="${1:-$(pwd)}"
    local env_file
    env_file="$(resolve_agora_env_file "$workdir")"

    if [ ! -f "$env_file" ]; then
        return 0
    fi

    local line name value
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*)
                continue
                ;;
        esac

        if [[ "$line" != *=* ]]; then
            continue
        fi

        name="${line%%=*}"
        value="${line#*=}"

        if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            continue
        fi

        if [ -n "${!name+x}" ]; then
            continue
        fi

        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:-1}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:-1}"
        fi

        export "$name=$value"
    done < "$env_file"
}

extract_agora_agent_id() {
    awk '
        /^[[:space:]]*Agent ID:/ {
            sub(/^[[:space:]]*Agent ID:[[:space:]]*/, "", $0)
            print
            found = 1
            exit
        }
        /^[[:space:]]*Identity:/ {
            next
        }
        /^[[:space:]]*$/ {
            next
        }
        {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            print
            found = 1
            exit
        }
    '
}
