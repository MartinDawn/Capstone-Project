#!/usr/bin/env bash
# ============================================================
# VDAM Master Orchestration Script (Bash / Linux & Remote VM)
# ============================================================
# Usage:
#   ./manage.sh <local|bank|tpp|wallet> prepare <baseline>   Build images and create containers, stopped
#   ./manage.sh <local|bank|tpp|wallet> start   <baseline>   Start prepared containers (no rebuild)
#   ./manage.sh <local|bank|tpp|wallet> stop    <baseline>   Stop containers, keep them for the next start
#   ./manage.sh <local|bank|tpp|wallet> down    <baseline>   Remove containers and networks (volumes are kept)
#   ./manage.sh stop [all | b0 | b1-classical | b1-pqc]      Stop, keep containers
#   ./manage.sh down [all | b0 | b1-classical | b1-pqc]      Remove containers
#   ./manage.sh status
# <baseline> is b0, b1-classical or b1-pqc (the wallet role has no b0).
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    . "$SCRIPT_DIR/.env"
    set +a
fi

show_help() {
    echo "============================================================"
    echo "  VDAM Master Orchestration CLI (Local & Multi-VM)"
    echo "============================================================"
    echo "Usage:"
    echo "  ./manage.sh <local|bank|tpp|wallet> prepare <baseline>  Build images, create containers (stopped)"
    echo "  ./manage.sh <local|bank|tpp|wallet> start   <baseline>  Start prepared containers (no rebuild)"
    echo "  ./manage.sh <local|bank|tpp|wallet> stop    <baseline>  Stop containers (kept for the next start)"
    echo "  ./manage.sh <local|bank|tpp|wallet> down    <baseline>  Remove containers and networks"
    echo "  ./manage.sh stop [all | b0 | b1-classical | b1-pqc]     Stop containers of a baseline"
    echo "  ./manage.sh down [all | b0 | b1-classical | b1-pqc]     Remove containers of a baseline"
    echo "  ./manage.sh status                                      Show all VDAM containers"
    echo "  baseline: b0 | b1-classical | b1-pqc (the wallet role has no b0)"
    echo ""
}

get_compose_file() {
    local role="$1"
    local base="$2"

    case "$role" in
        local)
            case "$base" in
                b0)           echo "$SCRIPT_DIR/traditional-fapi/docker-compose.yml" ;;
                b1-classical) echo "$SCRIPT_DIR/wallet-vc-model-classical/docker-compose.yml" ;;
                b1-pqc)       echo "$SCRIPT_DIR/wallet-vc-model/docker-compose.yml" ;;
                *) echo "" ;;
            esac
            ;;
        bank)
            case "$base" in
                b0)           echo "$SCRIPT_DIR/traditional-fapi/docker-compose.bank.yml" ;;
                b1-classical) echo "$SCRIPT_DIR/wallet-vc-model-classical/bank/docker-compose.yml" ;;
                b1-pqc)       echo "$SCRIPT_DIR/wallet-vc-model/pqc-bank/docker-compose.yml" ;;
                *) echo "" ;;
            esac
            ;;
        tpp)
            case "$base" in
                b0)           echo "$SCRIPT_DIR/traditional-fapi/docker-compose.tpp.yml" ;;
                b1-classical) echo "$SCRIPT_DIR/wallet-vc-model-classical/tpp/docker-compose.yml" ;;
                b1-pqc)       echo "$SCRIPT_DIR/wallet-vc-model/pqc-tpp/docker-compose.yml" ;;
                *) echo "" ;;
            esac
            ;;
        wallet)
            case "$base" in
                b1-classical) echo "$SCRIPT_DIR/wallet-vc-model-classical/wallet/docker-compose.yml" ;;
                b1-pqc)       echo "$SCRIPT_DIR/wallet-vc-model/pqc-wallet/docker-compose.yml" ;;
                *) echo "" ;;
            esac
            ;;
        *)
            echo ""
            ;;
    esac
}

show_status() {
    echo ""
    echo "=== Active VDAM Containers ==="
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "fapi|classical|pqc|NAMES" || true
}

# Baseline-wide operations. `verb` is "stop" (containers are kept) or "down" (containers are removed).
each_compose() {
    local verb="$1" base="$2" role="" file=""
    for role in local bank tpp wallet; do
        file=$(get_compose_file "$role" "$base")
        if [ -n "$file" ] && [ -f "$file" ]; then
            docker compose -f "$file" "$verb" 2>/dev/null || true
        fi
    done
}

stop_baseline() {
    local verb="$1" base="$2"
    echo "Running '$verb' for: $base..."
    case "$base" in
        b0|b1-classical|b1-pqc)
            each_compose "$verb" "$base"
            ;;
        all|*)
            stop_baseline "$verb" "b0"
            stop_baseline "$verb" "b1-classical"
            stop_baseline "$verb" "b1-pqc"
            ;;
    esac
    echo "Done."
}

TARGET="${1:-help}"
ACTION="${2:-}"
BASELINE="${3:-}"

case "$TARGET" in
    status)
        show_status
        exit 0
        ;;
    stop|down)
        stop_baseline "$TARGET" "${ACTION:-all}"
        exit 0
        ;;
    local|bank|tpp|wallet)
        case "$ACTION" in
            prepare|start|stop|down)
                if [ -z "$BASELINE" ]; then
                    echo "Error: Baseline is required (e.g. b0, b1-classical, b1-pqc)."
                    show_help
                    exit 1
                fi
                COMPOSE_FILE=$(get_compose_file "$TARGET" "$BASELINE")
                if [ -z "$COMPOSE_FILE" ] || [ ! -f "$COMPOSE_FILE" ]; then
                    echo "Error: Compose file not found for Target '$TARGET' and Baseline '$BASELINE'."
                    exit 1
                fi
                ENV_ARG=""
                if [ -f "$SCRIPT_DIR/.env" ]; then
                    ENV_ARG="--env-file $SCRIPT_DIR/.env"
                fi
                echo "[$ACTION] $TARGET / $BASELINE using: $COMPOSE_FILE"
                case "$ACTION" in
                    prepare)
                        # Build the images and create the containers without starting them.
                        docker compose $ENV_ARG -f "$COMPOSE_FILE" up --no-start --build </dev/null
                        ;;
                    start)
                        # Starts the prepared containers; never rebuilds, so a measurement never waits on a build.
                        if ! docker compose $ENV_ARG -f "$COMPOSE_FILE" up -d --no-build </dev/null; then
                            echo "Error: start failed. If the images do not exist yet, run: ./manage.sh $TARGET prepare $BASELINE"
                            exit 1
                        fi
                        show_status
                        ;;
                    stop)
                        docker compose $ENV_ARG -f "$COMPOSE_FILE" stop
                        ;;
                    down)
                        docker compose $ENV_ARG -f "$COMPOSE_FILE" down
                        ;;
                esac
                echo "[$ACTION] $TARGET / $BASELINE done."
                exit 0
                ;;
        esac
        ;;
esac

show_help
