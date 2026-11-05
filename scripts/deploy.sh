#!/usr/bin/env bash
#
# license-service 部署脚本（在**服务器上**执行，不是本地）
#
#   bash scripts/deploy.sh              # 备份 -> 拉取 -> 重启 -> 核对
#   bash scripts/deploy.sh --check-only # 只做部署后核对，不拉取、不重启
#   bash scripts/deploy.sh --no-pull    # 不拉代码，只重启并核对
#
# 可用环境变量覆盖：APP_DIR / BASE_URL / BRANCH / PYTHON / DB_PATH / RESTART_CMD /
#                   SKIP_BACKUP / HEALTH_TIMEOUT
#
# 失败时会打印精确的回滚步骤（不自动执行回滚，避免二次事故）。

set -uo pipefail

APP_DIR="${APP_DIR:-/www/wwwroot/license-service}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8765}"
BRANCH="${BRANCH:-main}"
PYTHON="${PYTHON:-python3}"
DB_PATH="${DB_PATH:-$APP_DIR/data/license-service.db}"
RESTART_CMD="${RESTART_CMD:-}"
SKIP_BACKUP="${SKIP_BACKUP:-0}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"

CHECK_ONLY=0
NO_PULL=0

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --check-only) CHECK_ONLY=1 ;;
        --no-pull) NO_PULL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $arg（用 --help 查看用法）" >&2; exit 64 ;;
    esac
done

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '[%s] WARN  %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
fail() { printf '[%s] FAIL  %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

# ---------- 状态读取 ----------

# 输出: <device_count> <active_issues> <schema_version>
read_state() {
    "$PYTHON" - "$DB_PATH" <<'PY'
import sqlite3, sys
path = sys.argv[1]
try:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    devices = conn.execute("SELECT COUNT(*) FROM device_registry").fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM license_issues WHERE status='active'").fetchone()[0]
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    print(devices, active, version)
except Exception as exc:  # noqa: BLE001
    print("ERR", "ERR", "ERR")
    print(f"读取数据库失败: {exc}", file=sys.stderr)
PY
}

expected_schema() {
    grep -E '^SCHEMA_VERSION[[:space:]]*=' "$APP_DIR/license_service/db.py" \
        | head -1 | awk -F'=' '{gsub(/[^0-9]/,"",$2); print $2}'
}

http_code() {
    # $1 = method, $2 = path, $3 = body(可选)
    if [ "$1" = "GET" ]; then
        curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL$2" || echo "000"
    else
        curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X "$1" \
            -H 'Content-Type: application/json' --data-binary "${3:-{}}" "$BASE_URL$2" || echo "000"
    fi
}

wait_health() {
    local waited=0
    while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
        if curl -fsS --max-time 3 "$BASE_URL/api/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

restart_service() {
    if [ -n "$RESTART_CMD" ]; then
        log "重启服务: $RESTART_CMD"
        bash -c "$RESTART_CMD" || return 1
        return 0
    fi

    local panel_py=/www/server/panel/pyenv/bin/python3
    if [ -x "$panel_py" ]; then
        log "重启服务: 宝塔面板 Python 项目接口"
        "$panel_py" - <<'PY'
import sys
sys.path.insert(0, "/www/server/panel/class")
sys.path.insert(0, "/www/server/panel")
import public
from projectModel.pythonModel import main as pyproj

manager = pyproj()
request_obj = public.dict_obj()
request_obj.name = "license-service"
if not manager.get_project_find("license-service"):
    print("面板中找不到 license-service 项目", file=sys.stderr)
    raise SystemExit(1)
if hasattr(manager, "RestartProject"):
    manager.RestartProject(request_obj)
    print("已请求重启")
else:
    manager.StopProject(request_obj)
    manager.StartProject(request_obj)
    print("已请求停止 + 启动")
PY
        return $?
    fi

    fail "没有可用的重启方式：请设置 RESTART_CMD，或在面板里手动重启项目后加 --check-only 重跑"
    return 1
}

rollback_hint() {
    local before_sha="$1" before_schema="$2" after_schema="$3"
    echo
    echo "================ 回滚步骤 ================"
    echo "1) 代码回退： git -C $APP_DIR checkout $before_sha"
    if [ "$before_schema" != "$after_schema" ] && [ "$before_schema" = "1" ] && [ "$after_schema" = "2" ]; then
        echo "2) 数据库回退到 schema v1（v2 只新增了表，回退只需改版本号）："
        echo "   $PYTHON - <<'PY'"
        echo "import sqlite3; c = sqlite3.connect(\"$DB_PATH\")"
        echo "c.execute('PRAGMA user_version = 1'); c.commit()"
        echo "PY"
    else
        echo "2) 数据库 schema：未发生版本变化，无需回退"
    fi
    echo "3) 重启服务，再核对： curl -s $BASE_URL/api/v1/health"
    echo "4) 如需恢复数据：停服 -> 用本次备份覆盖 $DB_PATH（同时删除 -wal/-shm）-> 启动"
    echo "========================================="
}

# ---------- 主流程 ----------

cd "$APP_DIR" 2>/dev/null || { fail "目录不存在: $APP_DIR"; exit 1; }
[ -f "$APP_DIR/license_service/db.py" ] || { fail "$APP_DIR 不是 license-service 仓库"; exit 1; }

BEFORE_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
read -r BEFORE_DEVICES BEFORE_ACTIVE BEFORE_SCHEMA <<<"$(read_state)"
log "当前: commit=$BEFORE_SHA 设备=$BEFORE_DEVICES 有效授权=$BEFORE_ACTIVE schema=$BEFORE_SCHEMA"

if [ "$CHECK_ONLY" -eq 0 ]; then
    if [ "$SKIP_BACKUP" != "1" ]; then
        log "备份数据库（VACUUM INTO）"
        if ! "$PYTHON" scripts/backup_db.py; then
            fail "备份失败，终止部署（设 SKIP_BACKUP=1 可跳过，但不推荐）"
            exit 1
        fi
    else
        warn "已跳过备份（SKIP_BACKUP=1）"
    fi

    if [ "$NO_PULL" -eq 0 ]; then
        log "拉取代码: origin/$BRANCH"
        if ! git fetch --quiet origin "$BRANCH" || ! git merge --ff-only "origin/$BRANCH" >/dev/null; then
            fail "拉取失败（工作区是否干净？）"
            git status --short
            exit 1
        fi
        log "已更新到 $(git rev-parse --short HEAD)：$(git log -1 --format=%s)"
    fi

    restart_service || { fail "重启失败"; rollback_hint "$BEFORE_SHA" "$BEFORE_SCHEMA" "$BEFORE_SCHEMA"; exit 1; }

    if ! wait_health; then
        fail "服务在 ${HEALTH_TIMEOUT}s 内没有恢复健康"
        rollback_hint "$BEFORE_SHA" "$BEFORE_SCHEMA" "$BEFORE_SCHEMA"
        exit 1
    fi
    log "服务已恢复"
fi

# ---------- 核对 ----------

EXPECTED_SCHEMA="$(expected_schema)"
read -r AFTER_DEVICES AFTER_ACTIVE AFTER_SCHEMA <<<"$(read_state)"
errors=0

check() {
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        log "PASS  $name = $actual"
    else
        fail "$name = $actual（期望 $expected）"
        errors=$((errors + 1))
    fi
}

HEALTH_BODY="$(curl -fsS --max-time 5 "$BASE_URL/api/v1/health" 2>/dev/null || echo '')"
if printf '%s' "$HEALTH_BODY" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
    log "PASS  health ok"
else
    fail "health 返回异常: ${HEALTH_BODY:-<空>}"
    errors=$((errors + 1))
fi

check "GET  /licenses/latest" "$(http_code GET /api/v1/licenses/latest)" "405"
check "POST /validate（400=已上线，404=未部署）" "$(http_code POST /api/v1/validate)" "400"
check "GET  /admin" "$(http_code GET /admin)" "200"
check "schema version" "$AFTER_SCHEMA" "$EXPECTED_SCHEMA"
check "设备数（迁移前后应一致）" "$AFTER_DEVICES" "$BEFORE_DEVICES"
check "有效授权数（迁移前后应一致）" "$AFTER_ACTIVE" "$BEFORE_ACTIVE"

if [ "$errors" -eq 0 ]; then
    log "部署核对全部通过：commit=$(git rev-parse --short HEAD) schema=$AFTER_SCHEMA"
    exit 0
fi

fail "核对未通过：$errors 项失败"
rollback_hint "$BEFORE_SHA" "$BEFORE_SCHEMA" "$AFTER_SCHEMA"
exit 2
