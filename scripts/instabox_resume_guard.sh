#!/usr/bin/env bash
# instabox 盒子续命守卫 —— 把被挂起的盒子叫醒。
#
# 为什么需要它：免费档盒子单次运行上限 480 分钟（maxRunMinutes 被锁死 480，
# 只有 admin 会话能改，见 PATCH /v1/machines/{id} 的 permission_denied），
# 到点必被平台挂起；resume 之后计时器重置，再跑满 480 分钟。
#
# 为什么要两个副本：华为云上的 minimax_farm_watchdog.sh 是主防线，但它跑在
# 一台会 swap 活锁、会被 OOM group-kill 的机器上——它自己先死，盒子就没人管。
# 这个脚本 + GitHub Actions 是**异地备份**：CI 跑在 GitHub 的机器上，不依赖
# 任何一台自有服务器活着，也不占 Mac 的常驻进程。
#
# 本地与 CI 共用同一份逻辑，避免两边行为漂移。
#
# ── 时序模型（改这个脚本前先读这段）────────────────────────────
# 停机时刻 = runStartedAt + maxRunMinutes，是完全确定的。
# resume 完成后 runStartedAt 重置为**完成时刻**，所以：
#     下轮停机时刻 = 上轮 resume 完成时刻 + 480min
# 而 480min = 16 × 30min（cron 网格周期），所以「停机时刻相对 cron 网格的
# 相位」每轮恒定、不累积漂移 —— 这让对齐是可行的。
#
# 已知平台语义（2026-10-29 实测）：
#   - 对 running 的盒子调 resume → 409 machine_is_not_paused
#     ⇒ **不能提前 resume**，必须等盒子真的挂起
#   - 对 suspended 的盒子调 resume → 202，随后异步恢复
#   - ⚠️ **平台 8h 到点自动挂起时，desiredState 也会被置成 suspended**
#     （17:22:22 CST 实测：state=suspended desired=suspended
#      runStartedAt=null cooldownUntil=挂起时刻+15min）
#     ⇒ desiredState **不是**"人为停机"的可靠信号。早期版本拿
#      `desiredState != running` 当否决条件，结果每次平台挂起都被
#      误判成"有人故意停的"而跳过唤醒 —— 备份防线等于没建。
#     现在按 state 判定挂起；desiredState 只记日志。
#     真要人工停机时用 INSTABOX_MANUAL_STOP=1 显式豁免。
#   - 挂起后有 cooldownUntil（挂起 + 15 分钟）冷却期。本脚本**不 sleep
#     等冷却**：一天 3 次事件 × 15 分钟 = 2700 分钟/月，超 Actions 免费档
#     2000 分钟。等冷却这件事交给华为云侧看门狗（不消耗 Actions 配额），
#     本脚本只在冷却已过时唤醒，保住「每轮 ≤1 分钟」的配额预算。
#   ⇒ 正确做法：算准停机时刻 → 等到那一刻之后 → 确认已挂起 → resume
#
# 环境变量：
#   INSTABOX_API_KEY    必填，instabox API key
#   INSTABOX_BOX        盒子名，默认 minimax-farm
#   INSTABOX_API_URL    默认 https://api.instabox.sh
#   INSTABOX_FORCE      1 = 不看状态判定，直接 resume（仅排障用）
#   INSTABOX_ALIGN      对齐窗口（秒），默认 240
#
# 退出码：0 = 盒子在跑、或已成功唤醒、或本次无需动作；1 = 唤醒失败

set -uo pipefail

API="${INSTABOX_API_URL:-https://api.instabox.sh}"
BOX="${INSTABOX_BOX:-minimax-farm}"
KEY="${INSTABOX_API_KEY:-}"
FORCE="${INSTABOX_FORCE:-0}"
RETRY="${INSTABOX_RETRY:-4}"
# 对齐窗口（秒）：距停机时刻在这个范围内就等到点再唤醒。
#
# 时序模型：resume 完成后 runStartedAt 重置为**完成时刻**，故
#   下轮停机 = 上轮 resume 完成时刻 + 480min
# 480min = 16 个 30min cron 网格周期 ⇒ 「停机相对网格的相位」每轮恒定，
# 不累积漂移。稳态下相位锁定在 (30min - C)，C = 平台恢复耗时（~45s），
# 于是每次触发时「距停机」都是负的 ~29 分钟 → 走「已挂起即唤醒」路径，
# 空转 ≈ 29min（8h 周期的 6%）。
#
# 本窗口覆盖的是**相位漂移**（平台恢复耗时波动）：一旦某轮网格点恰好落进
# [停机-C, 停机] 区间，就等到点精确唤醒，把那一次的空转压到几秒。
# 稳态下不触发 ⇒ 不 sleep ⇒ 不额外占配额。
ALIGN="${INSTABOX_ALIGN:-120}"
# 等挂起的宽限（秒）：平台可能在标称停机时刻之后才真正挂起。
GRACE="${INSTABOX_GRACE:-120}"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

if [ -z "$KEY" ]; then
    log "缺少 INSTABOX_API_KEY"
    exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# ⚠️ 绝不 echo $KEY —— CI 的 job log 对有仓库权限的人可见。
# 认证头用 Authorization: Bearer（CLI 走的就是这条；X-API-Key 也通）。
api_get() {
    curl -sS -m 25 -o "$TMP" -w '%{http_code}' \
        -H "Authorization: Bearer ${KEY}" \
        -H 'Accept: application/json' \
        "${API}$1" 2>/dev/null
}

read_field() { jq -r "$1 // \"\"" "$TMP" 2>/dev/null; }

# ── 查状态 ──────────────────────────────────────────────────────
# 源站是 AWS ELB，会周期性抽风（单次调用 0.8s ~ 13s 都见过），
# 失败要重试——不能把一次抖动当成"盒子没了"。
code=""
for attempt in $(seq 1 "$RETRY"); do
    code="$(api_get "/v1/machines/${BOX}")"
    [ "$code" = "200" ] && break
    log "查询盒子状态失败 (HTTP ${code:-连接错误})，重试 ${attempt}/${RETRY}"
    sleep $(( attempt * 3 ))
done
if [ "$code" != "200" ]; then
    log "查询状态最终失败 (HTTP ${code:-连接错误})，本轮放弃"
    exit 1
fi

state="$(read_field '.state')"
desired="$(read_field '.desiredState')"
mid="$(read_field '.id')"
started="$(read_field '.runStartedAt')"
maxrun="$(read_field '.maxRunMinutes')"
cooldown="$(read_field '.cooldownUntil')"

log "state=${state} desired=${desired} runStartedAt=${started} maxRunMinutes=${maxrun} cooldownUntil=${cooldown}"

# 人工停机豁免：确实要手动停掉盒子时置 1（CI 侧用 repo variable 传）。
# 没有这个口子就没法在不改代码的前提下停机。
if [ "${INSTABOX_MANUAL_STOP:-0}" = "1" ]; then
    log "INSTABOX_MANUAL_STOP=1，人工停机豁免生效，不自动拉起"
    exit 0
fi

# ⚠️ 不要再用 `desiredState != running` 当否决条件。
#    实测（2026-10-29 17:22:22 CST，8h 到点自动挂起）：平台挂起时平台
#    **也会**把 desiredState 置成 suspended，和人为 stop 完全一样。
#    早先版本拿它当"意图信号"，结果每次平台挂起都被判成"有人故意停的"
#    而跳过唤醒 —— 这条备份防线等于没建。判据统一用 state。
desired_note="仅记录，不作判据（平台挂起时它同样是 suspended）"

# ── 冷却期 ──────────────────────────────────────────────────────
# 挂起后平台给一个 cooldownUntil（实测 = 挂起时刻 + 15 分钟）。
# 冷却没过就 resume 会被平台拒。
# ⚠️ 本脚本刻意**不 sleep 等冷却**：Actions 免费档 2000 分钟/月，
#    一天 3 次事件 × 15 分钟 = 2700 分钟，直接超额度。
#    等冷却交给华为云侧看门狗（它不消耗 Actions 配额），
#    本脚本只在冷却已过时唤醒，保持「每轮 ≤1 分钟」的配额预算。
#
# 剩余秒数（<=0 表示不在冷却期）；拿不到就当 0（宁可试一次，平台会拒）。
cooldown_left() {
    local c="$1" left
    [ -n "$c" ] && [ "$c" != "null" ] || { echo 0; return; }
    left="$(python3 - "$c" <<'PY' 2>/dev/null
import sys, datetime
try:
    t = datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
    print(int((t - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
except Exception:
    print(0)
PY
)"
    case "$left" in ''|*[!0-9-]*) left=0 ;; esac
    echo "$left"
}

# 强制模式：不管状态，直接尝试 resume（仅排障用）
if [ "$FORCE" = "1" ]; then
    log "FORCE=1，跳过状态判定，直接尝试 resume"
    state="suspended"
fi

# ── 算停机时刻 ──────────────────────────────────────────────────
STOP_AT=""
if [ -n "$started" ] && [ "$started" != "null" ] && [ "$maxrun" != "null" ] && [ -n "$maxrun" ]; then
    STOP_AT="$(python3 - "$started" "$maxrun" <<'PY' 2>/dev/null
import sys, datetime
started, maxrun = sys.argv[1], sys.argv[2]
try:
    t = datetime.datetime.fromisoformat(started.replace("Z", "+00:00"))
    print(int((t + datetime.timedelta(minutes=int(maxrun))).timestamp()))
except Exception:
    print("")
PY
)"
fi

now="$(date -u +%s)"

# ── 等待挂起（不能提前 resume：对 running 盒子调 resume 返回 409）────
wait_until_suspended() {
    # 返回 0 = 已挂起；1 = 超时仍在跑
    local deadline=$(( $(date -u +%s) + $1 ))
    while [ "$(date -u +%s)" -lt "$deadline" ]; do
        [ "$(api_get "/v1/machines/${BOX}")" = "200" ] || { sleep 10; continue; }
        local st; st="$(read_field '.state')"
        case "$st" in
            suspended|paused) return 0 ;;
        esac
        sleep 10
    done
    return 1
}

case "$state" in
    suspended|paused)
        log "盒子已挂起，准备唤醒"
        ;;
    running)
        if [ -z "$STOP_AT" ]; then
            log "算不出停机时刻（runStartedAt=${started}），本轮跳过"
            exit 0
        fi
        remain=$(( STOP_AT - now ))
        if [ "$remain" -le 0 ]; then
            # 已过标称停机时刻，平台可能还没真正挂起
            log "已过停机时刻 ${remain}s，等平台挂起（宽限 ${GRACE}s）"
            if ! wait_until_suspended "$GRACE"; then
                log "宽限内仍未挂起（平台延迟），本轮跳过，下轮再试"
                exit 0
            fi
        elif [ "$remain" -le "$ALIGN" ]; then
            log "距停机还有 ${remain}s（对齐窗口 ${ALIGN}s），等 ${remain}s + ${GRACE}s 宽限"
            sleep $(( remain + GRACE ))
            if ! wait_until_suspended "$GRACE"; then
                log "到点后仍未挂起，本轮跳过，下轮再试"
                exit 0
            fi
        else
            log "无需唤醒（state=running，距停机 $(( remain / 60 )) 分钟）"
            exit 0
        fi
        ;;
    *)
        log "state=${state} 非预期，不动作"
        exit 0
        ;;
esac

# ── 冷却闸 ──────────────────────────────────────────────────────
# 放在 resume 之前统一判：走「等待挂起」路径时冷却是刚产生的，
# 开头那次读到的 cooldownUntil 已经过期，必须重查。
if [ "$(api_get "/v1/machines/${BOX}")" = "200" ]; then
    cooldown="$(read_field '.cooldownUntil')"
    left="$(cooldown_left "$cooldown")"
    if [ "$left" -gt 0 ]; then
        log "冷却中（还剩 ${left}s），本轮不抢，下轮再来（配额约束，不 sleep 等）"
        exit 0
    fi
fi

if [ -z "$mid" ]; then
    log "拿不到盒子 id，无法 resume"
    exit 1
fi

# ── 发起 resume ────────────────────────────────────────────────
log "发起 resume：POST /v1/machines/${mid}/resume"

# Idempotency-Key：网络抖动重试时不要重复触发同一个操作。
IK="resume-${BOX}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
resume_code="$(curl -sS -m 30 -o "$TMP" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer ${KEY}" \
    -H 'Content-Type: application/json' \
    -H "Idempotency-Key: ${IK}" \
    -d '{}' \
    "${API}/v1/machines/${mid}/resume" 2>/dev/null)"

if [ "$resume_code" != "200" ] && [ "$resume_code" != "202" ]; then
    err="$(jq -r '.error.message // .message // "（无错误体）"' "$TMP" 2>/dev/null)"
    # ⚠️ 409 = 盒子还没挂起（不是"别人已唤醒"）。这里**不能**当成功：
    #    若此时仍判成功，盒子随后照样会被挂起，白等一个 cron 周期。
    #    唯一可以当成功的情况：已过停机时刻很久，且盒子确实在跑
    #    （说明另一条看门狗已经唤醒过它）。
    if [ "$resume_code" = "409" ]; then
        # ⚠️ 409 有**两种**完全不同的含义，必须看错误码区分：
        #    · machine_cooldown     → 盒子已挂起，只是还在冷却（平台会带
        #                              retryAfterSeconds，实测 392 秒）
        #    · machine_is_not_paused → 盒子还没挂起（我们到早了）
        #    把冷却误当成"还没挂起"，会白等一整个 cron 周期。
        err_code="$(jq -r '.error.code // ""' "$TMP" 2>/dev/null)"
        if [ "$err_code" = "machine_cooldown" ]; then
            retry_after="$(jq -r '.error.retryAfterSeconds // 0' "$TMP" 2>/dev/null)"
            log "resume 被冷却拒（machine_cooldown，还需 ${retry_after}s），本轮不抢，下轮再来"
            exit 0
        fi
        # 唯一可以当成功的情况：已过停机时刻很久，且盒子确实在跑
        # （说明另一条看门狗已经唤醒过它）。
        if [ -n "$STOP_AT" ] && [ $(( now - STOP_AT )) -gt "$GRACE" ]; then
            log "resume 409（${err}），但已过停机时刻且盒子在跑（他方已唤醒），算成功"
            exit 0
        fi
        log "resume 409（${err}）：盒子尚未挂起，本轮不算成功，下轮再试"
        exit 1
    fi
    log "resume 失败 (HTTP ${resume_code:-连接错误}): ${err}"
    exit 1
fi

log "resume 已受理 (HTTP ${resume_code})，等待盒子起来"

# 平台异步执行 resume；轮询状态确认真的跑起来了。
for _ in $(seq 1 18); do
    sleep 10
    [ "$(api_get "/v1/machines/${BOX}")" = "200" ] || { log "等待中… 查询失败"; continue; }
    newstate="$(read_field '.state')"
    if [ "$newstate" = "running" ]; then
        log "盒子已恢复运行 (state=running)"
        exit 0
    fi
    log "等待中… state=${newstate}"
done

log "等待超时，盒子当前 state=$(read_field '.state')（下一轮再看）"
exit 1
