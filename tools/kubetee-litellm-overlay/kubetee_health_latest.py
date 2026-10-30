# kubetee_health_latest — patch litellm's latest-health-check SQL to be name-first.
#
# WHY (2026-10-30): LATEST_HEALTH_CHECKS(_FOR_MODELS)_SQL in
# litellm/proxy/db/health_check_latest.py does
#   SELECT DISTINCT ON ("model_id", "model_name") ... ORDER BY "model_id" ASC, "model_name" ASC, "checked_at" DESC
# and the public model hub (/public/model_hub, /public/v1/model_hub) keys health
# by model_name ONLY. Legacy/manual rows carry model_id = <model_name> (not a
# UUID) which sorts AFTER uuids, so in a name-keyed dict the stale legacy row
# clobbered the fresh per-pod rows — the hub showed e.g. z-ai/glm-5.2 healthy
# but dated 2026-08-09 while /health/latest had 2026-10-30 rows. Ordering
# DISTINCT ON ("model_name") ... ORDER BY "model_name", "checked_at" DESC makes
# the NEWEST row per model name win, which is what the hub wants.
#
# Applied as a module patch at callback-import time (same pattern as
# kubetee_mcp_trust): the module ships in site-packages next to litellm, and
# patching the two SQL constants at import keeps the fork's upstream-tracked
# file untouched. The fork ALSO carries the source-level fix (dd1874a7411) so a
# future base bump picks it up natively.

from __future__ import annotations

import litellm.proxy.db.health_check_latest as _hcl

_NAME_FIRST_SQL = """
SELECT DISTINCT ON ("model_name")
       "health_check_id", "model_name", "model_id", "status",
       "healthy_count", "unhealthy_count", "error_message",
       "response_time_ms", "details", "checked_by",
       "checked_at", "created_at", "updated_at"
FROM "LiteLLM_HealthCheckTable"
ORDER BY "model_name" ASC, "checked_at" DESC
"""

_NAME_FIRST_MODELS_SQL = """
SELECT DISTINCT ON ("model_name")
       "health_check_id", "model_name", "model_id", "status",
       "healthy_count", "unhealthy_count", "error_message",
       "response_time_ms", "details", "checked_by",
       "checked_at", "created_at", "updated_at"
FROM "LiteLLM_HealthCheckTable"
WHERE "model_name" = ANY($1)
ORDER BY "model_name" ASC, "checked_at" DESC
"""

_hcl.LATEST_HEALTH_CHECKS_SQL = _NAME_FIRST_SQL
_hcl.LATEST_HEALTH_CHECKS_FOR_MODELS_SQL = _NAME_FIRST_MODELS_SQL


class KubeTEEHealthLatest:
    """No-op logger; applying the patch at import/registration is the feature."""

    async def async_log_success_event(self, *args, **kwargs):  # noqa: D401
        return None


kubetee_health_latest_logger = KubeTEEHealthLatest()
