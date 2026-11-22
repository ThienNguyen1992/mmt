"""Chính sách Fail-Closed có giới hạn (sau 3 ngày offline) & Ngoại lệ khẩn cấp NT6.

Triết lý thiết kế (dùng cho giải trình báo cáo/vấn đáp):
- Trong 3 ngày đầu mất mạng: tiếp tục áp dụng nguyên vẹn policy cache gần nhất.
- Từ ngày thứ 3 trở đi (>= 3 ngày): kích hoạt Fail-Closed có giới hạn:
  1. Không khóa cứng hoàn toàn máy tính (tránh cản trở học tập khi mất mạng thật).
  2. Siết quota còn 50% (tối thiểu 30 phút/ngày).
  3. Chỉ cho phép nhóm giáo dục ('education') và danh sách miễn chặn khẩn cấp NT6
     (Tổng đài 111, Bộ GD&ĐT, cổng thông tin chính phủ/trường học).
  4. Luôn giải trình rõ lý do minh bạch qua IPC/Tray và trong báo cáo.
"""

import copy
from datetime import datetime

from agent.core.offline_tracker import OfflineTracker

EMERGENCY_ALLOWLIST = (
    "tongdai111.vn",
    "moet.gov.vn",
    "chinhphu.vn",
    "edu.vn",
)

NON_EDUCATION_CATEGORIES = [
    "entertainment",
    "social_media",
    "gaming",
    "inappropriate",
    "uncategorized",
]


def is_emergency_domain(domain: str) -> bool:
    """Kiểm tra tên miền thuộc danh sách miễn chặn khẩn cấp NT6 (khớp exact hoặc subdomain)."""
    cleaned = domain.strip().lower().rstrip(".")
    if not cleaned:
        return False
    for allowed in EMERGENCY_ALLOWLIST:
        if cleaned == allowed or cleaned.endswith(f".{allowed}"):
            return True
    return False


class FailModeEvaluator:
    def __init__(self, offline_tracker: OfflineTracker, grace_days: int = 3):
        self.offline_tracker = offline_tracker
        self.grace_days = grace_days

    def evaluate(
        self,
        policy_content: dict | None,
        now: datetime | None = None,
    ) -> dict:
        base = copy.deepcopy(policy_content) if policy_content else {}
        offline_days = self.offline_tracker.get_offline_duration_days(now=now)

        if offline_days < self.grace_days:
            base["fail_mode_active"] = False
            base["education_only"] = False
            base["reason"] = ""
            return base

        weekday_q = int(base.get("quota_weekday_min", 90))
        weekend_q = int(base.get("quota_weekend_min", 120))
        base["quota_weekday_min"] = max(30, weekday_q // 2)
        base["quota_weekend_min"] = max(30, weekend_q // 2)

        domain_rules = dict(base.get("domain_rules") or {})
        domain_rules["blocked_categories"] = list(NON_EDUCATION_CATEGORIES)
        existing_allowed = list(domain_rules.get("custom_allowed_domains") or [])
        for em in EMERGENCY_ALLOWLIST:
            if em not in existing_allowed:
                existing_allowed.append(em)
        domain_rules["custom_allowed_domains"] = existing_allowed
        base["domain_rules"] = domain_rules

        base["fail_mode_active"] = True
        base["education_only"] = True
        base["emergency_allowlist"] = list(EMERGENCY_ALLOWLIST)
        base["reason"] = (
            f"Mất kết nối máy chủ {offline_days:.1f} ngày (>= {self.grace_days} ngày): "
            "giảm 50% thời lượng (tối thiểu 30 phút), chỉ mở nhóm Giáo dục và "
            "danh sách khẩn cấp NT6 (Tổng đài 111, trường học)."
        )
        return base
