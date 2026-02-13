"""GUI section builders for NetScouter."""

from .ai_auditor import build_ai_auditor_tab
from .dashboard import build_dashboard_tab
from .intelligence import build_intelligence_tab
from .operations import build_operations_tab
from .packet_filtering import build_packet_filtering_tab
from .possible_threats import build_possible_threats_tab
from .settings import build_settings_tab

__all__ = [
    "build_ai_auditor_tab",
    "build_dashboard_tab",
    "build_intelligence_tab",
    "build_operations_tab",
    "build_packet_filtering_tab",
    "build_possible_threats_tab",
    "build_settings_tab",
]
