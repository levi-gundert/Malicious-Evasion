"""
GUI Screens module.

Contains all application screens:
- Dashboard: Main overview and status
- Browse: Browse and filter artifacts  
- Placement: Place artifacts with confirmation
- Settings: Configure API key and preferences
"""

from gui.screens.dashboard import DashboardScreen
from gui.screens.browse import BrowseScreen
from gui.screens.placement import PlacementScreen
from gui.screens.settings import SettingsScreen

__all__ = [
    "DashboardScreen",
    "BrowseScreen",
    "PlacementScreen",
    "SettingsScreen",
]
