"""
Dashboard Screen.

Main home screen showing:
- Mascot and welcome message
- Summary of available artifacts
- Placed artifacts status
- Last update time
- Quick navigation to other screens

Built with KivyMD Material Design components.
"""

import logging
from datetime import datetime
from pathlib import Path

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.gridlayout import MDGridLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.progressbar import MDProgressBar
from kivy.uix.scrollview import ScrollView
from kivy.uix.image import Image
from kivy.metrics import dp
from kivy.clock import Clock

logger = logging.getLogger(__name__)

# Get the path to the assets folder
ASSETS_PATH = Path(__file__).parent.parent / "assets"


class StatCard(MDCard):
    """
    A stat card with Material Design styling.
    Shows a large value and title with accent color indicator.
    """
    
    def __init__(
        self, 
        title: str, 
        value: str, 
        accent_color: tuple = (0.102, 0.451, 0.91, 1),
        **kwargs
    ):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.padding = dp(16)
        self.spacing = dp(8)
        self.size_hint_y = None
        self.height = dp(110)
        self.radius = [dp(12)]
        self.md_bg_color = (0.071, 0.129, 0.212, 1)  # Navy surface
        self.line_color = accent_color
        self.line_width = dp(3)
        
        # Value label (large)
        self.value_label = MDLabel(
            text=str(value),
            font_style="H4",
            halign="center",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        self.add_widget(self.value_label)
        
        # Title label
        self.title_label = MDLabel(
            text=title,
            font_style="Caption",
            halign="center",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        self.add_widget(self.title_label)
    
    def update_value(self, value: str):
        """Update the displayed value."""
        self.value_label.text = str(value)


class DashboardScreen(MDScreen):
    """Main dashboard screen with KivyMD Material Design."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._progress_value = 0
        self._build_ui()
    
    def _build_ui(self):
        """Build the dashboard UI with KivyMD components."""
        # Main container
        root = MDBoxLayout(
            orientation="vertical",
            padding=[dp(24), dp(20), dp(24), dp(20)],
            spacing=dp(20),
            md_bg_color=(0.039, 0.086, 0.157, 1),  # Dark background
        )
        
        # ===== HEADER =====
        header = MDBoxLayout(
            size_hint_y=None,
            height=dp(150),
            spacing=dp(20),
        )
        
        # Mascot image
        mascot_path = ASSETS_PATH / "mascot.png"
        if mascot_path.exists():
            mascot = Image(
                source=str(mascot_path),
                size_hint=(None, None),
                size=(dp(140), dp(140)),
                fit_mode="contain",
            )
            header.add_widget(mascot)
        
        # Title section
        title_box = MDBoxLayout(orientation="vertical", spacing=dp(4))
        
        title = MDLabel(
            text="Malicious Evasion",
            font_style="H4",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        title_box.add_widget(title)
        
        subtitle = MDLabel(
            text="Artifact Placer",
            font_style="Subtitle1",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        title_box.add_widget(subtitle)
        
        header.add_widget(title_box)
        
        # Settings button
        settings_btn = MDRaisedButton(
            text="Settings",
            size_hint=(None, None),
            size=(dp(120), dp(46)),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._navigate_to("settings"),
        )
        header.add_widget(settings_btn)
        
        root.add_widget(header)
        
        # ===== STATS CARDS =====
        stats_grid = MDGridLayout(
            cols=4,
            spacing=dp(16),
            size_hint_y=None,
            height=dp(120),
            adaptive_height=False,
        )
        
        self.total_card = StatCard(
            "Total Artifacts", "0",
            accent_color=(0.102, 0.451, 0.91, 1)  # Blue
        )
        self.placed_card = StatCard(
            "Placed", "0",
            accent_color=(0.204, 0.659, 0.325, 1)  # Green
        )
        self.user_card = StatCard(
            "User-Space", "0",
            accent_color=(0, 0.831, 1, 1)  # Cyan
        )
        self.admin_card = StatCard(
            "Admin Required", "0",
            accent_color=(0.984, 0.737, 0.016, 1)  # Yellow
        )
        
        stats_grid.add_widget(self.total_card)
        stats_grid.add_widget(self.placed_card)
        stats_grid.add_widget(self.user_card)
        stats_grid.add_widget(self.admin_card)
        
        root.add_widget(stats_grid)
        
        # ===== STATUS + UPDATE SOURCES ROW =====
        mid_row = MDBoxLayout(
            size_hint_y=None,
            height=dp(130),
            spacing=dp(16),
        )
        
        # Status card
        status_card = MDCard(
            orientation="vertical",
            padding=dp(16),
            spacing=dp(10),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
        )
        
        status_header = MDBoxLayout(spacing=dp(10))
        self.status_label = MDLabel(
            text="Status: Ready",
            font_style="Body1",
            theme_text_color="Custom",
            text_color=(0.204, 0.659, 0.325, 1),  # Green
        )
        status_header.add_widget(self.status_label)
        
        self.progress_percent = MDLabel(
            text="",
            font_style="Body2",
            halign="right",
            size_hint_x=None,
            width=dp(60),
            theme_text_color="Custom",
            text_color=(0, 0.831, 1, 1),  # Cyan
        )
        status_header.add_widget(self.progress_percent)
        status_card.add_widget(status_header)
        
        # Progress bar
        self.progress_bar = MDProgressBar(
            value=0,
            size_hint_y=None,
            height=dp(6),
            color=(0.102, 0.451, 0.91, 1),
        )
        status_card.add_widget(self.progress_bar)
        
        self.update_label = MDLabel(
            text="Last update: Never",
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        status_card.add_widget(self.update_label)
        
        mid_row.add_widget(status_card)
        
        # Update Sources card
        sources_card = MDCard(
            orientation="vertical",
            padding=dp(16),
            spacing=dp(10),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
        )
        
        sources_title = MDLabel(
            text="Update Sources",
            font_style="Subtitle2",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(24),
        )
        sources_card.add_widget(sources_title)
        
        os_row = MDBoxLayout(spacing=dp(8))
        self.os_checkboxes = {}
        
        for os_name in ["Android", "Windows", "Linux", "macOS"]:
            os_container = MDBoxLayout(spacing=dp(4))
            
            cb = MDCheckbox(
                active=True,
                size_hint=(None, None),
                size=(dp(28), dp(28)),
                color_active=(0.102, 0.451, 0.91, 1),
            )
            self.os_checkboxes[os_name.lower()] = cb
            os_container.add_widget(cb)
            
            os_label = MDLabel(
                text=os_name,
                font_style="Caption",
                theme_text_color="Custom",
                text_color=(0.91, 0.918, 0.929, 1),
            )
            os_container.add_widget(os_label)
            os_row.add_widget(os_container)
        
        sources_card.add_widget(os_row)
        mid_row.add_widget(sources_card)
        
        root.add_widget(mid_row)
        
        # ===== ACTION BUTTONS =====
        actions = MDGridLayout(
            cols=2,
            rows=2,
            spacing=dp(14),
            size_hint_y=None,
            height=dp(120),
        )
        
        browse_btn = MDRaisedButton(
            text="Browse Artifacts",
            size_hint=(1, 1),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._navigate_to("browse"),
        )
        actions.add_widget(browse_btn)
        
        place_btn = MDRaisedButton(
            text="Place Artifacts",
            size_hint=(1, 1),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._navigate_to("placement"),
        )
        actions.add_widget(place_btn)
        
        update_btn = MDRaisedButton(
            text="Check for Updates",
            size_hint=(1, 1),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._check_updates(),
        )
        actions.add_widget(update_btn)
        
        remove_btn = MDRaisedButton(
            text="Remove All Placed",
            size_hint=(1, 1),
            md_bg_color=(0.918, 0.263, 0.208, 1),  # Red
            on_release=lambda x: self._remove_placed(),
        )
        actions.add_widget(remove_btn)
        
        root.add_widget(actions)
        
        # ===== RECENT ACTIVITY =====
        activity_header = MDLabel(
            text="Recent Activity",
            font_style="Subtitle1",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(32),
        )
        root.add_widget(activity_header)
        
        # Activity card with scroll
        activity_card = MDCard(
            orientation="vertical",
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            size_hint_y=1,
        )
        
        scroll = ScrollView(
            size_hint=(1, 1),
            bar_width=dp(12),
            bar_color=(0.3, 0.5, 0.8, 0.9),
            bar_inactive_color=(0.3, 0.5, 0.8, 0.4),
            scroll_type=['bars', 'content'],
        )
        self.activity_layout = MDBoxLayout(
            orientation="vertical",
            size_hint_y=None,
            padding=dp(16),
            spacing=dp(8),
            adaptive_height=True,
        )
        self.activity_layout.bind(minimum_height=self.activity_layout.setter("height"))
        
        self.no_activity_label = MDLabel(
            text="No recent activity. Start by browsing artifacts!",
            font_style="Body2",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=None,
            height=dp(50),
            halign="center",
        )
        self.activity_layout.add_widget(self.no_activity_label)
        
        scroll.add_widget(self.activity_layout)
        activity_card.add_widget(scroll)
        root.add_widget(activity_card)
        
        self.add_widget(root)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering dashboard screen")
        self._refresh_stats()
        
        # Check if there's an active update
        app = MDApp.get_running_app()
        if app and hasattr(app, "updater") and app.updater:
            if app.updater.is_running:
                self._on_update_progress(app.updater.progress)
    
    def _set_progress(self, percent: float):
        """Set progress bar value (0-100)."""
        self._progress_value = max(0, min(100, percent))
        # MDProgressBar uses 0-100 scale (not 0-1)
        self.progress_bar.value = self._progress_value
        
        if percent > 0:
            self.progress_percent.text = f"{int(percent)}%"
        else:
            self.progress_percent.text = ""
    
    def _on_update_progress(self, progress):
        """Handle progress updates from the updater service."""
        from gui.services.updater import UpdateProgress
        
        if progress.status == "running":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.text_color = (0.102, 0.451, 0.91, 1)  # Blue
            self._set_progress(progress.percent)
            
            if progress.artifacts_found > 0:
                self._refresh_stats()
        
        elif progress.status == "complete":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.text_color = (0.204, 0.659, 0.325, 1)  # Green
            self._set_progress(100)
            self.update_label.text = f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            self._refresh_stats()
            
            Clock.schedule_once(lambda dt: self._set_progress(0), 3.0)
        
        elif progress.status == "error":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.text_color = (0.918, 0.263, 0.208, 1)  # Red
            self._set_progress(0)
    
    def _refresh_stats(self):
        """Refresh the statistics from database."""
        app = MDApp.get_running_app()
        if app and app.database:
            stats = app.database.get_statistics()
            self.total_card.update_value(str(stats.get("total", 0)))
            self.placed_card.update_value(str(stats.get("placed", 0)))
            self.user_card.update_value(str(stats.get("user_space", 0)))
            self.admin_card.update_value(str(stats.get("admin_required", 0)))
            
            last_update = stats.get("last_update")
            if last_update:
                self.update_label.text = f"Last update: {last_update}"
    
    def _navigate_to(self, screen_name: str):
        """Navigate to another screen."""
        app = MDApp.get_running_app()
        if app:
            app.navigate_to(screen_name)
    
    def _check_updates(self):
        """Trigger a manual update check."""
        selected_os = []
        for os_name, checkbox in self.os_checkboxes.items():
            if checkbox.active:
                selected_os.append(os_name)
        
        if not selected_os:
            self.status_label.text = "Status: Select at least one OS"
            self.status_label.text_color = (0.984, 0.737, 0.016, 1)  # Yellow
            return
        
        self.status_label.text = "Status: Starting update..."
        self.status_label.text_color = (0.102, 0.451, 0.91, 1)  # Blue
        self._set_progress(0)
        logger.info(f"Manual update check triggered for: {selected_os}")
        
        app = MDApp.get_running_app()
        if app and hasattr(app, "updater") and app.updater:
            app.updater.trigger_update(os_types=selected_os)
    
    def _remove_placed(self):
        """Remove all placed artifacts."""
        logger.info("Remove placed artifacts requested")
        self.status_label.text = "Status: Removing placed artifacts..."
        self.status_label.text_color = (0.984, 0.737, 0.016, 1)  # Yellow
        
        Clock.schedule_once(lambda dt: self._finish_remove(), 1.0)
    
    def _finish_remove(self):
        """Finish the removal process."""
        self.status_label.text = "Status: Ready"
        self.status_label.text_color = (0.204, 0.659, 0.325, 1)  # Green
        self._refresh_stats()
