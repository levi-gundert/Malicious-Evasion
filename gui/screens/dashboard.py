"""
Dashboard Screen.

Main home screen showing:
- Mascot and welcome message
- Summary of available artifacts
- Placed artifacts status
- Last update time
- Quick navigation to other screens

Theme: Recorded Future inspired (Electric Blue + Dark)
"""

import logging
from datetime import datetime
from pathlib import Path

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.factory import Factory
from kivy.uix.scrollview import ScrollView
from kivy.uix.image import Image
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.app import App
from kivy.clock import Clock

logger = logging.getLogger(__name__)

# Get the path to the assets folder
ASSETS_PATH = Path(__file__).parent.parent / "assets"


class StatCard(BoxLayout):
    """
    A stat card with Recorded Future styling.
    Clean navy background with accent color indicator.
    """
    
    def __init__(
        self, 
        title: str, 
        value: str, 
        color: tuple = (0.102, 0.451, 0.91, 1),  # RF Blue
        **kwargs
    ):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.padding = [14, 12, 14, 12]
        self.spacing = 6
        self.size_hint_y = None
        self.height = 110
        
        self._accent_color = color
        
        # Card background
        with self.canvas.before:
            # Fill
            Color(0.071, 0.129, 0.212, 1)  # BG_SURFACE navy
            self.rect = RoundedRectangle(
                pos=self.pos, 
                size=self.size, 
                radius=[8]
            )
            # Border
            Color(0.118, 0.227, 0.373, 1)  # BORDER
            self.border_line = RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[8]
            )
            # Accent line at top
            Color(*color)
            self.accent = Rectangle(
                pos=(self.pos[0], self.pos[1] + self.size[1] - 3),
                size=(self.size[0], 3)
            )
        
        self.bind(pos=self._update_rect, size=self._update_rect)
        
        # Value label (large)
        self.value_label = Label(
            text=str(value),
            font_size="30sp",
            bold=True,
            halign="center",
            valign="middle",
            color=(1, 1, 1, 1),
            size_hint_y=0.6,
        )
        self.add_widget(self.value_label)
        
        # Title label
        self.title_label = Label(
            text=title,
            font_size="12sp",
            halign="center",
            valign="top",
            color=(0.604, 0.627, 0.651, 1),  # TEXT_MUTED
            size_hint_y=0.4,
        )
        self.add_widget(self.title_label)
    
    def _update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size
        self.border_line.pos = self.pos
        self.border_line.size = self.size
        self.accent.pos = (self.pos[0], self.pos[1] + self.size[1] - 3)
        self.accent.size = (self.size[0], 3)
    
    def update_value(self, value: str):
        """Update the displayed value."""
        self.value_label.text = str(value)


class DashboardScreen(Screen):
    """Main dashboard screen with premium Recorded Future styling."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._build_ui()
    
    def _build_ui(self):
        """Build the dashboard UI from a clean slate."""
        from kivy.uix.checkbox import CheckBox

        root = BoxLayout(orientation="vertical", padding=[24, 20, 24, 20], spacing=18)

        # ===== HEADER =====
        header = BoxLayout(size_hint_y=None, height=110, spacing=18)
        mascot_path = ASSETS_PATH / "mascot.png"
        if mascot_path.exists():
            header.add_widget(Image(
                source=str(mascot_path),
                size_hint=(None, None),
                size=(80, 80),
                allow_stretch=True,
                keep_ratio=True,
            ))

        title_box = BoxLayout(orientation="vertical", spacing=6)
        title = Label(
            text="Malicious Evasion",
            font_size="30sp",
            bold=True,
            halign="left",
            valign="bottom",
            color=(1, 1, 1, 1),
            size_hint_y=0.6,
        )
        title.bind(size=title.setter("text_size"))
        title_box.add_widget(title)

        subtitle = Label(
            text="Artifact Placer",
            font_size="16sp",
            halign="left",
            valign="top",
            color=(0.604, 0.627, 0.651, 1),
            size_hint_y=0.4,
        )
        subtitle.bind(size=subtitle.setter("text_size"))
        title_box.add_widget(subtitle)
        header.add_widget(title_box)

        settings_btn = Button(
            text="Settings",
            size_hint=(None, None),
            size=(120, 46),
            on_release=lambda x: self._navigate_to("settings"),
        )
        header.add_widget(settings_btn)
        root.add_widget(header)

        # ===== STATS =====
        stats_grid = GridLayout(cols=4, spacing=16, size_hint_y=None, height=120)
        self.total_card = StatCard("Total Artifacts", "0", color=(0.102, 0.451, 0.91, 1))
        self.placed_card = StatCard("Placed", "0", color=(0.204, 0.659, 0.325, 1))
        self.user_card = StatCard("User-Space", "0", color=(0, 0.831, 1, 1))
        self.admin_card = StatCard("Admin Required", "0", color=(0.984, 0.737, 0.016, 1))
        stats_grid.add_widget(self.total_card)
        stats_grid.add_widget(self.placed_card)
        stats_grid.add_widget(self.user_card)
        stats_grid.add_widget(self.admin_card)
        root.add_widget(stats_grid)

        # ===== STATUS + SOURCES ROW =====
        mid_row = BoxLayout(size_hint_y=None, height=120, spacing=16)

        status_box = BoxLayout(orientation="vertical", padding=[16, 12, 16, 12], spacing=8)
        with status_box.canvas.before:
            Color(0.071, 0.129, 0.212, 1)
            self.status_rect = RoundedRectangle(pos=status_box.pos, size=status_box.size, radius=[8])
        status_box.bind(pos=lambda w, p: setattr(self.status_rect, "pos", p),
                        size=lambda w, s: setattr(self.status_rect, "size", s))

        status_row = BoxLayout()
        self.status_label = Label(
            text="Status: Ready",
            font_size="14sp",
            halign="left",
            valign="middle",
            color=(0.204, 0.659, 0.325, 1),
        )
        self.status_label.bind(size=self.status_label.setter("text_size"))
        status_row.add_widget(self.status_label)

        self.progress_percent = Label(
            text="",
            font_size="14sp",
            halign="right",
            valign="middle",
            size_hint_x=None,
            width=60,
            color=(0, 0.831, 1, 1),
        )
        status_row.add_widget(self.progress_percent)
        status_box.add_widget(status_row)

        self.progress_bar_bg = BoxLayout(size_hint_y=None, height=10)
        with self.progress_bar_bg.canvas.before:
            Color(0.118, 0.227, 0.373, 1)
            self.progress_track = RoundedRectangle(pos=self.progress_bar_bg.pos, size=self.progress_bar_bg.size, radius=[5])
            Color(0.102, 0.451, 0.91, 1)
            self.progress_fill = RoundedRectangle(pos=self.progress_bar_bg.pos, size=(0, 10), radius=[5])
        self.progress_bar_bg.bind(pos=self._update_progress_bar, size=self._update_progress_bar)
        self._progress_value = 0
        status_box.add_widget(self.progress_bar_bg)

        self.update_label = Label(
            text="Last update: Never",
            font_size="12sp",
            halign="left",
            valign="middle",
            color=(0.604, 0.627, 0.651, 1),
            size_hint_y=None,
            height=20,
        )
        self.update_label.bind(size=self.update_label.setter("text_size"))
        status_box.add_widget(self.update_label)
        mid_row.add_widget(status_box)

        sources_box = BoxLayout(orientation="vertical", padding=[16, 12, 16, 12], spacing=8)
        with sources_box.canvas.before:
            Color(0.071, 0.129, 0.212, 1)
            self.os_section_rect = RoundedRectangle(pos=sources_box.pos, size=sources_box.size, radius=[8])
        sources_box.bind(pos=lambda w, p: setattr(self.os_section_rect, "pos", p),
                         size=lambda w, s: setattr(self.os_section_rect, "size", s))

        sources_label = Label(
            text="Update Sources",
            font_size="13sp",
            bold=True,
            halign="left",
            valign="middle",
            color=(1, 1, 1, 1),
            size_hint_y=None,
            height=22,
        )
        sources_label.bind(size=sources_label.setter("text_size"))
        sources_box.add_widget(sources_label)

        os_row = BoxLayout(spacing=10)
        self.os_checkboxes = {}
        for os_name in ["Android", "Windows", "Linux", "macOS"]:
            os_container = BoxLayout(spacing=4)
            cb = CheckBox(active=True, size_hint=(None, 1), width=26)
            self.os_checkboxes[os_name.lower()] = cb
            os_container.add_widget(cb)
            os_container.add_widget(Label(text=os_name, font_size="12sp", color=(0.91, 0.918, 0.929, 1)))
            os_row.add_widget(os_container)
        sources_box.add_widget(os_row)
        mid_row.add_widget(sources_box)
        root.add_widget(mid_row)

        # ===== ACTIONS =====
        actions = GridLayout(cols=2, rows=2, spacing=14, size_hint_y=None, height=140)
        actions.add_widget(Button(text="Browse Artifacts", on_release=lambda x: self._navigate_to("browse")))
        actions.add_widget(Button(text="Place Artifacts", on_release=lambda x: self._navigate_to("placement")))
        actions.add_widget(Button(text="Check for Updates", on_release=lambda x: self._check_updates()))
        actions.add_widget(Factory.DangerButton(text="Remove All Placed", on_release=lambda x: self._remove_placed()))
        root.add_widget(actions)

        # ===== RECENT ACTIVITY =====
        activity_header = Label(
            text="Recent Activity",
            font_size="15sp",
            bold=True,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=30,
            color=(1, 1, 1, 1),
        )
        activity_header.bind(size=activity_header.setter("text_size"))
        root.add_widget(activity_header)

        activity_container = BoxLayout(size_hint_y=1)
        with activity_container.canvas.before:
            Color(0.071, 0.129, 0.212, 1)
            self.activity_bg = RoundedRectangle(pos=activity_container.pos, size=activity_container.size, radius=[8])
        activity_container.bind(pos=lambda w, p: setattr(self.activity_bg, "pos", p),
                                 size=lambda w, s: setattr(self.activity_bg, "size", s))

        scroll = ScrollView(size_hint=(1, 1))
        self.activity_layout = BoxLayout(orientation="vertical", size_hint_y=None, padding=[16, 12, 16, 12], spacing=8)
        self.activity_layout.bind(minimum_height=self.activity_layout.setter("height"))
        self.no_activity_label = Label(
            text="No recent activity. Start by browsing artifacts!",
            font_size="13sp",
            color=(0.604, 0.627, 0.651, 1),
            size_hint_y=None,
            height=50,
        )
        self.no_activity_label.bind(size=self.no_activity_label.setter("text_size"))
        self.activity_layout.add_widget(self.no_activity_label)
        scroll.add_widget(self.activity_layout)
        activity_container.add_widget(scroll)
        root.add_widget(activity_container)

        self.add_widget(root)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering dashboard screen")
        self._refresh_stats()
        
        # Check if there's an active update and show its progress
        app = App.get_running_app()
        if app and hasattr(app, "updater") and app.updater:
            if app.updater.is_running:
                # Update is in progress, show current status
                self._on_update_progress(app.updater.progress)
    
    def _update_progress_bar(self, *args):
        """Update progress bar graphics when container resizes."""
        self.progress_track.pos = self.progress_bar_bg.pos
        self.progress_track.size = self.progress_bar_bg.size
        
        # Calculate fill width based on progress
        fill_width = self.progress_bar_bg.width * (self._progress_value / 100)
        self.progress_fill.pos = self.progress_bar_bg.pos
        self.progress_fill.size = (fill_width, self.progress_bar_bg.height)
    
    def _set_progress(self, percent: float):
        """Set progress bar value (0-100)."""
        self._progress_value = max(0, min(100, percent))
        self._update_progress_bar()
        
        if percent > 0:
            self.progress_percent.text = f"{int(percent)}%"
        else:
            self.progress_percent.text = ""
    
    def _on_update_progress(self, progress):
        """Handle progress updates from the updater service."""
        from gui.services.updater import UpdateProgress
        
        if progress.status == "running":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.color = (0.102, 0.451, 0.91, 1)  # RF Blue
            self._set_progress(progress.percent)
            
            # Update artifacts count in real-time
            if progress.artifacts_found > 0:
                self._refresh_stats()
        
        elif progress.status == "complete":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.color = (0.204, 0.659, 0.325, 1)  # Success green
            self._set_progress(100)
            self.update_label.text = f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            self._refresh_stats()
            
            # Fade out progress bar after completion
            Clock.schedule_once(lambda dt: self._set_progress(0), 3.0)
        
        elif progress.status == "error":
            self.status_label.text = f"Status: {progress.description}"
            self.status_label.color = (0.918, 0.263, 0.208, 1)  # Error red
            self._set_progress(0)
    
    def _refresh_stats(self):
        """Refresh the statistics from database."""
        app = App.get_running_app()
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
        app = App.get_running_app()
        if app:
            app.navigate_to(screen_name)
    
    def _check_updates(self):
        """Trigger a manual update check."""
        # Get selected OS types from checkboxes
        selected_os = []
        for os_name, checkbox in self.os_checkboxes.items():
            if checkbox.active:
                selected_os.append(os_name)
        
        if not selected_os:
            self.status_label.text = "Status: Select at least one OS"
            self.status_label.color = (0.984, 0.737, 0.016, 1)  # Warning yellow
            return
        
        self.status_label.text = "Status: Starting update..."
        self.status_label.color = (0.102, 0.451, 0.91, 1)  # RF Blue
        self._set_progress(0)
        logger.info(f"Manual update check triggered for: {selected_os}")
        
        # Trigger the update with selected OS types
        app = App.get_running_app()
        if app and hasattr(app, "updater") and app.updater:
            app.updater.trigger_update(os_types=selected_os)
    
    def _do_update(self):
        """Perform the update - deprecated, use _check_updates instead."""
        pass
    
    def _remove_placed(self):
        """Remove all placed artifacts."""
        logger.info("Remove placed artifacts requested")
        self.status_label.text = "Status: Removing placed artifacts..."
        self.status_label.color = (0.984, 0.737, 0.016, 1)  # Warning
        
        # Would show confirmation dialog and remove placed artifacts
        Clock.schedule_once(lambda dt: self._finish_remove(), 1.0)
    
    def _finish_remove(self):
        """Finish the removal process."""
        self.status_label.text = "Status: Ready"
        self.status_label.color = (0.204, 0.659, 0.325, 1)  # Success
        self._refresh_stats()