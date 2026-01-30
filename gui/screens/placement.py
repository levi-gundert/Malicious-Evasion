"""
Placement Screen.

Handles the placement wizard flow:
1. Show selected artifacts
2. Display privilege requirements with warnings
3. Require explicit confirmation for each
4. Trigger OS elevation when needed
5. Log all placements for later removal
"""

import logging
from typing import List, Optional

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.app import App
from kivy.clock import Clock

logger = logging.getLogger(__name__)


class PlacementItemWidget(BoxLayout):
    """Widget showing a single artifact to be placed."""
    
    def __init__(self, artifact: dict, on_place=None, on_skip=None, **kwargs):
        super().__init__(**kwargs)
        self.artifact = artifact
        self.on_place = on_place
        self.on_skip = on_skip
        self.orientation = "vertical"
        self.size_hint_y = None
        self.height = 140
        self.padding = 15
        self.spacing = 8
        
        # Determine privilege styling
        privilege = artifact.get("privilege_level", "user")
        if privilege == "admin":
            bg_color = (0.3, 0.2, 0.15, 1)
            badge_color = (0.8, 0.4, 0.2, 1)
            warning_text = "Requires Administrator privileges"
        elif privilege == "root":
            bg_color = (0.3, 0.15, 0.15, 1)
            badge_color = (0.8, 0.2, 0.2, 1)
            warning_text = "Requires Root access"
        else:
            bg_color = (0.15, 0.25, 0.15, 1)
            badge_color = (0.3, 0.6, 0.3, 1)
            warning_text = "No special privileges required"
        
        # Background
        with self.canvas.before:
            Color(*bg_color)
            self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[10])
        self.bind(pos=self._update_rect, size=self._update_rect)
        
        # Header with type badge
        header = BoxLayout(size_hint_y=None, height=30, spacing=10)
        
        # Type label
        type_text = f"{artifact.get('artifact_type', 'unknown').upper()}"
        type_label = Label(
            text=type_text,
            font_size="12sp",
            bold=True,
            halign="left",
            valign="middle",
            color=(0.8, 0.8, 0.8, 1),
        )
        type_label.bind(size=type_label.setter("text_size"))
        header.add_widget(type_label)
        
        # Privilege badge
        badge = BoxLayout(size_hint=(None, None), size=(70, 24))
        with badge.canvas.before:
            Color(*badge_color)
            self.badge_rect = RoundedRectangle(pos=badge.pos, size=badge.size, radius=[4])
        badge.bind(
            pos=lambda w, p: setattr(self.badge_rect, "pos", p),
            size=lambda w, s: setattr(self.badge_rect, "size", s),
        )
        badge_label = Label(text=privilege.upper(), font_size="10sp", bold=True)
        badge.add_widget(badge_label)
        header.add_widget(badge)
        
        self.add_widget(header)
        
        # Value (the actual artifact path/key)
        value = artifact.get("value", "Unknown")
        value_label = Label(
            text=value,
            font_size="14sp",
            bold=True,
            halign="left",
            valign="middle",
        )
        value_label.bind(size=value_label.setter("text_size"))
        self.add_widget(value_label)
        
        # Warning/info text
        warning_label = Label(
            text=warning_text,
            font_size="12sp",
            halign="left",
            valign="middle",
            color=(0.7, 0.7, 0.5, 1) if privilege != "user" else (0.5, 0.7, 0.5, 1),
        )
        warning_label.bind(size=warning_label.setter("text_size"))
        self.add_widget(warning_label)
        
        # Action buttons
        buttons = BoxLayout(size_hint_y=None, height=35, spacing=10)
        
        place_btn = Button(
            text="Place This Artifact",
            font_size="13sp",
            on_release=lambda x: self._do_place(),
        )
        buttons.add_widget(place_btn)
        
        skip_btn = Button(
            text="Skip",
            font_size="13sp",
            size_hint_x=0.3,
            on_release=lambda x: self._do_skip(),
        )
        buttons.add_widget(skip_btn)
        
        self.add_widget(buttons)
    
    def _update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size
    
    def _do_place(self):
        """Handle place button click."""
        if self.on_place:
            self.on_place(self.artifact)
    
    def _do_skip(self):
        """Handle skip button click."""
        if self.on_skip:
            self.on_skip(self.artifact)


class PlacementScreen(Screen):
    """Artifact placement wizard screen."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.artifacts_to_place = []
        self.placed_artifacts = []
        self.skipped_artifacts = []
        self._build_ui()
    
    def _build_ui(self):
        """Build the placement UI."""
        main_layout = BoxLayout(orientation="vertical", padding=15, spacing=10)
        
        # Header
        header = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        back_btn = Button(
            text="< Cancel",
            size_hint=(None, None),
            size=(100, 40),
            on_release=lambda x: self._cancel(),
        )
        header.add_widget(back_btn)
        
        title = Label(
            text="Place Artifacts",
            font_size="24sp",
            bold=True,
            halign="left",
            valign="middle",
        )
        title.bind(size=title.setter("text_size"))
        header.add_widget(title)
        
        main_layout.add_widget(header)
        
        # Progress/status
        self.status_label = Label(
            text="Select artifacts from Browse to place.",
            font_size="14sp",
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=30,
        )
        self.status_label.bind(size=self.status_label.setter("text_size"))
        main_layout.add_widget(self.status_label)
        
        # Warning banner
        warning_box = BoxLayout(size_hint_y=None, height=50, padding=10)
        with warning_box.canvas.before:
            Color(0.4, 0.3, 0.1, 1)
            self.warning_rect = Rectangle(pos=warning_box.pos, size=warning_box.size)
        warning_box.bind(
            pos=lambda w, p: setattr(self.warning_rect, "pos", p),
            size=lambda w, s: setattr(self.warning_rect, "size", s),
        )
        
        warning_label = Label(
            text="Review each artifact carefully. Admin/Root artifacts will prompt for elevation.",
            font_size="13sp",
            halign="center",
            valign="middle",
        )
        warning_label.bind(size=warning_label.setter("text_size"))
        warning_box.add_widget(warning_label)
        main_layout.add_widget(warning_box)
        
        # Artifacts list (scrollable)
        scroll = ScrollView(size_hint=(1, 1))
        self.items_layout = BoxLayout(
            orientation="vertical",
            spacing=10,
            size_hint_y=None,
            padding=[0, 0, 10, 0],
        )
        self.items_layout.bind(minimum_height=self.items_layout.setter("height"))
        scroll.add_widget(self.items_layout)
        main_layout.add_widget(scroll)
        
        # Footer with summary
        footer = BoxLayout(size_hint_y=None, height=60, spacing=10, padding=10)
        with footer.canvas.before:
            Color(0.12, 0.12, 0.12, 1)
            self.footer_rect = Rectangle(pos=footer.pos, size=footer.size)
        footer.bind(
            pos=lambda w, p: setattr(self.footer_rect, "pos", p),
            size=lambda w, s: setattr(self.footer_rect, "size", s),
        )
        
        self.summary_label = Label(
            text="Placed: 0 | Skipped: 0 | Remaining: 0",
            font_size="14sp",
            halign="left",
            valign="middle",
        )
        self.summary_label.bind(size=self.summary_label.setter("text_size"))
        footer.add_widget(self.summary_label)
        
        place_all_btn = Button(
            text="Place All User-Space",
            size_hint=(None, None),
            size=(160, 40),
            on_release=lambda x: self._place_all_user(),
        )
        footer.add_widget(place_all_btn)
        
        done_btn = Button(
            text="Done",
            size_hint=(None, None),
            size=(100, 40),
            on_release=lambda x: self._finish(),
        )
        footer.add_widget(done_btn)
        
        main_layout.add_widget(footer)
        
        self.add_widget(main_layout)
    
    def set_artifacts(self, artifacts: List[dict]):
        """Set the artifacts to be placed."""
        self.artifacts_to_place = artifacts
        self.placed_artifacts = []
        self.skipped_artifacts = []
        self._refresh_ui()
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering placement screen")
        self._refresh_ui()
    
    def _refresh_ui(self):
        """Refresh the placement items list."""
        self.items_layout.clear_widgets()
        
        if not self.artifacts_to_place:
            empty_label = Label(
                text="No artifacts to place. Go to Browse to select artifacts.",
                font_size="14sp",
                color=(0.6, 0.6, 0.6, 1),
                size_hint_y=None,
                height=40,
            )
            self.items_layout.add_widget(empty_label)
            self.status_label.text = "No artifacts selected."
        else:
            self.status_label.text = f"{len(self.artifacts_to_place)} artifacts ready to place"
            
            for artifact in self.artifacts_to_place:
                item = PlacementItemWidget(
                    artifact,
                    on_place=self._on_place_artifact,
                    on_skip=self._on_skip_artifact,
                )
                self.items_layout.add_widget(item)
        
        self._update_summary()
    
    def _update_summary(self):
        """Update the summary label."""
        placed = len(self.placed_artifacts)
        skipped = len(self.skipped_artifacts)
        remaining = len(self.artifacts_to_place)
        self.summary_label.text = f"Placed: {placed} | Skipped: {skipped} | Remaining: {remaining}"
    
    def _on_place_artifact(self, artifact: dict):
        """Handle placing a single artifact."""
        privilege = artifact.get("privilege_level", "user")
        
        if privilege in ("admin", "root"):
            # Show confirmation popup for privileged placement
            self._show_privilege_confirmation(artifact)
        else:
            # Direct placement for user-space
            self._do_place(artifact)
    
    def _show_privilege_confirmation(self, artifact: dict):
        """Show confirmation popup for privileged artifact."""
        privilege = artifact.get("privilege_level", "admin")
        value = artifact.get("value", "Unknown")
        
        content = BoxLayout(orientation="vertical", spacing=10, padding=10)
        
        warning = Label(
            text=f"This artifact requires {privilege.upper()} privileges.\n\n"
                 f"Value: {value}\n\n"
                 f"The system will prompt you for elevation.\n"
                 f"Do you want to proceed?",
            font_size="14sp",
            halign="center",
            valign="middle",
        )
        warning.bind(size=warning.setter("text_size"))
        content.add_widget(warning)
        
        buttons = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        popup = Popup(
            title="Privilege Required",
            content=content,
            size_hint=(0.8, 0.5),
            auto_dismiss=False,
        )
        
        cancel_btn = Button(
            text="Cancel",
            on_release=lambda x: popup.dismiss(),
        )
        buttons.add_widget(cancel_btn)
        
        proceed_btn = Button(
            text="Proceed",
            on_release=lambda x: self._on_privilege_confirmed(artifact, popup),
        )
        buttons.add_widget(proceed_btn)
        
        content.add_widget(buttons)
        popup.open()
    
    def _on_privilege_confirmed(self, artifact: dict, popup: Popup):
        """Handle privilege confirmation."""
        popup.dismiss()
        self._do_place(artifact, with_elevation=True)
    
    def _do_place(self, artifact: dict, with_elevation: bool = False):
        """Actually place the artifact."""
        app = App.get_running_app()
        if not app:
            return
        
        # Import placement engine
        from gui.services.placement_engine import PlacementEngine
        
        engine = PlacementEngine(app.current_os)
        
        try:
            success = engine.place_artifact(artifact, elevate=with_elevation)
            
            if success:
                logger.info(f"Placed artifact: {artifact.get('value')}")
                self.placed_artifacts.append(artifact)
                self.artifacts_to_place.remove(artifact)
                
                # Log placement for undo
                if app.database:
                    app.database.log_placement(artifact)
            else:
                logger.warning(f"Failed to place artifact: {artifact.get('value')}")
                # Show error but don't remove from list
                
        except Exception as e:
            logger.error(f"Error placing artifact: {e}")
        
        self._refresh_ui()
    
    def _on_skip_artifact(self, artifact: dict):
        """Handle skipping an artifact."""
        self.skipped_artifacts.append(artifact)
        self.artifacts_to_place.remove(artifact)
        self._refresh_ui()
    
    def _place_all_user(self):
        """Place all user-space artifacts at once."""
        user_artifacts = [a for a in self.artifacts_to_place 
                         if a.get("privilege_level", "user") == "user"]
        
        for artifact in user_artifacts:
            self._do_place(artifact)
    
    def _cancel(self):
        """Cancel placement and go back."""
        self.artifacts_to_place = []
        self.placed_artifacts = []
        self.skipped_artifacts = []
        
        app = App.get_running_app()
        if app:
            app.navigate_to("browse", direction="right")
    
    def _finish(self):
        """Finish placement and return to dashboard."""
        count = len(self.placed_artifacts)
        logger.info(f"Placement complete: {count} artifacts placed")
        
        self.artifacts_to_place = []
        self.placed_artifacts = []
        self.skipped_artifacts = []
        
        app = App.get_running_app()
        if app:
            app.go_back()
