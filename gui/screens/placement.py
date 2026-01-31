"""
Placement Screen.

Handles the placement wizard flow:
1. Show selected artifacts
2. Display privilege requirements with warnings
3. Require explicit confirmation for each
4. Trigger OS elevation when needed
5. Log all placements for later removal

Built with KivyMD Material Design components.
"""

import logging
from typing import List

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp
from kivy.clock import Clock

logger = logging.getLogger(__name__)


class PlacementItemWidget(MDCard):
    """Widget showing a single artifact to be placed."""
    
    def __init__(self, artifact: dict, on_place=None, on_skip=None, **kwargs):
        super().__init__(**kwargs)
        self.artifact = artifact
        self.on_place = on_place
        self.on_skip = on_skip
        self.orientation = "vertical"
        self.size_hint_y = None
        self.height = dp(150)
        self.padding = dp(16)
        self.spacing = dp(10)
        self.radius = [dp(12)]
        
        # Determine styling based on privilege
        privilege = artifact.get("privilege_level", "user")
        if privilege == "admin":
            bg_color = (0.15, 0.12, 0.08, 1)
            badge_color = (0.984, 0.737, 0.016, 1)
            warning_text = "Requires Administrator privileges"
        elif privilege == "root":
            bg_color = (0.15, 0.08, 0.08, 1)
            badge_color = (0.918, 0.263, 0.208, 1)
            warning_text = "Requires Root access"
        else:
            bg_color = (0.08, 0.15, 0.08, 1)
            badge_color = (0.204, 0.659, 0.325, 1)
            warning_text = "No special privileges required"
        
        self.md_bg_color = bg_color
        
        # Header with type badge
        header = MDBoxLayout(size_hint_y=None, height=dp(30), spacing=dp(10))
        
        type_text = f"{artifact.get('artifact_type', 'unknown').upper()}"
        type_label = MDLabel(
            text=type_text,
            font_style="Caption",
            bold=True,
            theme_text_color="Custom",
            text_color=(0.8, 0.8, 0.8, 1),
        )
        header.add_widget(type_label)
        
        # Privilege badge
        badge = MDCard(
            size_hint=(None, None),
            size=(dp(70), dp(24)),
            radius=[dp(4)],
            md_bg_color=badge_color,
        )
        badge_label = MDLabel(
            text=privilege.upper(),
            font_style="Caption",
            bold=True,
            halign="center",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        badge.add_widget(badge_label)
        header.add_widget(badge)
        
        self.add_widget(header)
        
        # Value (the actual artifact path/key)
        value = artifact.get("value", "Unknown")
        display_value = value if len(value) < 80 else value[:77] + "..."
        value_label = MDLabel(
            text=display_value,
            font_style="Body1",
            bold=True,
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(24),
        )
        self.add_widget(value_label)
        
        # Warning/info text
        warning_color = (0.7, 0.7, 0.5, 1) if privilege != "user" else (0.5, 0.7, 0.5, 1)
        warning_label = MDLabel(
            text=warning_text,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=warning_color,
            size_hint_y=None,
            height=dp(20),
        )
        self.add_widget(warning_label)
        
        # Action buttons
        buttons = MDBoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
        
        place_btn = MDRaisedButton(
            text="Place This Artifact",
            size_hint_x=0.7,
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._do_place(),
        )
        buttons.add_widget(place_btn)
        
        skip_btn = MDFlatButton(
            text="Skip",
            size_hint_x=0.3,
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            on_release=lambda x: self._do_skip(),
        )
        buttons.add_widget(skip_btn)
        
        self.add_widget(buttons)
    
    def _do_place(self):
        """Handle place button click."""
        if self.on_place:
            self.on_place(self.artifact)
    
    def _do_skip(self):
        """Handle skip button click."""
        if self.on_skip:
            self.on_skip(self.artifact)


class PlacementScreen(MDScreen):
    """Artifact placement wizard screen with KivyMD styling."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.artifacts_to_place = []
        self.placed_artifacts = []
        self.skipped_artifacts = []
        self._privilege_dialog = None
        self._build_ui()
    
    def _build_ui(self):
        """Build the placement UI with KivyMD components."""
        main_layout = MDBoxLayout(
            orientation="vertical",
            padding=[dp(24), dp(20), dp(24), dp(20)],
            spacing=dp(16),
            md_bg_color=(0.039, 0.086, 0.157, 1),
        )
        
        # ===== HEADER =====
        header = MDBoxLayout(
            size_hint_y=None,
            height=dp(50),
            spacing=dp(10),
        )
        
        back_btn = MDRaisedButton(
            text="< Cancel",
            size_hint=(None, None),
            size=(dp(110), dp(44)),
            md_bg_color=(0.918, 0.263, 0.208, 1),
            on_release=lambda x: self._cancel(),
        )
        header.add_widget(back_btn)
        
        title = MDLabel(
            text="Place Artifacts",
            font_style="H5",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        header.add_widget(title)
        
        main_layout.add_widget(header)
        
        # ===== STATUS =====
        self.status_label = MDLabel(
            text="Select artifacts from Browse to place.",
            font_style="Body1",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=None,
            height=dp(28),
        )
        main_layout.add_widget(self.status_label)
        
        # ===== WARNING BANNER =====
        warning_card = MDCard(
            size_hint_y=None,
            height=dp(50),
            radius=[dp(8)],
            md_bg_color=(0.4, 0.3, 0.1, 1),
        )
        warning_label = MDLabel(
            text="Review each artifact carefully. Admin/Root artifacts will prompt for elevation.",
            font_style="Caption",
            halign="center",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        warning_card.add_widget(warning_label)
        main_layout.add_widget(warning_card)
        
        # ===== ARTIFACTS LIST =====
        scroll = ScrollView(
            size_hint=(1, 1),
            bar_width=dp(12),
            bar_color=(0.3, 0.5, 0.8, 0.9),
            bar_inactive_color=(0.3, 0.5, 0.8, 0.4),
            scroll_type=['bars', 'content'],
        )
        self.items_layout = MDBoxLayout(
            orientation="vertical",
            spacing=dp(12),
            size_hint_y=None,
            padding=[0, 0, dp(10), 0],
            adaptive_height=True,
        )
        self.items_layout.bind(minimum_height=self.items_layout.setter("height"))
        scroll.add_widget(self.items_layout)
        main_layout.add_widget(scroll)
        
        # ===== FOOTER =====
        footer = MDCard(
            size_hint_y=None,
            height=dp(60),
            radius=[dp(8)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            padding=dp(10),
        )
        
        footer_content = MDBoxLayout(spacing=dp(10))
        
        self.summary_label = MDLabel(
            text="Placed: 0 | Skipped: 0 | Remaining: 0",
            font_style="Body2",
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        )
        footer_content.add_widget(self.summary_label)
        
        place_all_btn = MDRaisedButton(
            text="Place All User-Space",
            size_hint=(None, None),
            size=(dp(180), dp(40)),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._place_all_user(),
        )
        footer_content.add_widget(place_all_btn)
        
        done_btn = MDRaisedButton(
            text="Done",
            size_hint=(None, None),
            size=(dp(100), dp(40)),
            md_bg_color=(0.204, 0.659, 0.325, 1),
            on_release=lambda x: self._finish(),
        )
        footer_content.add_widget(done_btn)
        
        footer.add_widget(footer_content)
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
            empty_label = MDLabel(
                text="No artifacts to place. Go to Browse to select artifacts.",
                font_style="Body2",
                theme_text_color="Custom",
                text_color=(0.604, 0.627, 0.651, 1),
                size_hint_y=None,
                height=dp(40),
                halign="center",
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
            self._show_privilege_confirmation(artifact)
        else:
            self._do_place(artifact)
    
    def _show_privilege_confirmation(self, artifact: dict):
        """Show confirmation dialog for privileged artifact."""
        privilege = artifact.get("privilege_level", "admin")
        value = artifact.get("value", "Unknown")
        display_value = value if len(value) < 60 else value[:57] + "..."
        
        self._privilege_dialog = MDDialog(
            title="Privilege Required",
            text=(
                f"This artifact requires {privilege.upper()} privileges.\n\n"
                f"Value: {display_value}\n\n"
                f"The system will prompt you for elevation.\n"
                f"Do you want to proceed?"
            ),
            buttons=[
                MDFlatButton(
                    text="Cancel",
                    on_release=lambda x: self._privilege_dialog.dismiss(),
                ),
                MDRaisedButton(
                    text="Proceed",
                    md_bg_color=(0.984, 0.737, 0.016, 1),
                    text_color=(0, 0, 0, 1),
                    on_release=lambda x: self._on_privilege_confirmed(artifact),
                ),
            ],
        )
        self._privilege_dialog.open()
    
    def _on_privilege_confirmed(self, artifact: dict):
        """Handle privilege confirmation."""
        if self._privilege_dialog:
            self._privilege_dialog.dismiss()
        self._do_place(artifact, with_elevation=True)
    
    def _do_place(self, artifact: dict, with_elevation: bool = False):
        """Actually place the artifact."""
        app = MDApp.get_running_app()
        if not app:
            return
        
        from gui.services.placement_engine import PlacementEngine
        
        engine = PlacementEngine(app.current_os)
        
        try:
            success = engine.place_artifact(artifact, elevate=with_elevation)
            
            if success:
                logger.info(f"Placed artifact: {artifact.get('value')}")
                self.placed_artifacts.append(artifact)
                self.artifacts_to_place.remove(artifact)
                
                if app.database:
                    app.database.log_placement(artifact)
            else:
                logger.warning(f"Failed to place artifact: {artifact.get('value')}")
                
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
        
        app = MDApp.get_running_app()
        if app:
            app.navigate_to("browse", direction="right")
    
    def _finish(self):
        """Finish placement and return to dashboard."""
        count = len(self.placed_artifacts)
        logger.info(f"Placement complete: {count} artifacts placed")
        
        self.artifacts_to_place = []
        self.placed_artifacts = []
        self.skipped_artifacts = []
        
        app = MDApp.get_running_app()
        if app:
            app.go_back()
