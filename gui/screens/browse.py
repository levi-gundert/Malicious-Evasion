"""
Browse Screen.

Displays artifacts in a filterable list with:
- OS filter (auto-detected or manual)
- Category filter
- Privilege level filter (user/admin)
- Search by value
- Sort by confidence

Built with KivyMD Material Design components.
"""

import logging
from typing import List, Optional

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.gridlayout import MDGridLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton, MDIconButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.textfield import MDTextField
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.metrics import dp
from kivy.clock import Clock

logger = logging.getLogger(__name__)


class ArtifactCard(MDCard):
    """
    Card widget displaying an artifact's details.
    
    Shows:
    - Artifact value (file path, registry key, etc.)
    - Category and type
    - Evasion purpose
    - Source sample info
    - Privilege requirement badge
    - Confidence score
    - Select checkbox
    """
    
    def __init__(self, artifact: dict, on_select=None, **kwargs):
        super().__init__(**kwargs)
        self.artifact = artifact
        self.on_select_callback = on_select
        self.orientation = "horizontal"
        self.size_hint_y = None
        self.height = dp(140)
        self.padding = dp(16)
        self.spacing = dp(16)
        self.radius = [dp(12)]
        self.md_bg_color = (0.071, 0.129, 0.212, 1)  # Navy surface
        
        # Determine badge color based on privilege
        privilege = artifact.get("privilege_level", "user")
        if privilege == "admin":
            badge_color = (0.984, 0.737, 0.016, 1)  # Yellow
        elif privilege == "root":
            badge_color = (0.918, 0.263, 0.208, 1)  # Red
        else:
            badge_color = (0.204, 0.659, 0.325, 1)  # Green
        
        # Checkbox for selection
        checkbox_container = MDBoxLayout(
            size_hint=(None, 1),
            width=dp(40),
        )
        self.checkbox = MDCheckbox(
            size_hint=(None, None),
            size=(dp(40), dp(40)),
            pos_hint={"center_y": 0.5},
            color_active=(0.102, 0.451, 0.91, 1),
        )
        if on_select:
            self.checkbox.bind(active=lambda cb, val: on_select(artifact, val))
        checkbox_container.add_widget(self.checkbox)
        self.add_widget(checkbox_container)
        
        # Main content
        content = MDBoxLayout(orientation="vertical", spacing=dp(4))
        
        # Row 1: Value (file path, registry key, etc.)
        value = artifact.get("value", "Unknown")
        display_value = value if len(value) < 70 else value[:67] + "..."
        value_label = MDLabel(
            text=f"[b]Placement:[/b] {display_value}",
            markup=True,
            font_style="Body1",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=0.22,
        )
        content.add_widget(value_label)
        
        # Row 2: Type and category
        artifact_type = artifact.get("artifact_type", "unknown")
        category = artifact.get("category", "unknown")
        os_type = artifact.get("os", "unknown")
        type_text = f"{os_type.upper()} | {artifact_type} | {category}"
        type_label = MDLabel(
            text=type_text,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=0.16,
        )
        content.add_widget(type_label)
        
        # Row 3: Evasion purpose
        evasion_purpose = artifact.get("evasion_purpose", "")
        description = artifact.get("description", "")
        purpose_display = evasion_purpose or description or "Evasion technique"
        purpose_formatted = purpose_display.replace("_", " ").title()
        purpose_label = MDLabel(
            text=f"[b]Purpose:[/b] {purpose_formatted}",
            markup=True,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0, 0.831, 1, 1),  # Cyan
            size_hint_y=0.18,
        )
        content.add_widget(purpose_label)
        
        # Row 4: Source sample info
        source_sha1 = artifact.get("source_sha1", "")
        sample_id = artifact.get("source_sample_id", "")
        
        if source_sha1:
            sha1_short = source_sha1[:12] + "..." if len(source_sha1) > 12 else source_sha1
            source_text = f"Source: SHA1 {sha1_short}"
            if sample_id:
                source_text += f" | Triage: {sample_id}"
        else:
            source_text = "Source: Unknown"
        
        source_label = MDLabel(
            text=source_text,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=0.16,
        )
        content.add_widget(source_label)
        
        # Row 5: Confidence and sample count
        confidence = artifact.get("confidence", 0)
        sample_count = artifact.get("sample_count", 1)
        if isinstance(confidence, (int, float)):
            conf_text = f"Confidence: {confidence:.0%} | Seen in {sample_count} sample(s)"
        else:
            conf_text = f"Confidence: {confidence} | Seen in {sample_count} sample(s)"
        conf_label = MDLabel(
            text=conf_text,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=0.14,
        )
        content.add_widget(conf_label)
        
        self.add_widget(content)
        
        # Right side: Badge + View button
        right_container = MDBoxLayout(
            orientation="vertical",
            size_hint=(None, 1),
            width=dp(90),
            spacing=dp(8),
        )
        
        # Privilege badge
        badge = MDCard(
            size_hint=(1, None),
            height=dp(28),
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
        right_container.add_widget(badge)
        
        # View in Triage button
        triage_url = artifact.get("triage_url", "")
        if triage_url:
            view_btn = MDFlatButton(
                text="View",
                size_hint=(1, None),
                height=dp(36),
                theme_text_color="Custom",
                text_color=(0, 0.831, 1, 1),
                on_release=lambda x: self._open_triage(),
            )
            right_container.add_widget(view_btn)
        
        # Spacer
        right_container.add_widget(MDBoxLayout())
        
        self.triage_url = triage_url
        self.add_widget(right_container)
    
    def _open_triage(self):
        """Open the Triage URL in the default browser."""
        import webbrowser
        if self.triage_url:
            logger.info(f"Opening Triage URL: {self.triage_url}")
            webbrowser.open(self.triage_url)


class BrowseScreen(MDScreen):
    """Browse and filter artifacts screen with KivyMD styling."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_artifacts = []
        self.current_filters = {
            "os": None,
            "category": None,
            "privilege": None,
            "search": "",
        }
        self._build_ui()
    
    def _build_ui(self):
        """Build the browse UI with KivyMD components."""
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
            spacing=dp(16),
        )
        
        back_btn = MDRaisedButton(
            text="< Back",
            size_hint=(None, None),
            size=(dp(100), dp(44)),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._go_back(),
        )
        header.add_widget(back_btn)
        
        title = MDLabel(
            text="Browse Artifacts",
            font_style="H5",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        header.add_widget(title)
        
        self.place_btn = MDRaisedButton(
            text="Place Selected (0)",
            size_hint=(None, None),
            size=(dp(180), dp(44)),
            md_bg_color=(0.204, 0.659, 0.325, 1),
            on_release=lambda x: self._place_selected(),
        )
        self.place_btn.disabled = True
        header.add_widget(self.place_btn)
        
        main_layout.add_widget(header)
        
        # ===== FILTER ROW =====
        filter_card = MDCard(
            orientation="horizontal",
            size_hint_y=None,
            height=dp(60),
            padding=dp(16),
            spacing=dp(12),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
        )
        
        # OS filter
        os_layout = MDBoxLayout(size_hint_x=None, width=dp(140), spacing=dp(8))
        os_label = MDLabel(
            text="OS:",
            font_style="Caption",
            size_hint=(None, 1),
            width=dp(30),
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        os_layout.add_widget(os_label)
        
        self.os_spinner = Spinner(
            text="All",
            values=["All", "Android", "Windows", "Linux", "macOS"],
            size_hint=(1, None),
            height=dp(40),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        self.os_spinner.bind(text=self._on_filter_change)
        os_layout.add_widget(self.os_spinner)
        filter_card.add_widget(os_layout)
        
        # Category filter
        cat_layout = MDBoxLayout(size_hint_x=None, width=dp(200), spacing=dp(8))
        cat_label = MDLabel(
            text="Category:",
            font_style="Caption",
            size_hint=(None, 1),
            width=dp(65),
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        cat_layout.add_widget(cat_label)
        
        self.category_spinner = Spinner(
            text="All",
            values=["All", "vm_files", "root_indicators", "sandbox_files",
                    "emulator_files", "hooking_frameworks", "analysis_tools",
                    "vm_registry", "vm_processes"],
            size_hint=(1, None),
            height=dp(40),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        self.category_spinner.bind(text=self._on_filter_change)
        cat_layout.add_widget(self.category_spinner)
        filter_card.add_widget(cat_layout)
        
        # Privilege filter
        priv_layout = MDBoxLayout(size_hint_x=None, width=dp(150), spacing=dp(8))
        priv_label = MDLabel(
            text="Privilege:",
            font_style="Caption",
            size_hint=(None, 1),
            width=dp(60),
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        priv_layout.add_widget(priv_label)
        
        self.privilege_spinner = Spinner(
            text="All",
            values=["All", "User", "Admin", "Root"],
            size_hint=(1, None),
            height=dp(40),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        self.privilege_spinner.bind(text=self._on_filter_change)
        priv_layout.add_widget(self.privilege_spinner)
        filter_card.add_widget(priv_layout)
        
        # Search box
        search_layout = MDBoxLayout(spacing=dp(8))
        search_label = MDLabel(
            text="Search:",
            font_style="Caption",
            size_hint=(None, 1),
            width=dp(55),
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        search_layout.add_widget(search_label)
        
        self.search_input = MDTextField(
            hint_text="Filter by value...",
            mode="fill",
            size_hint=(1, None),
            height=dp(40),
        )
        self.search_input.bind(text=self._on_search_change)
        search_layout.add_widget(self.search_input)
        filter_card.add_widget(search_layout)
        
        main_layout.add_widget(filter_card)
        
        # ===== RESULTS COUNT =====
        self.results_label = MDLabel(
            text="Showing 0 artifacts",
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=None,
            height=dp(28),
        )
        main_layout.add_widget(self.results_label)
        
        # ===== ARTIFACTS LIST =====
        scroll = ScrollView(size_hint=(1, 1))
        self.artifacts_layout = MDBoxLayout(
            orientation="vertical",
            spacing=dp(10),
            size_hint_y=None,
            padding=[0, dp(8), dp(8), dp(8)],
            adaptive_height=True,
        )
        self.artifacts_layout.bind(minimum_height=self.artifacts_layout.setter("height"))
        scroll.add_widget(self.artifacts_layout)
        main_layout.add_widget(scroll)
        
        self.add_widget(main_layout)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering browse screen")
        
        app = MDApp.get_running_app()
        if app:
            os_map = {
                "android": "Android",
                "windows": "Windows",
                "linux": "Linux",
                "macos": "macOS",
            }
            if getattr(app, "last_update_os", None):
                self.os_spinner.text = os_map.get(app.last_update_os, "All")
            else:
                self.os_spinner.text = "All"
        
        self._refresh_artifacts()
    
    def _on_filter_change(self, spinner, text):
        """Handle filter spinner change."""
        Clock.schedule_once(lambda dt: self._refresh_artifacts(), 0.1)
    
    def _on_search_change(self, input_widget, text):
        """Handle search text change."""
        Clock.unschedule(self._do_search)
        Clock.schedule_once(lambda dt: self._do_search(), 0.3)
    
    def _do_search(self):
        """Perform search after debounce."""
        self._refresh_artifacts()
    
    def _refresh_artifacts(self):
        """Refresh the artifacts list based on filters."""
        app = MDApp.get_running_app()
        if not app or not app.database:
            logger.warning("No database available")
            return
        
        os_filter = self.os_spinner.text.lower() if self.os_spinner.text != "All" else None
        cat_filter = self.category_spinner.text if self.category_spinner.text != "All" else None
        priv_filter = self.privilege_spinner.text.lower() if self.privilege_spinner.text != "All" else None
        search_text = self.search_input.text.strip()
        
        logger.debug(f"Refreshing artifacts: os={os_filter}, cat={cat_filter}, priv={priv_filter}")
        
        artifacts = app.database.get_artifacts(
            os_type=os_filter,
            category=cat_filter,
            privilege_level=priv_filter,
            search_text=search_text if search_text else None,
            limit=500,
        )
        
        logger.debug(f"Got {len(artifacts)} artifacts from database")
        
        self.artifacts_layout.clear_widgets()
        self.selected_artifacts = []
        self._update_place_button()
        
        for artifact in artifacts:
            card = ArtifactCard(artifact, on_select=self._on_artifact_select)
            self.artifacts_layout.add_widget(card)
        
        self.results_label.text = f"Showing {len(artifacts)} artifacts"
        
        if not artifacts:
            if os_filter:
                hint = (
                    f"No {os_filter.capitalize()} artifacts in database.\n"
                    "Run 'Check for Updates' on the dashboard with that OS selected."
                )
            else:
                hint = "No artifacts match the current filters.\nTry changing filters or run 'Check for Updates'."
            
            no_results = MDLabel(
                text=hint,
                font_style="Body2",
                theme_text_color="Custom",
                text_color=(0.604, 0.627, 0.651, 1),
                size_hint_y=None,
                height=dp(80),
                halign="center",
            )
            self.artifacts_layout.add_widget(no_results)
    
    def _on_artifact_select(self, artifact: dict, selected: bool):
        """Handle artifact selection/deselection."""
        if selected:
            if artifact not in self.selected_artifacts:
                self.selected_artifacts.append(artifact)
        else:
            if artifact in self.selected_artifacts:
                self.selected_artifacts.remove(artifact)
        
        self._update_place_button()
    
    def _update_place_button(self):
        """Update the place button text and state."""
        count = len(self.selected_artifacts)
        self.place_btn.text = f"Place Selected ({count})"
        self.place_btn.disabled = count == 0
    
    def _place_selected(self):
        """Navigate to placement screen with selected artifacts."""
        if not self.selected_artifacts:
            return
        
        app = MDApp.get_running_app()
        if app:
            placement_screen = app.screen_manager.get_screen("placement")
            placement_screen.set_artifacts(self.selected_artifacts.copy())
            app.navigate_to("placement")
    
    def _go_back(self):
        """Navigate back to dashboard."""
        app = MDApp.get_running_app()
        if app:
            app.go_back()
