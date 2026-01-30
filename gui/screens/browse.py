"""
Browse Screen.

Displays artifacts in a filterable list with:
- OS filter (auto-detected or manual)
- Category filter
- Privilege level filter (user/admin)
- Search by value
- Sort by confidence

Theme: Recorded Future inspired (Electric Blue + Dark)
"""

import logging
from typing import List, Optional

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.checkbox import CheckBox
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.app import App
from kivy.clock import Clock

logger = logging.getLogger(__name__)


class ArtifactCard(BoxLayout):
    """
    Card widget displaying an artifact's details.
    
    Shows:
    - Artifact value (file path, registry key, etc.) - WHERE it will be placed
    - Category and type
    - Evasion purpose - WHY this artifact is used
    - Source sample SHA1 and Triage link
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
        self.height = 150  # Taller to fit more info
        self.padding = [16, 12, 16, 12]
        self.spacing = 16
        
        # Determine badge color based on privilege
        privilege = artifact.get("privilege_level", "user")
        if privilege == "admin":
            badge_color = (0.984, 0.737, 0.016, 1)  # Warning yellow
        elif privilege == "root":
            badge_color = (0.918, 0.263, 0.208, 1)  # Error red
        else:
            badge_color = (0.204, 0.659, 0.325, 1)  # Success green
        
        # Card background
        with self.canvas.before:
            # Fill
            Color(0.071, 0.129, 0.212, 1)  # Navy surface
            self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[8])
            # Border
            Color(0.118, 0.227, 0.373, 1)
            self.border_rect = RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[8]
            )
        self.bind(pos=self._update_rect, size=self._update_rect)
        
        # Checkbox for selection
        checkbox_container = BoxLayout(size_hint=(None, 1), width=40)
        self.checkbox = CheckBox(
            size_hint=(None, None),
            size=(40, 40),
            pos_hint={"center_y": 0.5},
        )
        if on_select:
            self.checkbox.bind(active=lambda cb, val: on_select(artifact, val))
        checkbox_container.add_widget(self.checkbox)
        self.add_widget(checkbox_container)
        
        # Main content
        content = BoxLayout(orientation="vertical", spacing=4)
        
        # Row 1: Value (file path, registry key, etc.) - WHERE it will be placed
        value = artifact.get("value", "Unknown")
        # Truncate long values
        display_value = value if len(value) < 80 else value[:77] + "..."
        value_label = Label(
            text=f"[b]Placement:[/b] {display_value}",
            markup=True,
            font_size="13sp",
            halign="left",
            valign="middle",
            color=(1, 1, 1, 1),  # White
            size_hint_y=0.22,
        )
        value_label.bind(size=value_label.setter("text_size"))
        content.add_widget(value_label)
        
        # Row 2: Type and category
        artifact_type = artifact.get("artifact_type", "unknown")
        category = artifact.get("category", "unknown")
        os_type = artifact.get("os", "unknown")
        type_text = f"{os_type.upper()} • {artifact_type} • {category}"
        type_label = Label(
            text=type_text,
            font_size="11sp",
            halign="left",
            valign="middle",
            color=(0.604, 0.627, 0.651, 1),  # Muted
            size_hint_y=0.16,
        )
        type_label.bind(size=type_label.setter("text_size"))
        content.add_widget(type_label)
        
        # Row 3: Evasion purpose - WHY
        evasion_purpose = artifact.get("evasion_purpose", "")
        description = artifact.get("description", "")
        purpose_display = evasion_purpose or description or "Evasion technique"
        # Format purpose nicely
        purpose_formatted = purpose_display.replace("_", " ").title()
        purpose_label = Label(
            text=f"[b]Purpose:[/b] {purpose_formatted}",
            markup=True,
            font_size="11sp",
            halign="left",
            valign="middle",
            color=(0, 0.831, 1, 1),  # Cyan accent
            size_hint_y=0.18,
        )
        purpose_label.bind(size=purpose_label.setter("text_size"))
        content.add_widget(purpose_label)
        
        # Row 4: Source sample info (SHA1 + Triage link)
        source_sha1 = artifact.get("source_sha1", "")
        triage_url = artifact.get("triage_url", "")
        sample_id = artifact.get("source_sample_id", "")
        
        if source_sha1:
            sha1_short = source_sha1[:12] + "..." if len(source_sha1) > 12 else source_sha1
            source_text = f"Source: SHA1 {sha1_short}"
            if sample_id:
                source_text += f" | Triage: {sample_id}"
        else:
            source_text = "Source: Unknown"
        
        source_label = Label(
            text=source_text,
            font_size="10sp",
            halign="left",
            valign="middle",
            color=(0.604, 0.627, 0.651, 1),  # Muted
            size_hint_y=0.16,
        )
        source_label.bind(size=source_label.setter("text_size"))
        content.add_widget(source_label)
        
        # Row 5: Confidence and sample count
        confidence = artifact.get("confidence", 0)
        sample_count = artifact.get("sample_count", 1)
        if isinstance(confidence, (int, float)):
            conf_text = f"Confidence: {confidence:.0%} | Seen in {sample_count} sample(s)"
        else:
            conf_text = f"Confidence: {confidence} | Seen in {sample_count} sample(s)"
        conf_label = Label(
            text=conf_text,
            font_size="10sp",
            halign="left",
            valign="middle",
            color=(0.604, 0.627, 0.651, 1),  # Muted
            size_hint_y=0.14,
        )
        conf_label.bind(size=conf_label.setter("text_size"))
        content.add_widget(conf_label)
        
        # Store triage URL for potential future click handling
        self.triage_url = triage_url
        
        self.add_widget(content)
        
        # Right side: Badge + View button
        right_container = BoxLayout(orientation="vertical", size_hint=(None, 1), width=90, spacing=8)
        
        # Privilege badge
        badge_container = BoxLayout(size_hint_y=0.4, padding=[0, 8, 0, 0])
        badge_layout = BoxLayout(size_hint=(1, None), height=26)
        
        with badge_layout.canvas.before:
            Color(*badge_color)
            self.badge_rect = RoundedRectangle(pos=badge_layout.pos, size=badge_layout.size, radius=[4])
        badge_layout.bind(
            pos=lambda w, p: setattr(self.badge_rect, "pos", p),
            size=lambda w, s: setattr(self.badge_rect, "size", s),
        )
        
        badge_text = privilege.upper()
        badge_label = Label(
            text=badge_text,
            font_size="10sp",
            bold=True,
            color=(1, 1, 1, 1),
        )
        badge_layout.add_widget(badge_label)
        badge_container.add_widget(badge_layout)
        right_container.add_widget(badge_container)
        
        # View in Triage button (if URL available)
        if triage_url:
            view_btn = Button(
                text="View",
                font_size="11sp",
                size_hint=(1, 0.35),
                on_release=lambda x: self._open_triage(),
            )
            right_container.add_widget(view_btn)
        else:
            # Spacer
            right_container.add_widget(BoxLayout(size_hint_y=0.35))
        
        # Bottom spacer
        right_container.add_widget(BoxLayout(size_hint_y=0.25))
        
        self.add_widget(right_container)
    
    def _open_triage(self):
        """Open the Triage URL in the default browser."""
        import webbrowser
        if self.triage_url:
            logger.info(f"Opening Triage URL: {self.triage_url}")
            webbrowser.open(self.triage_url)
    
    def _update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size
        self.border_rect.pos = self.pos
        self.border_rect.size = self.size


class BrowseScreen(Screen):
    """Browse and filter artifacts screen with premium styling."""
    
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
        """Build the browse UI with Recorded Future theme."""
        main_layout = BoxLayout(orientation="vertical", padding=[24, 20, 24, 20], spacing=16)
        
        # =====================================================================
        # Header with back button and title
        # =====================================================================
        header = BoxLayout(size_hint_y=None, height=50, spacing=16)
        
        back_btn = Button(
            text="< Back",
            size_hint=(None, None),
            size=(100, 44),
            font_size="14sp",
            on_release=lambda x: self._go_back(),
        )
        header.add_widget(back_btn)
        
        title = Label(
            text="Browse Artifacts",
            font_size="24sp",
            bold=True,
            halign="left",
            valign="middle",
            color=(1, 1, 1, 1),  # White
        )
        title.bind(size=title.setter("text_size"))
        header.add_widget(title)
        
        # Place selected button
        self.place_btn = Button(
            text="Place Selected (0)",
            size_hint=(None, None),
            size=(160, 44),
            font_size="14sp",
            on_release=lambda x: self._place_selected(),
        )
        # Initially disabled styling
        self.place_btn.disabled = True
        header.add_widget(self.place_btn)
        
        main_layout.add_widget(header)
        
        # =====================================================================
        # Filter row with proper spacing
        # =====================================================================
        filter_container = BoxLayout(
            size_hint_y=None, 
            height=60, 
            padding=[16, 8, 16, 8],
            spacing=12,
        )
        
        # Background for filter bar
        with filter_container.canvas.before:
            Color(0.071, 0.129, 0.212, 1)  # Navy surface
            self.filter_bg = RoundedRectangle(
                pos=filter_container.pos,
                size=filter_container.size,
                radius=[8]
            )
        filter_container.bind(
            pos=lambda w, p: setattr(self.filter_bg, "pos", p),
            size=lambda w, s: setattr(self.filter_bg, "size", s),
        )
        
        # OS filter
        os_layout = BoxLayout(size_hint_x=None, width=140, spacing=8)
        os_label = Label(
            text="OS:", 
            size_hint=(None, 1), 
            width=30,
            font_size="13sp",
            color=(0.604, 0.627, 0.651, 1),  # Muted
        )
        os_layout.add_widget(os_label)
        
        self.os_spinner = Spinner(
            text="All",
            values=["All", "Android", "Windows", "Linux", "macOS"],
            size_hint=(1, None),
            height=40,
        )
        self.os_spinner.bind(text=self._on_filter_change)
        os_layout.add_widget(self.os_spinner)
        filter_container.add_widget(os_layout)
        
        # Category filter
        cat_layout = BoxLayout(size_hint_x=None, width=200, spacing=8)
        cat_label = Label(
            text="Category:", 
            size_hint=(None, 1), 
            width=65,
            font_size="13sp",
            color=(0.604, 0.627, 0.651, 1),  # Muted
        )
        cat_layout.add_widget(cat_label)
        
        self.category_spinner = Spinner(
            text="All",
            values=["All", "vm_files", "root_indicators", "sandbox_files", 
                    "emulator_files", "hooking_frameworks", "analysis_tools",
                    "vm_registry", "vm_processes"],
            size_hint=(1, None),
            height=40,
        )
        self.category_spinner.bind(text=self._on_filter_change)
        cat_layout.add_widget(self.category_spinner)
        filter_container.add_widget(cat_layout)
        
        # Privilege filter
        priv_layout = BoxLayout(size_hint_x=None, width=150, spacing=8)
        priv_label = Label(
            text="Privilege:", 
            size_hint=(None, 1), 
            width=60,
            font_size="13sp",
            color=(0.604, 0.627, 0.651, 1),  # Muted
        )
        priv_layout.add_widget(priv_label)
        
        self.privilege_spinner = Spinner(
            text="All",
            values=["All", "User", "Admin", "Root"],
            size_hint=(1, None),
            height=40,
        )
        self.privilege_spinner.bind(text=self._on_filter_change)
        priv_layout.add_widget(self.privilege_spinner)
        filter_container.add_widget(priv_layout)
        
        # Search box (takes remaining space)
        search_layout = BoxLayout(spacing=8)
        search_label = Label(
            text="Search:", 
            size_hint=(None, 1), 
            width=55,
            font_size="13sp",
            color=(0.604, 0.627, 0.651, 1),  # Muted
        )
        search_layout.add_widget(search_label)
        
        self.search_input = TextInput(
            hint_text="Filter by value...",
            multiline=False,
            size_hint=(1, None),
            height=40,
        )
        self.search_input.bind(text=self._on_search_change)
        search_layout.add_widget(self.search_input)
        filter_container.add_widget(search_layout)
        
        main_layout.add_widget(filter_container)
        
        # =====================================================================
        # Results count
        # =====================================================================
        self.results_label = Label(
            text="Showing 0 artifacts",
            font_size="13sp",
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=30,
            color=(0.604, 0.627, 0.651, 1),  # Muted
        )
        self.results_label.bind(size=self.results_label.setter("text_size"))
        main_layout.add_widget(self.results_label)
        
        # =====================================================================
        # Artifacts list (scrollable)
        # =====================================================================
        scroll = ScrollView(size_hint=(1, 1))
        self.artifacts_layout = BoxLayout(
            orientation="vertical",
            spacing=10,
            size_hint_y=None,
            padding=[0, 8, 8, 8],
        )
        self.artifacts_layout.bind(minimum_height=self.artifacts_layout.setter("height"))
        scroll.add_widget(self.artifacts_layout)
        main_layout.add_widget(scroll)
        
        self.add_widget(main_layout)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering browse screen")
        
        # Auto-detect OS and set filter
        app = App.get_running_app()
        if app:
            os_map = {
                "android": "Android",
                "windows": "Windows",
                "linux": "Linux",
                "macos": "macOS",
            }
            # If user ran an update for a single OS, default the filter to it
            if getattr(app, "last_update_os", None):
                self.os_spinner.text = os_map.get(app.last_update_os, "All")
            else:
                # Default to all
                self.os_spinner.text = "All"
        
        self._refresh_artifacts()
    
    def _on_filter_change(self, spinner, text):
        """Handle filter spinner change."""
        Clock.schedule_once(lambda dt: self._refresh_artifacts(), 0.1)
    
    def _on_search_change(self, input_widget, text):
        """Handle search text change."""
        # Debounce search
        Clock.unschedule(self._do_search)
        Clock.schedule_once(lambda dt: self._do_search(), 0.3)
    
    def _do_search(self):
        """Perform search after debounce."""
        self._refresh_artifacts()
    
    def _refresh_artifacts(self):
        """Refresh the artifacts list based on filters."""
        app = App.get_running_app()
        if not app or not app.database:
            logger.warning("No database available")
            return
        
        # Build filter criteria
        os_filter = self.os_spinner.text.lower() if self.os_spinner.text != "All" else None
        cat_filter = self.category_spinner.text if self.category_spinner.text != "All" else None
        priv_filter = self.privilege_spinner.text.lower() if self.privilege_spinner.text != "All" else None
        search_text = self.search_input.text.strip()
        
        logger.debug(f"Refreshing artifacts: os={os_filter}, cat={cat_filter}, priv={priv_filter}, search={search_text}")
        
        # Get filtered artifacts (higher limit so all OS types show)
        artifacts = app.database.get_artifacts(
            os_type=os_filter,
            category=cat_filter,
            privilege_level=priv_filter,
            search_text=search_text if search_text else None,
            limit=500,
        )
        
        logger.debug(f"Got {len(artifacts)} artifacts from database (os_filter={os_filter})")
        
        # Clear current list
        self.artifacts_layout.clear_widgets()
        self.selected_artifacts = []
        self._update_place_button()
        
        # Add artifact cards
        for artifact in artifacts:
            card = ArtifactCard(artifact, on_select=self._on_artifact_select)
            self.artifacts_layout.add_widget(card)
        
        # Update results count
        self.results_label.text = f"Showing {len(artifacts)} artifacts"
        
        if not artifacts:
            # Helpful message when filtered by OS (e.g. Windows) but no results
            if os_filter:
                hint = (
                    f"No {os_filter.capitalize()} artifacts in database.\n"
                    "Run 'Check for Updates' on the dashboard with that OS selected to fetch samples."
                )
            else:
                hint = "No artifacts match the current filters.\nTry changing the filters or run 'Check for Updates'."
            no_results = Label(
                text=hint,
                font_size="14sp",
                color=(0.604, 0.627, 0.651, 1),  # Muted
                size_hint_y=None,
                height=80,
                halign="center",
            )
            no_results.bind(size=no_results.setter("text_size"))
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
        
        app = App.get_running_app()
        if app:
            # Store selected artifacts for placement screen
            placement_screen = app.screen_manager.get_screen("placement")
            placement_screen.set_artifacts(self.selected_artifacts.copy())
            app.navigate_to("placement")
    
    def _go_back(self):
        """Navigate back to dashboard."""
        app = App.get_running_app()
        if app:
            app.go_back()
