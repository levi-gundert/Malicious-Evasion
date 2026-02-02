"""
Browse Screen.

Displays artifacts in a filterable list with:
- OS filter (auto-detected or manual)
- Category filter
- Privilege level filter (user/admin)
- Search by value
- Sort options (OS, Category, Confidence, Recent)

Built with KivyMD Material Design components.
Uses ScrollView with dynamically created widgets for reliability.
"""

import logging
import webbrowser
from typing import List, Optional, Dict, Any

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.textfield import MDTextField
from kivy.uix.spinner import Spinner
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp
from kivy.clock import Clock

logger = logging.getLogger(__name__)


class ArtifactCard(MDBoxLayout):
    """
    A card widget representing a single artifact in the browse list.
    
    Displays artifact value, metadata, and selection checkbox.
    """
    
    def __init__(self, artifact_data: Dict[str, Any], index: int, on_select_callback, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "horizontal"
        self.size_hint_y = None
        self.height = dp(90)
        self.padding = [dp(12), dp(8)]
        self.spacing = dp(12)
        self.md_bg_color = (0.071, 0.129, 0.212, 1)  # Dark card background
        
        # Store artifact data and index for later reference
        self.artifact_data = artifact_data
        self.index = index
        self.on_select_callback = on_select_callback
        self.selected = False
        
        self._build_ui()
    
    def _build_ui(self):
        """Build the card UI."""
        # Checkbox for selection
        self.checkbox = MDCheckbox(
            size_hint=(None, None),
            size=(dp(36), dp(36)),
            pos_hint={"center_y": 0.5},
            color_active=(0.102, 0.451, 0.91, 1),
        )
        self.checkbox.bind(active=self._on_checkbox_change)
        self.add_widget(self.checkbox)
        
        # Main content column
        content = MDBoxLayout(orientation="vertical", spacing=dp(2))
        
        # Row 1: Artifact value (path/key)
        value = self.artifact_data.get("value", "")
        display_value = value if len(value) < 80 else value[:77] + "..."
        
        value_label = MDLabel(
            text=display_value,
            font_style="Body2",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=0.35,
            shorten=True,
            shorten_from="right",
        )
        content.add_widget(value_label)
        
        # Row 2: OS | Category | Purpose
        os_type = self.artifact_data.get("os", "unknown").upper()
        category = self.artifact_data.get("category", "unknown")
        purpose = (self.artifact_data.get("evasion_purpose") or "evasion").replace("_", " ").title()
        
        meta_label = MDLabel(
            text=f"{os_type} | {category} | {purpose}",
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
            size_hint_y=0.3,
        )
        content.add_widget(meta_label)
        
        # Row 3: Confidence | Sample count | Triage link
        confidence = self.artifact_data.get("confidence", 0) or 0
        conf_pct = f"{confidence:.0%}" if isinstance(confidence, float) else str(confidence)
        sample_count = self.artifact_data.get("sample_count", 1)
        sample_id = self.artifact_data.get("source_sample_id", "")
        
        if sample_id:
            info_text = f"Conf: {conf_pct} | Seen: {sample_count}x | [ref=triage]{sample_id}[/ref]"
        else:
            info_text = f"Conf: {conf_pct} | Seen: {sample_count}x"
        
        self.info_label = MDLabel(
            text=info_text,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0, 0.831, 1, 1),
            size_hint_y=0.35,
            markup=True,
        )
        self.info_label.bind(on_ref_press=self._on_link_press)
        content.add_widget(self.info_label)
        
        self.add_widget(content)
        
        # Right side: Privilege badge
        priv_level = self.artifact_data.get("privilege_level", "user").lower()
        if priv_level == "admin":
            badge_color = (0.984, 0.737, 0.016, 1)  # Yellow
        elif priv_level == "root":
            badge_color = (0.918, 0.263, 0.208, 1)  # Red
        else:
            badge_color = (0.204, 0.659, 0.325, 1)  # Green
        
        badge = MDLabel(
            text=priv_level.upper(),
            size_hint=(None, None),
            size=(dp(60), dp(24)),
            halign="center",
            valign="middle",
            font_style="Caption",
            bold=True,
            theme_text_color="Custom",
            text_color=badge_color,
        )
        self.add_widget(badge)
    
    def _on_checkbox_change(self, checkbox, active):
        """Handle checkbox state change."""
        self.selected = active
        if self.on_select_callback:
            self.on_select_callback(self.index, active)
    
    def _on_link_press(self, instance, ref):
        """Handle link clicks in labels."""
        if ref == "triage":
            triage_url = self.artifact_data.get("triage_url", "")
            if triage_url:
                logger.info(f"Opening Triage URL: {triage_url}")
                webbrowser.open(triage_url)


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
        self._artifact_data: List[Dict[str, Any]] = []
        self._artifact_widgets: List[ArtifactCard] = []
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
        
        # Sort dropdown
        sort_layout = MDBoxLayout(size_hint_x=None, width=dp(160), spacing=dp(8))
        sort_label = MDLabel(
            text="Sort:",
            font_style="Caption",
            size_hint=(None, 1),
            width=dp(35),
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        sort_layout.add_widget(sort_label)
        
        self.sort_spinner = Spinner(
            text="OS",
            values=["OS", "Category", "Confidence", "Recent"],
            size_hint=(1, None),
            height=dp(40),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        self.sort_spinner.bind(text=self._on_filter_change)
        sort_layout.add_widget(self.sort_spinner)
        filter_card.add_widget(sort_layout)
        
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
        
        # ===== ARTIFACTS LIST (ScrollView with dynamic widgets) =====
        # Create container with background color
        list_container = MDBoxLayout(
            orientation="vertical",
            md_bg_color=(0.05, 0.09, 0.16, 1),
            padding=[dp(4), dp(4)],
        )
        
        # ScrollView for scrollable artifact list
        # scroll_type must include 'bars' for draggable scrollbar
        self.scroll_view = ScrollView(
            size_hint=(1, 1),
            bar_width=dp(14),
            bar_color=(0.4, 0.6, 0.9, 1.0),
            bar_inactive_color=(0.3, 0.5, 0.8, 0.6),
            do_scroll_x=False,
            do_scroll_y=True,
            scroll_type=['bars', 'content'],  # Enable both bar dragging and content scrolling
            bar_margin=dp(2),
            bar_pos_y='right',
            effect_cls='ScrollEffect',  # Smoother scrolling
        )
        
        # Container for artifact cards - must have size_hint_y=None for scrolling
        self.artifacts_container = MDBoxLayout(
            orientation="vertical",
            size_hint_y=None,
            spacing=dp(4),
            padding=[dp(4), dp(4)],
        )
        # Bind height to minimum_height so it grows with content
        self.artifacts_container.bind(minimum_height=self.artifacts_container.setter('height'))
        
        self.scroll_view.add_widget(self.artifacts_container)
        list_container.add_widget(self.scroll_view)
        main_layout.add_widget(list_container)
        
        self.add_widget(main_layout)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.info("Entering browse screen")
        
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
        
        logger.info(f"Refreshing artifacts: os={os_filter}, cat={cat_filter}, priv={priv_filter}")
        
        artifacts = app.database.get_artifacts(
            os_type=os_filter,
            category=cat_filter,
            privilege_level=priv_filter,
            search_text=search_text if search_text else None,
            limit=200,  # Limit for performance with dynamic widgets
        )
        
        logger.info(f"Got {len(artifacts)} artifacts from database")
        
        # Sort artifacts
        sort_option = self.sort_spinner.text
        artifacts = self._sort_artifacts(artifacts, sort_option)
        
        # Store artifact data
        self._artifact_data = [dict(a, selected=False) for a in artifacts]
        
        # Clear existing widgets
        self.artifacts_container.clear_widgets()
        self._artifact_widgets = []
        
        # Create new artifact cards
        for i, artifact in enumerate(self._artifact_data):
            card = ArtifactCard(
                artifact_data=artifact,
                index=i,
                on_select_callback=self._on_artifact_select,
            )
            self._artifact_widgets.append(card)
            self.artifacts_container.add_widget(card)
        
        logger.info(f"Created {len(self._artifact_widgets)} artifact cards")
        
        # Reset selections
        self.selected_artifacts = []
        self._update_place_button()
        
        self.results_label.text = f"Showing {len(artifacts)} artifacts"
    
    def _on_artifact_select(self, index: int, selected: bool):
        """Handle artifact selection/deselection."""
        if index < len(self._artifact_data):
            self._artifact_data[index]["selected"] = selected
            
            if selected:
                if self._artifact_data[index] not in self.selected_artifacts:
                    self.selected_artifacts.append(self._artifact_data[index])
            else:
                # Remove by matching id
                art_id = self._artifact_data[index].get("id")
                self.selected_artifacts = [a for a in self.selected_artifacts if a.get("id") != art_id]
            
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
    
    def _sort_artifacts(self, artifacts: List[dict], sort_option: str) -> List[dict]:
        """
        Sort artifacts based on the selected sort option.
        
        Args:
            artifacts: List of artifact dicts
            sort_option: One of "OS", "Category", "Confidence", "Recent"
            
        Returns:
            Sorted list of artifacts
        """
        if not artifacts:
            return artifacts
        
        # Define OS order for consistent sorting
        os_order = {"android": 0, "windows": 1, "linux": 2, "macos": 3}
        
        if sort_option == "OS":
            return sorted(
                artifacts,
                key=lambda a: (
                    os_order.get(a.get("os", "").lower(), 99),
                    a.get("category", ""),
                    a.get("value", ""),
                )
            )
        elif sort_option == "Category":
            return sorted(
                artifacts,
                key=lambda a: (
                    a.get("category", ""),
                    os_order.get(a.get("os", "").lower(), 99),
                    a.get("value", ""),
                )
            )
        elif sort_option == "Confidence":
            return sorted(
                artifacts,
                key=lambda a: (
                    -(a.get("confidence", 0) or 0),
                    os_order.get(a.get("os", "").lower(), 99),
                    a.get("value", ""),
                )
            )
        elif sort_option == "Recent":
            return sorted(
                artifacts,
                key=lambda a: (
                    a.get("last_seen", "") or "",
                    os_order.get(a.get("os", "").lower(), 99),
                ),
                reverse=True,
            )
        
        return artifacts
    
    def _go_back(self):
        """Navigate back to dashboard."""
        app = MDApp.get_running_app()
        if app:
            app.go_back()
