"""
Settings Screen.

Configure:
- Triage API key
- Update frequency
- Default OS filter
- Data directory

Built with KivyMD Material Design components.
"""

import logging

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.selectioncontrol import MDSwitch
from kivymd.uix.dialog import MDDialog
from kivy.uix.spinner import Spinner
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp

logger = logging.getLogger(__name__)


class SettingRow(MDBoxLayout):
    """A single setting row with label and control."""
    
    def __init__(self, label: str, widget, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "horizontal"
        self.size_hint_y = None
        self.height = dp(56)
        self.spacing = dp(20)
        self.padding = [dp(10), dp(5)]
        
        label_widget = MDLabel(
            text=label,
            font_style="Body1",
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
            size_hint_x=0.4,
        )
        self.add_widget(label_widget)
        
        self.add_widget(widget)


class SettingsScreen(MDScreen):
    """Settings configuration screen with KivyMD styling."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._dialog = None
        self._build_ui()
    
    def _build_ui(self):
        """Build the settings UI with KivyMD components."""
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
            text="< Back",
            size_hint=(None, None),
            size=(dp(100), dp(44)),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._go_back(),
        )
        header.add_widget(back_btn)
        
        title = MDLabel(
            text="Settings",
            font_style="H5",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
        )
        header.add_widget(title)
        
        save_btn = MDRaisedButton(
            text="Save",
            size_hint=(None, None),
            size=(dp(100), dp(44)),
            md_bg_color=(0.204, 0.659, 0.325, 1),
            on_release=lambda x: self._save_settings(),
        )
        header.add_widget(save_btn)
        
        main_layout.add_widget(header)
        
        # ===== SCROLLABLE CONTENT =====
        scroll = ScrollView(
            size_hint=(1, 1),
            bar_width=dp(12),
            bar_color=(0.3, 0.5, 0.8, 0.9),
            bar_inactive_color=(0.3, 0.5, 0.8, 0.4),
            scroll_type=['bars', 'content'],
        )
        content = MDBoxLayout(
            orientation="vertical",
            spacing=dp(20),
            size_hint_y=None,
            padding=[0, dp(10), 0, dp(10)],
            adaptive_height=True,
        )
        content.bind(minimum_height=content.setter("height"))
        
        # --- API Configuration Section ---
        api_card = MDCard(
            orientation="vertical",
            padding=dp(20),
            spacing=dp(12),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            size_hint_y=None,
            height=dp(220),
        )
        
        api_header = MDLabel(
            text="API Configuration",
            font_style="H6",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(32),
        )
        api_card.add_widget(api_header)
        
        # API Key
        self.api_key_input = MDTextField(
            hint_text="Enter Triage API key",
            password=True,
            mode="fill",
            size_hint_y=None,
            height=dp(48),
        )
        api_card.add_widget(self.api_key_input)
        
        # Show key toggle
        show_key_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(40))
        show_key_row.add_widget(MDLabel(
            text="Show API Key:",
            font_style="Body2",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.show_key_switch = MDSwitch(
            size_hint=(None, None),
            size=(dp(48), dp(28)),
        )
        self.show_key_switch.bind(active=self._on_show_key_toggle)
        show_key_row.add_widget(self.show_key_switch)
        show_key_row.add_widget(MDBoxLayout())  # Spacer
        api_card.add_widget(show_key_row)
        
        # Test connection button
        test_btn = MDRaisedButton(
            text="Test Connection",
            size_hint=(None, None),
            size=(dp(160), dp(40)),
            md_bg_color=(0.102, 0.451, 0.91, 1),
            on_release=lambda x: self._test_connection(),
        )
        api_card.add_widget(test_btn)
        
        content.add_widget(api_card)
        
        # --- Update Settings Section ---
        update_card = MDCard(
            orientation="vertical",
            padding=dp(20),
            spacing=dp(12),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            size_hint_y=None,
            height=dp(220),  # Increased for samples per update field
        )
        
        update_header = MDLabel(
            text="Update Settings",
            font_style="H6",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(32),
        )
        update_card.add_widget(update_header)
        
        # Update frequency
        freq_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        freq_row.add_widget(MDLabel(
            text="Update Frequency:",
            font_style="Body2",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.update_freq_spinner = Spinner(
            text="Daily",
            values=["Hourly", "Daily", "Weekly", "Manual"],
            size_hint=(None, None),
            size=(dp(150), dp(40)),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        freq_row.add_widget(self.update_freq_spinner)
        update_card.add_widget(freq_row)
        
        # Auto-update switch
        auto_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        auto_row.add_widget(MDLabel(
            text="Auto-Update:",
            font_style="Body2",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.auto_update_switch = MDSwitch(
            size_hint=(None, None),
            size=(dp(48), dp(28)),
        )
        auto_row.add_widget(self.auto_update_switch)
        auto_row.add_widget(MDBoxLayout())  # Spacer
        update_card.add_widget(auto_row)
        
        # Samples per update
        samples_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        samples_row.add_widget(MDLabel(
            text="Samples per Update:",
            font_style="Body2",
            size_hint_x=0.5,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.samples_per_update_input = MDTextField(
            text="50",
            hint_text="50",
            mode="fill",
            input_filter="int",
            size_hint=(None, None),
            size=(dp(80), dp(40)),
        )
        samples_row.add_widget(self.samples_per_update_input)
        samples_row.add_widget(MDLabel(
            text="per OS",
            font_style="Caption",
            size_hint_x=0.3,
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        ))
        update_card.add_widget(samples_row)
        
        content.add_widget(update_card)
        
        # --- Preferences Section ---
        pref_card = MDCard(
            orientation="vertical",
            padding=dp(20),
            spacing=dp(12),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            size_hint_y=None,
            height=dp(160),
        )
        
        pref_header = MDLabel(
            text="Preferences",
            font_style="H6",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(32),
        )
        pref_card.add_widget(pref_header)
        
        # Default OS filter
        os_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        os_row.add_widget(MDLabel(
            text="Default OS Filter:",
            font_style="Body2",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.default_os_spinner = Spinner(
            text="Auto-detect",
            values=["Auto-detect", "Android", "Windows", "Linux", "macOS"],
            size_hint=(None, None),
            size=(dp(150), dp(40)),
            background_color=(0.118, 0.227, 0.373, 1),
            color=(1, 1, 1, 1),
        )
        os_row.add_widget(self.default_os_spinner)
        pref_card.add_widget(os_row)
        
        # Show admin artifacts
        admin_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        admin_row.add_widget(MDLabel(
            text="Show Admin Artifacts:",
            font_style="Body2",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        self.show_admin_switch = MDSwitch(
            size_hint=(None, None),
            size=(dp(48), dp(28)),
        )
        admin_row.add_widget(self.show_admin_switch)
        admin_row.add_widget(MDBoxLayout())  # Spacer
        pref_card.add_widget(admin_row)
        
        content.add_widget(pref_card)
        
        # --- Data Management Section ---
        data_card = MDCard(
            orientation="vertical",
            padding=dp(20),
            spacing=dp(12),
            radius=[dp(12)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
            size_hint_y=None,
            height=dp(160),
        )
        
        data_header = MDLabel(
            text="Data Management",
            font_style="H6",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),
            size_hint_y=None,
            height=dp(32),
        )
        data_card.add_widget(data_header)
        
        # Data directory
        app = MDApp.get_running_app()
        data_dir = str(app.get_data_dir()) if app else "Unknown"
        data_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        data_row.add_widget(MDLabel(
            text="Data Directory:",
            font_style="Body2",
            size_hint_x=0.3,
            theme_text_color="Custom",
            text_color=(0.91, 0.918, 0.929, 1),
        ))
        data_row.add_widget(MDLabel(
            text=data_dir,
            font_style="Caption",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        ))
        data_card.add_widget(data_row)
        
        # Clear data buttons
        buttons_row = MDBoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        
        clear_log_btn = MDRaisedButton(
            text="Clear Placed Log",
            size_hint_x=0.5,
            md_bg_color=(0.984, 0.737, 0.016, 1),
            text_color=(0, 0, 0, 1),
            on_release=lambda x: self._clear_placed_log(),
        )
        buttons_row.add_widget(clear_log_btn)
        
        clear_all_btn = MDRaisedButton(
            text="Clear All Data",
            size_hint_x=0.5,
            md_bg_color=(0.918, 0.263, 0.208, 1),
            on_release=lambda x: self._clear_all_data(),
        )
        buttons_row.add_widget(clear_all_btn)
        
        data_card.add_widget(buttons_row)
        content.add_widget(data_card)
        
        scroll.add_widget(content)
        main_layout.add_widget(scroll)
        
        # ===== FOOTER =====
        footer = MDCard(
            size_hint_y=None,
            height=dp(44),
            radius=[dp(8)],
            md_bg_color=(0.071, 0.129, 0.212, 1),
        )
        version_label = MDLabel(
            text="Evasion Artifact Placer v1.0.0",
            font_style="Caption",
            halign="center",
            theme_text_color="Custom",
            text_color=(0.604, 0.627, 0.651, 1),
        )
        footer.add_widget(version_label)
        main_layout.add_widget(footer)
        
        self.add_widget(main_layout)
    
    def on_enter(self):
        """Called when screen is displayed."""
        logger.debug("Entering settings screen")
        self._load_settings()
    
    def _load_settings(self):
        """Load current settings from storage."""
        app = MDApp.get_running_app()
        if not app or not app.database:
            return
        
        settings = app.database.get_settings()
        
        self.api_key_input.text = settings.get("api_key", "")
        self.update_freq_spinner.text = settings.get("update_frequency", "Daily")
        self.auto_update_switch.active = settings.get("auto_update", True)
        self.samples_per_update_input.text = str(settings.get("samples_per_update", 50))
        self.default_os_spinner.text = settings.get("default_os", "Auto-detect")
        self.show_admin_switch.active = settings.get("show_admin", True)
    
    def _save_settings(self):
        """Save settings to storage."""
        app = MDApp.get_running_app()
        if not app or not app.database:
            self._show_message("Error", "Database not available")
            return
        
        # Parse samples per update (with validation)
        try:
            samples_per_update = int(self.samples_per_update_input.text or "50")
            samples_per_update = max(10, min(200, samples_per_update))  # Clamp between 10-200
        except ValueError:
            samples_per_update = 50
        
        settings = {
            "api_key": self.api_key_input.text,
            "update_frequency": self.update_freq_spinner.text,
            "auto_update": self.auto_update_switch.active,
            "samples_per_update": samples_per_update,
            "default_os": self.default_os_spinner.text,
            "show_admin": self.show_admin_switch.active,
        }
        
        app.database.save_settings(settings)
        logger.info(f"Settings saved (samples_per_update: {samples_per_update})")
        
        self._show_message("Success", "Settings saved successfully!")
    
    def _on_show_key_toggle(self, switch, active):
        """Toggle API key visibility."""
        self.api_key_input.password = not active
    
    def _test_connection(self):
        """Test the Triage API connection."""
        api_key = self.api_key_input.text.strip()
        
        if not api_key:
            self._show_message("Error", "Please enter an API key first.")
            return
        
        logger.info("Testing API connection...")
        
        try:
            from extractor.triage.client import TriageClient
            
            client = TriageClient(api_key=api_key)
            if client.test_connection():
                self._show_message("Success", "API connection successful!")
            else:
                self._show_message("Error", "API connection failed. Check your key.")
        except Exception as e:
            logger.error(f"API test failed: {e}")
            self._show_message("Error", f"Connection error: {str(e)[:100]}")
    
    def _clear_placed_log(self):
        """Clear the placed artifacts log."""
        app = MDApp.get_running_app()
        if app and app.database:
            app.database.clear_placed_log()
            self._show_message("Success", "Placed artifacts log cleared.")
    
    def _clear_all_data(self):
        """Clear all cached data (with confirmation)."""
        if not self._dialog:
            self._dialog = MDDialog(
                title="Confirm Clear Data",
                text="This will delete all cached artifacts and settings.\n\nAre you sure?",
                buttons=[
                    MDFlatButton(
                        text="Cancel",
                        on_release=lambda x: self._dialog.dismiss(),
                    ),
                    MDRaisedButton(
                        text="Clear All",
                        md_bg_color=(0.918, 0.263, 0.208, 1),
                        on_release=lambda x: self._do_clear_all(),
                    ),
                ],
            )
        self._dialog.open()
    
    def _do_clear_all(self):
        """Actually clear all data."""
        if self._dialog:
            self._dialog.dismiss()
        
        app = MDApp.get_running_app()
        if app and app.database:
            app.database.clear_all()
            self._show_message("Success", "All data cleared.")
    
    def _show_message(self, title: str, message: str):
        """Show a message dialog."""
        dialog = MDDialog(
            title=title,
            text=message,
            buttons=[
                MDRaisedButton(
                    text="OK",
                    md_bg_color=(0.102, 0.451, 0.91, 1),
                    on_release=lambda x: dialog.dismiss(),
                ),
            ],
        )
        dialog.open()
    
    def _go_back(self):
        """Navigate back to dashboard."""
        app = MDApp.get_running_app()
        if app:
            app.go_back()
