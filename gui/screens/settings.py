"""
Settings Screen.

Configure:
- Triage API key
- Update frequency
- Default OS filter
- Data directory
"""

import logging
import os

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.uix.popup import Popup
from kivy.graphics import Color, Rectangle
from kivy.app import App

logger = logging.getLogger(__name__)


class SettingRow(BoxLayout):
    """A single setting row with label and control."""
    
    def __init__(self, label: str, widget, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "horizontal"
        self.size_hint_y = None
        self.height = 50
        self.spacing = 20
        self.padding = [10, 5]
        
        label_widget = Label(
            text=label,
            font_size="14sp",
            halign="left",
            valign="middle",
            size_hint_x=0.4,
        )
        label_widget.bind(size=label_widget.setter("text_size"))
        self.add_widget(label_widget)
        
        self.add_widget(widget)


class SettingsScreen(Screen):
    """Settings configuration screen."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._build_ui()
    
    def _build_ui(self):
        """Build the settings UI."""
        main_layout = BoxLayout(orientation="vertical", padding=15, spacing=10)
        
        # Header
        header = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        back_btn = Button(
            text="< Back",
            size_hint=(None, None),
            size=(80, 40),
            on_release=lambda x: self._go_back(),
        )
        header.add_widget(back_btn)
        
        title = Label(
            text="Settings",
            font_size="24sp",
            bold=True,
            halign="left",
            valign="middle",
        )
        title.bind(size=title.setter("text_size"))
        header.add_widget(title)
        
        save_btn = Button(
            text="Save",
            size_hint=(None, None),
            size=(80, 40),
            on_release=lambda x: self._save_settings(),
        )
        header.add_widget(save_btn)
        
        main_layout.add_widget(header)
        
        # Settings content
        settings_layout = BoxLayout(orientation="vertical", spacing=15, padding=10)
        
        # Section: API Configuration
        api_header = Label(
            text="API Configuration",
            font_size="18sp",
            bold=True,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=40,
        )
        api_header.bind(size=api_header.setter("text_size"))
        settings_layout.add_widget(api_header)
        
        # API Key
        self.api_key_input = TextInput(
            hint_text="Enter Triage API key",
            password=True,
            multiline=False,
            size_hint_x=0.6,
        )
        settings_layout.add_widget(SettingRow("Triage API Key:", self.api_key_input))
        
        # API Key visibility toggle
        show_key_layout = BoxLayout(size_hint_x=0.6)
        show_key_switch = Switch(active=False, size_hint=(None, None), size=(60, 40))
        show_key_switch.bind(active=self._on_show_key_toggle)
        show_key_layout.add_widget(show_key_switch)
        show_key_label = Label(text="Show key", font_size="12sp", halign="left")
        show_key_label.bind(size=show_key_label.setter("text_size"))
        show_key_layout.add_widget(show_key_label)
        settings_layout.add_widget(SettingRow("", show_key_layout))
        
        # Test connection button
        test_btn = Button(
            text="Test Connection",
            size_hint=(None, None),
            size=(150, 40),
            on_release=lambda x: self._test_connection(),
        )
        settings_layout.add_widget(SettingRow("", test_btn))
        
        # Section: Update Settings
        update_header = Label(
            text="Update Settings",
            font_size="18sp",
            bold=True,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=40,
        )
        update_header.bind(size=update_header.setter("text_size"))
        settings_layout.add_widget(update_header)
        
        # Update frequency
        self.update_freq_spinner = Spinner(
            text="Daily",
            values=["Hourly", "Daily", "Weekly", "Manual"],
            size_hint=(None, None),
            size=(150, 40),
        )
        settings_layout.add_widget(SettingRow("Update Frequency:", self.update_freq_spinner))
        
        # Auto-update switch
        auto_update_layout = BoxLayout(size_hint_x=0.6)
        self.auto_update_switch = Switch(active=True, size_hint=(None, None), size=(60, 40))
        auto_update_layout.add_widget(self.auto_update_switch)
        auto_label = Label(text="Enable automatic updates", font_size="12sp", halign="left")
        auto_label.bind(size=auto_label.setter("text_size"))
        auto_update_layout.add_widget(auto_label)
        settings_layout.add_widget(SettingRow("Auto-Update:", auto_update_layout))
        
        # Section: Preferences
        pref_header = Label(
            text="Preferences",
            font_size="18sp",
            bold=True,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=40,
        )
        pref_header.bind(size=pref_header.setter("text_size"))
        settings_layout.add_widget(pref_header)
        
        # Default OS filter
        self.default_os_spinner = Spinner(
            text="Auto-detect",
            values=["Auto-detect", "Android", "Windows", "Linux", "macOS"],
            size_hint=(None, None),
            size=(150, 40),
        )
        settings_layout.add_widget(SettingRow("Default OS Filter:", self.default_os_spinner))
        
        # Show admin artifacts by default
        show_admin_layout = BoxLayout(size_hint_x=0.6)
        self.show_admin_switch = Switch(active=True, size_hint=(None, None), size=(60, 40))
        show_admin_layout.add_widget(self.show_admin_switch)
        admin_label = Label(text="Include in browse", font_size="12sp", halign="left")
        admin_label.bind(size=admin_label.setter("text_size"))
        show_admin_layout.add_widget(admin_label)
        settings_layout.add_widget(SettingRow("Show Admin Artifacts:", show_admin_layout))
        
        # Section: Data Management
        data_header = Label(
            text="Data Management",
            font_size="18sp",
            bold=True,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=40,
        )
        data_header.bind(size=data_header.setter("text_size"))
        settings_layout.add_widget(data_header)
        
        # Data directory display
        app = App.get_running_app()
        data_dir = str(app.get_data_dir()) if app else "Unknown"
        data_dir_label = Label(
            text=data_dir,
            font_size="12sp",
            halign="left",
            valign="middle",
            color=(0.6, 0.6, 0.6, 1),
            size_hint_x=0.6,
        )
        data_dir_label.bind(size=data_dir_label.setter("text_size"))
        settings_layout.add_widget(SettingRow("Data Directory:", data_dir_label))
        
        # Clear data buttons
        buttons_layout = BoxLayout(spacing=10, size_hint_x=0.6)
        
        clear_placed_btn = Button(
            text="Clear Placed Log",
            size_hint_x=0.5,
            on_release=lambda x: self._clear_placed_log(),
        )
        buttons_layout.add_widget(clear_placed_btn)
        
        clear_cache_btn = Button(
            text="Clear All Data",
            size_hint_x=0.5,
            on_release=lambda x: self._clear_all_data(),
        )
        buttons_layout.add_widget(clear_cache_btn)
        
        settings_layout.add_widget(SettingRow("", buttons_layout))
        
        # Add spacer
        settings_layout.add_widget(BoxLayout())
        
        main_layout.add_widget(settings_layout)
        
        # Version info footer
        footer = BoxLayout(size_hint_y=None, height=40, padding=10)
        with footer.canvas.before:
            Color(0.1, 0.1, 0.1, 1)
            self.footer_rect = Rectangle(pos=footer.pos, size=footer.size)
        footer.bind(
            pos=lambda w, p: setattr(self.footer_rect, "pos", p),
            size=lambda w, s: setattr(self.footer_rect, "size", s),
        )
        
        version_label = Label(
            text="Evasion Artifact Placer v1.0.0",
            font_size="12sp",
            color=(0.5, 0.5, 0.5, 1),
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
        app = App.get_running_app()
        if not app or not app.database:
            return
        
        settings = app.database.get_settings()
        
        # Populate fields
        self.api_key_input.text = settings.get("api_key", "")
        self.update_freq_spinner.text = settings.get("update_frequency", "Daily")
        self.auto_update_switch.active = settings.get("auto_update", True)
        self.default_os_spinner.text = settings.get("default_os", "Auto-detect")
        self.show_admin_switch.active = settings.get("show_admin", True)
    
    def _save_settings(self):
        """Save settings to storage."""
        app = App.get_running_app()
        if not app or not app.database:
            self._show_message("Error", "Database not available")
            return
        
        settings = {
            "api_key": self.api_key_input.text,
            "update_frequency": self.update_freq_spinner.text,
            "auto_update": self.auto_update_switch.active,
            "default_os": self.default_os_spinner.text,
            "show_admin": self.show_admin_switch.active,
        }
        
        app.database.save_settings(settings)
        logger.info("Settings saved")
        
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
        app = App.get_running_app()
        if app and app.database:
            app.database.clear_placed_log()
            self._show_message("Success", "Placed artifacts log cleared.")
    
    def _clear_all_data(self):
        """Clear all cached data (with confirmation)."""
        content = BoxLayout(orientation="vertical", spacing=10, padding=10)
        
        warning = Label(
            text="This will delete all cached artifacts and settings.\n\n"
                 "Are you sure?",
            font_size="14sp",
            halign="center",
            valign="middle",
        )
        warning.bind(size=warning.setter("text_size"))
        content.add_widget(warning)
        
        buttons = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        popup = Popup(
            title="Confirm Clear Data",
            content=content,
            size_hint=(0.6, 0.4),
            auto_dismiss=False,
        )
        
        cancel_btn = Button(
            text="Cancel",
            on_release=lambda x: popup.dismiss(),
        )
        buttons.add_widget(cancel_btn)
        
        confirm_btn = Button(
            text="Clear All",
            on_release=lambda x: self._do_clear_all(popup),
        )
        buttons.add_widget(confirm_btn)
        
        content.add_widget(buttons)
        popup.open()
    
    def _do_clear_all(self, popup):
        """Actually clear all data."""
        popup.dismiss()
        
        app = App.get_running_app()
        if app and app.database:
            app.database.clear_all()
            self._show_message("Success", "All data cleared.")
    
    def _show_message(self, title: str, message: str):
        """Show a message popup."""
        content = BoxLayout(orientation="vertical", padding=10)
        
        msg_label = Label(
            text=message,
            font_size="14sp",
            halign="center",
            valign="middle",
        )
        msg_label.bind(size=msg_label.setter("text_size"))
        content.add_widget(msg_label)
        
        popup = Popup(
            title=title,
            content=content,
            size_hint=(0.6, 0.3),
        )
        
        ok_btn = Button(
            text="OK",
            size_hint_y=None,
            height=40,
            on_release=lambda x: popup.dismiss(),
        )
        content.add_widget(ok_btn)
        
        popup.open()
    
    def _go_back(self):
        """Navigate back to dashboard."""
        app = App.get_running_app()
        if app:
            app.go_back()
