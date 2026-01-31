"""
Main KivyMD Application class.

Handles screen management, navigation, and app lifecycle.
Uses Material Design components for a polished, professional UI.
"""

import logging
from pathlib import Path

from kivymd.app import MDApp
from kivymd.uix.screenmanager import MDScreenManager
from kivy.core.window import Window
from kivy.utils import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class EvasionArtifactApp(MDApp):
    """
    Main application class for the Malicious Evasion Artifact Placement GUI.
    
    Uses KivyMD for Material Design components and theming.
    Theme inspired by Recorded Future's brand identity.
    """
    
    title = "Malicious Evasion Artifact Placer"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.screen_manager = None
        self.database = None
        self.updater = None
        self.current_os = self._detect_os()
        self.last_update_os = None
        
        logger.info(f"Detected platform: {self.current_os}")
    
    def _detect_os(self) -> str:
        """Detect the current operating system."""
        if platform == "android":
            return "android"
        elif platform == "ios":
            return "ios"
        elif platform == "win":
            return "windows"
        elif platform == "macosx":
            return "macos"
        elif platform == "linux":
            return "linux"
        else:
            return "unknown"
    
    def build(self):
        """Build the application UI with KivyMD theming."""
        # Configure theme - Recorded Future inspired dark theme
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.primary_hue = "600"
        self.theme_cls.accent_palette = "Cyan"
        self.theme_cls.accent_hue = "400"
        
        # Custom colors matching Recorded Future brand
        # Primary: #1A73E8, Accent: #00D4FF
        self.theme_cls.material_style = "M3"
        
        # Set window properties for desktop
        if self.current_os in ("windows", "linux", "macos"):
            Window.size = (1100, 800)
            Window.minimum_width = 900
            Window.minimum_height = 700
        
        # Set dark background
        Window.clearcolor = (0.039, 0.086, 0.157, 1)  # #0A1628
        
        # Import screens here to avoid circular imports
        from gui.screens.dashboard import DashboardScreen
        from gui.screens.browse import BrowseScreen
        from gui.screens.placement import PlacementScreen
        from gui.screens.settings import SettingsScreen
        
        # Create screen manager
        self.screen_manager = MDScreenManager()
        
        # Add screens
        self.screen_manager.add_widget(DashboardScreen(name="dashboard"))
        self.screen_manager.add_widget(BrowseScreen(name="browse"))
        self.screen_manager.add_widget(PlacementScreen(name="placement"))
        self.screen_manager.add_widget(SettingsScreen(name="settings"))
        
        # Start on dashboard
        self.screen_manager.current = "dashboard"
        
        logger.info("Application UI built successfully with KivyMD")
        
        return self.screen_manager
    
    def navigate_to(self, screen_name: str, direction: str = "left"):
        """
        Navigate to a different screen.
        
        Args:
            screen_name: Name of the screen to navigate to
            direction: Slide direction ('left' or 'right')
        """
        if self.screen_manager:
            self.screen_manager.current = screen_name
            logger.debug(f"Navigated to: {screen_name}")
    
    def go_back(self):
        """Navigate back to the previous screen (dashboard)."""
        self.navigate_to("dashboard", direction="right")
    
    def on_start(self):
        """Called when the application starts."""
        logger.info("Application started")
        
        # Initialize database service
        from gui.services.database import ArtifactDatabase
        self.database = ArtifactDatabase()
        self.database.initialize()
        
        logger.info(f"Database initialized with {self.database.get_artifact_count()} artifacts")
        
        # Initialize and start update service
        from gui.services.updater import UpdateService
        self.updater = UpdateService()
        
        # Get update settings
        settings = self.database.get_settings()
        if settings.get("auto_update", True):
            frequency = settings.get("update_frequency", "Daily")
            self.updater.start(
                frequency=frequency,
                on_complete=self._on_update_complete,
                on_error=self._on_update_error,
                on_new_artifacts=self._on_new_artifacts,
                on_progress=self._on_update_progress,
            )
    
    def _on_update_progress(self, progress):
        """Handle update progress - forward to dashboard."""
        if self.screen_manager and self.screen_manager.current == "dashboard":
            dashboard = self.screen_manager.get_screen("dashboard")
            if hasattr(dashboard, "_on_update_progress"):
                dashboard._on_update_progress(progress)
    
    def _on_update_complete(self):
        """Handle update completion."""
        logger.info("Update completed successfully")
        if self.screen_manager and self.screen_manager.current == "dashboard":
            dashboard = self.screen_manager.get_screen("dashboard")
            dashboard._refresh_stats()
    
    def _on_update_error(self, error: str):
        """Handle update error."""
        logger.error(f"Update failed: {error}")
    
    def _on_new_artifacts(self, count: int):
        """Handle new artifacts notification."""
        logger.info(f"Found {count} new artifacts")
    
    def on_stop(self):
        """Called when the application stops."""
        logger.info("Application stopping")
        
        if self.updater:
            self.updater.stop()
        
        if self.database:
            self.database.close()
    
    def get_data_dir(self) -> Path:
        """Get the application data directory."""
        if self.current_os == "android":
            from android.storage import app_storage_path
            return Path(app_storage_path())
        else:
            return Path(self.user_data_dir)
