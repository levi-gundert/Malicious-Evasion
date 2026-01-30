"""
Theme configuration for Malicious Evasion Artifact Placer.

Recorded Future Brand Identity:
- Primary Blue: #1A73E8 for main actions
- Accent Cyan: #00D4FF for highlights and links
- Navy backgrounds: Deep, professional dark theme
- Clean white/light text for readability
"""

from kivy.utils import get_color_from_hex


# =============================================================================
# Recorded Future Color Palette
# =============================================================================

class Colors:
    """Color palette based on Recorded Future branding."""
    
    # Primary - Recorded Future Blue
    PRIMARY = get_color_from_hex("#1A73E8")
    PRIMARY_DARK = get_color_from_hex("#1557B0")
    PRIMARY_LIGHT = get_color_from_hex("#4A90E8")
    
    # Accent - Cyan highlights
    ACCENT = get_color_from_hex("#00D4FF")
    ACCENT_DARK = get_color_from_hex("#00A3CC")
    ACCENT_LIGHT = get_color_from_hex("#66E5FF")
    
    # Background colors - Navy theme
    BG_DARK = get_color_from_hex("#0A1628")       # Darkest - main background
    BG_SURFACE = get_color_from_hex("#122136")    # Cards, elevated surfaces
    BG_ELEVATED = get_color_from_hex("#1E3A5F")   # Hover states, inputs
    BG_HOVER = get_color_from_hex("#2A4A70")      # Active hover
    
    # Text colors
    TEXT_PRIMARY = get_color_from_hex("#FFFFFF")      # Main headings
    TEXT_SECONDARY = get_color_from_hex("#E8EAED")    # Body text
    TEXT_MUTED = get_color_from_hex("#9AA0A6")        # Hints, disabled
    TEXT_ON_PRIMARY = get_color_from_hex("#FFFFFF")   # Text on blue buttons
    
    # Semantic colors
    SUCCESS = get_color_from_hex("#34A853")       # Green
    WARNING = get_color_from_hex("#FBBC04")       # Yellow
    ERROR = get_color_from_hex("#EA4335")         # Red
    INFO = get_color_from_hex("#4285F4")          # Blue
    
    # Border colors
    BORDER_DEFAULT = get_color_from_hex("#1E3A5F")
    BORDER_MUTED = get_color_from_hex("#122136")
    BORDER_EMPHASIS = get_color_from_hex("#2A4A70")
    
    # OS-specific colors
    CAT_ANDROID = get_color_from_hex("#3DDC84")   # Android green
    CAT_WINDOWS = get_color_from_hex("#00BCF2")   # Windows blue
    CAT_LINUX = get_color_from_hex("#FCC624")     # Linux yellow
    CAT_MACOS = get_color_from_hex("#A2AAAD")     # macOS silver
    
    # Privilege level colors
    PRIV_USER = get_color_from_hex("#34A853")     # Green - user level
    PRIV_ADMIN = get_color_from_hex("#FBBC04")    # Yellow - admin
    PRIV_SYSTEM = get_color_from_hex("#EA4335")   # Red - system/root


# =============================================================================
# Typography
# =============================================================================

class Typography:
    """Typography configuration."""
    
    FONT_FAMILY = "Roboto"
    FONT_FAMILY_MONO = "RobotoMono"
    
    # Font sizes
    SIZE_H1 = "28sp"
    SIZE_H2 = "22sp"
    SIZE_H3 = "18sp"
    SIZE_BODY = "14sp"
    SIZE_BODY_SMALL = "13sp"
    SIZE_CAPTION = "11sp"
    SIZE_BUTTON = "14sp"
    
    # Line heights
    LINE_HEIGHT_TIGHT = 1.2
    LINE_HEIGHT_NORMAL = 1.5
    LINE_HEIGHT_LOOSE = 1.8


# =============================================================================
# Spacing (8dp baseline grid)
# =============================================================================

class Spacing:
    """Spacing constants based on 8dp grid."""
    
    XS = 4
    SM = 8
    MD = 16
    LG = 24
    XL = 32
    XXL = 48
    
    PADDING_CARD = 16
    PADDING_SCREEN = 20
    PADDING_BUTTON = 12
    MARGIN_SECTION = 24
    BORDER_RADIUS = 6
    BORDER_RADIUS_LG = 8


# =============================================================================
# Component Dimensions
# =============================================================================

class Dimensions:
    """Standard component dimensions."""
    
    BUTTON_HEIGHT = 44
    BUTTON_HEIGHT_SM = 36
    BUTTON_MIN_WIDTH = 88
    
    INPUT_HEIGHT = 44
    INPUT_BORDER_WIDTH = 1
    
    CARD_BORDER_RADIUS = 8
    
    NAV_HEIGHT = 56
    NAV_ITEM_WIDTH = 80
    
    ICON_SM = 16
    ICON_MD = 24
    ICON_LG = 32
    ICON_XL = 48


# =============================================================================
# Animation Durations
# =============================================================================

class Animation:
    """Animation timing constants."""
    
    FAST = 0.15
    NORMAL = 0.25
    SLOW = 0.4
    RIPPLE = 0.2
    FADE = 0.3


# =============================================================================
# Helper Functions
# =============================================================================

def get_os_color(os_type: str) -> list:
    """Get the color for an OS type."""
    os_colors = {
        "android": Colors.CAT_ANDROID,
        "windows": Colors.CAT_WINDOWS,
        "linux": Colors.CAT_LINUX,
        "macos": Colors.CAT_MACOS,
    }
    return os_colors.get(os_type.lower(), Colors.TEXT_MUTED)


def get_privilege_color(privilege: str) -> list:
    """Get the color for a privilege level."""
    priv_colors = {
        "user": Colors.PRIV_USER,
        "admin": Colors.PRIV_ADMIN,
        "root": Colors.PRIV_ADMIN,
        "system": Colors.PRIV_SYSTEM,
    }
    return priv_colors.get(privilege.lower(), Colors.TEXT_MUTED)
