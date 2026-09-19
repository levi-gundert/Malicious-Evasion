"""Lazy service exports; importing a backend never initializes Kivy."""
def __getattr__(name):
    from importlib import import_module
    modules = {"ArtifactDatabase": "database", "PlacementEngine": "placement_engine", "PrivilegeManager": "privilege_manager"}
    if name not in modules:
        raise AttributeError(name)
    return getattr(import_module(f"gui.services.{modules[name]}"), name)
