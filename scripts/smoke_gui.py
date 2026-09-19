"""Build all GUI screens against temporary data; never touches user settings."""

import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    with tempfile.TemporaryDirectory(prefix="meap-gui-smoke-") as directory:
        os.environ["KIVY_HOME"] = directory
        os.environ["KIVY_NO_ARGS"] = "1"
        os.environ["KIVY_NO_FILELOG"] = "1"
        from kivy.clock import Clock
        from kivy.core.window import Window
        from gui.app import EvasionArtifactApp
        from gui.services.database import ArtifactDatabase
        from gui.services.placement_engine import PlacementEngine
        from extractor.placement import host_os
        from extractor.models.id import artifact_id

        class SmokeApp(EvasionArtifactApp):
            def on_start(self):
                Window.hide()
                self.database = ArtifactDatabase(Path(directory) / "artifacts.db")
                self.database.initialize()
                self.placement_engine = PlacementEngine(
                    journal_path=Path(directory) / "placement-journal.db"
                )
                self.credentials = type("FakeCredentials", (), {"get": lambda _: ""})()
                self.updater = None
                target = str(Path(directory) / "decoy.txt")
                record = {
                    "id": artifact_id(host_os(), "file", target),
                    "os": host_os(),
                    "artifact_type": "file",
                    "category": "probe",
                    "value": target,
                    "privilege_level": "user",
                    "confidence": 0.0,
                    "sample_count": 0,
                }
                self.database.add_artifact(record)
                screen = self.screen_manager.get_screen("placement")
                screen.set_artifacts([record])
                screen._on_place_artifact(record)
                screen._privilege_dialog.dismiss()
                self.screen_manager.get_screen("browse")._refresh_artifacts()
                self.screen_manager.get_screen("settings")._load_settings()
                assert not Path(target).exists()
                Clock.schedule_once(lambda _: self.stop(), 0.2)

        SmokeApp().run()
        print(
            "GUI smoke passed: four screens, candidate browsing, settings, placement preview; no placement performed"
        )


if __name__ == "__main__":
    main()
