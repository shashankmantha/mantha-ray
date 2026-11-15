import tempfile
import unittest
from pathlib import Path

from static_triage.config import ScanLimits
from static_triage.container.command import DockerScanRequest, build_docker_command
from static_triage.inventory import inventory_tree
from static_triage.scanner import _file_limit
from static_triage.selection import Selection


class BuildingTests(unittest.TestCase):
    def test_nothing_asked_for_is_no_selection(self) -> None:
        for empty in ((), [], None, ("",), ("  ", "/")):
            self.assertIsNone(Selection.of(empty), empty)

    def test_patterns_are_tidied_and_deduplicated(self) -> None:
        selection = Selection.of(
            ("/bin/a.dll ", "bin\\b.dll", "bin/a.dll", "data/")
        )
        assert selection is not None
        self.assertEqual(
            selection.patterns, ("bin/a.dll", "bin/b.dll", "data")
        )


class MatchingTests(unittest.TestCase):
    def match(self, pattern: str, path: str) -> bool:
        selection = Selection.of((pattern,))
        assert selection is not None
        return selection.matches(path)

    def test_an_exact_path_matches_only_itself(self) -> None:
        self.assertTrue(self.match("bin/steam_api.dll", "bin/steam_api.dll"))
        self.assertFalse(self.match("bin/steam_api.dll", "bin/steam_api64.dll"))
        self.assertFalse(self.match("bin/steam_api.dll", "lib/steam_api.dll"))

    def test_case_is_ignored_because_the_paths_are_windows(self) -> None:
        self.assertTrue(self.match("bin/Steam.dll", "BIN/steam.DLL"))
        self.assertTrue(self.match("BIN/*.DLL", "bin/steam.dll"))

    def test_a_folder_takes_everything_beneath_it(self) -> None:
        self.assertTrue(self.match("bin", "bin/steam_api.dll"))
        self.assertTrue(self.match("bin", "bin/deep/er/file.dll"))
        self.assertFalse(self.match("bin", "binaries/file.dll"))
        # Directories never reach the matcher, so a bare "bin" here is a
        # file of that name, which the pattern does name.
        self.assertTrue(self.match("bin", "bin"))

    def test_a_bare_name_matches_the_file_anywhere(self) -> None:
        self.assertTrue(self.match("steam_api.dll", "bin/steam_api.dll"))
        self.assertTrue(self.match("*.exe", "bin/deep/game.exe"))
        # With a separator it is a path, not a name, so it does not float.
        self.assertFalse(self.match("deep/game.exe", "bin/deep/game.exe"))

    def test_backslashes_are_separators_on_both_sides(self) -> None:
        self.assertTrue(self.match("bin\\steam.dll", "bin\\steam.dll"))
        self.assertTrue(self.match("bin/steam.dll", "bin\\steam.dll"))

    def test_patterns_that_matched_nothing_are_remembered(self) -> None:
        selection = Selection.of(("bin/a.dll", "bin/b.dll", "*.exe"))
        assert selection is not None
        self.assertEqual(selection.unmatched, ("bin/a.dll", "bin/b.dll", "*.exe"))
        selection.matches("bin/b.dll")
        selection.matches("game.exe")
        self.assertEqual(selection.unmatched, ("bin/a.dll",))

    def test_the_report_block_says_the_scan_was_partial(self) -> None:
        selection = Selection.of(("bin/a.dll", "nope"))
        assert selection is not None
        selection.matches("bin/a.dll")
        block = selection.to_dict(1)
        self.assertEqual(block["patterns"], ["bin/a.dll", "nope"])
        self.assertEqual(block["matched"], 1)
        self.assertEqual(block["unmatched"], ["nope"])
        self.assertIn("not the whole folder", str(block["note"]))


class InventoryFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        for name in ("bin/game.exe", "bin/steam_api.dll", "bin/deep/x.dll",
                     "data/level.pak", "readme.txt"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"MZ" + bytes(64))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def files(self, selection: Selection | None) -> list[str]:
        entries, _ = inventory_tree(self.root, ScanLimits(), selection)
        return sorted(
            e.relative_path for e in entries if e.kind.value == "regular_file"
        )

    def test_without_a_selection_everything_is_taken_in(self) -> None:
        self.assertEqual(len(self.files(None)), 5)

    def test_only_the_named_files_are_taken_in(self) -> None:
        self.assertEqual(
            self.files(Selection.of(("bin/steam_api.dll", "readme.txt"))),
            ["bin/steam_api.dll", "readme.txt"],
        )

    def test_a_folder_reaches_files_nested_below_it(self) -> None:
        self.assertEqual(
            self.files(Selection.of(("bin",))),
            ["bin/deep/x.dll", "bin/game.exe", "bin/steam_api.dll"],
        )

    def test_unselected_files_are_not_hashed(self) -> None:
        _, summary = inventory_tree(
            self.root, ScanLimits(), Selection.of(("readme.txt",))
        )
        self.assertEqual(summary.hashed_files, 1)
        self.assertEqual(summary.regular_files, 1)

    def test_a_selection_matching_nothing_inventories_nothing(self) -> None:
        self.assertEqual(self.files(Selection.of(("nope.dll",))), [])


class BudgetTests(unittest.TestCase):
    def test_a_full_scan_keeps_the_presets_per_file_ceiling(self) -> None:
        self.assertEqual(_file_limit(1800.0, 3600.0, None), 1800.0)
        self.assertIsNone(_file_limit(None, 3600.0, None))

    def test_a_targeted_scan_gives_a_file_the_whole_stage_budget(self) -> None:
        selection = Selection.of(("bin/steam_api.dll",))
        # The preset would stop at 30 min; the stage has 2 h, and nothing
        # else is competing for it.
        self.assertEqual(_file_limit(1800.0, 7200.0, selection), 7200.0)
        self.assertEqual(_file_limit(None, 7200.0, selection), 7200.0)
        # Never shorter than the preset would have allowed.
        self.assertEqual(_file_limit(1800.0, 600.0, selection), 1800.0)


class ContainerCommandTests(unittest.TestCase):
    def command(self, only: tuple[str, ...]) -> list[str]:
        return build_docker_command(
            DockerScanRequest(
                source_directory=Path("/src"),
                results_directory=Path("/out"),
                only=only,
            ),
            "/usr/bin/docker",
            "mr-test",
        )

    def test_a_full_scan_passes_no_only_flag(self) -> None:
        self.assertNotIn("--only", self.command(()))

    def test_each_pattern_is_passed_separately(self) -> None:
        command = self.command(("bin/a.dll", "bin/*.exe"))
        self.assertEqual(command[-4:], ["--only", "bin/a.dll", "--only", "bin/*.exe"])


if __name__ == "__main__":
    unittest.main()
