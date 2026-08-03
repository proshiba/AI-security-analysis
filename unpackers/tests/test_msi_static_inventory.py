from __future__ import annotations

from pathlib import Path

import pytest

from unpackers import msi_static_inventory as inventory


def test_collect_inventory_correlates_custom_action_source(tmp_path: Path) -> None:
    sample = tmp_path / "sample.msi"
    sample.write_bytes(b"fixture")

    def fake_query(_path, _query, fields, _max_rows):
        if fields[0] == "File":
            return (
                [
                    {
                        "File": "launch_id",
                        "Component_": "c",
                        "FileName": "A_System.exe",
                        "FileSize": "1",
                        "Version": None,
                        "Language": None,
                        "Attributes": "0",
                        "Sequence": "1",
                    }
                ],
                False,
            )
        if fields[0] == "Action":
            if len(fields) == 4:
                return (
                    [
                        {
                            "Action": "LaunchFile",
                            "Type": "210",
                            "Source": "launch_id",
                            "Target": None,
                        }
                    ],
                    False,
                )
            return (
                [{"Action": "LaunchFile", "Condition": None, "Sequence": "6601"}],
                False,
            )
        if fields[0] == "DiskId":
            return (
                [
                    {
                        "DiskId": "1",
                        "LastSequence": "33",
                        "DiskPrompt": None,
                        "Cabinet": "#cab1.cab",
                        "VolumeLabel": None,
                        "Source": None,
                    }
                ],
                False,
            )
        raise AssertionError(fields)

    report = inventory.collect_inventory(sample, query_function=fake_query)

    action = report["relationships"]["custom_actions"][0]
    assert action["source_file_name"] == "A_System.exe"
    assert action["execute_sequence"] == "6601"
    assert report["tables"]["Media"]["rows"][0]["Cabinet"] == "#cab1.cab"
    assert report["safety"]["installer_executed"] is False
    assert report["sample"]["name"] == "sample.msi"
    assert "path" not in report["sample"]


def test_collect_inventory_rejects_oversized_input(tmp_path: Path) -> None:
    sample = tmp_path / "sample.msi"
    sample.write_bytes(b"fixture")

    with pytest.raises(inventory.MsiInventoryError, match="上限"):
        inventory.collect_inventory(sample, max_input_size=4)


def test_collect_inventory_rejects_non_positive_bound(tmp_path: Path) -> None:
    sample = tmp_path / "sample.msi"
    sample.write_bytes(b"fixture")
    with pytest.raises(ValueError):
        inventory.collect_inventory(sample, max_rows=0)
