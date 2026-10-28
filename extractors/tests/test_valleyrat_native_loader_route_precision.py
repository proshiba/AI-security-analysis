"""ValleyRAT native loader routeのimport-only誤検出を防ぐ。"""

from __future__ import annotations

from types import SimpleNamespace

from extractors.valleyrat import native_loader_lineage as lineage


def _context(*, imports: tuple[str, ...], libraries: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        imports={index: name for index, name in enumerate(imports)},
        image=SimpleNamespace(
            DIRECTORY_ENTRY_IMPORT=[
                SimpleNamespace(dll=library.encode("ascii")) for library in libraries
            ]
        ),
    )


def test_graphics_imports_alone_are_not_a_loader_route() -> None:
    """D3D11／Event Logのimportだけではloader lineageを構成しない。"""

    context = _context(
        imports=("d3d11createdevice", "evtquery"),
        libraries=("d3d11.dll", "wevtapi.dll"),
    )

    assert lineage._structural_cluster(context) is None


def test_resource_write_process_import_group_remains_a_candidate() -> None:
    """既存の複合resource／write／process候補は次段解析へ維持する。"""

    context = _context(
        imports=(
            "findresourcew",
            "loadresource",
            "lockresource",
            "sizeofresource",
            "writefile",
            "createprocessw",
        ),
        libraries=("kernel32.dll",),
    )

    assert lineage._structural_cluster(context) == "resource_copy_process_loader_candidate"
