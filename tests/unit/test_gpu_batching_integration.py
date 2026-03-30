"""Unit tests for memory forensics GPU batching integration."""

from types import SimpleNamespace

import pytest

from reveng.malware.memory_forensics import MemoryForensics
from reveng.ml.gpu_accelerator import GPUAccelerator


def test_process_memory_forensics_tasks_batches_by_batch_size():
    accelerator = GPUAccelerator(device="cpu", enable_mixed_precision=False)
    observed_batches: list[list[str]] = []

    def process_fn(batch: list[str]) -> list[str]:
        observed_batches.append(list(batch))
        return [f"processed:{item}" for item in batch]

    result = accelerator.process_memory_forensics_tasks(
        ["region-1", "region-2", "region-3", "region-4", "region-5"],
        process_fn,
        batch_size=2,
        max_wait_seconds=60.0,
    )

    assert observed_batches == [
        ["region-1", "region-2"],
        ["region-3", "region-4"],
        ["region-5"],
    ]
    assert result.results == [
        "processed:region-1",
        "processed:region-2",
        "processed:region-3",
        "processed:region-4",
        "processed:region-5",
    ]
    assert [dispatch.batch_size for dispatch in accelerator.memory_forensics_dispatch_history] == [
        2,
        2,
        1,
    ]
    assert [dispatch.trigger for dispatch in accelerator.memory_forensics_dispatch_history] == [
        "batch_size_limit",
        "batch_size_limit",
        "flush",
    ]


def test_dispatch_ready_memory_forensics_tasks_flushes_on_wait_window(
    monkeypatch: pytest.MonkeyPatch,
):
    current_time = [100.0]
    monkeypatch.setattr(
        "reveng.ml.gpu_accelerator.time.monotonic",
        lambda: current_time[0],
    )

    accelerator = GPUAccelerator(device="cpu", enable_mixed_precision=False)
    observed_batches: list[list[str]] = []

    def process_fn(batch: list[str]) -> list[str]:
        observed_batches.append(list(batch))
        return [item.upper() for item in batch]

    accelerator.queue_memory_forensics_task("region-a")
    current_time[0] += 0.02
    accelerator.queue_memory_forensics_task("region-b")

    assert (
        accelerator.dispatch_ready_memory_forensics_tasks(
            process_fn,
            batch_size=4,
            max_wait_seconds=0.05,
        )
        is None
    )

    current_time[0] += 0.05
    dispatch = accelerator.dispatch_ready_memory_forensics_tasks(
        process_fn,
        batch_size=4,
        max_wait_seconds=0.05,
    )

    assert dispatch is not None
    assert observed_batches == [["region-a", "region-b"]]
    assert dispatch.batch_size == 2
    assert dispatch.trigger == "time_window"
    assert dispatch.results == ["REGION-A", "REGION-B"]


def test_memory_forensics_extract_artifacts_uses_batched_gpu_dispatch():
    accelerator = GPUAccelerator(device="cpu", enable_mixed_precision=False)
    forensics = MemoryForensics(
        accelerator=accelerator,
        memory_scan_batch_size=2,
        memory_scan_max_wait_seconds=60.0,
    )

    forensics._read_memory_region = lambda region: b"A" * 32

    memory_regions = [
        SimpleNamespace(start_address=0x1000, size=32, is_executable=False),
        SimpleNamespace(start_address=0x2000, size=32, is_executable=False),
        SimpleNamespace(start_address=0x3000, size=32, is_executable=False),
    ]

    artifacts = forensics._extract_memory_artifacts(memory_regions)

    assert [artifact.address for artifact in artifacts] == [0x1000, 0x2000, 0x3000]
    assert [dispatch.batch_size for dispatch in accelerator.memory_forensics_dispatch_history] == [
        2,
        1,
    ]


def test_memory_forensics_dispatch_history_is_capped():
    accelerator = GPUAccelerator(
        device="cpu",
        enable_mixed_precision=False,
        max_history=2,
    )

    accelerator.process_memory_forensics_tasks(
        ["region-1", "region-2", "region-3"],
        lambda batch: [f"processed:{item}" for item in batch],
        batch_size=1,
        max_wait_seconds=60.0,
    )

    assert len(accelerator.memory_forensics_dispatch_history) == 2
    assert [dispatch.results for dispatch in accelerator.memory_forensics_dispatch_history] == [
        ["processed:region-2"],
        ["processed:region-3"],
    ]


def test_gpu_accelerator_defaults_to_cpu_without_device_metadata(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    monkeypatch.setattr(GPUAccelerator, "_initialize", lambda self: None)

    accelerator = GPUAccelerator(device="cpu", enable_mixed_precision=False)

    assert accelerator.is_available() is False
    assert accelerator._estimate_batch_size() == 1
    assert accelerator.get_memory_stats() == {}

    accelerator.clear_memory()
    accelerator.print_device_info()

    captured = capsys.readouterr()
    assert "Device type:    cpu" in captured.out
    assert "Device name:    CPU" in captured.out
