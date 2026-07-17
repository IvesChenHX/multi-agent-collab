from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from mac.ids import is_identifier, prefixed


def test_prefixed_ids_are_unique_valid_and_lexically_monotonic() -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: prefixed("EVT"), range(2_000)))

    assert len(values) == len(set(values))
    assert all(is_identifier(value, "EVT") for value in values)
    sequential = [prefixed("EVT") for _ in range(100)]
    assert sequential == sorted(sequential)


def test_task_slug_is_normalized_without_weakening_ulid_identity() -> None:
    value = prefixed("TASK", " Refund Auth / 权限 ")

    assert value.endswith("-refund-auth")
    assert is_identifier(value, "TASK")
