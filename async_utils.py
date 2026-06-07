"""Run async coroutines safely from sync code and Streamlit handlers."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")

_nest_asyncio_applied = False


def _is_uvloop(loop: asyncio.AbstractEventLoop) -> bool:
    return type(loop).__module__.startswith("uvloop")


def _apply_nest_asyncio(loop: asyncio.AbstractEventLoop) -> bool:
    """
    Patch the active loop for nested asyncio.run() calls.

    Returns False for uvloop (used by Streamlit) — nest_asyncio cannot patch it.
    """
    global _nest_asyncio_applied
    if _is_uvloop(loop):
        return False
    if _nest_asyncio_applied:
        return True
    try:
        import nest_asyncio

        nest_asyncio.apply(loop)
        _nest_asyncio_applied = True
        return True
    except (ImportError, ValueError):
        return False


def run_async(coro: Coroutine[object, object, T]) -> T:
    """
    Execute *coro* whether or not an event loop is already running.

    - No active loop: uses asyncio.run().
    - Active uvloop (Streamlit): runs asyncio.run() in a worker thread.
    - Other active loops: tries nest_asyncio, else worker thread.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    if _apply_nest_asyncio(loop):
        return asyncio.run(coro)

    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()
