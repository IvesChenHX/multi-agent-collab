"""Runtime adapters that bridge governance artifacts to external executors.

The adapters in this package deliberately do not decide whether a task may
close.  They only prepare handoff artifacts or collect a structured result;
scope, evidence, review, and close gates remain owned by the governance core.
"""

from .agtx import AgTxPrototypeAdapter
from .conductor import ConductorCompiler
from .plain_terminal import HandoffPacket, PlainTerminalAdapter, ResultCollectionError

__all__ = [
    "AgTxPrototypeAdapter",
    "ConductorCompiler",
    "HandoffPacket",
    "PlainTerminalAdapter",
    "ResultCollectionError",
]
