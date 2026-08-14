"""Atomically persist one structured agent checkpoint."""

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

import vaultlet


async def main() -> None:
    """Run the checkpoint example."""
    with TemporaryDirectory(prefix="vaultlet-agent-") as directory:
        key = vaultlet.MasterKey.generate()
        async with await vaultlet.Vaultlet.open(
            vaultlet.FileBackend(Path(directory) / "agent.vaultlet"), key=key
        ) as store:
            agent = store.tenant("agent-session-123")
            await agent.set_many_json(
                {
                    "checkpoint": {"step": 4, "messages": []},
                    "pending-writes": [],
                }
            )
            checkpoint = await agent.get_json("checkpoint")
            if not isinstance(
                checkpoint, vaultlet.JsonObject
            ) or checkpoint.to_builtin() != {
                "step": 4,
                "messages": [],
            }:
                raise RuntimeError("checkpoint did not round-trip")


asyncio.run(main())
