"""Data ingestion pipelines for populating the Organizational Memory."""

from __future__ import annotations

import json
from typing import Any

from specter.memory.graph import get_knowledge_graph
from specter.models.memory import EntityType, MemoryEntity, RelationshipType


class MemoryIngestionPipeline:
    """Pipelines for ingesting CMDB, IdP, topology, and threat intel into memory."""

    def __init__(self) -> None:
        self.graph = get_knowledge_graph()

    async def ingest_asset_inventory(self, assets: list[dict[str, Any]]) -> list[str]:
        """Ingest asset inventory rows into ``memory_entities``."""
        entity_ids: list[str] = []

        for asset in assets:
            entity = MemoryEntity(
                entity_type=EntityType.ASSET,
                name=asset["name"],
                properties={
                    "asset_type": asset.get("type", "unknown"),
                    "criticality": asset.get("criticality", "medium"),
                    "environment": asset.get("environment", "unknown"),
                    "owner": asset.get("owner"),
                    "ip_address": asset.get("ip"),
                    "tags": asset.get("tags", []),
                },
                source=asset.get("source", "asset_inventory"),
                confidence=float(asset.get("confidence", 1.0)),
            )

            orm_entity = await self.graph.create_entity(entity)
            entity_ids.append(str(orm_entity.id))

            if asset.get("connected_to"):
                for connected_name in asset["connected_to"]:
                    connected = await self.graph.find_entities(
                        entity_type="asset",
                        name_pattern=str(connected_name),
                        limit=1,
                    )
                    if connected:
                        await self.graph.create_relationship(
                            source_id=str(orm_entity.id),
                            target_id=connected[0]["id"],
                            relationship_type=RelationshipType.CONNECTS_TO.value,
                        )

        return entity_ids

    async def ingest_user_directory(self, users: list[dict[str, Any]]) -> list[str]:
        """Ingest users from an IdP and optional baselines / access edges."""
        entity_ids: list[str] = []

        for user in users:
            entity = MemoryEntity(
                entity_type=EntityType.USER,
                name=str(user.get("name", user["user_id"])),
                properties={
                    "user_id": user["user_id"],
                    "email": user.get("email", user["user_id"]),
                    "department": user.get("department"),
                    "role": user.get("role"),
                    "manager": user.get("manager"),
                    "status": user.get("status", "active"),
                },
                source="user_directory",
            )

            orm_entity = await self.graph.create_entity(entity)
            entity_ids.append(str(orm_entity.id))

            await self.graph.upsert_user_baseline(
                {
                    "user_id": user["user_id"],
                    "typical_login_times": user.get("typical_login_times", []),
                    "typical_locations": user.get("typical_locations", []),
                    "typical_devices": user.get("typical_devices", []),
                    "accessed_assets": user.get("accessed_assets", []),
                    "risk_score": user.get("risk_score", 0.0),
                }
            )

            if user.get("accessed_assets"):
                for asset_name in user["accessed_assets"]:
                    assets = await self.graph.find_entities(
                        entity_type="asset",
                        name_pattern=str(asset_name),
                        limit=1,
                    )
                    if assets:
                        await self.graph.create_relationship(
                            source_id=str(orm_entity.id),
                            target_id=assets[0]["id"],
                            relationship_type=RelationshipType.HAS_ACCESS.value,
                            properties={"access_type": user.get("role", "unknown")},
                        )

        return entity_ids

    async def ingest_network_topology(self, connections: list[dict[str, Any]]) -> int:
        """Ingest network edges between known assets."""
        count = 0
        for conn in connections:
            source = await self.graph.find_entities(
                entity_type="asset", name_pattern=str(conn["source"]), limit=1
            )
            target = await self.graph.find_entities(
                entity_type="asset", name_pattern=str(conn["target"]), limit=1
            )

            if source and target:
                await self.graph.create_relationship(
                    source_id=source[0]["id"],
                    target_id=target[0]["id"],
                    relationship_type=RelationshipType.CONNECTS_TO.value,
                    properties={
                        "protocol": conn.get("protocol"),
                        "description": conn.get("description"),
                    },
                )
                count += 1

        return count

    async def ingest_threat_intel(self, threats: list[dict[str, Any]]) -> list[str]:
        """Ingest threat actor / IOC summaries."""
        entity_ids: list[str] = []

        for threat in threats:
            entity = MemoryEntity(
                entity_type=EntityType.THREAT_ACTOR,
                name=threat["name"],
                properties={
                    "threat_type": threat.get("type", "unknown"),
                    "ttps": threat.get("ttps", []),
                    "iocs": threat.get("iocs", []),
                    "description": threat.get("description"),
                    "confidence": threat.get("confidence", 0.7),
                    "source": threat.get("source", "threat_intel"),
                },
                source=str(threat.get("source", "threat_intel")),
            )

            orm_entity = await self.graph.create_entity(entity)
            entity_ids.append(str(orm_entity.id))

        return entity_ids

    async def ingest_from_json_file(self, filepath: str, data_type: str) -> dict[str, Any]:
        """Load a JSON file and dispatch to the appropriate ingestor."""
        with open(filepath, encoding="utf-8") as handle:
            data = json.load(handle)

        if data_type == "assets":
            ids = await self.ingest_asset_inventory(data)
            return {"entity_ids": ids, "count": len(ids), "type": data_type}
        if data_type == "users":
            ids = await self.ingest_user_directory(data)
            return {"entity_ids": ids, "count": len(ids), "type": data_type}
        if data_type == "network":
            count = await self.ingest_network_topology(data)
            return {"count": count, "type": data_type}
        if data_type == "threats":
            ids = await self.ingest_threat_intel(data)
            return {"entity_ids": ids, "count": len(ids), "type": data_type}

        raise ValueError(f"Unknown data_type: {data_type}")
