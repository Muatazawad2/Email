"""Attack Simulation Training -> Azure Table Storage sync.

Reads Microsoft Graph attack-simulation data and writes it to seven tables
(Simulations, SimulationUsers, SimulationUserEvents, Users, Trainings,
Payloads, TrainingUserCoverage) with the same table and column names as
cammurray/ASTSync, so existing Power BI reports keep working.

Configuration (app settings or environment variables):
    STORAGE_ACCOUNT_NAME      Table Storage account (managed identity is used)
    STORAGE_CONNECTION_STRING Optional; overrides managed identity (local runs)
    GRAPH_TENANT_ID           Tenant that holds the simulation data
    GRAPH_CLIENT_ID           App registration (omit to use managed identity)
    GRAPH_CLIENT_SECRET       App registration secret (omit to use managed identity)
    SYNC_ENTRA_USERS          "true" (default) to enrich users from Entra ID
    USER_REFRESH_DAYS         Re-read a user's profile after this many days (default 7)
    SIM_RESYNC_DAYS           Re-read users of simulations completed within this many days (default 7)
    MAX_PARALLEL_SIMULATIONS  Simulations read at the same time (default 4)
    CATALOGUE_REFRESH_HOURS   Refresh Microsoft's training and global payload catalogues
                              this often (default 24; 0 = every run)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import httpx
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.data.tables import UpdateMode
from azure.data.tables.aio import TableServiceClient
from azure.identity.aio import ClientSecretCredential, DefaultAzureCredential

log = logging.getLogger("ast_sync")

GRAPH = "https://graph.microsoft.com"
TABLES = ("Simulations", "SimulationUsers", "SimulationUserEvents", "Users",
          "Trainings", "Payloads", "TrainingUserCoverage", "SyncState")
USER_FIELDS = "id,displayName,givenName,surname,mail,department,companyName,city,country,jobTitle,accountEnabled"
NEVER = datetime(1986, 1, 1, tzinfo=timezone.utc)
RETRY_STATUS = {429, 500, 502, 503, 504}


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _enum(value: Any) -> str | None:
    # Graph JSON returns camelCase enum values; the C# SDK (and existing reports) use PascalCase.
    if value is None:
        return None
    text = str(value)
    return text[:1].upper() + text[1:] if text else text


def _who(obj: dict | None, prefix: str) -> dict:
    obj = obj or {}
    return {f"{prefix}_Id": obj.get("id"),
            f"{prefix}_DisplayName": obj.get("displayName"),
            f"{prefix}_Email": obj.get("email")}


def _clean(entity: dict) -> dict:
    # Table Storage rejects None values; omit them instead.
    return {k: v for k, v in entity.items() if v is not None}


class Graph:
    """Minimal async Graph client: paging, $batch and Retry-After aware retries."""

    def __init__(self, credential, http: httpx.AsyncClient):
        self._credential = credential
        self._http = http
        self._token: str | None = None
        self._expires = 0.0
        self.calls = 0

    async def _auth(self) -> dict:
        if not self._token or time.time() > self._expires - 300:
            token = await self._credential.get_token(f"{GRAPH}/.default")
            self._token, self._expires = token.token, token.expires_on
        return {"Authorization": f"Bearer {self._token}"}

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        for attempt in range(6):
            self.calls += 1
            response = await self._http.request(method, url, headers=await self._auth(), **kwargs)
            if response.status_code not in RETRY_STATUS:
                return response
            wait = float(response.headers.get("Retry-After", 0)) or min(60, 2 ** attempt + random.random())
            log.warning("Graph %s on %s, retrying in %.1fs", response.status_code, url.split("?")[0], wait)
            await asyncio.sleep(wait)
        return response

    async def pages(self, url: str) -> AsyncIterator[dict]:
        while url:
            response = await self.request("GET", url)
            response.raise_for_status()
            body = response.json()
            for item in body.get("value", []):
                yield item
            url = body.get("@odata.nextLink")

    async def get_users(self, ids: list[str]) -> dict[str, dict | None]:
        """Read up to 20 users per $batch call. Returns None for users that no longer exist."""
        results: dict[str, dict | None] = {}
        for start in range(0, len(ids), 20):
            chunk = ids[start:start + 20]
            pending = {str(i): uid for i, uid in enumerate(chunk)}
            for attempt in range(6):
                body = {"requests": [{"id": rid, "method": "GET", "url": f"/users/{uid}?$select={USER_FIELDS}"}
                                     for rid, uid in pending.items()]}
                response = await self.request("POST", f"{GRAPH}/v1.0/$batch", json=body)
                response.raise_for_status()
                retry_after = 0.0
                for item in response.json().get("responses", []):
                    uid = pending.get(item["id"])
                    status = item.get("status")
                    if status == 200:
                        results[uid] = item.get("body")
                        pending.pop(item["id"])
                    elif status == 404:
                        results[uid] = None
                        pending.pop(item["id"])
                    elif status in RETRY_STATUS:
                        retry_after = max(retry_after, float((item.get("headers") or {}).get("Retry-After", 2)))
                    else:
                        log.error("User %s lookup failed with %s", uid, status)
                        pending.pop(item["id"])
                if not pending:
                    break
                await asyncio.sleep(retry_after or 2 ** attempt)
        return results


class Writer:
    """Batches upserts per table and partition (Table Storage allows 100 per transaction)."""

    def __init__(self, service: TableServiceClient):
        self._service = service
        self._queues: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
        self.rows: dict[str, int] = defaultdict(int)

    def add(self, table: str, entity: dict, mode: UpdateMode = UpdateMode.REPLACE) -> None:
        self._queues[(table, entity["PartitionKey"], mode.value)].append(_clean(entity))

    async def flush(self) -> None:
        queues, self._queues = self._queues, defaultdict(list)
        for (table, _, mode), entities in queues.items():
            client = self._service.get_table_client(table)
            unique = list({e["RowKey"]: e for e in entities}.values())
            for start in range(0, len(unique), 100):
                chunk = unique[start:start + 100]
                await client.submit_transaction([("upsert", e, {"mode": UpdateMode(mode)}) for e in chunk])
                self.rows[table] += len(chunk)


async def _read_index(service: TableServiceClient, table: str, partition: str) -> dict[str, datetime]:
    """RowKey -> LastUserSync for one partition, read in a single query."""
    client = service.get_table_client(table)
    index: dict[str, datetime] = {}
    async for entity in client.query_entities(f"PartitionKey eq '{partition}'", select=["RowKey", "LastUserSync"]):
        value = entity.get("LastUserSync")
        if isinstance(value, str):
            value = _dt(value)
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        index[entity["RowKey"]] = value or NEVER
    return index


def _simulation_row(sim: dict, last_user_sync: datetime) -> dict:
    payload = sim.get("payload") or {}
    return {
        "PartitionKey": "Simulations", "RowKey": sim["id"],
        "DisplayName": sim.get("displayName"), "Description": sim.get("description"),
        "Status": _enum(sim.get("status")), "AttackType": _enum(sim.get("attackType")),
        "AttackTechnique": _enum(sim.get("attackTechnique")),
        "CreatedDateTime": _dt(sim.get("createdDateTime")),
        "CompletionDateTime": _dt(sim.get("completionDateTime")),
        "LastModifiedDateTime": _dt(sim.get("lastModifiedDateTime")),
        "DurationInDays": sim.get("durationInDays"), "IsAutomated": sim.get("isAutomated"),
        "AutomationId": sim.get("automationId"),
        "Payload_Id": payload.get("id"), "Payload_DisplayName": payload.get("displayName"),
        "Payload_Platform": _enum(payload.get("platform")),
        **_who(sim.get("createdBy"), "CreatedBy"), **_who(sim.get("lastModifiedBy"), "LastModifiedBy"),
        "LastUserSync": last_user_sync,
    }


async def _sync_simulation_users(graph: Graph, writer: Writer, sim_id: str, user_ids: set[str]) -> None:
    url = f"{GRAPH}/beta/security/attackSimulation/simulations/{sim_id}/report/simulationUsers?$top=1000"
    async for detail in graph.pages(url):
        user = detail.get("simulationUser") or {}
        uid = user.get("userId")
        if not uid:
            continue
        user_ids.add(uid)
        su_id = f"{sim_id}-{uid}"
        writer.add("SimulationUsers", {
            "PartitionKey": sim_id, "RowKey": uid,
            "SimulationUser_Id": su_id, "SimulationId": sim_id,
            "SimulationUser_UserId": uid, "SimulationUser_Email": user.get("email"),
            "CompromisedDateTime": _dt(detail.get("compromisedDateTime")),
            "ReportedPhishDateTime": _dt(detail.get("reportedPhishDateTime")),
            "AssignedTrainingsCount": detail.get("assignedTrainingsCount"),
            "CompletedTrainingsCount": detail.get("completedTrainingsCount"),
            "InProgressTrainingsCount": detail.get("inProgressTrainingsCount"),
            "IsCompromised": detail.get("isCompromised"),
            "HasReported": detail.get("reportedPhishDateTime") is not None,
        })
        for event in detail.get("simulationEvents") or []:
            when = _dt(event.get("eventDateTime"))
            if not when:
                continue
            writer.add("SimulationUserEvents", {
                "PartitionKey": sim_id,
                "RowKey": f"{uid}_{event.get('eventName')}_{int(when.timestamp())}",
                "SimulationUser_Id": su_id, "SimulationUser_UserId": uid,
                "SimulationUserEvent_EventName": event.get("eventName"),
                "SimulationUserEvent_EventDateTime": when,
                "SimulationUserEvent_Browser": event.get("browser"),
                "SimulationUserEvent_IpAddress": event.get("ipAddress"),
                "SimulationUserEvent_OsPlatformDeviceDetails": event.get("osPlatformDeviceDetails"),
            })
    writer.add("Simulations", {"PartitionKey": "Simulations", "RowKey": sim_id, "LastUserSync": _now()},
               UpdateMode.MERGE)


async def _catalogue_is_fresh(service: TableServiceClient, name: str, hours: int) -> bool:
    """True when the named catalogue was refreshed within `hours` (tracked in the SyncState table)."""
    if hours <= 0:
        return False
    client = service.get_table_client("SyncState")
    try:
        entity = await client.get_entity("Catalogue", name)
    except ResourceNotFoundError:
        return False
    refreshed = entity.get("LastRefresh")
    if refreshed is not None and refreshed.tzinfo is None:
        refreshed = refreshed.replace(tzinfo=timezone.utc)
    return bool(refreshed) and refreshed > _now() - timedelta(hours=hours)


async def _sync_trainings(graph: Graph, writer: Writer) -> None:
    async for t in graph.pages(f"{GRAPH}/beta/security/attackSimulation/trainings?$top=1000"):
        writer.add("Trainings", {
            "PartitionKey": "Trainings", "RowKey": t["id"], "TrainingId": t["id"],
            "DisplayName": t.get("displayName"), "Description": t.get("description"),
            "DurationInMinutes": t.get("durationInMinutes"), "Source": _enum(t.get("source")),
            "Type": _enum(t.get("type")), "availabilityStatus": _enum(t.get("availabilityStatus")),
            "HasEvaluation": t.get("hasEvaluation"),
            **_who(t.get("createdBy"), "CreatedBy"), **_who(t.get("lastModifiedBy"), "LastModifiedBy"),
            "LastModifiedDateTime": _dt(t.get("lastModifiedDateTime")),
        })


async def _sync_payloads(graph: Graph, writer: Writer, sources: tuple[str, ...] = ("tenant", "global")) -> None:
    for source in sources:
        url = f"{GRAPH}/beta/security/attackSimulation/payloads?$top=1000&$filter=source eq '{source}'"
        async for p in graph.pages(url):
            writer.add("Payloads", {
                "PartitionKey": "Payloads", "RowKey": p["id"], "PayloadId": p["id"],
                "DisplayName": p.get("displayName"), "Description": p.get("description"),
                "SimulationAttackType": _enum(p.get("simulationAttackType")),
                "Platform": _enum(p.get("platform")), "Status": _enum(p.get("status")),
                "Source": _enum(p.get("source")),
                "PredictedCompromiseRate": float(p["predictedCompromiseRate"])
                if p.get("predictedCompromiseRate") is not None else None,
                "Complexity": _enum(p.get("complexity")), "Technique": _enum(p.get("technique")),
                "Theme": _enum(p.get("theme")), "Brand": _enum(p.get("brand")),
                "Industry": _enum(p.get("industry")),
                "IsCurrentEvent": p.get("isCurrentEvent"), "IsControversial": p.get("isControversial"),
                **_who(p.get("createdBy"), "CreatedBy"), **_who(p.get("lastModifiedBy"), "LastModifiedBy"),
                "LastModifiedDateTime": _dt(p.get("lastModifiedDateTime")),
            })


async def _sync_training_coverage(graph: Graph, writer: Writer) -> None:
    # This report rejects $top, so let Graph choose the page size.
    url = f"{GRAPH}/beta/reports/security/getAttackSimulationTrainingUserCoverage"
    async for row in graph.pages(url):
        uid = (row.get("attackSimulationUser") or {}).get("userId")
        if not uid:
            continue
        for training in row.get("userTrainings") or []:
            assigned = _dt(training.get("assignedDateTime"))
            if not assigned:
                continue
            name = training.get("displayName") or ""
            name_hash = hashlib.md5(name.encode("ascii", "ignore")).hexdigest().upper()
            writer.add("TrainingUserCoverage", {
                "PartitionKey": "TrainingUserCoverage",
                "RowKey": f"{uid}{name_hash}{assigned.strftime('%Y%m%d%H%M%S')}",
                "UserId": uid, "DisplayName": name, "AssignedDateTime": assigned,
                "CompletionDateTime": _dt(training.get("completionDateTime")),
                "TrainingStatus": _enum(training.get("trainingStatus")),
            })


async def _sync_users(graph: Graph, writer: Writer, service: TableServiceClient,
                      user_ids: set[str], refresh_days: int) -> int:
    known = await _read_index(service, "Users", "Users")
    cutoff = _now() - timedelta(days=refresh_days)
    stale = sorted(uid for uid in user_ids if known.get(uid, NEVER) < cutoff)
    profiles = await graph.get_users(stale)
    stamp = _now()
    for uid, user in profiles.items():
        if user is None:
            writer.add("Users", {"PartitionKey": "Users", "RowKey": uid, "Exists": "false",
                                 "LastUserSync": stamp}, UpdateMode.MERGE)
            continue
        writer.add("Users", {
            "PartitionKey": "Users", "RowKey": uid,
            "DisplayName": user.get("displayName"), "GivenName": user.get("givenName"),
            "Surname": user.get("surname"), "Mail": user.get("mail"),
            "Department": user.get("department"), "CompanyName": user.get("companyName"),
            "City": user.get("city"), "Country": user.get("country"), "JobTitle": user.get("jobTitle"),
            "accountEnabled": str(user.get("accountEnabled")) if user.get("accountEnabled") is not None else None,
            "Exists": "true", "LastUserSync": stamp,
        })
    return len(stale)


def _graph_credential():
    tenant, client, secret = _env("GRAPH_TENANT_ID"), _env("GRAPH_CLIENT_ID"), _env("GRAPH_CLIENT_SECRET")
    if tenant and client and secret:
        return ClientSecretCredential(tenant, client, secret)
    return DefaultAzureCredential()


def _table_service() -> tuple[TableServiceClient, Any]:
    connection = _env("STORAGE_CONNECTION_STRING")
    if connection:
        return TableServiceClient.from_connection_string(connection), None
    account = _env("STORAGE_ACCOUNT_NAME")
    if not account:
        raise RuntimeError("Set STORAGE_ACCOUNT_NAME (or STORAGE_CONNECTION_STRING for local runs).")
    credential = DefaultAzureCredential()
    return TableServiceClient(f"https://{account}.table.core.windows.net", credential=credential), credential


async def run_sync() -> dict:
    started = time.monotonic()
    sync_users = (_env("SYNC_ENTRA_USERS", "true") or "true").lower() != "false"
    refresh_days = int(_env("USER_REFRESH_DAYS", "7"))
    resync_days = int(_env("SIM_RESYNC_DAYS", "7"))
    parallel = int(_env("MAX_PARALLEL_SIMULATIONS", "4"))
    catalogue_hours = int(_env("CATALOGUE_REFRESH_HOURS", "24"))

    graph_credential = _graph_credential()
    service, storage_credential = _table_service()
    try:
        async with service, httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as http:
            for table in TABLES:
                try:
                    await service.create_table(table)
                except ResourceExistsError:
                    pass

            graph = Graph(graph_credential, http)
            writer = Writer(service)

            # 1. Simulations. One table query tells us which ones were synced before.
            known = await _read_index(service, "Simulations", "Simulations")
            cutoff, month_ago = _now() - timedelta(days=resync_days), _now() - timedelta(days=30)
            to_sync: list[str] = []
            sim_count = 0
            async for sim in graph.pages(f"{GRAPH}/beta/security/attackSimulation/simulations?$top=1000"):
                sim_count += 1
                last = known.get(sim["id"])
                completed = _dt(sim.get("completionDateTime"))
                if (last is None or sim.get("status") == "running"
                        or (completed and completed > cutoff) or last < month_ago):
                    to_sync.append(sim["id"])
                writer.add("Simulations", _simulation_row(sim, last or NEVER))
            await writer.flush()
            log.info("Simulations: %d found, %d need a user sync", sim_count, len(to_sync))

            # 2. Users and events of those simulations, a few simulations at a time.
            user_ids: set[str] = set()
            gate = asyncio.Semaphore(parallel)

            async def one(sim_id: str) -> None:
                async with gate:
                    try:
                        await _sync_simulation_users(graph, writer, sim_id, user_ids)
                    except httpx.HTTPError as error:
                        log.error("Simulation %s failed: %s", sim_id, error)

            await asyncio.gather(*(one(s) for s in to_sync))
            await writer.flush()

            # 3. Catalogue data and training coverage. Microsoft's own trainings and global
            #    payloads (thousands of rows) are refreshed once per CATALOGUE_REFRESH_HOURS.
            fresh_payloads = await _catalogue_is_fresh(service, "GlobalPayloads", catalogue_hours)
            fresh_trainings = await _catalogue_is_fresh(service, "Trainings", catalogue_hours)
            steps = [("TrainingUserCoverage", _sync_training_coverage),
                     ("Payloads", (lambda g, w: _sync_payloads(g, w, ("tenant",))) if fresh_payloads
                      else _sync_payloads)]
            if not fresh_trainings:
                steps.append(("Trainings", _sync_trainings))
            failed: set[str] = set()
            for name, step in steps:
                try:
                    await step(graph, writer)
                except httpx.HTTPError as error:
                    failed.add(name)
                    log.error("%s failed: %s", name, error)
            await writer.flush()
            for name, was_fresh, table in (("GlobalPayloads", fresh_payloads, "Payloads"),
                                           ("Trainings", fresh_trainings, "Trainings")):
                if not was_fresh and table not in failed:
                    writer.add("SyncState", {"PartitionKey": "Catalogue", "RowKey": name, "LastRefresh": _now()})
            await writer.flush()
            log.info("Catalogues: global payloads %s, trainings %s",
                     "skipped (fresh)" if fresh_payloads else "refreshed",
                     "skipped (fresh)" if fresh_trainings else "refreshed")

            # 4. Entra profiles, only for users not refreshed recently, 20 per Graph call.
            looked_up = 0
            if sync_users and user_ids:
                looked_up = await _sync_users(graph, writer, service, user_ids, refresh_days)
                await writer.flush()

            summary = {"seconds": round(time.monotonic() - started, 1), "graphCalls": graph.calls,
                       "simulations": sim_count, "simulationsSynced": len(to_sync),
                       "usersLookedUp": looked_up, "rowsWritten": dict(writer.rows)}
            log.info("AST sync complete: %s", summary)
            return summary
    finally:
        await graph_credential.close()
        if storage_credential is not None:
            await storage_credential.close()


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    print(json.dumps(asyncio.run(run_sync()), indent=2))
