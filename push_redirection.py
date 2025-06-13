#!/usr/bin/env python3
import os
import argparse
import requests
import concurrent.futures
import logging
from urllib.parse import quote_plus

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table

# ==== Set up console & logging ====
console = Console()
logger = logging.getLogger("ndfc_gpo")
logger.setLevel(logging.WARNING)

fh = logging.FileHandler("ndfc_gpo.log", mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(ch)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ====== Configuration ======
ND_HOST = os.getenv("ND_HOST")
USERNAME  = "admin"
ND_PASSWORD  = os.getenv("ND_PASSWORD")
DOMAIN    = "local"

FABRICS = [
    {
        "fabric_name": "MIL1-PHY-VXLAN-1",
        "vteps": [
            {"name": "leaf-1102", "ip": "10.58.30.213"},
            {"name": "leaf-1103", "ip": "10.58.30.214"},
            {"name": "bgw-1104",  "ip": "10.58.30.215"},
            {"name": "bgw-1105",  "ip": "10.58.30.216"},
        ]
    },
    {
        "fabric_name": "MIL2-PHY-VXLAN-2",
        "vteps": [
            {"name": "leaf-1201", "ip": "10.58.30.224"},
            {"name": "leaf-1202", "ip": "10.58.30.225"},
            {"name": "leaf-1203", "ip": "10.58.30.226"},
            {"name": "bgw-1204",  "ip": "10.58.30.227"},
            {"name": "bgw-1205",  "ip": "10.58.30.228"},
        ]
    }
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "gpo_configs/services_definition.nxos")) as f:
    GLOBAL_CONF = f.read()
with open(os.path.join(BASE_DIR, "gpo_configs/features.nxos")) as f:
    FEATURES = f.read()
FABRIC_CONFS = {
    fdef["fabric_name"]: open(
        os.path.join(BASE_DIR, "gpo_configs", f"{fdef['fabric_name']}.nxos")
    ).read()
    for fdef in FABRICS
}


# ==== API Helpers ====

def login(host, user, passwd, domain):
    resp = requests.post(f"https://{host}/login",
                         json={"userName": user, "userPasswd": passwd, "domain": domain},
                         verify=False)
    resp.raise_for_status()
    token = resp.json()["token"]
    logger.info("✅ Login successful")
    logger.debug("Received token: %s", token)
    return token

def fetch_inventory(host, token, fabric):
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{quote_plus(fabric)}/inventory/switchesByFabric"
    headers = {"Cookie": f"AuthCookie={token}"}
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    return {sw["ipAddress"]: sw["serialNumber"] for sw in resp.json()}

def push_freeform(host, token, fabric, leaf, config_text, priority, desc, serial):
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/policies/bulk-create"
    headers = {"Cookie": f"AuthCookie={token}", "Content-Type": "application/json"}
    body = {
        "nvPairs": {
            "CONF":          config_text,
            "SERIAL_NUMBER": serial,
            "POLICY_ID":     "",
            "PRIORITY":      str(priority),
            "SECENTITY":     "",
            "SECENTTYPE":    "",
            "POLICY_DESC":   desc
        },
        "entityName":   "SWITCH",
        "entityType":   "SWITCH",
        "source":       "",
        "priority":     priority,
        "description":  desc,
        "templateName": "switch_freeform",
        "serialNumber": serial
    }
    resp = requests.post(url, headers=headers, json=body, verify=False)
    resp.raise_for_status()
    return resp.json()

def list_policies_for_switch(host, token, serial):
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/policies/switches/{quote_plus(serial)}"
    headers = {"Cookie": f"AuthCookie={token}"}
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    return resp.json()

def delete_policies_by_id(host, token, policy_ids):
    if not policy_ids:
        return {}
    ids_csv = ",".join(policy_ids)
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/policies/policyIds?policyIds={quote_plus(ids_csv)}"
    headers = {"Cookie": f"AuthCookie={token}"}
    resp = requests.delete(url, headers=headers, verify=False)
    resp.raise_for_status()
    return resp.json()

def recalc(host, token, fabric):
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{quote_plus(fabric)}/config-save"
    headers = {"Cookie": f"AuthCookie={token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json={}, verify=False)
    resp.raise_for_status()
    logger.info(f"🔄 Recalculate triggered on {fabric}")

def deploy(host, token, fabric):
    url = f"https://{host}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{quote_plus(fabric)}/config-deploy"
    headers = {"Cookie": f"AuthCookie={token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json={}, verify=False)
    resp.raise_for_status()
    logger.info(f"🚀 Deploy triggered on {fabric}")


# ==== Status Table Printer ====

def print_status_table(statuses, title):
    table = Table(title=title)
    table.add_column("Device", no_wrap=True)
    table.add_column("Feature", justify="center")
    table.add_column("Global", justify="center")
    table.add_column("Fabric", justify="center")
    for device, cols in statuses.items():
        def cell(sym):
            return "[green]✔[/]" if sym == "ok" else ("[yellow]⚠[/]" if sym == "skipped" else "")
        table.add_row(
            device,
            cell(cols.get("Feature")),
            cell(cols.get("Global")),
            cell(cols.get("Fabric"))
        )
    console.print(table)


# ==== Main Execution ====

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Push/remove free-form GPO policies")
    parser.add_argument("--action", choices=["add", "remove"], default="add")
    args = parser.parse_args()

    console.rule("[bold blue]🔐 Logging In")
    token = login(ND_HOST, USERNAME, ND_PASSWORD, DOMAIN)

    # Build per-fabric IP→serial
    serial_map = {}
    for fdef in FABRICS:
        fab = fdef["fabric_name"]
        try:
            serial_map[fab] = fetch_inventory(ND_HOST, token, fab)
        except Exception as e:
            logger.error("Failed to fetch inventory for %s: %s", fab, e)
            serial_map[fab] = {}

    # Build list of all device names
    all_devices = []
    for fdef in FABRICS:
        for leaf in fdef["vteps"]:
            all_devices.append(leaf["name"])

    # Initialize statuses: None = not touched; "ok" = added/removed; "skipped" = skipped
    statuses = {dev: {"Feature": None, "Global": None, "Fabric": None} for dev in all_devices}

    if args.action == "add":
        ops = []
        for fdef in FABRICS:
            fab = fdef["fabric_name"]
            for leaf in fdef["vteps"]:
                serial = serial_map[fab].get(leaf["ip"])
                if not serial:
                    logger.info("Skip: no serial for %s (%s)", leaf["name"], leaf["ip"])
                    continue

                descs = {
                    "Feature": f"{leaf['name']} Feature configuration from features.nxos",
                    "Global":  f"{leaf['name']} Global configuration from services_definition.nxos",
                    "Fabric":  f"{leaf['name']} Fabric specific configuration for {fab}"
                }
                texts = {
                    "Feature": FEATURES,
                    "Global":  GLOBAL_CONF,
                    "Fabric":  FABRIC_CONFS.get(fab, "")
                }
                priorities = {"Feature": 5, "Global": 10, "Fabric": 15}

                # Pre-fetch existing policies on this switch once
                try:
                    existing = list_policies_for_switch(ND_HOST, token, serial)
                except Exception as e:
                    logger.error("Failed to list policies for %s (%s): %s", leaf["name"], serial, e)
                    existing = []

                for key in ("Feature", "Global", "Fabric"):
                    content = texts[key].strip()
                    desc = descs[key]
                    if not content:
                        logger.warning("Skip: '%s' has no content", desc)
                        statuses[leaf["name"]][key] = "skipped"
                        continue

                    found = False
                    for p in existing:
                        if (p.get("templateName") == "switch_freeform"
                                and p.get("description") == desc
                                and p.get("serialNumber", "") == serial):
                            found = True
                            break

                    if found:
                        logger.info("Skip (already present): %s on %s", desc, leaf["name"])
                        statuses[leaf["name"]][key] = "skipped"
                    else:
                        ops.append((leaf["name"], key,
                                    lambda h=ND_HOST, t=token, fb=fab, lf=leaf, tx=content, pr=priorities[key], ds=desc, sr=serial:
                                        push_freeform(h, t, fb, lf, tx, pr, ds, sr)))

        console.rule("[bold green]⚙️  Adding Policies")
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TimeElapsedColumn(), TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Processing…", total=len(ops))
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for dev, key, fn in ops:
                    fut = executor.submit(fn)
                    futures.append((dev, key, fut))

                for dev, key, fut in futures:
                    try:
                        fut.result()
                        statuses[dev][key] = "ok"
                    except Exception as e:
                        logger.error("ADD failed for %s %s: %s", dev, key, e)
                    finally:
                        progress.advance(task)

        print_status_table(statuses, "Policy-Push Status")

    else:  # args.action == "remove"
        to_delete_ids = []
        console.rule("[bold red]🗑 Removing Policies")
        for fdef in FABRICS:
            fab = fdef["fabric_name"]
            for leaf in fdef["vteps"]:
                serial = serial_map[fab].get(leaf["ip"])
                if not serial:
                    logger.warning("Skip: no serial for %s (%s)", leaf["name"], leaf["ip"])
                    continue

                descs = {
                    "Feature": f"{leaf['name']} Feature configuration from features.nxos",
                    "Global":  f"{leaf['name']} Global configuration from services_definition.nxos",
                    "Fabric":  f"{leaf['name']} Fabric specific configuration for {fab}"
                }

                try:
                    existing = list_policies_for_switch(ND_HOST, token, serial)
                except Exception as e:
                    logger.error("Failed to list policies for %s (%s): %s", leaf["name"], serial, e)
                    existing = []

                skipped_all = True
                for p in existing:
                    if p.get("templateName") == "switch_freeform":
                        desc = p.get("description", "")
                        for key, d in descs.items():
                            if desc == d and p.get("serialNumber", "") == serial:
                                to_delete_ids.append(p["policyId"])
                                statuses[leaf["name"]][key] = "ok"
                                skipped_all = False
                                break

                if skipped_all:
                    # If none of that leaf's three descs found, mark them all skipped
                    for key in ("Feature", "Global", "Fabric"):
                        if statuses[leaf["name"]][key] is None:
                            statuses[leaf["name"]][key] = "skipped"
                    logger.warning("Skip remove: no matching freeform on %s", leaf["name"])

        if to_delete_ids:
            try:
                delete_policies_by_id(ND_HOST, token, to_delete_ids)
            except Exception as e:
                logger.error("Batch delete failed: %s", e)
        else:
            console.print("[yellow]⚠ No matching switch_freeform policies found to delete[/]")

        print_status_table(statuses, "Policy-Remove Status")

    console.rule("[bold yellow]🔄 Recalculating Configurations")
    with Progress(TextColumn("{task.description}"), BarColumn(), console=console) as prog:
        t = prog.add_task("Recalculating…", total=len(FABRICS))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(FABRICS)) as ex:
            for fdef in FABRICS:
                ex.submit(lambda f=fdef["fabric_name"]: (recalc(ND_HOST, token, f), prog.advance(t)))

    console.rule("[bold magenta]🚀 Deploying Configurations")
    with Progress(TextColumn("{task.description}"), BarColumn(), console=console) as prog:
        t = prog.add_task("Deploying…", total=len(FABRICS))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(FABRICS)) as ex:
            for fdef in FABRICS:
                ex.submit(lambda f=fdef["fabric_name"]: (deploy(ND_HOST, token, f), prog.advance(t)))

    console.rule(f"[bold green]✅ Done: Policies {'added' if args.action=='add' else 'removed'}")
    logger.info("Script completed successfully")
