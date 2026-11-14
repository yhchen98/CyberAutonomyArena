from __future__ import annotations
from ...config import env_backend

import asyncio
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional

from ....config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
from ....experiment import Experiment
from ....experiment_log import init_logger, log, output_root


_EXC_RE = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception): ")


def _mhbench_error(action: str, returncode: int, mhbench_log: Path) -> RuntimeError:
    """Build a failure whose message carries MHBench's real cause from the log tail."""
    detail = ""
    try:
        lines = [ln.rstrip() for ln in mhbench_log.read_text(errors="replace").splitlines() if ln.strip()]
        err_lines = [ln for ln in lines if _EXC_RE.match(ln.strip())]
        detail = (err_lines[-1] if err_lines else lines[-1]).strip()
    except Exception:
        pass
    detail = f": {detail}" if detail else ""
    return RuntimeError(f"MHBench {action} failed (exit {returncode}){detail} (see {mhbench_log})")


def _is_kali_vm(vm_type: Optional[str]) -> bool:
    """True for the shared Kali profile and any dedicated Kali attacker profile."""
    return str(vm_type or "").startswith("kali")


def _kali_ip_from_spec(topology_path: Path) -> Optional[str]:
    topology = json.loads(topology_path.read_text())
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                if _is_kali_vm(host.get("vm_type")):
                    return host.get("ip_address")
    return None


def resolve_topology_path(environment_spec: str, cfg) -> Path:
    """Resolve environment_spec (absolute, or relative to mhbench_dir) to the topology JSON path."""
    p = Path(environment_spec)
    return p if p.is_absolute() else cfg.mhbench_dir / p


def _mhb_config_args(cfg) -> list:
    """The --config args routing MHBench at a non-default backend config, or []."""
    return ["--config", env_backend(cfg).mhbench_config] if env_backend(cfg).mhbench_config else []


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> str:
    """The key MHBench injected into the hosts, read from MHBench's own config (backend-aware)."""
    import yaml
    default = str(Path("~/.ssh/id_ed25519").expanduser())
    try:
        rel = env_backend(cfg).mhbench_config or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return os.path.expanduser(key) if key else default
    except Exception:  # noqa: BLE001
        return default


_KALI_FOOTHOLD = "kali"


def attacker_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Build the adversary-safe AttackerEnvSpec (objective + foothold identity only)."""
    from ....attacker.env_spec import AttackerEnvSpec, AttackerBox
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    return AttackerEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        box=AttackerBox(name=_KALI_FOOTHOLD, ip=kali_ip, user="root") if kali_ip else None,
    )


def attacker_setup_access(deployed: Optional[DeployedEnvironment], bastion_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Build the harness-only SetupAccess for the attacker's foothold (key + bastion routing)."""
    from ....attacker.env_spec import AttackerSetupAccess
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    if not kali_ip:
        return []
    key = _mhbench_ssh_key(cfg)
    def proxy_for(host: str) -> str:
        if not bastion_ip:
            return ""
        return (
            f'-o ProxyCommand="ssh -W %h:%p -i {key} -o BatchMode=yes -o PasswordAuthentication=no '
            f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{bastion_ip}"'
        )
    topo = Path(deployed.topology_spec) if deployed and deployed.topology_spec else None
    relay = None
    if topo and topo.exists():
        data = json.loads(topo.read_text())
        for network in data.get("networks", []):
            for subnet in network.get("subnets", []):
                for host in subnet.get("hosts", []):
                    if host.get("infrastructure"):
                        relay = host
                        break
                if relay:
                    break
            if relay:
                break
    keydir = Path(cfg.mhbench_dir) / "keys"
    admin_key = keydir / "relay_admin"
    mh_hop_key = keydir / "mh_hop"
    c2_proxy_key = keydir / "c2_proxy"
    guest_proxy_key = keydir / "guest_proxy"
    relay_ip = str(relay.get("ip_address")) if relay else None
    if relay_ip and mh_hop_key.exists() and guest_proxy_key.exists():
        kali_proxy = _forced_guest_proxy_args(bastion_ip, relay_ip, guest_proxy_key, mh_hop_key)
    else:
        kali_proxy = proxy_for(kali_ip)
    access = [AttackerSetupAccess(name=_KALI_FOOTHOLD, host=kali_ip, user="root",
                                  ssh_key=key, ssh_common_args=kali_proxy)]
    if relay and relay_ip:
        data_ip = next((i.get("ip_address") for i in relay.get("extra_interfaces", [])
                        if i.get("subnet") in {"relay_lan"}), None)
        if admin_key.exists() and mh_hop_key.exists() and c2_proxy_key.exists():
            mh_proxy = _mh_hop_proxy_args(bastion_ip, mh_hop_key)
            access.append(AttackerSetupAccess(
                name="c2", host=relay_ip, user="root",
                ssh_key=str(admin_key), ssh_common_args=mh_proxy,
                service_host=str(data_ip) if data_ip else None,
                tunnel_user="relay-c2-proxy", tunnel_key=str(c2_proxy_key),
                tunnel_ssh_common_args=mh_proxy))
        else:
            access.append(AttackerSetupAccess(
                name="c2", host=relay_ip, user="root",
                ssh_key=key, ssh_common_args=proxy_for(relay_ip),
                service_host=str(data_ip) if data_ip else None))
    return access


_ATTACKER_SUBNET = "attacker_subnet"
_DEFENDER_SUBNET = "defender_subnet"


def _iter_victims(topology_path: Path):
    """Yield each victim host dict — every host that is neither the attacker foothold nor the defender box."""
    topo = json.loads(Path(topology_path).read_text())
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            if sub.get("name") in (_ATTACKER_SUBNET, _DEFENDER_SUBNET):
                continue
            for h in sub.get("hosts", []):
                if _is_kali_vm(h.get("vm_type")):
                    continue
                yield h


def _defender_box_host(topology_path: Path) -> Optional[dict]:
    """Return the defender box host dict (the single host in defender_subnet), or None."""
    topo = json.loads(Path(topology_path).read_text())
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            if sub.get("name") == _DEFENDER_SUBNET:
                hosts = sub.get("hosts", [])
                return hosts[0] if hosts else None
    return None


def defender_box_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """The agent-facing DefenderBox derived from the topology's defender_subnet, or None if absent."""
    from ....defender.env_spec import DefenderBox
    topo = deployed.topology_spec if deployed else None
    if not (topo and Path(topo).exists()):
        return None
    bh = _defender_box_host(topo)
    if not bh:
        return None
    ip = bh.get("ip_address")
    return DefenderBox(name=bh["name"], ip=str(ip) if ip else None, subnet=_DEFENDER_SUBNET)


def _role_from_name(name: str) -> Optional[str]:
    """Derive a role from a host name by stripping the trailing index (webserver0 -> webserver)."""
    return re.sub(r"\d+$", "", name) or None


def _host_users(vm_type: str) -> list[str]:
    """Login accounts a host of this MHBench vm_type has (ubuntu everywhere, +tomcat on webservers)."""
    if vm_type.startswith("kali"):
        return []
    if vm_type.startswith("webserver"):
        return ["ubuntu", "tomcat"]
    return ["ubuntu"]


def _defender_subnets(topology_path: Path, project_name: Optional[str]):
    """Resolve the defended-estate subnet structure (backend network/sg names, attacker segment excluded)."""
    from ....defender.env_spec import DefenderSubnet, DefenderHost, DefenderUser

    topo = json.loads(Path(topology_path).read_text())
    nets = topo.get("networks", [])
    if not nets:
        return [], None, None
    network_data = nets[0]

    def _n(name: str) -> str:
        return f"{project_name}-{name}" if project_name else name

    subnets = []
    for sd in network_data["subnets"]:
        if sd["name"] in (_ATTACKER_SUBNET, _DEFENDER_SUBNET):
            continue
        if any(h.get("vm_type", "").startswith("kali") for h in sd["hosts"]):
            continue
        hosts = []
        for h in sd["hosts"]:
            ip = h.get("ip_address")
            hosts.append(DefenderHost(
                name=h["name"],
                ip=str(ip) if ip else None,
                role=_role_from_name(h["name"]),
                users=[DefenderUser(name=u) for u in _host_users(h.get("vm_type", ""))],
                telemetry=h.get("vm_type", "").endswith("_instrumented"),
            ))
        subnets.append(DefenderSubnet(
            name=sd["name"],
            network=_n(sd["name"]),
            sec_group=_n(f"{sd['name']}_sg"),
            hosts=hosts,
            perimeter=bool(sd.get("perimeter", False)),
        ))
    return subnets, network_data.get("name"), _n("management_sg")


def _bastion_proxy_args(bastion_ip: Optional[str], key: str) -> str:
    """ssh args that route through the bastion with IdentitiesOnly, so ssh offers only this scoped key."""
    if not bastion_ip:
        return ""
    return (
        f'-o IdentitiesOnly=yes '
        f'-o ProxyCommand="ssh -W %h:%p -i {key} -o IdentitiesOnly=yes -o BatchMode=yes '
        f'-o PasswordAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'root@{bastion_ip}"'
    )


def _forced_guest_proxy_args(bastion_ip: Optional[str], relay_ip: str,
                              guest_proxy_key: Path, mh_hop_key: Path) -> str:
    """ProxyCommand for an experimental guest: mh-hop -> relay guest-proxy -> guest:22."""
    if not bastion_ip:
        return ""
    inner = (
        f"ssh -i {mh_hop_key} -o BatchMode=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null mh-hop@{bastion_ip} {relay_ip} 22"
    )
    return (
        f'-o ProxyCommand="ssh -i {guest_proxy_key} -o BatchMode=yes '
        f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'-o ProxyCommand=\'{inner}\' relay-guest-proxy@{relay_ip} %h %p"'
    )


def _mh_hop_proxy_args(bastion_ip: Optional[str], mh_hop_key: Path) -> str:
    """Proxy to a relay through the management host's forced mh-hop account, not root -W."""
    if not bastion_ip:
        return ""
    return (
        f'-o IdentitiesOnly=yes '
        f'-o ProxyCommand="ssh -i {mh_hop_key} -o IdentitiesOnly=yes -o BatchMode=yes '
        f'-o PasswordAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'mh-hop@{bastion_ip} %h %p"'
    )


def issue_scoped_keys(cfg: ExperimentManagerConfig) -> tuple[Path, Path]:
    """Generate (idempotently) the attacker_key + defender_key keypairs the env issues."""
    keydir = Path(cfg.mhbench_dir) / "keys"
    keydir.mkdir(parents=True, exist_ok=True)
    out = []
    for name in ("attacker_key", "defender_key"):
        p = keydir / name
        if not p.exists():
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(p), "-N", "", "-q",
                            "-C", f"arena-{name}"], check=True)
            p.chmod(0o600)
        out.append(p)
    return out[0], out[1]


def _inject_bastion_jump(pubkey: str, targets: list[str], bastion_ip: str, mgmt_key: str) -> bool:
    """Add a forward-only entry for pubkey to the bastion's authorized_keys (tunnel to targets only)."""
    if not targets:
        return True
    opts = ('command="/bin/false",restrict,port-forwarding,'
            + ",".join(f'permitopen="{t}"' for t in targets))
    entry = f"{opts} {pubkey}"
    keymat = pubkey.split()[1]
    remote = (
        "install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"{{ grep -vF {keymat!r} ~/.ssh/authorized_keys || true; }} > ~/.ssh/ak.tmp && "
        "mv ~/.ssh/ak.tmp ~/.ssh/authorized_keys && "
        f"printf '%s\\n' {entry!r} >> ~/.ssh/authorized_keys"
    )
    r = subprocess.run(
        ["ssh", "-i", mgmt_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", f"root@{bastion_ip}", remote],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode == 0


def _inject_pubkey(pubkey: str, host_ip: str, bastion_ip: str, mgmt_key: str) -> bool:
    """Append pubkey to root's authorized_keys on host_ip (via the bastion with the mgmt key)."""
    proxy = (f"ssh -W %h:%p -i {mgmt_key} -o BatchMode=yes -o StrictHostKeyChecking=no "
             f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 root@{bastion_ip}")
    remote = ("install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
              f"grep -qxF {pubkey!r} ~/.ssh/authorized_keys || echo {pubkey!r} >> ~/.ssh/authorized_keys")
    r = subprocess.run(
        ["ssh", "-i", mgmt_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
         "-o", f"ProxyCommand={proxy}", f"root@{host_ip}", remote],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode == 0


def inject_scoped_keys(experiment: Experiment, bastion_ip: Optional[str], cfg: ExperimentManagerConfig) -> None:
    """Issue + inject the per-system scoped keys (full shell on own hosts + forward-only on the bastion)."""
    name = experiment.experiment_name
    if not bastion_ip:
        log(name, "inject_scoped_keys: no bastion_ip; skipping per-system key injection.")
        return
    topo = resolve_topology_path(experiment.environment_spec, cfg)
    ak, dk = issue_scoped_keys(cfg)
    ak_pub = Path(str(ak) + ".pub").read_text().strip()
    dk_pub = Path(str(dk) + ".pub").read_text().strip()
    mgmt_key = _mhbench_ssh_key(cfg)

    kali_ip = _kali_ip_from_spec(topo)
    if kali_ip:
        ok = _inject_pubkey(ak_pub, kali_ip, bastion_ip, mgmt_key)
        log(name, f"per-system key: attacker_key -> foothold {kali_ip}: {'ok' if ok else 'FAILED'}")
        jok = _inject_bastion_jump(ak_pub, [f"{kali_ip}:22"], bastion_ip, mgmt_key)
        log(name, f"jump: attacker_key forward-only on bastion -> {kali_ip}:22: {'ok' if jok else 'FAILED'}")

    targets: list[tuple[str, str]] = []
    box = _defender_box_host(topo)
    if box and box.get("ip_address"):
        targets.append((box["name"], str(box["ip_address"])))
    for h in _iter_victims(topo):
        if h.get("ip_address"):
            targets.append((h["name"], str(h["ip_address"])))
    for hname, hip in targets:
        ok = _inject_pubkey(dk_pub, hip, bastion_ip, mgmt_key)
        log(name, f"per-system key: defender_key -> {hname} {hip}: {'ok' if ok else 'FAILED'}")
    if targets:
        jok = _inject_bastion_jump(dk_pub, [f"{ip}:22" for _, ip in targets], bastion_ip, mgmt_key)
        log(name, f"jump: defender_key forward-only on bastion -> {len(targets)} hosts: {'ok' if jok else 'FAILED'}")


async def inject_scoped_keys_env(experiment: Experiment, bastion_ip: Optional[str], cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, inject_scoped_keys, experiment, bastion_ip, cfg)


def defender_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Build the agent-facing DefenderEnvSpec: objective, victim inventory, and subnet structure."""
    from ....defender.env_spec import DefenderEnvSpec, DefenderHost, DefenderUser
    topo = deployed.topology_spec if deployed else None
    project_name = deployed.project_name if deployed else None
    hosts = []
    subnets, network_name, management_sg = [], None, None
    if topo and Path(topo).exists():
        for h in _iter_victims(topo):
            ip = h.get("ip_address")
            hosts.append(DefenderHost(
                name=h["name"], ip=str(ip) if ip else None, role=_role_from_name(h["name"]),
                users=[DefenderUser(name=u) for u in _host_users(h.get("vm_type", ""))],
                telemetry=h.get("vm_type", "").endswith("_instrumented"),
            ))
        subnets, network_name, management_sg = _defender_subnets(Path(topo), project_name)
    return DefenderEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        hosts=hosts,
        subnets=subnets,
        network_name=network_name,
        management_sg=management_sg,
        box=defender_box_spec(deployed, cfg),
    )


def defender_setup_access(deployed: Optional[DeployedEnvironment], bastion_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Build the harness-only SetupAccess for each victim (+ defender box) — key + bastion routing."""
    from ....defender.env_spec import DefenderSetupAccess
    topo = deployed.topology_spec if deployed else None
    if not (topo and Path(topo).exists()):
        return []
    key = _mhbench_ssh_key(cfg)
    proxy = _bastion_proxy_args(bastion_ip, key)
    out = []
    for h in _iter_victims(topo):
        ip = h.get("ip_address")
        if ip:
            out.append(DefenderSetupAccess(name=h["name"], host=str(ip), user="root",
                                   ssh_key=key, ssh_common_args=proxy))
    box = _defender_box_host(topo)
    if box and box.get("ip_address"):
        out.append(DefenderSetupAccess(name=box["name"], host=str(box["ip_address"]), user="root",
                               ssh_key=key, ssh_common_args=proxy))
    return out


def _provision_sync(
    experiment_name: str,
    environment_spec: str,
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> tuple[DeployedEnvironment, Optional[str]]:
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    provision_result_path = (output_root(experiment_name, cfg) / experiment_name / "experiment" / "provision_result.json").resolve()

    cmd = [
        str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
        "provision", str(topology_path),
        "--project-name", experiment_name,
        "--output-file", str(provision_result_path),
    ]
    if c2c_url:
        cmd += ["--c2c-url", c2c_url]

    init_logger(experiment_name, output_root(experiment_name, cfg))
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Provisioning environment via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error("provision", result.returncode, mhbench_log)

    bastion_ip: Optional[str] = None
    if provision_result_path.exists():
        bastion_ip = json.loads(provision_result_path.read_text()).get("mgmt_ip")

    kali_ip = _kali_ip_from_spec(topology_path)
    log(experiment_name, f"Provisioning complete. Kali IP: {kali_ip}, mgmt IP: {bastion_ip}")
    return DeployedEnvironment(
        topology_spec=str(topology_path),
        ip=kali_ip,
        spec=Path(environment_spec).stem,
        project_name=experiment_name,
    ), bastion_ip


def run_control_plane_lifecycle(
    experiment_name: str,
    environment_spec: str,
    cfg: ExperimentManagerConfig,
    command: str,
    mgmt_ip: Optional[str] = None,
) -> dict:
    """Run MHBench's seal/restore control-plane command for a deployed isolated topology."""
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(python), str(cli), *_mhb_config_args(cfg), command, str(topology_path),
           "--project-name", experiment_name]
    if mgmt_ip:
        cmd += ["--mgmt-ip", str(mgmt_ip)]
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error(command, result.returncode, mhbench_log)
    # The CLI prints one JSON report line; re-read the log tail for the most recent report.
    for line in reversed(mhbench_log.read_text(errors="replace").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {}


def _configure_sync(
    experiment_name: str,
    environment_spec: str,
    bastion_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    if bastion_ip is None:
        return

    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"

    cmd = [
        str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
        "configure", str(topology_path),
        "--project-name", experiment_name,
        "--mgmt-ip", bastion_ip,
    ]
    if c2c_url:
        cmd += ["--c2c-url", c2c_url]

    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    ansible_log_dir = output_root(experiment_name, cfg) / experiment_name / cfg.ansible_log_dir
    ansible_log_dir.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Running Ansible configuration via MHBench CLI (per-host logs: {ansible_log_dir})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT,
                                env={**os.environ, "MHBENCH_ANSIBLE_LOG_DIR": str(ansible_log_dir)})
    if result.returncode != 0:
        raise _mhbench_error("configure", result.returncode, mhbench_log)

    log(experiment_name, "Configuration complete.")


async def provision_environment(
    experiment: Experiment,
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> tuple[DeployedEnvironment, Optional[str]]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _provision_sync, experiment.experiment_name, experiment.environment_spec, c2c_url, cfg
    )


def _openstack_json(args: list[str]) -> object | None:
    try:
        r = subprocess.run(["openstack", *args, "-f", "json"], capture_output=True, text=True, timeout=90)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None


def _topology_hosts(experiment: Experiment) -> list[dict]:
    deployed = experiment.deployed_environment
    topo = deployed.topology_spec if deployed else None
    if not topo or not Path(topo).exists():
        return []
    data = json.loads(Path(topo).read_text())
    hosts = []
    for network in data.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                hosts.append(host)
    return hosts


def verify_ready(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    deployed = experiment.deployed_environment
    if not deployed or not deployed.project_name:
        return
    project = deployed.project_name
    ports = _openstack_json(["port", "list"]) or []
    by_name = {p.get("Name"): p for p in ports if isinstance(p, dict)}
    for host in _topology_hosts(experiment):
        if host.get("infrastructure") or not host.get("name"):
            continue
        port = by_name.get(f"{project}-{host['name']}-nic-0")
        if port is None:
            raise RuntimeError(f"readiness: control port for {host['name']} is missing")
        if port.get("Status") == "ACTIVE" or port.get("device_id"):
            raise RuntimeError(f"readiness: control port for {host['name']} is still attached")
    relay = next((h for h in _topology_hosts(experiment) if h.get("infrastructure")), None)
    if relay:
        port = by_name.get(f"{project}-{relay['name']}-nic-0")
        if port is None or port.get("Status") != "ACTIVE":
            raise RuntimeError("readiness: relay control port is not active")
    # The console audit is supporting evidence; its absence is recorded, not treated as independent proof.
    names = [h["name"] for h in _topology_hosts(experiment) if not h.get("infrastructure") and h.get("name")]
    if names:
        try:
            r = subprocess.run(["openstack", "console", "log", "show", "--lines", "80",
                                f"{project}-{names[0]}"], capture_output=True, text=True, timeout=60)
            if "mhbench-console-audit" not in r.stdout:
                log(experiment.experiment_name, "readiness: console audit marker not visible yet")
        except Exception:
            pass


def verify_restoration(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    deployed = experiment.deployed_environment
    if not deployed or not deployed.project_name:
        return
    project = deployed.project_name
    ports = _openstack_json(["port", "list"]) or []
    by_name = {p.get("Name"): p for p in ports if isinstance(p, dict)}
    for host in _topology_hosts(experiment):
        if host.get("infrastructure") or not host.get("name"):
            continue
        port = by_name.get(f"{project}-{host['name']}-nic-0")
        if port is None or port.get("Status") != "ACTIVE":
            raise RuntimeError(f"restoration: control port for {host['name']} is not active")


def capture_attack_state(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    deployed = experiment.deployed_environment
    out = output_root(experiment.experiment_name, cfg) / experiment.experiment_name / "attack_state"
    out.mkdir(parents=True, exist_ok=True)
    for name, args in (
        ("servers", ["server", "list"]),
        ("ports", ["port", "list"]),
        ("routers", ["router", "list"]),
        ("subnets", ["subnet", "list"]),
        ("security_groups", ["security", "group", "list"]),
    ):
        data = _openstack_json(args)
        if data is not None:
            (out / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
    if deployed and deployed.project_name:
        for host in _topology_hosts(experiment):
            name = host.get("name")
            if not name:
                continue
            try:
                r = subprocess.run(["openstack", "console", "log", "show", "--lines", "200",
                                    f"{deployed.project_name}-{name}"],
                                   capture_output=True, text=True, timeout=60)
                if r.returncode == 0:
                    (out / f"console-{name}.log").write_text(r.stdout)
            except Exception:
                continue
    prepared = getattr(experiment, "_attacker_prepared", None)
    local_url = getattr(prepared, "local_url", None) if prepared else None
    if local_url:
        for name, path in (("c2_agents", "/agents"), ("c2_logs", "/get_latest_logs")):
            try:
                with urllib.request.urlopen(local_url.rstrip("/") + path, timeout=10) as r:
                    (out / f"{name}.json").write_bytes(r.read())
            except Exception:
                continue


async def configure_environment(
    experiment: Experiment,
    bastion_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, _configure_sync, experiment.experiment_name, experiment.environment_spec, bastion_ip, c2c_url, cfg
    )


def _request_ingress_sync(experiment_name: str, environment_spec: str, bastion_ip: str,
                          cfg: ExperimentManagerConfig, ingress: dict) -> None:
    """Provision the defender-requested box ingress via `cli.py request-ingress`."""
    telemetry = list(ingress.get("telemetry", []))
    forward = list(ingress.get("forward", []))
    if not (telemetry or forward):
        return
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    cmd = [str(python), str(cli), *_mhb_config_args(cfg), "request-ingress", str(topology_path),
           "--project-name", experiment_name, "--mgmt-ip", bastion_ip]
    for p in telemetry:
        cmd += ["--telemetry", str(p)]
    for p in forward:
        cmd += ["--forward", str(p)]
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Requesting defender box ingress {ingress} via MHBench CLI...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error("request-ingress", result.returncode, mhbench_log)
    log(experiment_name, "Defender box ingress provisioned.")


async def request_ingress_env(experiment: Experiment, bastion_ip: Optional[str],
                              cfg: ExperimentManagerConfig, ingress: dict) -> None:
    if not bastion_ip or not ingress:
        return
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _request_ingress_sync,
                               experiment.experiment_name, experiment.environment_spec, bastion_ip, cfg, ingress)


def _host_op_sync(op: str, experiment_name: str, environment_spec: str, cfg: ExperimentManagerConfig,
                  *, name: Optional[str] = None, role: Optional[str] = None,
                  subnet: Optional[str] = None, target: Optional[str] = None) -> dict:
    """Run one MHBench per-host CLI subcommand (add-host / rebuild-host / remove-host) and return its
    JSON result ({name, ip} for add-host, {ok: true} otherwise)."""
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    out_path = (output_root(experiment_name, cfg) / experiment_name / "experiment" / f"{op}_result.json").resolve()
    cmd = [str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
           op, str(topology_path), "--project-name", experiment_name, "--output-file", str(out_path)]
    if name:
        cmd += ["--name", name]
    if role:
        cmd += ["--role", role]
    if subnet:
        cmd += ["--subnet", subnet]
    if target:
        cmd += ["--target", target]
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"MHBench {op} via CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error(op, result.returncode, mhbench_log)
    return json.loads(out_path.read_text()) if out_path.exists() else {}


def new_host_setup_access(name: str, ip: str, cfg: ExperimentManagerConfig):
    """SetupAccess for a freshly added host (decoy), box-relative: scoped key + empty routing."""
    from ....defender.env_spec import DefenderSetupAccess
    return DefenderSetupAccess(name=name, host=str(ip), user="root",
                       ssh_key=_mhbench_ssh_key(cfg), ssh_common_args="")
