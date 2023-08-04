import ipaddress
import json
import logging
import os

import charms.contextual_status as status
from ops import BlockedStatus, MaintenanceStatus
from subprocess import call, CalledProcessError, check_call, check_output, DEVNULL

log = logging.getLogger(__name__)


def get_bind_addresses(ipv4=True, ipv6=True):
    def _as_address(addr_str):
        try:
            return ipaddress.ip_address(addr_str)
        except ValueError:
            return None

    try:
        output = check_output(["ip", "-j", "-br", "addr", "show", "scope", "global"])
    except CalledProcessError as e:
        # stderr will have any details, and go to the log
        log.error("Unable to determine global addresses")
        log.exception(e)
        return []

    ignore_interfaces = ("lxdbr", "flannel", "cni", "virbr", "docker")
    accept_versions = set()
    if ipv4:
        accept_versions.add(4)
    if ipv6:
        accept_versions.add(6)

    addrs = []
    for addr in json.loads(output.decode("utf8")):
        if addr["operstate"].upper() != "UP" or any(
            addr["ifname"].startswith(prefix) for prefix in ignore_interfaces
        ):
            log.debug(f"Skipping bind address for interface {addr.get('ifname')}")
            continue

        for ifc in addr["addr_info"]:
            local_addr = _as_address(ifc.get("local"))
            if local_addr and local_addr.version in accept_versions:
                addrs.append(str(local_addr))

    return addrs


def get_kubernetes_service_addresses(cidrs):
    """Get the IP address(es) for the kubernetes service based on the cidr."""
    networks = [ipaddress.ip_interface(cidr).network for cidr in cidrs]
    return [
        next(network.hosts()).exploded
        for network in networks
    ]


def get_public_address():
    cmd = ["unit-get", "public-address"]
    return check_output(cmd).decode("UTF-8").strip()


@status.on_error(BlockedStatus("Failed to install Kubernetes snaps"))
def install(channel, control_plane=False):
    """ Install or refresh Kubernetes snaps. This includes the basic snaps to
    talk to Kubernetes and run a Kubernetes nodes.

    If control_plane=True, then also install the Kubernetes control plane snaps.
    """

    # Refresh with ignore_running=True ONLY for non-daemon apps (i.e. kubectl)
    # https://bugs.launchpad.net/bugs/1987331
    install_snap("kubectl", channel=channel, classic=True, ignore_running=True)
    install_snap("kubelet", channel=channel, classic=True)
    install_snap("kube-proxy", channel=channel, classic=True)

    if control_plane:
        install_snap("kube-apiserver", channel=channel)
        install_snap("kube-controller-manager", channel=channel)
        install_snap("kube-scheduler", channel=channel)
        install_snap("cdk-addons", channel=channel)


def install_snap(name, channel, classic=False, ignore_running=False):
    """ Install or refresh a snap """
    status.add(MaintenanceStatus(f"Installing {name} snap"))

    is_refresh = is_snap_installed(name)

    cmd = [
        "snap",
        "refresh" if is_refresh else "install",
        name,
        "--channel",
        channel
    ]

    if classic:
        cmd.append('--classic')

    if is_refresh and ignore_running:
        cmd.append('--ignore-running')

    check_call(cmd)


def is_snap_installed(name):
    """ Return True if the given snap is installed, otherwise False. """
    cmd = ["snap", "list", name]
    return call(cmd, stdout=DEVNULL, stderr=DEVNULL) == 0


def write_certificates(ca, client_cert, client_key, server_cert, server_key):
    cert_dir = "/root/cdk"
    os.makedirs(cert_dir, exist_ok=True)

    with open(cert_dir + '/ca.crt', 'w') as f:
        f.write(ca)
    with open(cert_dir + '/server.crt', 'w') as f:
        f.write(server_cert)
    with open(cert_dir + '/server.key', 'w') as f:
        f.write(server_key)
    with open(cert_dir + '/client.crt', 'w') as f:
        f.write(client_cert)
    with open(cert_dir + '/client.key', 'w') as f:
        f.write(client_key)
