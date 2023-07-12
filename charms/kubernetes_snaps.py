import charms.contextual_status as status
from ops import BlockedStatus, MaintenanceStatus
from subprocess import call, check_call, DEVNULL


@status.on_error(BlockedStatus("Failed to install Kubernetes snaps"))
def install(channel, control_plane=False):
    """ Install or refresh Kubernetes snaps. This includes the basic snaps to
    talk to Kubernetes and run a Kubernetes nodes.

    If control_plane=True, then also install the Kubernetes control plane snaps.
    """

    install_snap("kubectl", channel=channel, classic=True)
    install_snap("kubelet", channel=channel, classic=True)
    install_snap("kube-proxy", channel=channel, classic=True)

    if control_plane:
        install_snap("kube-apiserver", channel=channel)
        install_snap("kube-controller-manager", channel=channel)
        install_snap("kube-scheduler", channel=channel)
        install_snap("cdk-addons", channel=channel)


def install_snap(name, channel, classic=False):
    """ Install or refresh a snap """
    status.add(MaintenanceStatus(f"Installing {name} snap"))

    cmd = [
        "snap",
        "refresh" if is_snap_installed(name) else "install",
        name,
        "--channel",
        channel
    ]

    if classic:
        cmd.append('--classic')

    check_call(cmd)


def is_snap_installed(name):
    """ Return True if the given snap is installed, otherwise False. """
    cmd = ["snap", "list", name]
    return call(cmd, stdout=DEVNULL, stderr=DEVNULL) == 0
