"""Fixed inputs run through a version of `charms.kubernetes_snaps`.

The scenario records every service file the library writes (path and text) and
every `snap set` argument string. `golden_0_0_1.json` holds what the published
`0.0.1` wheel produced (see `capture_golden.py`); `test_golden.py` checks that the
current code produces the same bytes, which is what keeps the first upgrade from
restarting services.

Hard-coded paths (`/root/cdk`, `/etc/systemd`, `/var/snap`) are intercepted, never
written, so the scenario is safe to run as root.
"""

import builtins
import io
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_HARD_PREFIXES = ("/root/cdk", "/etc/systemd", "/var/snap")


def _hard(path) -> bool:
    return str(path).startswith(_HARD_PREFIXES)


class _Capture(io.StringIO):
    def __init__(self, sink, path):
        super().__init__()
        self._sink, self._path = sink, path

    def close(self):
        self._sink[self._path] = self.getvalue()
        super().close()


def run(ks, workdir: Path) -> dict:
    """Run the scenario against the module `ks` and return what it did."""
    real_open, real_path_open = builtins.open, Path.open
    real_write_text, real_mkdir, real_makedirs = (
        Path.write_text,
        Path.mkdir,
        os.makedirs,
    )
    writes, commands = {}, []

    def fake_open(file, mode="r", *args, **kwargs):
        if "w" in mode and _hard(file):
            return _Capture(writes, str(file))
        return real_open(file, mode, *args, **kwargs)

    def fake_path_open(self, mode="r", *args, **kwargs):
        if "w" in mode and _hard(self):
            return _Capture(writes, str(self))
        return real_path_open(self, mode, *args, **kwargs)

    def fake_write_text(self, data, *args, **kwargs):
        if _hard(self):
            writes[str(self)] = data
            return len(data)
        return real_write_text(self, data, *args, **kwargs)

    def fake_mkdir(self, *args, **kwargs):
        return None if _hard(self) else real_mkdir(self, *args, **kwargs)

    def fake_makedirs(path, *args, **kwargs):
        return None if _hard(path) else real_makedirs(path, *args, **kwargs)

    def recorder(path, content):
        writes[str(path)] = content.decode() if isinstance(content, bytes) else content
        return True

    def fake_check_output(cmd, *args, **kwargs):
        if cmd[:2] == ["snap", "get"]:
            raise subprocess.CalledProcessError(1, cmd)
        if cmd[:2] == ["snap", "list"]:
            return (
                b"Name Version Rev Tracking Publisher Notes\n"
                b"kube-apiserver 1.35.10 1 1.35/stable canonical -\n"
            )
        if cmd[0] == "systemctl":
            return b"ActiveState=inactive\nNeedDaemonReload=no\n"
        raise AssertionError(f"unexpected command {cmd}")

    def fake_check_call(cmd, *args, **kwargs):
        if cmd[:2] == ["snap", "set"]:
            commands.append(list(cmd))

    patches = [
        mock.patch.object(ks, "check_output", fake_check_output),
        mock.patch.object(ks, "check_call", fake_check_call),
        mock.patch.object(ks, "call", lambda *a, **k: 1),
        mock.patch.object(ks, "gethostname", lambda: "Host-1"),
        mock.patch.object(ks, "getfqdn", lambda: "Host-1.example.com"),
        mock.patch.object(ks, "remove_if_exists", lambda path: None),
        mock.patch.object(os.path, "realpath", lambda p: p),
        mock.patch.object(builtins, "open", fake_open),
        mock.patch.object(Path, "open", fake_path_open),
        mock.patch.object(Path, "write_text", fake_write_text),
        mock.patch.object(Path, "mkdir", fake_mkdir),
        mock.patch.object(os, "makedirs", fake_makedirs),
    ]
    if hasattr(ks, "write_if_changed"):
        patches.append(mock.patch.object(ks, "write_if_changed", recorder))

    steps = []

    def step(name, fn):
        writes.clear()
        commands.clear()
        fn()
        steps.append({"name": name, "writes": dict(writes), "snap_set": list(commands)})

    clouds = {
        "no-cloud": SimpleNamespace(name=None, has_xcp=False),
        "aws": SimpleNamespace(name="aws", has_xcp=True),
    }

    for stack in patches:
        stack.start()
    try:
        for label, cloud in clouds.items():
            step(
                f"apiserver-{label}",
                lambda cloud=cloud: ks.configure_apiserver(
                    "10.0.0.1",
                    "apiVersion: audit.k8s.io/v1\nkind: Policy\n",
                    "apiVersion: v1\nkind: Config\n",
                    "/root/cdk/auth-webhook/auth-webhook-conf.yaml",
                    "Node,RBAC",
                    "10.1.0.0/16",
                    "https://10.0.0.2:2379,https://10.0.0.3:2379",
                    "extra-flag=1 other",
                    "true",
                    "10.152.183.0/24",
                    cloud,
                ),
            )
            step(
                f"controller-manager-{label}",
                lambda cloud=cloud: ks.configure_controller_manager(
                    "10.1.0.0/16",
                    "cluster",
                    "v=3",
                    "/root/cdk/kubecontrollermanagerconfig",
                    "10.152.183.0/24",
                    cloud,
                ),
            )
            step(
                f"kube-proxy-{label}",
                lambda cloud=cloud: ks.configure_kube_proxy(
                    "10.1.0.0/16",
                    "",
                    {"mode": "iptables"},
                    "/root/cdk/kubeproxyconfig",
                    cloud,
                ),
            )
            step(
                f"kubelet-{label}",
                lambda cloud=cloud: ks.configure_kubelet(
                    "unix:///run/containerd/containerd.sock",
                    "cluster.local",
                    "10.152.183.10",
                    "max-pods=110",
                    {"maxPods": 110},
                    cloud,
                    "/root/cdk/kubeconfig",
                    "10.0.0.1",
                    "registry.example.com",
                    ["node-role.kubernetes.io/control-plane:NoSchedule"],
                ),
            )
        step("scheduler", lambda: ks.configure_scheduler("", "/root/cdk/kubeconfig"))
        step(
            "certificates",
            lambda: ks.write_certificates(
                "ca", "client-cert", "client-key", "server-cert", "server-key"
            ),
        )
        step(
            "etcd-credentials",
            lambda: ks.write_etcd_client_credentials(
                "etcd-ca", "etcd-cert", "etcd-key"
            ),
        )
        step("service-account-key", lambda: ks.write_service_account_key("sa-key"))
        step(
            "restart-always",
            lambda: ks.configure_services_restart_always(control_plane=True),
        )

        kubeconfig = workdir / "kubeconfig"
        created = {}

        def kubeconfigs():
            ks.create_kubeconfig(
                kubeconfig, "ca-data", "https://10.0.0.1:6443", "admin", "token"
            )
            created["created"] = kubeconfig.read_text()
            ks.update_kubeconfig(kubeconfig, ca="new-ca-data", token="new-token")
            created["updated"] = kubeconfig.read_text()

        step("kubeconfigs", kubeconfigs)
        steps[-1]["files"] = created
    finally:
        for stack in reversed(patches):
            stack.stop()
    return {"steps": steps}
