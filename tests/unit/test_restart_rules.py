"""Restart only when something changed: `write_if_changed`, `restart_reason`,
`configure_kubernetes_service` and the `install()` refresh skip."""

import os
import subprocess
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

import charms.contextual_status as status
import pytest
from ops import BlockedStatus

from charms import kubernetes_snaps as ks

UNIT = "snap.kube-apiserver.daemon"


def show(state="active", reload="no", started_ago=100.0, calendar_ago="same"):
    """`systemctl show` output for a unit started `started_ago` seconds ago.

    Returns (output, start): `start` is the wall-clock start time the library
    derives from the monotonic value. `started_ago=None` means never started.
    """
    if started_ago is None:
        monotonic_us, calendar, start = 0, "", 0.0
    else:
        monotonic_us = int((time.monotonic() - started_ago) * 1e6)
        start = time.time() - time.monotonic() + monotonic_us / 1e6
        ago = started_ago if calendar_ago == "same" else calendar_ago
        calendar = datetime.fromtimestamp(time.time() - ago, timezone.utc).strftime(
            "%a %Y-%m-%d %H:%M:%S.%f UTC"
        )
    out = (
        f"ActiveState={state}\nNeedDaemonReload={reload}\n"
        f"ExecMainStartTimestampMonotonic={monotonic_us}\n"
        f"ExecMainStartTimestamp={calendar}\n"
    )
    return out.encode(), start


@pytest.fixture
def systemd(monkeypatch):
    """Fake `systemctl` and `snap get`. Tests set `.show`, `.snap_args`, `.restart_fails`."""
    sd = SimpleNamespace(show=show()[0], snap_args=None, calls=[], restart_fails=False)

    def check_output(cmd, *args, **kwargs):
        if cmd[0] == "systemctl":
            return sd.show
        if cmd[:2] == ["snap", "get"]:
            if sd.snap_args is None:
                raise subprocess.CalledProcessError(1, cmd)
            return sd.snap_args.encode()
        raise AssertionError(f"unexpected command {cmd}")

    def check_call(cmd, *args, **kwargs):
        sd.calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "restart"] and sd.restart_fails:
            raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(ks, "check_output", check_output)
    monkeypatch.setattr(ks, "check_call", check_call)
    return sd


def restarted(sd):
    return ["systemctl", "restart", UNIT] in sd.calls


def snap_set_calls(sd):
    return [c for c in sd.calls if c[:2] == ["snap", "set"]]


# --- write_if_changed -------------------------------------------------------


def test_write_if_changed_identical_content_leaves_file_untouched(tmp_path):
    f = tmp_path / "f"
    f.write_text("same")
    f.chmod(0o600)
    os.utime(f, (1000, 1000))
    before = f.stat()

    assert ks.write_if_changed(f, "same") is False
    assert ks.write_if_changed(f, b"same") is False

    after = f.stat()
    assert (after.st_ino, after.st_mtime, stat_mode(after)) == (
        before.st_ino,
        1000,
        0o600,
    )


def stat_mode(st):
    return st.st_mode & 0o777


def test_write_if_changed_different_content_writes_in_place(tmp_path):
    f = tmp_path / "f"
    f.write_text("old")
    f.chmod(0o600)
    inode = f.stat().st_ino

    assert ks.write_if_changed(f, "new") is True

    assert f.read_text() == "new"
    assert f.stat().st_ino == inode
    assert stat_mode(f.stat()) == 0o600


def test_write_if_changed_creates_file_and_encodes_utf8(tmp_path):
    f = tmp_path / "f"
    assert ks.write_if_changed(f, "\u00fcber") is True
    assert f.read_bytes() == "\u00fcber".encode("utf-8")


def test_write_if_changed_does_not_create_parent_directories(tmp_path):
    with pytest.raises(FileNotFoundError):
        ks.write_if_changed(tmp_path / "missing" / "f", "x")


# --- restart_reason ---------------------------------------------------------


@pytest.mark.parametrize(
    "state, started_ago, expected",
    [
        ("inactive", 100.0, "inactive"),
        ("failed", 100.0, "failed"),
        ("active", None, "never started"),
        ("activating", None, None),
        ("reloading", None, None),
        ("deactivating", None, None),
        ("active", 100.0, None),
    ],
)
def test_restart_reason_by_service_state(systemd, state, started_ago, expected):
    systemd.show, _ = show(state=state, started_ago=started_ago)
    assert ks.restart_reason(UNIT) == expected


@pytest.mark.parametrize(
    "offset, expected",
    [
        (-50.0, None),  # written long before the service started
        (-0.020, None),  # older than the 10 ms margin
        (-0.005, "input newer than service start"),  # inside the margin
        (+1.0, "input newer than service start"),
    ],
)
def test_restart_reason_compares_input_with_start_time(
    systemd, tmp_path, offset, expected
):
    systemd.show, start = show()
    f = tmp_path / "input"
    f.write_text("x")
    os.utime(f, (start + offset, start + offset))
    assert ks.restart_reason(UNIT, [f]) == expected


def test_restart_reason_activating_service_restarts_for_newer_input(systemd, tmp_path):
    systemd.show, start = show(state="activating")
    f = tmp_path / "input"
    f.write_text("x")
    os.utime(f, (start + 1, start + 1))
    assert ks.restart_reason(UNIT, [f]) == "input newer than service start"


@pytest.mark.parametrize(
    "started_ago, calendar_ago",
    [(10.0, 3600.0), (3600.0, 10.0)],
)
def test_restart_reason_uses_the_earlier_start_time(
    systemd, tmp_path, started_ago, calendar_ago
):
    systemd.show, _ = show(started_ago=started_ago, calendar_ago=calendar_ago)
    f = tmp_path / "input"
    f.write_text("x")
    thirty_minutes_ago = time.time() - 1800
    os.utime(f, (thirty_minutes_ago, thirty_minutes_ago))
    # Newer than the 1 hour old start time, older than the 10 second old one.
    assert ks.restart_reason(UNIT, [f]) == "input newer than service start"


def test_restart_reason_skips_missing_and_non_regular_inputs(systemd, tmp_path):
    systemd.show, _ = show()
    directory = tmp_path / "dir"
    directory.mkdir()
    assert ks.restart_reason(UNIT, [tmp_path / "missing", directory]) is None


def test_restart_reason_reloads_systemd_when_unit_definition_changed(systemd):
    systemd.show, _ = show(state="inactive", reload="yes")
    assert ks.restart_reason(UNIT) == "unit definition changed"
    assert systemd.calls == [["systemctl", "daemon-reload"]]


def test_restart_reason_future_mtime_is_set_to_now_with_one_warning(
    systemd, tmp_path, caplog
):
    systemd.show, _ = show()
    f = tmp_path / "input"
    f.write_text("x")
    future = time.time() + 3600
    os.utime(f, (future, future))

    assert ks.restart_reason(UNIT, [f]) == "input newer than service start"
    assert ks.restart_reason(UNIT, [f]) == "input newer than service start"

    assert f.stat().st_mtime < time.time() + 5
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1 and "future" in warnings[0].getMessage()


def test_restart_reason_raises_when_systemctl_show_fails(monkeypatch):
    def failing(cmd, *args, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(ks, "check_output", failing)
    with pytest.raises(subprocess.CalledProcessError):
        ks.restart_reason(UNIT)


def test_restart_reason_logs_one_line_per_call(systemd, caplog):
    caplog.set_level("INFO")
    systemd.show, _ = show()
    ks.restart_reason(UNIT)
    systemd.show, _ = show(state="inactive")
    ks.restart_reason(UNIT)
    assert caplog.messages == [f"{UNIT}: no change", f"{UNIT}: inactive"]


# --- configure_kubernetes_service -------------------------------------------


def arg_string(**args):
    return " ".join(f'--{k}="{v}"' for k, v in args.items())


def test_matching_arguments_restart_nothing_even_when_the_audit_log_grows(
    systemd, tmp_path
):
    config = tmp_path / "config.yaml"
    config.write_text("x")
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("one")
    base = {"v": "2", "config": str(config), "audit-log-path": str(audit_log)}
    systemd.snap_args = arg_string(**base) + "\n"  # `snap get` ends with a newline
    systemd.show, start = show()
    os.utime(config, (start - 50, start - 50))

    for _ in range(2):
        audit_log.write_text("appended")  # newer than the service start
        ks.configure_kubernetes_service("kube-apiserver", base, "")

    assert systemd.calls == []


def test_changed_arguments_set_and_restart(systemd, caplog):
    caplog.set_level("INFO")
    systemd.snap_args = arg_string(v="2")

    ks.configure_kubernetes_service("kube-apiserver", {"v": "2"}, "v=5 extra")

    assert snap_set_calls(systemd) == [
        ["snap", "set", "kube-apiserver", 'args=--v="5" --extra="true"']
    ]
    assert restarted(systemd)
    assert f"{UNIT}: arguments changed" in caplog.messages


def test_snap_get_failure_logs_a_warning_then_sets_and_restarts(systemd, caplog):
    systemd.snap_args = None
    ks.configure_kubernetes_service("kube-apiserver", {"v": "2"}, "")
    assert len(snap_set_calls(systemd)) == 1
    assert restarted(systemd)
    assert any(
        r.levelname == "WARNING" and "snap get" in r.getMessage()
        for r in caplog.records
    )


def test_newer_input_file_restarts_without_snap_set(systemd, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("x")
    base = {"config": str(config)}
    systemd.snap_args = arg_string(**base)
    systemd.show, start = show()
    os.utime(config, (start + 1, start + 1))

    ks.configure_kubernetes_service("kube-apiserver", base, "")

    assert snap_set_calls(systemd) == []
    assert restarted(systemd)


def test_older_input_file_does_not_restart(systemd, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("x")
    base = {"config": str(config)}
    systemd.snap_args = arg_string(**base)
    systemd.show, start = show()
    os.utime(config, (start - 50, start - 50))

    ks.configure_kubernetes_service("kube-apiserver", base, "")

    assert systemd.calls == []


def test_explicit_inputs_are_checked(systemd, tmp_path):
    cert = tmp_path / "cert"
    cert.write_text("x")
    systemd.snap_args = arg_string(v="2")
    systemd.show, start = show()
    os.utime(cert, (start + 1, start + 1))

    ks.configure_kubernetes_service(
        "kube-apiserver", {"v": "2"}, "", inputs=[cert, None]
    )

    assert restarted(systemd)


def test_service_inputs_use_merged_values_of_library_keys_only(tmp_path):
    kept, overridden, extra_only = (tmp_path / n for n in ("kept", "over", "extra"))
    for f in (kept, overridden, extra_only):
        f.write_text("x")
    directory = tmp_path / "dir"
    directory.mkdir()
    base = {
        "kept": str(kept),
        "overridden": "/does/not/exist",
        "audit-log-path": str(kept),
        "relative": "relative/path",
        "directory": str(directory),
        "missing": str(tmp_path / "missing"),
        "number": "5",
    }
    merged = {**base, "overridden": str(overridden), "extra-flag": str(extra_only)}

    assert ks._service_inputs(base, merged) == [str(kept), str(overridden)]


def test_pending_daemon_reload_runs_even_when_arguments_changed(systemd):
    systemd.snap_args = arg_string(v="1")
    systemd.show, _ = show(reload="yes")

    ks.configure_kubernetes_service("kube-apiserver", {"v": "2"}, "")

    assert ["systemctl", "daemon-reload"] in systemd.calls
    assert restarted(systemd)


def test_failed_restart_is_blocked_and_retried_on_the_next_call(systemd, caplog):
    unit = mock.MagicMock()
    systemd.snap_args = arg_string(v="2")
    systemd.show, _ = show(state="inactive")
    systemd.restart_fails = True

    with status.context(unit), pytest.raises(status.ReconcilerError):
        ks.configure_kubernetes_service("kube-apiserver", {"v": "2"}, "")
    assert unit.status == BlockedStatus("Failed to restart Kubernetes services")
    assert any(UNIT in m and "restart failed" in m for m in caplog.messages)

    systemd.restart_fails = False
    systemd.calls.clear()
    ks.configure_kubernetes_service("kube-apiserver", {"v": "2"}, "")
    assert restarted(systemd)


def test_logs_never_contain_argument_values(systemd, caplog):
    caplog.set_level("DEBUG")
    secret = {"token": "s3cr3t-token-value"}
    systemd.snap_args = None
    ks.configure_kubernetes_service("kube-apiserver", secret, "")  # changed path
    systemd.snap_args = arg_string(**secret)
    ks.configure_kubernetes_service("kube-apiserver", secret, "")  # unchanged path
    assert "s3cr3t-token-value" not in caplog.text


# --- configure_* pass the inputs the service reads --------------------------


@mock.patch("charms.kubernetes_snaps.Path")
@mock.patch("charms.kubernetes_snaps.write_if_changed")
@mock.patch("charms.kubernetes_snaps.configure_kubernetes_service")
def test_kubelet_inputs_come_from_its_merged_config(configure, write, mock_path):
    cloud = mock.MagicMock(has_xcp=False)
    ks.configure_kubelet(
        "endpoint", "domain", "dns", "", {"tlsCertFile": "/custom/server.crt"},
        cloud, "kubeconfig", "node_ip", "registry.io", [],
    )  # fmt: skip
    assert configure.call_args.kwargs["inputs"] == [
        "/root/cdk/ca.crt",
        "/custom/server.crt",
        "/root/cdk/server.key",
    ]


@mock.patch("charms.kubernetes_snaps.os.makedirs")
@mock.patch("charms.kubernetes_snaps.write_if_changed")
@mock.patch("charms.kubernetes_snaps.configure_kubernetes_service")
def test_kube_proxy_input_is_the_kubeconfig_named_in_its_config(
    configure, write, makedirs
):
    cloud = mock.MagicMock(has_xcp=False)
    ks.configure_kube_proxy("", "", {}, "/root/cdk/kubeproxyconfig", cloud)
    assert configure.call_args.kwargs["inputs"] == ["/root/cdk/kubeproxyconfig"]


# --- install() --------------------------------------------------------------


def snap_list(tracking):
    """Fake `snap list <name>`; `tracking` maps snap -> Tracking column or None (missing)."""

    def check_output(cmd, *args, **kwargs):
        assert cmd[:2] == ["snap", "list"]
        value = tracking[cmd[2]]
        if value is None:
            raise subprocess.CalledProcessError(1, cmd)
        return (
            "Name  Version  Rev   Tracking  Publisher  Notes\n"
            f"{cmd[2]}  1.35.10  1234  {value}  canonical**  classic\n"
        ).encode()

    return check_output


@pytest.fixture
def install_env(monkeypatch):
    install_snap = mock.MagicMock()
    monkeypatch.setattr(ks, "is_channel_available", lambda *a: True)
    monkeypatch.setattr(ks, "is_channel_swap", lambda *a: False)
    monkeypatch.setattr(ks, "install_snap", install_snap)
    return install_snap


def run_install(monkeypatch, tracking, **kwargs):
    monkeypatch.setattr(ks, "check_output", snap_list(tracking))
    with status.context(mock.MagicMock()):
        ks.install("1.35/stable", control_plane=True, **kwargs)


ALL_SNAPS = ks.BASIC_SNAPS + ks.CONTROL_PLANE_SNAPS


def test_install_skips_snaps_already_tracking_the_channel(monkeypatch, install_env):
    run_install(monkeypatch, {s: "1.35/stable" for s in ALL_SNAPS})
    install_env.assert_not_called()


@pytest.mark.parametrize("tracking", ["1.34/stable", "1.35/candidate", "-", None])
def test_install_refreshes_only_the_snap_that_needs_it(
    monkeypatch, install_env, tracking
):
    states = {s: "1.35/stable" for s in ALL_SNAPS}
    states["kube-proxy"] = tracking
    run_install(monkeypatch, states)
    install_env.assert_called_once_with(
        "kube-proxy", channel="1.35/stable", classic=True, ignore_running=False
    )


def test_install_upgrade_refreshes_every_snap(monkeypatch, install_env):
    run_install(monkeypatch, {s: "1.35/stable" for s in ALL_SNAPS}, upgrade=True)
    assert [c.args[0] for c in install_env.call_args_list] == ALL_SNAPS
    kubectl = install_env.call_args_list[0]
    assert (
        kubectl.kwargs["ignore_running"] is True and kubectl.kwargs["classic"] is True
    )


def test_install_snap_still_refreshes_when_called_directly(monkeypatch):
    calls = []
    monkeypatch.setattr(ks, "call", lambda *a, **k: 0)  # snap is installed
    monkeypatch.setattr(ks, "check_call", lambda cmd, *a, **k: calls.append(cmd))
    with status.context(mock.MagicMock()):
        ks.install_snap("cdk-addons", "1.35/stable")
    assert calls == [["snap", "refresh", "cdk-addons", "--channel", "1.35/stable"]]


# --- update_kubeconfig ------------------------------------------------------


def test_update_kubeconfig_with_unchanged_content_leaves_the_file_alone(tmp_path):
    path = tmp_path / "kubeconfig"
    ks.create_kubeconfig(path, "ca", "https://1.1.1.1", "user", "token")
    os.utime(path, (1000, 1000))
    before = path.stat()

    ks.update_kubeconfig(path, ca="ca", token="token")

    after = path.stat()
    assert (after.st_ino, after.st_mtime) == (before.st_ino, 1000)
    assert not (tmp_path / "kubeconfig.new").exists()


def test_update_kubeconfig_with_new_content_replaces_the_file(tmp_path):
    path = tmp_path / "kubeconfig"
    ks.create_kubeconfig(path, "ca", "https://1.1.1.1", "user", "token")
    ks.update_kubeconfig(path, token="other-token")
    assert "other-token" in path.read_text()
    assert not (tmp_path / "kubeconfig.new").exists()
