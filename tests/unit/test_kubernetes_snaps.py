import pytest
import unittest.mock as mock


from charms import kubernetes_snaps


@pytest.fixture(autouse=True)
def subprocess_check_output():
    with mock.patch("charms.kubernetes_snaps.check_output") as mock_run:
        yield mock_run


@pytest.fixture(autouse=True)
def subprocess_call():
    with mock.patch("charms.kubernetes_snaps.call") as mock_run:
        yield mock_run


@mock.patch.object(kubernetes_snaps, "is_channel_swap", return_value=False)
@mock.patch.object(kubernetes_snaps, "is_channel_available", return_value=True)
@mock.patch.object(kubernetes_snaps, "install_snap", mock.MagicMock())
def test_upgrade_action_control_plane(is_channel_available, is_channel_swap, caplog):
    mock_event = mock.MagicMock()
    channel = "1.28/edge"
    kubernetes_snaps.upgrade_snaps(channel, mock_event, control_plane=True)
    snaps = kubernetes_snaps.BASIC_SNAPS + kubernetes_snaps.CONTROL_PLANE_SNAPS
    is_channel_available.assert_has_calls([mock.call(s, channel) for s in snaps])
    is_channel_swap.assert_has_calls([mock.call(s, channel) for s in snaps])
    assert (
        f"Starting the upgrade of Kubernetes snaps to '{channel}' channel."
        in caplog.messages
    )
    assert (
        f"Successfully upgraded Kubernetes snaps to the '{channel}' channel."
        in caplog.messages
    )


def test_is_snap_available(subprocess_check_output):
    snap_info = """
name:      my-snap
publisher: Canonical✓
channels:
  latest/stable:    --
  1.29/stable:   1.29.0  2024-01-03 (22606) 12MB -
"""
    subprocess_check_output.return_value = snap_info.encode()
    assert not kubernetes_snaps.is_channel_available("my-snap", "latest/stable")
    assert not kubernetes_snaps.is_channel_available("my-snap", "1.30/stable")
    assert kubernetes_snaps.is_channel_available("my-snap", "1.29/stable")


def test_is_channel_swap(subprocess_call, subprocess_check_output):
    snap_list = """
Name     Version       Rev    Tracking       Publisher   Notes
my-snap  1.29.0        22606  1.29/stable    canonical✓  -
"""
    subprocess_call.return_value = 0
    subprocess_check_output.return_value = snap_list.encode()
    assert kubernetes_snaps.is_channel_swap("my-snap", "1.28/stable")
    assert not kubernetes_snaps.is_channel_swap("my-snap", "1.29/stable")
    assert kubernetes_snaps.is_channel_swap("my-snap", "1.30/stable")


@pytest.fixture(params=[None, "external"])
def external_cloud(request):
    cloud = mock.MagicMock()
    cloud.has_xcp = request.param == "external"
    cloud.in_tree.return_value = {}
    yield cloud


def test_create_kubeconfig(tmp_path):
    path = tmp_path / "kubeconfig"
    created = kubernetes_snaps.create_kubeconfig(
        path, "ca-data", "https://192.168.0.1", "test-user", "test-token"
    )
    assert created == path
    assert created.exists()
    assert (created.stat().st_mode & 0o777) == 0o600
    text = created.read_text()
    assert "Y2EtZGF0YQ==" in text
    assert "https://192.168.0.1" in text
    assert "test-user" in text
    assert "test-token" in text

    updated = kubernetes_snaps.update_kubeconfig(path, "new-ca-data")
    assert updated == path
    assert updated.exists()
    assert (updated.stat().st_mode & 0o777) == 0o600
    text = updated.read_text()
    assert "bmV3LWNhLWRhdGE=" in text
    assert "https://192.168.0.1" in text
    assert "test-user" in text
    assert "test-token" in text


def test_update_kubeconfig_no_file(tmp_path):
    path = tmp_path / "kubeconfig"
    nothing = kubernetes_snaps.update_kubeconfig(path)
    assert not nothing.exists()

    with pytest.raises(FileNotFoundError):
        kubernetes_snaps.update_kubeconfig(nothing, ca="new-ca-data")


@mock.patch("charms.kubernetes_snaps.configure_kubernetes_service")
@mock.patch("charms.kubernetes_snaps.Path")
def test_configure_kubelet(
    mock_path,
    configure_kubernetes_service,
    external_cloud,
):
    kubernetes_snaps.configure_kubelet(
        "container_runtime_endpoint",
        "dns_domain",
        "dns_ip",
        {},
        {},
        external_cloud,
        "kubeconfig",
        "node_ip",
        "registry.io",
        ["taint:NoExecute"],
    )
    configure_kubernetes_service.assert_called_once()
    service, args, extra = configure_kubernetes_service.call_args[0]
    assert service == "kubelet"
    assert extra == {}
    expected_args = {
        "kubeconfig": "kubeconfig",
        "v": "0",
        "node-ip": "node_ip",
        "container-runtime-endpoint": "container_runtime_endpoint",
        "hostname-override": kubernetes_snaps.get_node_name(),
        "config": "/root/cdk/kubelet/config.yaml",
        **external_cloud.in_tree.return_value,
    }
    if external_cloud.has_xcp:
        expected_args["cloud-provider"] = "external"
    assert expected_args == args
