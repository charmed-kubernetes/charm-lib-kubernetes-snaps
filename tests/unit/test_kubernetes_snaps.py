import logging
import pytest
import yaml
import unittest.mock as mock

from charms import kubernetes_snaps
import charms.contextual_status as status


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
    with status.context(mock_event.model.unit):
        kubernetes_snaps.upgrade_snaps(channel, mock_event, control_plane=True)
    snaps = kubernetes_snaps.BASIC_SNAPS + kubernetes_snaps.CONTROL_PLANE_SNAPS
    is_channel_available.assert_has_calls([mock.call(s, channel) for s in snaps])
    is_channel_swap.assert_has_calls([mock.call(s, channel) for s in snaps])
    assert f"Starting the upgrade of Kubernetes snaps to {channel}." in caplog.messages
    assert (
        f"Successfully upgraded Kubernetes snaps to the {channel}." in caplog.messages
    )
    mock_event.set_results.assert_called_once()
    mock_event.fail.assert_not_called()


@mock.patch.object(kubernetes_snaps, "is_channel_swap", return_value=False)
@mock.patch.object(kubernetes_snaps, "is_channel_available", return_value=False)
@mock.patch.object(kubernetes_snaps, "install_snap", mock.MagicMock())
def test_upgrade_action_control_plane_fails_available(
    is_channel_available, is_channel_swap, caplog
):
    mock_event = mock.MagicMock()
    channel = "1.28/edge"
    with status.context(mock_event.model.unit):
        kubernetes_snaps.upgrade_snaps(channel, mock_event, control_plane=True)
    snaps = kubernetes_snaps.BASIC_SNAPS + kubernetes_snaps.CONTROL_PLANE_SNAPS
    is_channel_available.assert_has_calls([mock.call(s, channel) for s in snaps])
    is_channel_swap.assert_not_called()
    assert "Starting the upgrade of Kubernetes snaps to" in caplog.messages[0]
    assert "The following snaps do not have a revision on channel" in caplog.messages[1]
    assert "Upgrade failed with a detectable error" in caplog.messages[2]
    mock_event.fail.assert_called_once()
    mock_event.set_results.assert_not_called()


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
    text = created.read_text()
    assert "Y2EtZGF0YQ==" in text
    assert "https://192.168.0.1" in text
    assert "test-user" in text
    assert "test-token" in text

    updated = kubernetes_snaps.update_kubeconfig(path, "new-ca-data")
    assert updated == path
    assert updated.exists()
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
        "/path/to/kubeconfig",
        "node_ip",
        "registry.io",
        ["taint:NoExecute"],
    )
    configure_kubernetes_service.assert_called_once()
    service, args, extra, config_files = configure_kubernetes_service.call_args[0]
    assert service == "kubelet"
    assert extra == {}
    expected_args = {
        "kubeconfig": "/path/to/kubeconfig",
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
    assert config_files == {
        "/path/to/kubeconfig",
        "/root/cdk/ca.crt",
        "/root/cdk/kubelet/config.yaml",
        "/root/cdk/server.crt",
        "/root/cdk/server.key",
        "/run/systemd/resolve/resolv.conf",
    }


@mock.patch("charms.kubernetes_snaps.configure_kubernetes_service")
@mock.patch("charms.kubernetes_snaps.Path")
def test_configure_apiserver(mock_path, configure_kubernetes_service, external_cloud):
    mock_path().__truediv__().__str__.return_value = "/some/path"
    kubernetes_snaps.configure_apiserver(
        "advertise_address",
        "audit_policy",
        "audit_webhook_conf",
        "auth_webhook_conf",
        "Node,RBAC,Webhook",
        "ignored",
        "https://1.1.1.1,https://1.1.1.2",
        {},
        "false",
        "10.10.10.0/24",
        external_cloud,
        None,
    )
    configure_kubernetes_service.assert_called_once()
    service, args, extra, config_files = configure_kubernetes_service.call_args[0]
    assert service == "kube-apiserver"
    assert extra == {}
    expected_args = {
        "allow-privileged": "true",
        "service-cluster-ip-range": "10.10.10.0/24",
        "min-request-timeout": "300",
        "v": "4",
        "tls-cert-file": "/root/cdk/server.crt",
        "tls-private-key-file": "/root/cdk/server.key",
        "tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "kubelet-certificate-authority": "/root/cdk/ca.crt",
        "kubelet-client-certificate": "/root/cdk/client.crt",
        "kubelet-client-key": "/root/cdk/client.key",
        "storage-backend": "etcd3",
        "profiling": "false",
        "anonymous-auth": "false",
        "authentication-token-webhook-cache-ttl": "1m0s",
        "authentication-token-webhook-config-file": "auth_webhook_conf",
        "service-account-issuer": "https://kubernetes.default.svc",
        "service-account-signing-key-file": "/root/cdk/serviceaccount.key",
        "service-account-key-file": "/root/cdk/serviceaccount.key",
        "kubelet-preferred-address-types": "InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP",
        "encryption-provider-config": "/some/path",
        "advertise-address": "advertise_address",
        "etcd-cafile": "/root/cdk/etcd/client-ca.pem",
        "etcd-keyfile": "/root/cdk/etcd/client-key.pem",
        "etcd-certfile": "/root/cdk/etcd/client-cert.pem",
        "etcd-servers": "https://1.1.1.1,https://1.1.1.2",
        "authorization-mode": "Node,RBAC",
        "enable-admission-plugins": "NodeRestriction",
        "requestheader-client-ca-file": "/root/cdk/ca.crt",
        "requestheader-allowed-names": "system:kube-apiserver,client",
        "requestheader-extra-headers-prefix": "X-Remote-Extra-",
        "requestheader-group-headers": "X-Remote-Group",
        "requestheader-username-headers": "X-Remote-User",
        "proxy-client-cert-file": "/root/cdk/client.crt",
        "proxy-client-key-file": "/root/cdk/client.key",
        "enable-aggregator-routing": "true",
        "client-ca-file": "/root/cdk/ca.crt",
        "feature-gates": "",
        "audit-log-path": "/some/path",
        "audit-log-maxage": "30",
        "audit-log-maxsize": "100",
        "audit-log-maxbackup": "10",
        "audit-policy-file": "/some/path",
        "audit-webhook-config-file": "/some/path",
    }
    assert "/root/cdk/ca.crt" in config_files
    if external_cloud.has_xcp:
        expected_args["cloud-provider"] = "external"
    assert expected_args == args


@mock.patch("pathlib.Path.exists", mock.MagicMock(return_value=True))
@mock.patch("charms.kubernetes_snaps.check_call")
@mock.patch("charms.kubernetes_snaps.service_restart")
def test_configure_kubernetes_service_same_config(service_restart, check_call, caplog):
    caplog.set_level(logging.DEBUG)
    log_message = "Test: No config changes detected"
    base_args = {"arg1": "val1", "arg2": "val2"}
    extra_args = "arg2=val2-updated arg3=val3"
    hashed = {
        "arg1": "cc1d9c865e8380c2d566dc724c66369051acfaa3e9e8f36ad6c67d7d9b8461a5",  # val1
        "arg2": "05a202bd2f507925efc418afec49c00c5904bb532f5b59588dd1cb76773c5075",  # val2-updated
        "arg3": "bac8d4414984861d5199b7a97699c728bee36c4084299b2ca905434cf65d8944",  # val3
    }
    yamlized = yaml.safe_dump(hashed)
    with mock.patch(
        "pathlib.Path.open", mock.mock_open(read_data=yamlized)
    ) as mock_open:
        kubernetes_snaps.configure_kubernetes_service("test", base_args, extra_args)
    mock_open.assert_called_once()
    service_restart.assert_not_called()
    check_call.assert_not_called()
    assert log_message in caplog.text


@mock.patch("pathlib.Path.exists", mock.MagicMock(return_value=True))
@mock.patch("charms.kubernetes_snaps.check_call")
@mock.patch("charms.kubernetes_snaps.service_restart")
@pytest.mark.parametrize(
    "extra_args, log_message",
    [
        ("arg2=val2-updated", "Test: Dropped config value arg3"),
        (
            "arg2=val2-updated arg3=val3 arg4=val4",
            "Test: Added config value arg4",
        ),
        (
            "arg2=val2-updated arg3=val3-updated",
            "Test: Updated config value arg3",
        ),
    ],
    ids=["drop_key", "add_key", "update_key"],
)
def test_configure_kubernetes_service_difference(
    service_restart, check_call, extra_args, log_message, caplog
):
    caplog.set_level(logging.DEBUG)
    base_args = {"arg1": "val1", "arg2": "val2"}
    hashed = {
        "arg1": "cc1d9c865e8380c2d566dc724c66369051acfaa3e9e8f36ad6c67d7d9b8461a5",
        "arg2": "05a202bd2f507925efc418afec49c00c5904bb532f5b59588dd1cb76773c5075",  # val2-updated
        "arg3": "bac8d4414984861d5199b7a97699c728bee36c4084299b2ca905434cf65d8944",  # val3
    }
    yamlized = yaml.safe_dump(hashed)
    with mock.patch(
        "pathlib.Path.open", mock.mock_open(read_data=yamlized)
    ) as mock_open:
        with mock.patch("yaml.safe_dump") as safe_dump:
            kubernetes_snaps.configure_kubernetes_service("test", base_args, extra_args)
    service_restart.assert_called_once_with("snap.test.daemon")
    check_call.assert_called_once()
    mock_open.assert_has_calls([mock.call(), mock.call("w")], any_order=True)
    safe_dump.assert_called_once()
    assert log_message in caplog.text


@mock.patch("pathlib.Path.exists")
def test_sha256_file(mock_exists):
    # Non Existent file
    mock_exists.return_value = False
    hash = kubernetes_snaps._sha256_file("/path/to/file/1").hexdigest()
    assert hash == "8054b8176bf428f030f0fb8b62ca2c26cf0b983196cfe97358cfb1e206aa9d75"

    # Non Existent file with a different name
    mock_exists.return_value = False
    hash = kubernetes_snaps._sha256_file("/path/to/file/2").hexdigest()
    assert hash == "f337cf841ac045041455bff9cc3f2e0b8a2a5bf5dfe44a0152be04e4fc2355b5"

    # Existing file with same name but empty
    mock_exists.return_value = True
    with mock.patch("pathlib.Path.open", mock.mock_open(read_data=b"")):
        hash = kubernetes_snaps._sha256_file("/path/to/file/2").hexdigest()
    assert hash == "8d6fb329915afba8724a741f422894e127217854fe1934679e50d2115c2c3ca6"

    # Existing file with same name with data
    mock_exists.return_value = True
    with mock.patch("pathlib.Path.open", mock.mock_open(read_data=b"data")):
        hash = kubernetes_snaps._sha256_file("/path/to/file/2").hexdigest()
    assert hash == "63699fd3e47d9eb242fe6763bc387a9f3f6d1ae3f08bf7a7c437cec51ce2d0c4"
