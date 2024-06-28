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
    service, args, extra = configure_kubernetes_service.call_args[0]
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
        "enable-admission-plugins": "PersistentVolumeLabel,NodeRestriction",
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
    if external_cloud.has_xcp:
        expected_args["cloud-provider"] = "external"
    assert expected_args == args
