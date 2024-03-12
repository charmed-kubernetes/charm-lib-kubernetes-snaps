import ipaddress
import json
import logging
import os
import re
from base64 import b64encode
from pathlib import Path
from socket import getfqdn, gethostname
from subprocess import DEVNULL, CalledProcessError, call, check_call, check_output
from typing import Optional, Protocol
from ops import ActionEvent

import yaml
from ops import BlockedStatus, MaintenanceStatus
from packaging import version

import charms.contextual_status as status


class ExternalCloud(Protocol):
    """Definition of what attributes are available from external-cloud."""

    has_xcp: bool
    name: Optional[str]


log = logging.getLogger(__name__)
service_account_key_path = Path("/root/cdk/serviceaccount.key")
tls_ciphers_intermediate = [
    # https://wiki.mozilla.org/Security/Server_Side_TLS
    # https://ssl-config.mozilla.org/#server=go&config=intermediate
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
]


BASIC_SNAPS = ["kubectl", "kubelet", "kube-proxy"]
CONTROL_PLANE_SNAPS = [
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "cdk-addons",
]


def _snap_common_path(component) -> Path:
    return Path("/var/snap/{}/common".format(component))


def encryption_config_path() -> Path:
    return _snap_common_path("kube-apiserver") / "encryption/encryption_config.yaml"


def configure_apiserver(
    advertise_address,
    audit_policy,
    audit_webhook_conf,
    auth_webhook_conf,
    authorization_mode,
    cluster_cidr,
    etcd_connection_string,
    extra_args_config,
    privileged,
    service_cidr,
    external_cloud_provider: ExternalCloud,
):
    api_opts = {}
    feature_gates = []

    api_opts["allow-privileged"] = "true" if privileged else "false"
    api_opts["service-cluster-ip-range"] = service_cidr
    api_opts["min-request-timeout"] = "300"
    api_opts["v"] = "4"
    api_opts["tls-cert-file"] = "/root/cdk/server.crt"
    api_opts["tls-private-key-file"] = "/root/cdk/server.key"
    api_opts["tls-cipher-suites"] = ",".join(tls_ciphers_intermediate)
    api_opts["kubelet-certificate-authority"] = "/root/cdk/ca.crt"
    api_opts["kubelet-client-certificate"] = "/root/cdk/client.crt"
    api_opts["kubelet-client-key"] = "/root/cdk/client.key"
    api_opts["storage-backend"] = "etcd3"
    api_opts["profiling"] = "false"
    api_opts["anonymous-auth"] = "false"
    api_opts["authentication-token-webhook-cache-ttl"] = "1m0s"
    api_opts["authentication-token-webhook-config-file"] = auth_webhook_conf
    api_opts["service-account-issuer"] = "https://kubernetes.default.svc"
    api_opts["service-account-signing-key-file"] = str(service_account_key_path)
    api_opts["service-account-key-file"] = str(service_account_key_path)
    api_opts["kubelet-preferred-address-types"] = (
        "InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP"
    )
    enc_provider_config = encryption_config_path()
    if enc_provider_config.exists():
        api_opts["encryption-provider-config"] = str(enc_provider_config)

    api_opts["advertise-address"] = advertise_address

    api_opts["etcd-cafile"] = "/root/cdk/etcd/client-ca.pem"
    api_opts["etcd-keyfile"] = "/root/cdk/etcd/client-key.pem"
    api_opts["etcd-certfile"] = "/root/cdk/etcd/client-cert.pem"
    api_opts["etcd-servers"] = etcd_connection_string

    # In Kubernetes 1.10 and later, some admission plugins are enabled by
    # default. The current list of default plugins can be found at
    # https://bit.ly/2meP9XT, listed under the '--enable-admission-plugins'
    # option.
    #
    # The list below need only include the plugins we want to enable
    # in addition to the defaults.
    admission_plugins = [
        "PersistentVolumeLabel",
        "NodeRestriction",
    ]

    # TODO: keystone authz
    """
    ks = endpoint_from_flag("keystone-credentials.available")
    if ks:
        ks_ip = get_service_ip("k8s-keystone-auth-service", errors_fatal=False)
        if ks_ip:
            os.makedirs(keystone_root, exist_ok=True)

            keystone_webhook = keystone_root + "/webhook.yaml"
            context = {}
            context["keystone_service_cluster_ip"] = ks_ip
            render("keystone-api-server-webhook.yaml", keystone_webhook, context)

            if hookenv.config("enable-keystone-authorization"):
                # if user wants authorization, enable it
                if "Webhook" not in authorization_mode:
                    authorization_mode += ",Webhook"
                api_opts["authorization-webhook-config-file"] = keystone_webhook  # noqa
            set_state("keystone.apiserver.configured")
        else:
            hookenv.log("Unable to find k8s-keystone-auth-service. Will retry")
            # Note that we can get into a nasty state here
            # if the user has specified webhook and they're relying on
            # keystone auth to handle that, the api server will fail to
            # start because we push it Webhook and no webhook config.
            # We can't generate the config because we can't talk to the
            # apiserver to get the ip of the service to put into the
            # webhook template. A chicken and egg problem. To fix this,
            # remove Webhook if keystone is related and trying to come
            # up until we can find the service IP.
            if "Webhook" in authorization_mode:
                authorization_mode = ",".join(
                    [i for i in authorization_mode.split(",") if i != "Webhook"]
                )
            remove_state("keystone.apiserver.configured")
    elif is_state("leadership.set.keystone-cdk-addons-configured"):
        hookenv.log("Keystone endpoint not found, will retry.")
    """

    api_opts["authorization-mode"] = authorization_mode
    api_opts["enable-admission-plugins"] = ",".join(admission_plugins)

    api_opts["requestheader-client-ca-file"] = "/root/cdk/ca.crt"
    api_opts["requestheader-allowed-names"] = "system:kube-apiserver,client"
    api_opts["requestheader-extra-headers-prefix"] = "X-Remote-Extra-"
    api_opts["requestheader-group-headers"] = "X-Remote-Group"
    api_opts["requestheader-username-headers"] = "X-Remote-User"
    api_opts["proxy-client-cert-file"] = "/root/cdk/client.crt"
    api_opts["proxy-client-key-file"] = "/root/cdk/client.key"
    api_opts["enable-aggregator-routing"] = "true"
    api_opts["client-ca-file"] = "/root/cdk/ca.crt"

    if external_cloud_provider.has_xcp:
        log.info("KubeApi: Uses an External Cloud Provider")
        api_opts["cloud-provider"] = "external"
    else:
        log.info("KubeApi: No Cloud Features")

    api_opts["feature-gates"] = ",".join(feature_gates)

    audit_root = "/root/cdk/audit"
    audit_log_path = audit_root + "/audit.log"
    audit_policy_path = audit_root + "/audit-policy.yaml"
    audit_webhook_conf_path = audit_root + "/audit-webhook-config.yaml"
    os.makedirs(audit_root, exist_ok=True)

    api_opts["audit-log-path"] = audit_log_path
    api_opts["audit-log-maxage"] = "30"
    api_opts["audit-log-maxsize"] = "100"
    api_opts["audit-log-maxbackup"] = "10"

    if audit_policy:
        with open(audit_policy_path, "w") as f:
            f.write(audit_policy)
        api_opts["audit-policy-file"] = audit_policy_path
    else:
        remove_if_exists(audit_policy_path)

    if audit_webhook_conf:
        with open(audit_webhook_conf_path, "w") as f:
            f.write(audit_webhook_conf)
        api_opts["audit-webhook-config-file"] = audit_webhook_conf_path
    else:
        remove_if_exists(audit_webhook_conf_path)

    configure_kubernetes_service("kube-apiserver", api_opts, extra_args_config)


def configure_controller_manager(
    cluster_cidr,
    cluster_name,
    extra_args_config,
    kubeconfig,
    service_cidr,
    external_cloud_provider: ExternalCloud,
):
    controller_opts = {}

    controller_opts["min-resync-period"] = "3m"
    controller_opts["v"] = "2"
    controller_opts["root-ca-file"] = "/root/cdk/ca.crt"
    controller_opts["kubeconfig"] = kubeconfig
    controller_opts["authorization-kubeconfig"] = kubeconfig
    controller_opts["authentication-kubeconfig"] = kubeconfig
    controller_opts["use-service-account-credentials"] = "true"
    controller_opts["service-account-private-key-file"] = str(service_account_key_path)
    controller_opts["tls-cert-file"] = "/root/cdk/server.crt"
    controller_opts["tls-private-key-file"] = "/root/cdk/server.key"
    controller_opts["cluster-name"] = cluster_name
    controller_opts["terminated-pod-gc-threshold"] = "12500"
    controller_opts["profiling"] = "false"
    controller_opts["service-cluster-ip-range"] = service_cidr
    if cluster_cidr:
        controller_opts["cluster-cidr"] = cluster_cidr
    feature_gates = ["RotateKubeletServerCertificate=true"]

    if external_cloud_provider.has_xcp:
        log.info("KubeController: Uses an External Cloud Provider")
        controller_opts["cloud-provider"] = "external"
    else:
        log.info("KubeController: No Cloud Features")

    controller_opts["feature-gates"] = ",".join(feature_gates)

    configure_kubernetes_service(
        "kube-controller-manager",
        controller_opts,
        extra_args_config,
    )


def configure_kernel_parameters(params):
    if host_is_container():
        log.info("LXD detected, faking kernel params via bind mounts")
        workaround_lxd_kernel_params()
        return

    conf_file = "\n".join(f"{key} = {value}" for key, value in sorted(params.items()))

    dest = "/etc/sysctl.d/50-kubernetes-charm.conf"
    with open(dest, "w") as f:
        f.write(conf_file)

    check_call(["sysctl", "-p", dest])


def configure_kube_proxy(
    cluster_cidr,
    extra_args_config,
    extra_config,
    kubeconfig,
    external_cloud_provider: ExternalCloud,
):
    fqdn = external_cloud_provider.name == "aws" and external_cloud_provider.has_xcp
    kube_proxy_config = {
        "kind": "KubeProxyConfiguration",
        "apiVersion": "kubeproxy.config.k8s.io/v1alpha1",
        "clientConnection": {
            "kubeconfig": kubeconfig,
        },
        "hostnameOverride": get_node_name(fqdn),
    }
    if cluster_cidr:
        kube_proxy_config["clusterCIDR"] = cluster_cidr

    if host_is_container():
        kube_proxy_config["conntrack"] = {"maxPerCore": 0}

    kube_proxy_opts = {"config": "/root/cdk/kubeproxy/config.yaml", "v": "0"}

    # Add proxy-extra-config. This needs to happen last so that it
    # overrides any config provided by the charm.
    merge_extra_config(kube_proxy_config, extra_config)

    os.makedirs("/root/cdk/kubeproxy", exist_ok=True)
    with open("/root/cdk/kubeproxy/config.yaml", "w") as f:
        f.write("# Generated by kubernetes-common library, do not edit\n")
        yaml.dump(kube_proxy_config, f)

    configure_kubernetes_service(
        "kube-proxy",
        kube_proxy_opts,
        extra_args_config,
    )


def configure_kubelet(
    container_runtime_endpoint,
    dns_domain,
    dns_ip,
    extra_args_config,
    extra_config,
    external_cloud_provider: ExternalCloud,
    kubeconfig,
    node_ip,
    registry,
    taints,
):
    """Configures the kublet args and config file based on current relations.

    Configures command-line and config file arguments
    https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
    https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

    @param dns_domain: See `clusterDomain` the DNS domain for this cluster
    @param dns_ip: See `clusterDNS` IP addresses for the cluster DNS server
    @param registry: pre-1.27, used in the image for `pod-infra-container-image`
    @param taints: See `registerWithTaints`
           Array of taints to add to a node object when registering this node
    @param external_cloud_provider: relation to an external cloud provider
    """
    kubelet_config = {
        "apiVersion": "kubelet.config.k8s.io/v1beta1",
        "kind": "KubeletConfiguration",
        "address": "0.0.0.0",
        "authentication": {
            "anonymous": {"enabled": False},
            "x509": {"clientCAFile": "/root/cdk/ca.crt"},
        },
        # NB: authz webhook config tells the kubelet to ask the api server
        # if a request is authorized; it is not related to the authn
        # webhook config of the k8s control-plane services.
        "authorization": {"mode": "Webhook"},
        "clusterDomain": dns_domain,
        "failSwapOn": False,
        "port": 10250,
        "protectKernelDefaults": True,
        "readOnlyPort": 0,
        "tlsCertFile": "/root/cdk/server.crt",
        "tlsPrivateKeyFile": "/root/cdk/server.key",
    }
    if dns_ip:
        kubelet_config["clusterDNS"] = [dns_ip]
    if taints:
        kubelet_config["registerWithTaints"] = [
            v1_taint_from_string(taint) for taint in taints
        ]

    # Workaround for DNS on bionic and newer
    # https://github.com/juju-solutions/bundle-canonical-kubernetes/issues/655
    resolv_path = os.path.realpath("/etc/resolv.conf")
    if resolv_path == "/run/systemd/resolve/stub-resolv.conf":
        kubelet_config["resolvConf"] = "/run/systemd/resolve/resolv.conf"
    fqdn = external_cloud_provider.name == "aws" and external_cloud_provider.has_xcp

    kubelet_opts = {}
    kubelet_opts["kubeconfig"] = kubeconfig
    kubelet_opts["v"] = "0"
    kubelet_opts["node-ip"] = node_ip
    kubelet_opts["container-runtime-endpoint"] = container_runtime_endpoint
    kubelet_opts["hostname-override"] = get_node_name(fqdn)
    kubelet_opts["config"] = "/root/cdk/kubelet/config.yaml"
    if external_cloud_provider.has_xcp:
        log.info("Kubelet: Uses an External Cloud Provider")
        kubelet_opts["cloud-provider"] = "external"
    else:
        log.info("Kubelet: No Cloud Features")

    # Add kubelet-extra-config. This needs to happen last so that it
    # overrides any config provided by the charm.
    merge_extra_config(kubelet_config, extra_config)

    p = Path("/root/cdk/kubelet/config.yaml")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        f.write("# Generated by charm, do not edit\n")
        yaml.dump(kubelet_config, f)

    configure_kubernetes_service(
        "kubelet",
        kubelet_opts,
        extra_args_config,
    )


def configure_kubernetes_service(service, base_args, extra_args_config):
    extra_args = parse_extra_args(extra_args_config)

    args = {}
    args.update(base_args)
    args.update(extra_args)

    # TODO: CIS arg handling???
    # CIS benchmark action may inject kv config to pass failing tests. Merge
    # these after the func args as they should take precedence.
    # cis_args_key = "cis-" + service
    # cis_args = db.get(cis_args_key) or {}
    # args.update(cis_args)

    # Remove any args with 'None' values (all k8s args are 'k=v') and
    # construct an arg string for use by 'snap set'.
    args = {k: v for k, v in args.items() if v is not None}
    args = ['--%s="%s"' % arg for arg in args.items()]
    args = " ".join(args)

    cmd = ["snap", "set", service, f"args={args}"]
    check_call(cmd)
    service_restart(f"snap.{service}.daemon")


def configure_scheduler(extra_args_config, kubeconfig):
    kube_scheduler_config_path = "/root/cdk/kube-scheduler-config.yaml"
    scheduler_opts = {}

    scheduler_opts["v"] = "2"
    scheduler_opts["config"] = kube_scheduler_config_path
    scheduler_opts["authorization-kubeconfig"] = kubeconfig
    scheduler_opts["authentication-kubeconfig"] = kubeconfig

    feature_gates = []

    scheduler_opts["feature-gates"] = ",".join(feature_gates)
    scheduler_config = {
        "kind": "KubeSchedulerConfiguration",
        "clientConnection": {"kubeconfig": kubeconfig},
    }

    scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1"
    scheduler_config.update(
        enableContentionProfiling=False,
        enableProfiling=False,
    )

    with open(kube_scheduler_config_path, "w") as f:
        yaml.safe_dump(scheduler_config, f)

    configure_kubernetes_service("kube-scheduler", scheduler_opts, extra_args_config)


def configure_services_restart_always(control_plane=False):
    services = ["kubelet", "kube-proxy"]
    if control_plane:
        services += ["kube-apiserver", "kube-controller-manager", "kube-scheduler"]

    for service in services:
        dest_dir = f"/etc/systemd/system/snap.{service}.daemon.service.d"
        os.makedirs(dest_dir, exist_ok=True)
        with open(dest_dir + "/always-restart.conf", "w") as f:
            f.write(
                """[Unit]
StartLimitIntervalSec=0

[Service]
RestartSec=10"""
            )

    check_call(["systemctl", "daemon-reload"])


def create_kubeconfig(dest, ca, server, user, token):
    ca_base64 = b64encode(ca.encode("utf-8")).decode("utf-8")
    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "cluster": {"certificate-authority-data": ca_base64, "server": server},
                "name": "juju-cluster",
            }
        ],
        "contexts": [
            {
                "context": {"cluster": "juju-cluster", "user": user},
                "name": "juju-context",
            }
        ],
        "current-context": "juju-context",
        "preferences": {},
        "users": [{"name": user, "user": {"token": token}}],
    }

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    # Write to temp file so we can replace dest atomically
    temp_dest = dest + ".new"
    with open(temp_dest, "w") as f:
        yaml.safe_dump(kubeconfig, f)
    os.replace(temp_dest, dest)


def create_service_account_key():
    dest = service_account_key_path
    dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not dest.exists():
        cmd = ["openssl", "genrsa", "-out", str(dest), "2048"]
        check_call(cmd)
    return dest.read_text()


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
    return [next(network.hosts()).exploded for network in networks]


def get_node_name(fqdn=False):
    if fqdn:
        return getfqdn().lower()
    return gethostname().lower()


def get_public_address():
    cmd = ["unit-get", "public-address"]
    return check_output(cmd).decode("UTF-8").strip()


def get_sandbox_image(registry) -> str:
    # Try to track upstream version if possible, see for example:
    # https://github.com/kubernetes/kubernetes/blob/v1.28.1/build/dependencies.yaml#L175
    return f"{registry}/pause:3.9"


def get_snap_version(name: str) -> str:
    """
    Get the version of an installed snap package.

    Args:
    name (str): The name of the snap package.

    Returns:
    str or None: The version of the snap package if available, otherwise None.
    """
    cmd = ["snap", "list", name]
    result = check_output(cmd)
    output = result.decode().strip()
    match = re.search(r"\b\d+(?:\.\d+)*\b", output)

    if match:
        return match.group()
    else:
        log.info(f"Package '{name}' not found or no version available.")
    return None


def host_is_container():
    return call(["systemd-detect-virt", "--container"]) == 0


@status.on_error(BlockedStatus("Failed to install Kubernetes snaps"))
def install(channel, control_plane=False, upgrade=False):
    """Install or refresh Kubernetes snaps. This includes the basic snaps to
    talk to Kubernetes and run a Kubernetes node.

    Args:
        - channel (str): The snap channel to install from.
        - control_plane (bool, optional): If True, installs the Kubernetes control
        plane snaps. Defaults to False.
        - upgrade (bool, optional): If True, allows upgrading of snaps. Defaults to
        False.
    """
    which_snaps = BASIC_SNAPS + CONTROL_PLANE_SNAPS if control_plane else BASIC_SNAPS

    if missing := {s for s in which_snaps if not is_channel_available(s, channel)}:
        log.warning(
            "The following snaps do not have a revision on channel=%s: %s",
            channel,
            ",".join(sorted(missing)),
        )
        status.add(BlockedStatus(f"Not all snaps are available on channel={channel}"))
        return

    if any(is_channel_swap(snap, channel) for snap in which_snaps) and not upgrade:
        status.add(BlockedStatus("Needs manual upgrade, run the upgrade action."))
        return

    # Refresh with ignore_running=True ONLY for non-daemon apps (i.e. kubectl)
    # https://bugs.launchpad.net/bugs/1987331
    for snap in BASIC_SNAPS:
        install_snap(
            snap,
            channel=channel,
            classic=True,
            ignore_running=snap == "kubectl",
        )

    if control_plane:
        for snap in CONTROL_PLANE_SNAPS:
            install_snap(snap, channel=channel)


def install_snap(name: str, channel: str, classic=False, ignore_running=False):
    """Install or refresh a snap"""
    status.add(MaintenanceStatus(f"Installing {name} snap"))

    is_refresh = is_snap_installed(name)

    cmd = ["snap", "refresh" if is_refresh else "install", name, "--channel", channel]

    if classic:
        cmd.append("--classic")

    if is_refresh and ignore_running:
        cmd.append("--ignore-running")

    check_call(cmd)


def is_channel_available(snap_name: str, target_channel: str) -> bool:
    """
    Check if the target channel exists for a given snap.

    Args:
    snap_name (str): The name of the snap package.
    target_channel (str): The target channel to find.

    Returns:
    bool: True if snap channel contains a revision, False otherwise.
    """
    cmd = ["snap", "info", snap_name]
    result = check_output(cmd)
    output = yaml.safe_load(result)
    channels = output.get("channels", {})
    target = channels.get(target_channel, None)
    return target and target != "--"


def is_snap_installed(snap_name) -> bool:
    """Return True if the given snap is installed, otherwise False."""
    cmd = ["snap", "list", snap_name]
    return call(cmd, stdout=DEVNULL, stderr=DEVNULL) == 0


def is_channel_swap(snap_name: str, target_channel: str) -> bool:
    """
    Check if the installed version is not than the target channel version.

    Args:
    snap_name (str): Then name of the snap package.
    target_channel (str): The target channel to compare against.

    Returns:
    bool: True if an upgrade is needed, False otherwise.
    """
    is_refresh = is_snap_installed(snap_name)

    if is_refresh and (installed_version := get_snap_version(snap_name)):
        channel_version, *_ = target_channel.split("/")
        current = version.parse(installed_version)
        target = version.parse(channel_version)
        return (current.major, current.minor) != (target.major, target.minor)
    return False


is_upgrade = is_channel_swap


def merge_extra_config(config, extra_config):
    """Updates config to include the contents of extra_config. This is done
    recursively to allow deeply nested dictionaries to be merged.

    This is destructive: it modifies the config dict that is passed in.
    """
    for k, extra_config_value in extra_config.items():
        if isinstance(extra_config_value, dict):
            config_value = config.setdefault(k, {})
            merge_extra_config(config_value, extra_config_value)
        else:
            config[k] = extra_config_value


def parse_extra_args(extra_args_str):
    elements = extra_args_str.split()
    args = {}

    for element in elements:
        if "=" in element:
            key, _, value = element.partition("=")
            args[key] = value
        else:
            args[element] = "true"

    return args


def remove_if_exists(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def service_restart(name):
    cmd = ["systemctl", "restart", name]
    call(cmd)


def set_default_cni_conf_file(cni_conf_file):
    """Set the default CNI configuration to be used by CNI clients
    (kubelet, containerd).

    CNI clients choose whichever CNI config in /etc/cni/net.d/ is
    alphabetically first, so we accomplish this by creating a file named
    /etc/cni/net.d/01-default.conflist, which is alphabetically earlier than
    typical CNI config names, e.g. 10-flannel.conflist and 10-calico.conflist

    The created 01-default.conflist file is a symlink to whichever CNI config
    is actually going to be used.
    """
    cni_conf_dir = Path("/etc/cni/net.d")
    cni_conf_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Clean up current default
    for filename in cni_conf_dir.iterdir():
        if filename.stem == "01-default":
            filename.unlink()
    # Set new default if specified
    if cni_conf_file:
        ext = cni_conf_file.split(".")[-1]
        dest = cni_conf_dir / f"01-default.{ext}"
        dest.symlink_to(cni_conf_file)


def upgrade_snaps(channel: str, event: ActionEvent, control_plane: bool = False):
    log.info(f"Starting the upgrade of Kubernetes snaps to '{channel}' channel.")
    try:
        install(channel=channel, control_plane=control_plane, upgrade=True)
    except (CalledProcessError, Exception) as e:
        if isinstance(e, CalledProcessError):
            error_message = f"Upgrade failed with a process error. stdout: {e.stdout}, stderr: {e.stderr}"
        else:
            error_message = f"An unexpected error occurred during the upgrade: {e}"

        log.exception(error_message)
        status.add("Snap upgrade failed. Check action results for more information.")
        event.fail(error_message)
    else:
        result_message = (
            f"Successfully upgraded Kubernetes snaps to the '{channel}' channel."
        )
        log.info(result_message)
        event.set_results({"result": result_message})


def v1_taint_from_string(taint: str):
    """
    Create a taint object from given string.

    Schema defined here
    https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#taint-v1-core
    format:  key[=value]:effect
    """
    try:
        head, effect = taint.split(":")  # only 1 ':' may exist in the string
    except ValueError:
        err_msg = f"taint {taint} must have a single colon (':')"
        log.error(err_msg)
        raise ValueError(err_msg)

    key, *value = head.split("=")  # optionally, only 1 "=" may exist in the string
    valid_effects = {"NoSchedule", "PreferNoSchedule", "NoExecute"}

    err_msg = None
    if effect not in valid_effects:
        err_msg = f"taint {taint} effect may only be in {', '.join(valid_effects)}"
    elif len(value) > 1:
        err_msg = f"taint {taint} may have only a single equals ('=')"

    if err_msg:
        log.error(err_msg)
        raise ValueError(err_msg)

    obj = {"key": key, "effect": effect}
    if value:
        obj["value"] = value[0]
    return obj


def workaround_lxd_kernel_params():
    """
    Workaround for kubelet not starting in LXD when kernel params are not set
    to the desired values.
    """
    root_dir = "/root/cdk/lxd-kernel-params"
    os.makedirs(root_dir, exist_ok=True)
    Path("/etc/fstab").touch(mode=0o644, exist_ok=True)
    # Kernel params taken from:
    # https://github.com/kubernetes/kubernetes/blob/v1.22.0/pkg/kubelet/cm/container_manager_linux.go#L421-L426
    # https://github.com/kubernetes/kubernetes/blob/v1.22.0/pkg/util/sysctl/sysctl.go#L30-L64
    params = {
        "vm.overcommit_memory": 1,
        "vm.panic_on_oom": 0,
        "kernel.panic": 10,
        "kernel.panic_on_oops": 1,
        "kernel.keys.root_maxkeys": 1000000,
        "kernel.keys.root_maxbytes": 1000000 * 25,
    }

    with open("/etc/fstab") as f:
        fstab = f.read()

    fstab_lines = [
        line
        for line in fstab.splitlines()
        if not line.lstrip().startswith("/root/cdk/lxd-kernel-params/")
    ]

    for param, param_value in params.items():
        fake_param_path = root_dir + "/" + param
        with open(fake_param_path, "w") as f:
            f.write(str(param_value))
        real_param_path = "/proc/sys/" + param.replace(".", "/")
        fstab_lines.append(f"{fake_param_path} {real_param_path} none bind")

    with open("/etc/fstab", "w") as f:
        f.write("\n".join(fstab_lines))

    check_call(["mount", "-a"])


def write_certificates(ca, client_cert, client_key, server_cert, server_key):
    cert_dir = "/root/cdk"
    os.makedirs(cert_dir, exist_ok=True)

    with open(cert_dir + "/ca.crt", "w") as f:
        f.write(ca)
    with open(cert_dir + "/server.crt", "w") as f:
        f.write(server_cert)
    with open(cert_dir + "/server.key", "w") as f:
        f.write(server_key)
    with open(cert_dir + "/client.crt", "w") as f:
        f.write(client_cert)
    with open(cert_dir + "/client.key", "w") as f:
        f.write(client_key)


def write_etcd_client_credentials(ca, cert, key):
    cert_dir = "/root/cdk/etcd"
    os.makedirs(cert_dir, exist_ok=True)

    with open(cert_dir + "/client-ca.pem", "w") as f:
        f.write(ca)
    with open(cert_dir + "/client-cert.pem", "w") as f:
        f.write(cert)
    with open(cert_dir + "/client-key.pem", "w") as f:
        f.write(key)


def write_service_account_key(key: str) -> None:
    dest = service_account_key_path
    dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    dest.write_text(key)
