import ipaddress
import json
import logging
import os
from base64 import b64encode
from pathlib import Path
from socket import gethostname

import charms.contextual_status as status
import yaml
from ops import BlockedStatus, MaintenanceStatus
from subprocess import call, CalledProcessError, check_call, check_output, DEVNULL

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
    api_opts[
        "kubelet-preferred-address-types"
    ] = "InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP"
    # TODO: encryption at rest
    # api_opts["encryption-provider-config"] = str(encryption_config_path())

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

    # TODO: cloud provider config
    """
    api_cloud_config_path = cloud_config_path("kube-apiserver")
    if has_external_cloud_provider():
        api_opts["cloud-provider"] = "external"
    elif is_state("endpoint.aws.ready"):
        if kube_version < (1, 27, 0):
            api_opts["cloud-provider"] = "aws"
        else:
            hookenv.log(
                "AWS cloud-provider is no longer available in-tree. "
                "the out-of-tree provider is necessary",
                level="WARNING",
            )
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        api_opts["cloud-provider"] = "gce"
        api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version:
            api_opts["cloud-provider"] = "vsphere"
            api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")
    elif is_state("endpoint.azure.ready"):
        api_opts["cloud-provider"] = "azure"
        api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")
    """

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
    cluster_cidr, cluster_name, extra_args_config, kubeconfig, service_cidr
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

    # TODO: cloud config
    """
    cm_cloud_config_path = cloud_config_path("kube-controller-manager")
    if has_external_cloud_provider():
        controller_opts["cloud-provider"] = "external"
    elif is_state("endpoint.aws.ready"):
        if kube_version < (1, 27, 0):
            controller_opts["cloud-provider"] = "aws"
        else:
            hookenv.log(
                "AWS cloud-provider is no longer available in-tree. "
                "the out-of-tree provider is necessary",
                level="WARNING",
            )
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        controller_opts["cloud-provider"] = "gce"
        controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version:
            controller_opts["cloud-provider"] = "vsphere"
            controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")
    elif is_state("endpoint.azure.ready"):
        controller_opts["cloud-provider"] = "azure"
        controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")
    """

    controller_opts["feature-gates"] = ",".join(feature_gates)

    configure_kubernetes_service(
        "kube-controller-manager",
        controller_opts,
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

    feature_gates = []

    # TODO: cloud config
    """
    if is_state("endpoint.aws.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.azure.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")
    """

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


def get_node_name():
    return gethostname().lower()


def get_public_address():
    cmd = ["unit-get", "public-address"]
    return check_output(cmd).decode("UTF-8").strip()


def get_sandbox_image(registry) -> str:
    # Try to track upstream version if possible, see for example:
    # https://github.com/kubernetes/kubernetes/blob/v1.28.1/build/dependencies.yaml#L175
    return f"{registry}/pause:3.9"


@status.on_error(BlockedStatus("Failed to install Kubernetes snaps"))
def install(channel, control_plane=False):
    """Install or refresh Kubernetes snaps. This includes the basic snaps to
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
    """Install or refresh a snap"""
    status.add(MaintenanceStatus(f"Installing {name} snap"))

    is_refresh = is_snap_installed(name)

    cmd = ["snap", "refresh" if is_refresh else "install", name, "--channel", channel]

    if classic:
        cmd.append("--classic")

    if is_refresh and ignore_running:
        cmd.append("--ignore-running")

    check_call(cmd)


def is_snap_installed(name):
    """Return True if the given snap is installed, otherwise False."""
    cmd = ["snap", "list", name]
    return call(cmd, stdout=DEVNULL, stderr=DEVNULL) == 0


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
        dest = cni_conf_dir / "01-default." + cni_conf_file.split(".")[-1]
        dest.symlink_to(cni_conf_file)


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
