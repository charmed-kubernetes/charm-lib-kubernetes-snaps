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
