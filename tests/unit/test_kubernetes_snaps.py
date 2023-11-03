from dataclasses import dataclass
from ops.framework import Framework
import os
import pytest
import unittest.mock as mock

import ops
import ops.testing

from charms import kubernetes_snaps


@pytest.fixture
def subprocess_check_output():
    with mock.patch("charms.kubernetes_snaps.check_output") as mock_run:
        yield mock_run



def test_upgrade_action_control_plane(caplog):
    mock_event = mock.MagicMock()
    with mock.patch.object(kubernetes_snaps, 'is_upgrade', return_value=False):
        with mock.patch.object(kubernetes_snaps, 'install_snap'):
            kubernetes_snaps.upgrade_snaps("1.28/edge", mock_event, control_plane=True)
    assert "Starting the upgrade of Kubernetes snaps to '1.28/edge' channel." in caplog.messages
    assert "Successfully upgraded Kubernetes snaps to the '1.28/edge' channel." in caplog.messages