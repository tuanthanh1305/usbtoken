"""Test guard fail-safe của chính sách Phụ lục I/II."""

from __future__ import annotations

import pytest

from core.errors import PolicyNotConfiguredError
from core.trust.policy import CompliancePolicy


def test_policy_not_configured_by_default() -> None:
    # Phụ lục I/II ở trạng thái not_filled -> chưa cấu hình.
    pol = CompliancePolicy()
    assert pol.is_configured is False
    assert pol.status().appendix_i_filled is False
    assert pol.status().appendix_ii_filled is False


def test_require_configured_raises() -> None:
    with pytest.raises(PolicyNotConfiguredError):
        CompliancePolicy().require_configured()


def test_accessing_appendix_values_blocked() -> None:
    # Không được đọc tham số Phụ lục khi chưa điền (fail-safe).
    with pytest.raises(PolicyNotConfiguredError):
        CompliancePolicy().allowed_signature_algorithms()
