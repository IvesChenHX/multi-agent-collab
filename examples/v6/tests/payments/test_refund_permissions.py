from backend.payments.refund_service import can_refund


def test_unauthorized_user_cannot_refund() -> None:
    assert can_refund(set()) is False


def test_authorized_user_can_refund() -> None:
    assert can_refund({"payment.refund"}) is True
