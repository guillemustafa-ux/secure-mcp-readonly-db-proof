import pytest

from secure_mcp.params import DateParam, EnumParam, IntParam, ParamError, TextParam, validate_params

SPECS = {
    "customer_id": IntParam(1, 1000),
    "status": EnumParam(("open", "paid")),
}


def test_valid_params_pass_through():
    assert validate_params(SPECS, {"customer_id": 7, "status": "open"}) == {"customer_id": 7, "status": "open"}


@pytest.mark.parametrize(
    "supplied, message",
    [
        ({"customer_id": 7}, "missing"),
        ({"customer_id": 7, "status": "open", "limit": 10_000}, "unknown"),
        ({"customer_id": "7", "status": "open"}, "integer"),
        ({"customer_id": True, "status": "open"}, "integer"),  # bool is an int in Python
        ({"customer_id": 7.0, "status": "open"}, "integer"),
        ({"customer_id": 0, "status": "open"}, "between"),
        ({"customer_id": 7, "status": "open' OR '1'='1"}, "one of"),
        (["customer_id", 7], "object"),
    ],
)
def test_invalid_params_are_rejected(supplied, message):
    with pytest.raises(ParamError, match=message):
        validate_params(SPECS, supplied)


def test_text_length_and_pattern():
    spec = {"q": TextParam(5, r"[a-z]+")}
    assert validate_params(spec, {"q": "abc"}) == {"q": "abc"}
    with pytest.raises(ParamError, match="characters"):
        validate_params(spec, {"q": "ab;c"})
    with pytest.raises(ParamError, match="1 to 5"):
        validate_params(spec, {"q": "abcdef"})
    with pytest.raises(ParamError, match="1 to 5"):
        validate_params(spec, {"q": ""})


@pytest.mark.parametrize("value", ["2026-02-30", "2026-2-1", "yesterday", 20260101, "1999-12-31"])
def test_bad_dates_are_rejected(value):
    with pytest.raises(ParamError):
        validate_params({"d": DateParam()}, {"d": value})
