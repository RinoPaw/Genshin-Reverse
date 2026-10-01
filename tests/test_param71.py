from genshinre.param71 import decode_parameter_record, parameter_key


def test_parameter_decoder_matches_confirmed_handler_anchors() -> None:
    cases = [
        # DoSetPlayerBornDataNotify / ONKOPMILDMF
        (243_673, "5cb5d991fca4d250", 0xA065255E, 248_305, 0x0B186E6D),
        # PlayerNicknameNotify / PGAMFBPNNIC
        (243_763, "5dbc88e8f99b2308", 0xD9342C63, 248_269, 0x0B186E6D),
        # SetPlayerNameRsp / OBOADLPIEPL
        (243_933, "a18489c42881221c", 0xF53514AB, 248_313, 0x0B18B3F4),
    ]

    for index, raw_hex, expected_key, expected_type, expected_name_token in cases:
        decoded = decode_parameter_record(bytes.fromhex(raw_hex), index)
        assert parameter_key(index) == expected_key
        assert decoded["key"] == expected_key
        assert decoded["type_index"] == expected_type
        assert decoded["name_token"] == expected_name_token


def test_parameter_decoder_rejects_truncated_record() -> None:
    try:
        decode_parameter_record(b"\x00" * 7, 0)
    except ValueError as exc:
        assert "truncated" in str(exc)
    else:
        raise AssertionError("expected truncated parameter record to be rejected")
