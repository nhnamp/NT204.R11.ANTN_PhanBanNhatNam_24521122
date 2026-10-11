"""Tests for the TCP state machine: one case per row of the transition table."""

import pytest

from ids.stages.flow import FlowTracker, first_step, next_step

F, B = "forward", "backward"
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


@pytest.mark.parametrize(
    ("flags", "direction", "state", "fin_directions"),
    [
        (["SYN"], F, "HANDSHAKE", ()),
        (["SYN", "ACK"], B, "HANDSHAKE", ()),
        (["SYN", "RST"], F, "HANDSHAKE", ()),
        (["RST"], F, "RESET", ()),
        (["RST", "FIN"], F, "RESET", ()),
        (["FIN", "ACK"], B, "CLOSING", (B,)),
        (["ACK"], F, "ESTABLISHED", ()),
        (["PSH", "ACK"], B, "ESTABLISHED", ()),
        ([], F, "ESTABLISHED", ()),
    ],
)
def test_the_first_packet_sets_the_first_state(flags: list[str], direction: str, state: str, fin_directions: tuple) -> None:
    assert first_step(flags, direction) == (state, fin_directions, False)


@pytest.mark.parametrize(
    ("row", "state", "flags", "direction", "fin_directions", "expected", "expected_fins", "restart"),
    [
        (1, "CLOSING", ["SYN"], F, (F,), "CLOSING", (F,), True),
        (1, "CLOSED", ["SYN"], B, (F, B), "CLOSED", (F, B), True),
        (1, "RESET", ["SYN"], F, (), "RESET", (), True),
        (2, "CLOSED", ["SYN", "ACK"], B, (F, B), "CLOSED", (F, B), False),
        (2, "HANDSHAKE", ["SYN", "ACK"], B, (), "HANDSHAKE", (), False),
        (2, "HANDSHAKE", ["SYN"], F, (), "HANDSHAKE", (), False),
        (2, "ESTABLISHED", ["SYN"], F, (), "ESTABLISHED", (), False),
        (3, "ESTABLISHED", ["RST"], B, (), "RESET", (), False),
        (3, "CLOSING", ["RST"], F, (F,), "RESET", (F,), False),
        (3, "HANDSHAKE", ["RST", "ACK"], B, (), "RESET", (), False),
        (4, "CLOSED", ["RST"], F, (F, B), "CLOSED", (F, B), False),
        (4, "CLOSED", ["RST", "ACK"], B, (F, B), "CLOSED", (F, B), False),
        (5, "ESTABLISHED", ["FIN"], F, (), "CLOSING", (F,), False),
        (5, "HANDSHAKE", ["FIN", "ACK"], B, (), "CLOSING", (B,), False),
        (6, "CLOSING", ["FIN", "ACK"], B, (F,), "CLOSING", (F, B), False),
        (6, "CLOSING", ["FIN", "ACK"], F, (F,), "CLOSING", (F,), False),
        (6, "CLOSING", ["FIN"], F, (F, B), "CLOSING", (F, B), False),
        (7, "HANDSHAKE", ["ACK"], F, (), "ESTABLISHED", (), False),
        (7, "HANDSHAKE", ["PSH", "ACK"], B, (), "ESTABLISHED", (), False),
        (8, "CLOSING", ["ACK"], F, (F, B), "CLOSED", (F, B), False),
        (8, "CLOSING", ["ACK"], B, (F, B), "CLOSING", (F, B), False),
        (9, "CLOSING", ["PSH"], F, (F, B), "CLOSING", (F, B), False),
        (9, "CLOSING", ["ACK"], B, (F,), "CLOSING", (F,), False),
        (9, "CLOSING", ["ACK"], F, (F,), "CLOSING", (F,), False),
        (9, "ESTABLISHED", ["PSH", "ACK"], F, (), "ESTABLISHED", (), False),
        (9, "ESTABLISHED", [], B, (), "ESTABLISHED", (), False),
        (9, "HANDSHAKE", [], F, (), "HANDSHAKE", (), False),
        (9, "CLOSED", ["FIN", "ACK"], F, (F, B), "CLOSED", (F, B), False),
        (9, "CLOSED", ["ACK"], F, (F, B), "CLOSED", (F, B), False),
        (9, "RESET", ["ACK"], B, (), "RESET", (), False),
        (9, "RESET", ["FIN"], F, (), "RESET", (), False),
    ],
)
def test_a_packet_follows_the_first_matching_row(
    row: int, state: str, flags: list[str], direction: str, fin_directions: tuple, expected: str, expected_fins: tuple, restart: bool
) -> None:
    assert next_step(state, flags, direction, fin_directions) == (expected, expected_fins, restart)


def _flow_after(*packets: tuple[str, list[str]]) -> dict:
    """Send packets as (side, flags). Side "c" is the client and "s" is the server."""
    tracker = FlowTracker()
    for number, (side, flags) in enumerate(packets):
        source, destination = (CLIENT, SERVER) if side == "c" else (SERVER, CLIENT)
        tracker.update({
            "protocol": "TCP", "src_ip": source[0], "src_port": source[1], "dst_ip": destination[0],
            "dst_port": destination[1], "tcp_flags": flags, "timestamp": 1758441600.0 + number,
            "length": 60, "app_protocol": "UNKNOWN", "detection_method": None,
        })
    (flow,) = tracker.flush()
    return flow


THREE_WAY_HANDSHAKE = [("c", ["SYN"]), ("s", ["SYN", "ACK"]), ("c", ["ACK"])]


@pytest.mark.parametrize(
    ("packets", "expected"),
    [
        pytest.param(THREE_WAY_HANDSHAKE[:2], "HANDSHAKE", id="handshake not finished"),
        pytest.param(THREE_WAY_HANDSHAKE, "ESTABLISHED", id="handshake"),
        pytest.param([("s", ["SYN", "ACK"]), ("c", ["ACK"])], "ESTABLISHED", id="capture starts at the SYN/ACK"),
        pytest.param([("c", ["PSH", "ACK"]), ("s", ["ACK"])], "ESTABLISHED", id="capture starts in the middle"),
        pytest.param([("c", [])], "ESTABLISHED", id="first packet without flags"),
        pytest.param(
            THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"])],
            "CLOSED", id="close with four packets",
        ),
        pytest.param(
            THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"])],
            "CLOSED", id="close with three packets",
        ),
        pytest.param([("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"])], "CLOSED", id="capture starts at the FIN"),
        pytest.param(THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"])], "CLOSING", id="no ACK of the last FIN"),
        pytest.param(
            THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"]), ("s", ["ACK"])],
            "CLOSED", id="simultaneous FIN",
        ),
        pytest.param(
            THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["PSH", "ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"])],
            "CLOSED", id="half-close with data after the first FIN",
        ),
        pytest.param(THREE_WAY_HANDSHAKE + [("s", ["RST", "ACK"]), ("c", ["ACK"])], "RESET", id="reset"),
        pytest.param(
            THREE_WAY_HANDSHAKE + [("c", ["FIN", "ACK"]), ("s", ["FIN", "ACK"]), ("c", ["ACK"]), ("s", ["RST"])],
            "CLOSED", id="reset after a clean close",
        ),
    ],
)
def test_a_packet_sequence_ends_in_the_expected_state(packets: list, expected: str) -> None:
    assert _flow_after(*packets)["state"] == expected


def test_a_flow_that_starts_in_the_middle_counts_no_syn() -> None:
    flow = _flow_after(("c", ["PSH", "ACK"]), ("s", ["ACK"]))

    assert (flow["state"], flow["syn_count"]) == ("ESTABLISHED", 0)


def test_a_later_syn_on_an_established_flow_is_counted_and_keeps_the_state() -> None:
    flow = _flow_after(("c", ["PSH", "ACK"]), ("s", ["ACK"]), ("c", ["SYN"]))

    assert (flow["state"], flow["syn_count"], flow["packet_count"]) == ("ESTABLISHED", 1, 3)


def test_the_handshake_counts_two_syn_and_two_ack() -> None:
    flow = _flow_after(*THREE_WAY_HANDSHAKE)

    assert (flow["syn_count"], flow["ack_count"]) == (2, 2)
