"""Template for auth_unit_structure.py."""


RESPONSE_GENERATOR_CONFIG = {
    "register_width": 47,

    # Physical register cells: 1..register_width
    "linear_taps": (6, 10, 14, 22, 36, 40, 43, 47),
    "nonlinear_taps": ((3, 9), (26, 33), (35, 40)),

    "latch_event_period": 45,
    "response_bit_period": 160,
}
