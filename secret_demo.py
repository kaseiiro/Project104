"""
secret.py

Private fixed parameters for ResponseGenerator.
Keep this file out of version control if these values are confidential.
"""

################################ DEMO ONLY ################################
### cp secret_demo.py secret.py
### fill in the actual data
### before usage!
############################################################################

RESPONSE_GENERATOR_CONFIG = {

    "register_width": 47,

    # Physical cell numbers: 1..register_width
    "linear_taps": (
        1,
        5,
        12,
        47,
    ),

    # Physical cell numbers: 1..register_width
    # Grouped as:
    #   NAND(a, b) XOR NAND(c, d) XOR NAND(e, f)
    "nonlinear_taps": (
        2, 4,
        6, 7,
        13, 18,
    ),

    "latch_event_period": 80,
    "response_bit_period": 160,
    
}

MASTER_KEY = "0011223344556677 7766554433221100"

