"""
example_usage.py

Minimal runnable example for ResponseGenerator.

Edit the secret.py file and run:

    python example_usage.py

Tap numbering is physical and uniform:
    LINEAR_TAPS    : 1..WIDTH
    NONLINEAR_TAPS : 1..WIDTH

DATA is bytes.
The returned response is bytes with the correct bit order already applied.
No output-side bit reversal is required.
"""

from Cryptodome.Cipher import DES3
from secret import RESPONSE_GENERATOR_CONFIG, MASTER_KEY
from response_generator import ResponseGenerator



card_dump = bytes.fromhex(
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
)

cipher = DES3.new(bytes.fromhex(MASTER_KEY), DES3.MODE_ECB)
kc = cipher.encrypt(card_dump[0:8])[0:6]


rand = bytes.fromhex(
    "c9e543500952"
)



# =====================================================================
# RUN
# =====================================================================

def main():

    generator = ResponseGenerator(**RESPONSE_GENERATOR_CONFIG)

    DATA = card_dump + kc + rand
    response = generator.generate_response(DATA)

    print(f"Response:       {response.hex(' ').upper()}")


if __name__ == "__main__":
    main()
