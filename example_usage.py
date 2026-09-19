"""Minimal ResponseGenerator example."""

from Cryptodome.Cipher import DES3

from auth_unit_structure import RESPONSE_GENERATOR_CONFIG
from response_generator import KEY1, ResponseGenerator
from secret import MASTER_KEY


card_dump = bytes.fromhex(
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
)
challenge = bytes.fromhex("000000000000")


def main():
    cipher = DES3.new(bytes.fromhex(MASTER_KEY), DES3.MODE_ECB)
    kc = cipher.encrypt(card_dump[:8])[:6]
    data = card_dump + kc + challenge

    generator = ResponseGenerator(**RESPONSE_GENERATOR_CONFIG)
    key = KEY1
    cbc = True

    # Repeated CBC calls deliberately preserve the register state.
    for _ in range(3):
        response = generator.generate_response(data, key=key, cbc=cbc)
        print(f"Response: {response.hex(' ').upper()}")


if __name__ == "__main__":
    main()
