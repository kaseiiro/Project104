"""Compare card authentication responses with the reconstructed algorithm."""

from secrets import token_bytes

from Cryptodome.Cipher import DES3
from smartcard.System import readers

from auth_unit_structure import RESPONSE_GENERATOR_CONFIG
from response_generator import KEY1, KEY2, ResponseGenerator
from secret import MASTER_KEY


SW_SUCCESS = 0x9000
SW_AUTH_RESPONSE_READY = 0x6102


def _transmit(connection, apdu):
    data, sw1, sw2 = connection.transmit(list(apdu))
    return bytes(data), (sw1 << 8) | sw2


def set_card_type_104(connection):
    _, sw = _transmit(connection, bytes.fromhex("FF A4 00 00 01 07"))
    return sw == SW_SUCCESS


def get_card_atr(connection):
    return bytes(connection.getATR())


def read_card(connection):
    """Read card memory and remove a cyclic tail returned by the reader."""
    data, sw = _transmit(connection, bytes.fromhex("FF B0 00 00 80"))

    if sw != SW_SUCCESS:
        return False, b""

    for repeat_index in range(8, len(data) - 7):
        if (
            data[repeat_index:repeat_index + 8] == data[:8]
            and data[repeat_index:] == data[:len(data) - repeat_index]
        ):
            data = data[:repeat_index]
            break

    return True, data


def auth_card(connection, *, key, cbc, challenge):
    """Request the 16-bit authentication response from the card."""
    if key not in (KEY1, KEY2):
        raise ValueError(f"key must be {KEY1} or {KEY2}")
    if type(cbc) is not bool:
        raise TypeError("cbc must be bool")
    if len(challenge) != 6:
        raise ValueError("challenge must contain exactly 6 bytes")

    key_index = 0 if key == KEY1 else 1
    key_flags = (0x80 if cbc else 0) | key_index

    authenticate_apdu = bytes.fromhex(
        f"FF 84 00 00 08 {key_flags:02X} A0 {challenge.hex()}"
    )
    data, sw = _transmit(connection, authenticate_apdu)

    if sw == SW_AUTH_RESPONSE_READY:
        data, sw = _transmit(connection, bytes.fromhex("FF C0 00 00 02"))
        if sw != SW_SUCCESS or len(data) < 2:
            return False, b""
        return True, data[:2]

    if sw == SW_SUCCESS and len(data) >= 2:
        return True, data[:2]

    return False, b""


def main():
    generator = ResponseGenerator(**RESPONSE_GENERATOR_CONFIG)

    available_readers = readers()
    print(available_readers)

    connection = None
    for reader in available_readers:
        try:
            candidate = reader.createConnection()
            candidate.connect()
            connection = candidate
            print(f"Connected to reader {reader}.")
            break
        except Exception as exc:
            print(f"Can't connect to reader {reader}: {exc}")

    if connection is None:
        raise RuntimeError("No usable smart-card reader found")

    atr = get_card_atr(connection)
    print(f"ATR = {atr.hex().upper()}.")

    if not set_card_type_104(connection):
        raise RuntimeError("Failed to select card type 104")

    read_ok, dump = read_card(connection)
    if not read_ok:
        raise RuntimeError("Failed to read card")
    if len(dump) < 16:
        raise RuntimeError(
            f"Card dump is too short: {len(dump)} bytes, expected at least 16"
        )

    cipher = DES3.new(bytes.fromhex(MASTER_KEY), DES3.MODE_ECB)
    kc = cipher.encrypt(dump[:8])[:6]

    matches = 0
    mismatches = 0
    errors = 0

    key = KEY1
    cbc = True

    for _ in range(500):
        challenge = token_bytes(6)

        auth_ok, card_response = auth_card(
            connection,
            key=key,
            cbc=cbc,
            challenge=challenge,
        )

        if not auth_ok:
            print(f"Challenge:             {challenge.hex(' ').upper()}")
            print("Card authentication command failed.\n")
            errors += 1
            continue

        vsam_response = generator.generate_response(
            dump[:16] + kc + challenge,
            key=key,
            cbc=cbc,
        )

        print(f"Challenge:             {challenge.hex(' ').upper()}")
        print(f"Card Response:         {card_response.hex(' ').upper()}")
        print(f"Virtual SAM Response:  {vsam_response.hex(' ').upper()}")

        if card_response == vsam_response:
            print("Response matched.")
            matches += 1
        else:
            print("Response mismatch.")
            mismatches += 1

        print()

    print(f"matches = {matches}, mismatches = {mismatches}, errors = {errors}")


if __name__ == "__main__":
    main()
