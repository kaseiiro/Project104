"""
Reference implementation of the SLE4436 / Eurochip authentication response generator.

Tap numbers are physical register cell numbers: 1..register_width.
DATA is fed byte-by-byte, LSB-first. Response bits are emitted LSB-first.
"""


KEY1 = "KEY1"
KEY2 = "KEY2"
_VALID_KEYS = (KEY1, KEY2)


class ResponseGenerator:
    """Stateful model of the authentication response generator."""

    def __init__(
        self,
        *,
        register_width,
        linear_taps,
        nonlinear_taps,
        latch_event_period,
        response_bit_period,
        response_bit_count=16,
    ):
        self.register_width = register_width
        self.register_mask = (1 << register_width) - 1

        self.linear_taps = tuple(linear_taps)
        self.nonlinear_taps = tuple(nonlinear_taps)

        self.initial_register = 0
        self.latch_event_period = latch_event_period
        self.response_bit_period = response_bit_period
        self.emit_cycle_count = response_bit_count * response_bit_period
        self.register = self.initial_register

        self.reset()

    @staticmethod
    def _cell(register, cell):
        """Return physical register cell 1..register_width."""
        return (register >> (cell - 1)) & 1

    def reset(self, *, preserve_register=False):
        """Clear transient state; optionally preserve the register for CBC."""
        if not preserve_register:
            self.register = self.initial_register

        self.nonlinear_event_counter = 0
        self.response_cycle_counter = 0
        self.latch = 0
        self._response = bytearray()
        self._emitted_bit_count = 0

    def _linear_feedback(self):
        """XOR the configured linear taps in the current register state."""
        feedback = 0
        for cell in self.linear_taps:
            feedback ^= self._cell(self.register, cell)
        return feedback

    def _nonlinear_block(self, *, for_feedback=False):
        """Evaluate the shared nonlinear block in output or feedback mode."""
        result = 0

        for pair_index, (a, b) in enumerate(self.nonlinear_taps):
            if for_feedback and pair_index == 0:
                b = 1

            term = self._cell(self.register, a) & self._cell(self.register, b)
            if not for_feedback:
                term ^= 1  # NAND

            result ^= term

        return result

    def _clock_register(self, input_bit, nonlinear_feedback_active=False):
        """Clock the register once using the current pre-shift state."""
        feedback = self._linear_feedback()

        if nonlinear_feedback_active:
            feedback ^= self._nonlinear_block(for_feedback=True)

        self.register = (
            ((self.register << 1) | input_bit) & self.register_mask
        ) ^ feedback

    def _outgoing_bit(self):
        return self._cell(self.register, self.register_width)

    def _append_response_bit(self, bit):
        bit_in_byte = self._emitted_bit_count & 7

        if bit_in_byte == 0:
            self._response.append(0)

        if bit:
            self._response[-1] |= 1 << bit_in_byte

        self._emitted_bit_count += 1

    def _emit_cycle(self):
        """Run one emit cycle; the register clock is deliberately last."""
        if self._nonlinear_block():
            self.nonlinear_event_counter += 1
            if self.nonlinear_event_counter == self.latch_event_period:
                self.nonlinear_event_counter = 0
                self.latch = self._outgoing_bit()

        self.response_cycle_counter += 1
        if self.response_cycle_counter == self.response_bit_period:
            self.response_cycle_counter = 0
            self._append_response_bit(self.latch)

        self._clock_register(0)

    def feed(self, data: bytes, seed_bit, nonlinear_feedback_active=False):
        """Feed seed_bit followed by DATA, each byte LSB-first."""
        self._clock_register(seed_bit, nonlinear_feedback_active)

        for value in data:
            for bit_index in range(8):
                self._clock_register(
                    (value >> bit_index) & 1,
                    nonlinear_feedback_active,
                )

    def emit(self):
        """Run the emit phase and return the generated response."""
        for _ in range(self.emit_cycle_count):
            self._emit_cycle()
        return bytes(self._response)

    def generate_response(self, data: bytes, *, key, cbc: bool) -> bytes:
        """Process one DATA block and return its authentication response."""
        if key not in _VALID_KEYS:
            raise ValueError(f"key must be {KEY1} or {KEY2}")
        if type(cbc) is not bool:
            raise TypeError("cbc must be bool")

        seed_bit = 1 if key == KEY1 else 0

        self.reset(preserve_register=cbc)
        self.feed(data, seed_bit, nonlinear_feedback_active=cbc)
        response = self.emit()
        self.reset(preserve_register=cbc)
        return response
