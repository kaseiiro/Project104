"""
Reconstruction of the Active Authentication Algorithm 
Used in SLE4436 aka Eurochip Cards

Readable reference implementation of the response-generation algorithm.

Tap numbering is physical and uniform everywhere:

    cell 1     <-> register bit 0
    cell 2     <-> register bit 1
    ...
    cell WIDTH <-> register bit WIDTH - 1

Both linear_taps and nonlinear_taps therefore use physical cell numbers
1..WIDTH.

The complete processing consists of two stages:

    linear phase:
        prefix bit 1
        DATA, each byte LSB-first

    nonlinear phase:
        input bit is always 0
        nonlinear function, latch and response generation are active

DATA is bytes. The generated response is also bytes.

Response bits are packed in chronological order, LSB-first inside each byte:
the first emitted response bit becomes bit 0 of response[0].
"""


class ResponseGenerator:
    """
    Stateful model of the authentication-response generator.

    DATA is the complete input block. A challenge may occupy only part
    of DATA; this class intentionally does not assign meaning to DATA fields.
    """

    def __init__(
        self,
        *,
        register_width,
        linear_taps,
        nonlinear_taps,
        initial_register = 0,
        latch_event_period,
        response_bit_period,
        response_bit_count = 16,
    ):
        if len(nonlinear_taps) != 6:
            raise ValueError("nonlinear_taps must contain exactly 6 cells")

        all_taps = (*linear_taps, *nonlinear_taps)
        if any(cell < 1 or cell > register_width for cell in all_taps):
            raise ValueError(f"tap cell numbers must be in 1..{register_width}")

        if register_width < 1 or latch_event_period < 1 or response_bit_period < 1:
            raise ValueError("register width and counter periods must be positive")

        self.register_width = register_width
        self.register_mask = (1 << register_width) - 1

        self.linear_taps = tuple(linear_taps)
        self.nonlinear_taps = tuple(nonlinear_taps)

        self.initial_register = initial_register & self.register_mask
        self.latch_event_period = latch_event_period
        self.response_bit_period = response_bit_period
        self.nonlinear_phase_ticks = response_bit_count * response_bit_period

        self.reset()

    @staticmethod
    def _cell(register, cell):
        """Return the value of a physical cell numbered from 1."""
        return (register >> (cell - 1)) & 1

    def reset(self, register=None):
        """Reset mutable state before a new response calculation."""
        self.register = (
            self.initial_register
            if register is None
            else register & self.register_mask
        )

        self.nonlinear_event_counter = 0
        self.response_tick_counter = 0
        self.latch = 0

        self._response = bytearray()
        self._response_bit_count = 0

    @property
    def response(self):
        """Response bits generated so far, returned as immutable bytes."""
        return bytes(self._response)

    def _linear_feedback(self):
        """
        XOR physical linear taps in the pre-shift register state.

        This is equivalent to the old post-shift representation:

            tap 1     -> shifted bit 1 -> old physical cell 1
            ...
            tap WIDTH -> outgoing      -> old physical cell WIDTH

        Using the pre-shift state lets both tap sets use the same physical
        numbering convention.
        """
        feedback = 0
        for cell in self.linear_taps:
            feedback ^= self._cell(self.register, cell)
        return feedback

    def _nonlinear_output(self):
        """Compute NAND(a,b) XOR NAND(c,d) XOR NAND(e,f)."""
        a, b, c, d, e, f = self.nonlinear_taps
        r = self.register

        ab = self._cell(r, a) & self._cell(r, b)
        cd = self._cell(r, c) & self._cell(r, d)
        ef = self._cell(r, e) & self._cell(r, f)

        return (1 ^ ab) ^ (1 ^ cd) ^ (1 ^ ef)

    def _clock_register(self, input_bit):
        """
        Perform one register clock and return the outgoing MSB.

        1. capture physical cell WIDTH as outgoing;
        2. calculate linear feedback from the old physical cells;
        3. shift toward higher-numbered cells;
        4. insert input_bit into physical cell 1;
        5. XOR feedback into physical cell 1.
        """
        outgoing = self._cell(self.register, self.register_width)
        feedback = self._linear_feedback()

        self.register = (
            ((self.register << 1) | input_bit) & self.register_mask
        ) ^ feedback

        return outgoing

    def _append_response_bit(self, bit):
        """
        Append one emitted response bit.

        Emission order is preserved directly:
            response bit #0 -> response[0] bit 0
            response bit #1 -> response[0] bit 1
            ...
            response bit #8 -> response[1] bit 0
        """
        bit_in_byte = self._response_bit_count & 7

        if bit_in_byte == 0:
            self._response.append(0)

        if bit:
            self._response[-1] |= 1 << bit_in_byte

        self._response_bit_count += 1

    def _clock_nonlinear_phase(self):
        """Perform one nonlinear-phase clock; register input is always 0."""
        outgoing = self._clock_register(0)

        if self._nonlinear_output():
            self.nonlinear_event_counter += 1
            if self.nonlinear_event_counter == self.latch_event_period:
                self.nonlinear_event_counter = 0
                self.latch = outgoing

        self.response_tick_counter += 1
        if self.response_tick_counter == self.response_bit_period:
            self.response_tick_counter = 0
            self._append_response_bit(self.latch)

    def run_linear_phase(self, data: bytes):
        """Run prefix 1 -> DATA LSB-first."""
        self._clock_register(1)

        for value in data:
            for bit_index in range(8):
                self._clock_register((value >> bit_index) & 1)

        #self._clock_register(0)

    def run_nonlinear_phase(self):
        """Run the complete nonlinear phase."""
        for _ in range(self.nonlinear_phase_ticks):
            self._clock_nonlinear_phase()

    def generate_response(self, data: bytes) -> bytes:
        """Process one DATA block and return the response as bytes."""
        self.reset()
        self.run_linear_phase(data)
        self.run_nonlinear_phase()
        return self.response
