# Project104. SLE4436 / Eurochip authentication reconstruction

One more masterpiece.

Independent reconstruction of the authentication algorithm used in Siemens/Infineon SLE4436 aka Eurochip telephone cards. The SLE4436 belongs to the Type 104 card family. The implementation corresponds to the architecture described in EP0624839B1.

The code is documented inline.

To perform authentication, you need the master key value, which is normally kept secret by the card issuer. You also need the LFSR tap positions, nonlinear-function tap positions, and counter modulus values.
