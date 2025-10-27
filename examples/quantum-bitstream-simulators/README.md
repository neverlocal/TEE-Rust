# Quantum Bitstream Simulators

HW simulators for bitstreams that would be produced by simple quantum hardware configurations:

1. [`tee-otp-conjcode-single`](./tee-otp-conjcode-single/README.md) implements a simulated bitstream for the conjugate coding implementation described in the blog post [Securing TEEs against re-entry attacks](https://blog.neverlocal.com/tee-re-entry/), based on a heralded photon implementation where each herald-data photon pair carries a single bit of the secret table.
