# TEE-Rust
Because, frankly, doing this stuff in C sucked way too much.

TEE-Rust is a small rust library that implements what we did in [this post](https://blog.neverlocal.com/tee-re-entry/). It provides a bunch of functions which all implement traits to make it memory safe/cryptographically secure as much as possible. A detailed description of what the library does can be found [here](). The library is `no_std` friendly and can be used on embedded systems.

## Installation

If you use nix, we provide a flake. That should be enough to set you up.

Alternatively, you can just copy the `conjugate_coding_library` folder wherever you want and import it from cargo.

## Features

The library has the following features:
- `std`, useful if you want to use the library with code that should run on your PC;
- `no_std`, useful if you want to use the library in an embedded environment;
- `debug`, this feature makes available some diagnostics functions that are not available otherwise. These functions print information that is security sensitive and should not be used in production.
- `defmt`, useful to enable logging features in the `no_std` settings. Depends on [defmt](https://defmt.ferrous-systems.com/).

## Examples

Besides the library itself, you will find various examples in the `examples` folder. These are as follows:
- `tee_unencrypted` is an examples where an esp32c6 is used as the TEE. The user communicates with the TEE via serial interface, in an unencrypted way.
  - `esp32c6` contains the code to be flashed on the esp;
  - `preparation_serializer` creates the quantum preparing information. It takes the preparation data data in and produces the JSON object to be given to the TEE program at preparation stage;
  - `measurement_serializer` creates the JSON object comprising the information around the quantum measurement. It takes measurement data in (the outcomes, the choices of measurement basis) and produces the JSON object to be fed to the TEE.
- `tee_aes` does exactly the same as above, but in this case the JSON object is fed to the TEE encrypted, using aes. The encryption key is hardcoded both in the `esp32` code and in the `preparation_serializer` code. File structure is as above.

**please note that these examples are only toys, and should not be used in ANY production environment.** This is for two reasons: First of all, the esp32c6 is just a 'toy' TEE which we [know](https://www.espressif.com/sites/default/files/advisory_downloads/AR2023-007%20Security%20Advisory%20Concerning%20Bypassing%20Secure%20Boot%20and%20Flash%20Encryption%20using%20CPA%20and%20FI%20attack%20on%20ESP32-C3%20and%20ESP32-C6%20EN.pdf) has vulnerabilities. We use it because it's very cheap and nice to play with.
Secondly, notice that nothing in this examples is cryptographically standard: Unencrypted communication clearly defeats the purpose of using a TEE in the first place, and is only good for educational purpose. Hardcoded passwords are also a big no-no, and a system like TLS should be the standard. We avoided that as no consensus has already formed around quantum-resistant TLS. Another reason is that managing certificates is always a pain and not exactly the most friendly thing to do for a bunch of examples that are meant as prototypes for self-study purposes.