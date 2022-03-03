# key-set
Collections of Plonk keys.

A `KeySet` is an abstraction of a collection of proving or verifying keys for the
[CAP](https://github.com/EspressoSystems/cap) Plonk circuits. Each key works with the circuit for a
certain kind of transaction (e.g. "a freeze transaction with 1 output", or, "a transfer with 2
inputs and 3 outputs). The order by which the keys can be efficiently indexed is customizable (e.g.
ordering by number of inputs, or number of outputs).

## Usage
Add to your Cargo.toml:
```
key-set = { git = "https://github.com/EspressoSystems/key-set.git" }
```
