# dev — developer workspace

Local development scaffolding. **Not part of the shipped tool** and not required
to build or run it. Everything here supports working *on* OpenNetBench:
validating changes, benchmarking the engine, and driving external review.
        

Unit tests live next to the code (`cargo test`). This folder is for the heavier,
out-of-band checks that don't belong in the crate.
