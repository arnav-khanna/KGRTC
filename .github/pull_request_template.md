## Summary

Describe what this pull request changes and why.

## Type of change

- [ ] Bug fix
- [ ] New functionality
- [ ] Cryptanalysis / research result
- [ ] Performance improvement
- [ ] Refactor
- [ ] Documentation
- [ ] Tests

## Evidence

Describe how the change was validated.

- [ ] `cargo fmt --check`
- [ ] `cargo test`
- [ ] `cargo build --release`
- [ ] Relevant example(s) run
- [ ] New/updated tests included

## Cryptographic impact

Does this change alter the cryptographic construction, key derivation, topology generation, nonlinear functions, round behavior, authentication wrapper, nonce handling, or security assumptions?

If yes, explain the change precisely.

## Claims and evidence level

For any cryptographic result, identify whether it is:

- mathematically proved;
- exhaustively verified;
- tested on a finite sample; or
- empirically observed.

## Reproducibility

For research results, provide the commands, parameters, commit, and enough detail for an independent reader to reproduce the result.

## Documentation

- [ ] README updated if user-visible behavior changed
- [ ] Relevant `docs/` document updated
- [ ] Security documentation updated if assumptions changed

## Checklist

- [ ] I have not introduced real secrets or sensitive data.
- [ ] I have checked for unintended behavior changes.
- [ ] I have kept unrelated changes out of this PR.
- [ ] I understand that passing the existing tests does not establish full-cipher security.
