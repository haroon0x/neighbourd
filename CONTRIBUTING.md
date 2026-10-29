# Contributing

Small project, short rules.

- Read `docs/DESIGN.md` before proposing a feature. If it argues against your
  idea, argue back in an issue — the design is not sacred, but it should change
  deliberately.
- Anything that adds a network listener needs a paragraph in the threat model.
- Standard library first. A new dependency needs a reason that is not
  convenience.
- Tests for anything that parses input or compares secrets.
- `gofmt` and `go vet` clean before you open a PR.

The roadmap is ordered. If your change is not on it, open an issue first and
describe what breaks without it.
