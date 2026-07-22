# Contributing to auth2

Thank you for your interest in contributing to auth2.

## Development setup

```bash
git clone https://github.com/jmadler/auth2
cd auth2
go mod download
go run .
```

## Running tests

```bash
go test ./...                    # unit tests
go test -tags=integration ./...  # unit + integration tests
```

See [TEST.md](TEST.md) for the testing strategy.

## Code style

- Run `gofmt -s -w .` before committing
- Follow standard Go conventions
- Keep handlers focused; extract logic into packages

## Submitting changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests and ensure they pass
5. Commit with a clear message
6. Push and open a pull request

## Reporting issues

- Use the GitHub issue tracker
- Include steps to reproduce, expected vs actual behavior
- For security issues, please report privately before opening a public issue

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
