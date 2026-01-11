# Contributing to RansomWatch

Thanks for your interest in contributing! Here's how you can help.

## Ways to Contribute

- **Bug Reports** - Found a bug? Open an issue with steps to reproduce.
- **Feature Requests** - Have an idea? Open an issue to discuss.
- **Code** - Submit PRs for bug fixes or new features.
- **Documentation** - Help improve docs, examples, or tutorials.
- **Testing** - Test on different platforms and report issues.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ransomwatch.git
cd ransomwatch

# Build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- watch /tmp/test
```

## Pull Request Process

1. **Fork** the repo and create your branch from `main`
2. **Code** your changes
3. **Test** thoroughly
4. **Document** any new features
5. **Submit** a PR with a clear description

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Write tests for new functionality
- Keep commits focused and atomic

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add YARA rule integration
fix: handle symlinks in directory watching
docs: add webhook setup examples
refactor: simplify entropy calculation
```

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_entropy

# Run with output
cargo test -- --nocapture
```

## Adding Ransomware Patterns

To add new ransomware signatures, edit `src/monitor/patterns.rs`:

```rust
// Add extension to RANSOMWARE_EXTENSIONS
".newransomware",

// Add ransom note pattern to RANSOM_NOTE_PATTERNS
"NEW_RANSOM_NOTE.txt",
```

## Security

If you discover a security vulnerability, please email security@example.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open an issue or start a discussion. We're happy to help!
