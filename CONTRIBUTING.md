# Contributing to PinGuard

Thank you for your interest in contributing to PinGuard! We welcome contributions from the community and appreciate your efforts to make PinGuard better.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Issue Reporting](#issue-reporting)
- [Feature Requests](#feature-requests)
- [Security Issues](#security-issues)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

### Our Pledge

We pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- **Rust 1.70+**: [Install Rust](https://rustup.rs/)
- **Git**: [Install Git](https://git-scm.com/)
- **SQLite3**: For database functionality
- **OpenSSL**: For HTTPS communications
- **Docker** (optional): For containerized development

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/pinGuard.git
   cd pinGuard
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/reicalasso/pinGuard.git
   ```

## Development Setup

### Local Development

1. **Install Rust toolchain components**:
   ```bash
   rustup component add rustfmt clippy
   ```

2. **Install additional tools**:
   ```bash
   cargo install cargo-audit cargo-deny cargo-watch
   ```

3. **Build the project**:
   ```bash
   cd pinGuard
   cargo build
   ```

4. **Run tests**:
   ```bash
   cargo test
   ```

5. **Run the application**:
   ```bash
   cargo run -- --help
   ```

### Development with Docker

1. **Build development image**:
   ```bash
   docker build -f docker/Dockerfile.test -t pinGuard:dev .
   ```

2. **Run development container**:
   ```bash
   docker run -it --rm -v $(pwd):/app pinGuard:dev bash
   ```

3. **Use Docker Compose for full stack**:
   ```bash
   cd docker
   docker-compose -f docker-compose.test.yml up
   ```

## Contributing Process

### 1. Choose an Issue

- Check the [Issues](https://github.com/reicalasso/pinGuard/issues) page
- Look for issues labeled `good first issue` for beginners
- Comment on the issue to express your interest
- Wait for maintainer approval before starting work

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-fix-name
```

### 3. Make Changes

- Write clear, concise code
- Follow our coding standards
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run all tests
cargo test

# Run clippy for linting
cargo clippy -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Security audit
cargo audit

# Run benchmarks (if applicable)
cargo bench
```

### 5. Commit Your Changes

Use clear, descriptive commit messages:

```bash
git add .
git commit -m "feat: add package vulnerability scanning

- Implement package audit scanner
- Add support for dpkg and rpm packages
- Include comprehensive test suite
- Update documentation

Fixes #123"
```

#### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear title and description
- Reference to related issues
- Screenshots (if UI changes)
- Testing instructions

## Coding Standards

### Rust Guidelines

1. **Follow Rust idioms** and best practices
2. **Use `rustfmt`** for consistent formatting
3. **Pass `clippy`** without warnings
4. **Write comprehensive tests** for new code
5. **Add documentation** for public APIs

### Code Style

```rust
// Good: Clear function names and documentation
/// Scans the system for package vulnerabilities
/// 
/// # Arguments
/// * `packages` - List of packages to scan
/// 
/// # Returns
/// Vector of found vulnerabilities
pub async fn scan_packages(packages: &[Package]) -> Result<Vec<Vulnerability>, ScanError> {
    // Implementation
}

// Good: Use descriptive variable names
let vulnerable_packages = scan_result.packages
    .iter()
    .filter(|pkg| pkg.has_vulnerabilities())
    .collect();

// Good: Handle errors properly
match cve_client.fetch_cve(cve_id).await {
    Ok(cve_data) => process_cve(cve_data),
    Err(CveError::NetworkError(e)) => {
        warn!("Network error fetching CVE: {}", e);
        use_cached_data(cve_id)
    },
    Err(e) => return Err(e.into()),
}
```

### Error Handling

- Use `Result<T, E>` for fallible operations
- Create specific error types with `thiserror`
- Provide meaningful error messages
- Log errors appropriately

### Testing Standards

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_package_scanning_success() {
        // Arrange
        let packages = vec![
            Package::new("test-package", "1.0.0"),
        ];
        
        // Act
        let result = scan_packages(&packages);
        
        // Assert
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
    
    #[tokio::test]
    async fn test_cve_fetch_handles_network_error() {
        // Test async error handling
    }
}
```

## Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions/modules
2. **Integration Tests**: Test module interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Benchmark critical paths

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_package_scanning

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test '*'

# Benchmarks
cargo bench
```

### Test Data

- Use mock data for external services
- Create realistic test scenarios
- Test both success and failure cases
- Test edge cases and error conditions

## Documentation

### Code Documentation

- Document all public APIs with `///` comments
- Include examples in documentation
- Explain complex algorithms
- Document safety requirements for unsafe code

### User Documentation

- Update README.md for new features
- Add configuration examples
- Include troubleshooting guides
- Update command-line help text

### API Documentation

Generate and review documentation:

```bash
cargo doc --open
```

## Issue Reporting

### Bug Reports

Please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Numbered steps to reproduce
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**: OS, version, Rust version
6. **Logs**: Relevant log output
7. **Configuration**: Relevant config settings

### Bug Report Template

```markdown
**Bug Description**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
A clear description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 22.04]
 - PinGuard Version [e.g. 0.1.0]
 - Rust Version [e.g. 1.70.0]

**Additional Context**
Add any other context about the problem here.
```

## Feature Requests

### Before Submitting

- Check if the feature already exists
- Search existing feature requests
- Consider if it fits the project scope
- Think about implementation complexity

### Feature Request Template

```markdown
**Is your feature request related to a problem? Please describe.**
A clear description of what the problem is.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.

**Additional context**
Add any other context or screenshots about the feature request here.
```

## Security Issues

**Do not report security vulnerabilities in public issues.**

Please follow our [Security Policy](SECURITY.md) for reporting security vulnerabilities.

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Pull Requests**: Code review and collaboration

### Getting Help

1. **Check Documentation**: README, wiki, and code comments
2. **Search Issues**: Someone might have had the same problem
3. **Ask Questions**: Create a GitHub Discussion
4. **Join Community**: Participate in project discussions

### Mentorship

We welcome new contributors! If you're new to:
- **Rust**: Check out the [Rust Book](https://doc.rust-lang.org/book/)
- **Security**: Look for `good first issue` labels
- **Open Source**: Read the [Open Source Guide](https://opensource.guide/)

## Recognition

Contributors will be recognized in:
- CHANGELOG.md for each release
- README.md contributors section
- Git commit history
- Release notes

## Legal

By contributing to PinGuard, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to PinGuard! Your efforts help make Linux systems more secure for everyone.

## Quick Reference

### Common Commands

```bash
# Setup
git clone https://github.com/your-username/pinGuard.git
cd pinGuard
cargo build

# Development
cargo watch -x test           # Auto-run tests on file changes
cargo clippy                  # Linting
cargo fmt                     # Formatting
cargo audit                   # Security audit

# Testing
cargo test                    # All tests
cargo test --test integration # Integration tests
cargo bench                   # Benchmarks

# Documentation
cargo doc --open              # Generate and open docs
```

### Workflow Summary

1. Fork → Clone → Branch
2. Code → Test → Document
3. Commit → Push → Pull Request
4. Review → Merge

Happy coding! 🦀🛡️