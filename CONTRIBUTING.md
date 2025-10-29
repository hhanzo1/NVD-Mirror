# Contributing to NVD Mirror

Thank you for considering contributing to NVD Mirror! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Your environment (OS, Python version, PostgreSQL version)
- Relevant log excerpts (sanitize any sensitive data)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please create an issue with:

- A clear description of the enhancement
- Use cases and benefits
- Any implementation ideas you might have

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the code style guidelines below
3. **Test your changes** thoroughly
4. **Update documentation** as needed
5. **Commit with clear messages** describing what and why
6. **Submit a pull request** with a clear description

## Code Style Guidelines

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused on a single responsibility
- Maximum line length: 100 characters

### Documentation

- Update README.md if you change functionality
- Add inline comments for complex logic
- Keep comments up-to-date with code changes
- Use clear, concise language

### Commit Messages

Use clear, descriptive commit messages:

```
Good: "Add retry logic for database connection failures"
Bad: "Fix bug"
```

Format:
```
<type>: <short description>

<optional detailed description>

<optional issue reference>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Testing

Before submitting a PR:

- Test with a fresh database installation
- Test both full and incremental sync modes
- Verify error handling and edge cases
- Check that logging output is helpful and clear

## Code Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, your PR will be merged

## Questions?

Feel free to open an issue for any questions about contributing!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
