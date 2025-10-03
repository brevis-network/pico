# Contributing to Pico

Thank you for your interest in contributing to Pico! Your contributions—whether they involve bug fixes, new features, documentation, or tests—are vital to our mission of building a secure, scalable, and efficient zero-knowledge virtual machine. The following are guidelines for how you can contribute to Pico.

## Reporting Issues
- Search: Before opening a new issue, check the issue tracker to see if it already exists. 
- Report: If it doesn't, open an issue with a clear title, description, and steps to reproduce.

## Suggesting Enhancements
- Feature Requests: Open an issue tagged as an enhancement with details on the proposed feature and its benefits.

## Pull Requests
- Fork & Clone: Fork the repository and clone it locally.
- Create a Branch: Use a descriptive branch name (e.g., `feature/new-proof-system` or `bugfix/fix-crash`).
- Implement & Test: Add tests for your changes. You can review the testing commands in `.github/workflows/rust.yml` and use them or add your own tests as needed. Use [act](https://github.com/nektos/act) to simplify this process into `act pull_request`.
- Format & Lint: Before submitting your PR, run: `make fmt` and `make lint`.
- Submit PR: Open a pull request with a summary of your changes and reference any related issues (e.g., “Fixes #123”). 

## Code Style
- Follow the existing code style and conventions.
- Write clear and concise comments where necessary.
- Ensure your code is well-documented.

## Review Process
- Your pull request will be reviewed by the maintainers.
- Be responsive to feedback and make necessary changes.
- Once approved, your changes will be merged into the main branch.
