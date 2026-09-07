# Contributing to AuditKit

Thanks for your interest in contributing. AuditKit is becoming a compliance orchestration platform through community collaboration, and we need your help.

## Code of Conduct

Don't be a jerk. We're all trying to make compliance audits less painful. Harassment, discrimination, or toxic behavior will result in a ban.

## Ways to Contribute

### Reporting Bugs

Check existing issues first. If it's new, include:
- Steps to reproduce
- Expected vs actual behavior  
- Environment details (OS, cloud provider, versions)
- Error messages (sanitize sensitive data)

### Feature Requests

Tell us:
- What problem you're trying to solve
- How you handle it now
- How you think it should work
- Why existing features don't work for you

### Integration Contributions

We're building support for external tools (ScubaGear, Prowler, etc). You can help by:
- Contributing control mappings (tool findings → SOC2/PCI controls)
- Testing integrations with your environment
- Documenting tool-specific setup requirements
- Sharing sample outputs for parser development

### Code Contributions

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`go test ./...`)
5. Commit with clear messages (`git commit -m 'Add Azure Key Vault scanning'`)
6. Push to your fork
7. Open a Pull Request

#### Code Standards

- Go code must pass `go fmt` and `go vet`
- Functions need comments explaining what they do
- No passwords, keys, or tokens in code (use environment variables)
- Keep it simple - readable code beats clever code
- No emojis in output - this is a professional tool

#### Testing Requirements

- Unit tests for new functions
- Integration tests for new cloud provider features
- Test with multiple framework selections (SOC2, PCI, etc.)
- Include test data that doesn't contain real credentials

### Documentation Contributions

Good documentation is crucial. You can help by:
- Fixing typos and clarifying confusing sections
- Adding examples for complex features
- Writing guides for specific use cases
- Translating documentation (future)

### Governance Pack Contributions

We're building policy and procedure templates. If you have compliance expertise:
- Review and improve policy templates
- Validate control mappings against real audits
- Contribute industry-specific requirements
- Share anonymized audit experiences

## Pull Request Process

1. Update the README.md if you've added functionality
2. Update tests to cover your changes
3. Ensure your code follows existing patterns
4. PR description should explain what and why
5. One of the maintainers will review within 48 hours

## What We're Looking For

### High Priority
- CIS Azure and CIS GCP control expansion (108 and 71 controls today, against 158 for AWS)
- Integration parsers for common security tools
- Control mapping validation from actual auditors
- Performance improvements for large environments

### Medium Priority  
- Deeper crosswalk mappings for the frameworks already shipped (framework-crosswalk.yaml maps 18 HIPAA safeguards of 75 and 54 ISO 27001 controls of 93)
- Policy template contributions
- Dashboard improvements
- CI/CD integrations

### Nice to Have
- UI/UX improvements
- Additional output formats
- Localization support

## Questions?

Open a discussion in GitHub Discussions for:
- Architecture decisions
- Feature design questions
- General how-to questions

## Recognition

Contributors who make significant improvements will be:
- Credited in the release notes and the GitHub contributors list
- Mentioned in release notes
- Given credit in documentation

## Legal

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
