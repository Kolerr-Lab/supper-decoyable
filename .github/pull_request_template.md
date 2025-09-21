# Pull Request Template

## Description

Brief description of the changes made in this PR.

## Type of Change

What type of change does this PR introduce?

- [ ] 🐛 **Bug fix** (non-breaking change which fixes an issue)
- [ ] ✨ **New feature** (non-breaking change which adds functionality)
- [ ] 💥 **Breaking change** (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 **Documentation** (updates to documentation)
- [ ] 🎨 **Style** (code style changes, formatting, etc.)
- [ ] ♻️ **Refactor** (code refactoring without functional changes)
- [ ] ⚡ **Performance** (performance improvements)
- [ ] ✅ **Tests** (adding or updating tests)
- [ ] 🔧 **Build/CI** (changes to build process or CI configuration)
- [ ] 🔒 **Security** (security-related changes)

## Changes Made

### Files Changed

List the main files that were modified:

- `file1.py` - Description of changes
- `file2.py` - Description of changes
- `docs/file.md` - Description of changes

### Key Changes

Detail the important changes made:

1. **Change 1**: Description and rationale
2. **Change 2**: Description and rationale
3. **Change 3**: Description and rationale

## Testing

How have you tested these changes?

### Test Coverage

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Existing tests still pass

### Test Results

```bash
# Test output or summary
pytest results: 73 passed, 6 skipped
```

## Checklist

### Code Quality

- [ ] Code follows project style guidelines (Black, isort, ruff)
- [ ] Type hints added where appropriate
- [ ] Docstrings added/updated for public functions
- [ ] No new linting errors introduced
- [ ] Code is well-documented

### Security

- [ ] Security implications reviewed
- [ ] No sensitive data exposed
- [ ] Dependencies reviewed for vulnerabilities
- [ ] Security tests added if applicable

### Documentation

- [ ] README updated if needed
- [ ] API documentation updated
- [ ] Changelog updated (if applicable)
- [ ] Migration guide added for breaking changes

### Testing & Validation

- [ ] All tests pass locally
- [ ] CI checks pass
- [ ] Test coverage maintained or improved
- [ ] Edge cases considered

### Compatibility

- [ ] Backward compatibility maintained (unless breaking change)
- [ ] Python version compatibility verified
- [ ] Dependencies compatibility checked

## Breaking Changes

If this PR introduces breaking changes, please describe:

- **What breaks**: Description of what will no longer work
- **Migration path**: How users should update their code
- **Timeline**: When this change will be released

## Screenshots/Demos

If applicable, add screenshots or demos showing the changes:

## Related Issues

Closes: #issue_number
Related: #issue_number

## Additional Notes

Any additional information or context reviewers should know:

- **Performance impact**: Any performance implications
- **Dependencies**: New dependencies added
- **Future work**: Related work that should be done later
- feature, bug, docs, breaking-change, perf, test, ci

<!-- Keep PRs atomic and focused. Large changes may be split into multiple PRs. -->
