# Case Sensitivity Fix for keeenv Environment Variables

## Problem Analysis

The user reported that keeenv converts environment variable names to uppercase, which breaks Terraform's TF_VAR prefix functionality. Terraform expects environment variables with the exact case as defined (e.g., `TF_VAR_api_key` should remain `TF_VAR_api_key`, not become `TF_VAR_API_KEY`).

### Root Cause

In `keeenv/core.py` line 759, the code explicitly converts environment variable names to uppercase:

```python
exports.append(
    f"export {var_name.upper()}={shlex.quote(final_value)}"
)
```

This forces all environment variable names to uppercase, regardless of their original case in the `.keeenv` configuration file.

## Current Behavior

- Configuration file preserves case (verified by existing tests)
- `keeenv list` preserves case (verified by existing tests)
- `keeenv eval` converts to uppercase (the problem)

## Solution Plan

### 1. Modify Core Functionality
- Change `keeenv/core.py:759` to use `var_name` instead of `var_name.upper()`
- This will preserve the original case from the configuration file

### 2. Update Tests
- Add test cases to verify case preservation in `eval` command
- Test with Terraform TF_VAR prefixed variables
- Ensure mixed case variables work correctly

### 3. Update Documentation
- Clarify that environment variable case is preserved
- Add examples with case-sensitive variables
- Document TF_VAR compatibility

### 4. Test with Terraform
- Verify that TF_VAR prefixed variables work correctly
- Test various case combinations (TF_VAR_*, tf_var_*, etc.)

## Implementation Steps

1. **Fix the core issue** - Remove `.upper()` call in exports
2. **Add comprehensive tests** - Ensure case preservation works
3. **Update documentation** - Reflect new behavior
4. **Test with Terraform** - Verify real-world usage

## Expected Behavior After Fix

```ini
[env]
TF_VAR_api_key = ${"Entry".password}
tf_var_service_account = ${"Entry".password}
mixedCaseVar = ${"Entry".password}
```

Should produce:

```bash
export TF_VAR_api_key="secret-value"
export tf_var_service_account="secret-value"
export mixedCaseVar="secret-value"
```

Instead of current behavior:

```bash
export TF_VAR_API_KEY="secret-value"
export TF_VAR_SERVICE_ACCOUNT="secret-value"
export MIXEDCASEVAR="secret-value"