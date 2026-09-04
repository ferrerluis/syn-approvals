# ADR 0002: Syn-first, password-after-timeout

Status: accepted.

For the managed UID, Syn is attempted first. After exactly 90 seconds without a valid decision, an interactive terminal may authenticate through Ubuntu PAM.

Fallback is forbidden after explicit denial, local policy denial, invalid signatures, replay, malformed data, wrong targets, unsupported versions, or cancellation. Non-interactive sudo never prompts.

This is a convenience and agent-separation boundary, not a veto against someone who knows the Ubuntu password.
