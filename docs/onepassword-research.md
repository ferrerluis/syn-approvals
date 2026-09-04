# 1Password research gate

No 1Password adapter belongs to the sudo alpha.

Test the official 1Password Environments MCP for Codex first, specifically when the Codex UI runs on a Mac but commands execute on a connected Pi. Verify model context, terminal output, files, child inheritance, `/proc` access, shell tracing, crash dumps, and logs under deliberate exfiltration attempts.

A service account narrows vault access but does not by itself keep values out of context. Any future Syn adapter must broker a constrained operation and secret sink; it must not expose `op read`, an arbitrary secret-bearing environment, or an arbitrary child command to the agent.
