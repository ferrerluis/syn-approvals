# Syn approvals during a Codex task

For a Codex task connected to your phone, Codex can alert you when it needs attention. Enable phone notifications and keep the connected desktop host awake, online, and running ChatGPT. OpenAI's notification delivery is an external dependency; this does not cover sudo requests made outside Codex.

Give an agent these instructions in the project where it runs:

> When the original sudo process reports **Waiting for Syn approval**, promptly ask **Open Syn to review the pending request.** Use the normal asynchronous question tool if available. Keep the original process running and poll its session ID until it exits. Do not treat my reply here as approval. Do not change the command, cache approval, automatically repeat a denial, or extend the deadline. If the question tool is unavailable, report the wait in the conversation without claiming a phone alert was delivered.

Syn sends and verifies the request directly between the paired target and the open Syn app. Open Syn, review the pending request, and press **Approve** or **Deny** there. A Codex reply or notification cannot sign a decision. If the request expires after 300 seconds, review any explicitly requested retry as a new invocation.

Use the actual host-level invocation for testing: `/usr/bin/sudo -n /usr/bin/true`. `sudo -v` bypasses sudo's approval-plugin run path. In Codex, use host execution with a TTY and return promptly to let the agent raise the question while the process remains alive. Only that original process's exit status proves completion.

See [OpenAI Remote connections](https://learn.chatgpt.com/docs/remote-connections#what-you-can-do-remotely) for pairing and notification requirements. Real phone push delivery has not been verified by simulator testing.
