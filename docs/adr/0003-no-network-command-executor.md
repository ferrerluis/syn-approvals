# ADR 0003: No network command executor

Status: accepted.

Syn's network service relays signed intent and decision messages only. It has no endpoint that accepts a command, shell string, argv, script, or executable to run.

The root plug-in derives intent from sudo's post-policy data and returns a boolean approval result. Sudo executes its original in-memory command after the plug-in returns.
