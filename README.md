# pi-jev-guard

A safety-gate extension for [Pi](https://github.com/badlogic/pi-mono) powered by TypeSafe AI's Jev service.

The extension will inspect tool and shell calls, classify potentially dangerous actions, and request user approval before execution. Planned protections include destructive filesystem and Git operations, writes outside the project, system configuration changes, data exfiltration, download-and-execute chains, permission and IAM changes, irreversible edits, and complex shell composition.

Policy will be configurable through global and project-level configuration files.

## Status

Initial project setup. Implementation has not started.

## Documentation

- [TypeSafe AI documentation](https://docs.typesafe.ai/introduction)
- [Pi extension documentation](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md)

## License

A license has not yet been selected.
