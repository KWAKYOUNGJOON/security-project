# apps(앱)

Executable components for the security assessment workspace.

## Current apps

- `report-template/`: existing Web report rendering assets and tests
- `report-automation/`: minimal Python automation scaffold for report payload preparation

## Design rule

Keep rendering logic and automation logic separate. The current Web workflow depends on both apps, but they serve different roles and should stay loosely coupled.
