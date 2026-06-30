# Todo Plan - VPS Setup Script Rewrites

## Phase 1: Planning and Research
- [x] Analyze current `Vps_setup.py` script and identify issues and improvements.
- [ ] Create `implementation_plan.md` outlining the proposed Python and Bash script structures, features, and security recommendations.
- [ ] Conduct interactive interview (`/grill-me`) to align on user requirements:
  - [ ] Target OS and version.
  - [ ] Customization of variables (interactive, CLI, or config file).
  - [ ] SSH key provisioning method.
  - [ ] Missed security settings to include.
- [ ] Update `implementation_plan.md` based on interview results.
- [ ] Obtain user approval for the implementation plan.

## Phase 2: Implementation
- [x] Implement the Python version of the setup script (`vps_setup.py`).
- [x] Implement the Bash version of the setup script (`vps_setup.sh`).
- [x] Add comprehensive documentation / comments inside the scripts for safety, modularity, and readability.

## Phase 3: Verification and Polish
- [x] Lint and validate both Python and Bash scripts.
- [x] Verify security configurations match the recommendations.
- [x] Create a `walkthrough.md` with instructions on how to use both scripts and a summary of security hardening.
- [x] Document lessons learned in `tasks/lessons.md`.
