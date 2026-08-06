# Native analyze probe evidence

Only `latest.json` and the matching timestamped sibling from the same run are
release evidence. Synthetic/`true`-command runs and pre-v1.1 reports that
mislabeled nonzero exits as `completed` must not be retained here.
