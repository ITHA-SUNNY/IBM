# M2 data

Run `python data/generate.py` from repository root. No dependencies to install.

Start integration with `data/demo_stream.csv`. Use the unlabeled `data/demo_stream_events.csv` for live inference and join evaluation labels by event_id.

[Event vocabulary and integration notes](event_vocab.md).

Demo actor/session mapping is derived from scenario_id, not hardcoded usernames. Do not use scenario_id or stage_label as input features.
