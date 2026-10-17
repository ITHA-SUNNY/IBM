# M2 v3 data ? shared schema aligned

Run `python data/generate.py`; verify `python data/verify_data.py`.
Strict file check: `python data/validate_events.py data/demo_stream.csv data/train.csv`.
Tests: `python -m unittest discover -s data -p "test_*.py"`.

All constants come from schema.py, supplied by Vinayak. Exact 13 columns, no operation column; use DATASET_LIST/DATASET_READ/DATASET_COPY. Off-hours: UTC <06:00 or >=20:00.
Canonical demo_stream.csv has 24 events (two benign histories, one attack, one look-alike). rare_test.csv has 3% attack sessions. See [event_vocab.md](event_vocab.md).

IMPACT remains a reserved stage but has no training data, because the supplied event vocabulary has no reviewed impact/write/crypto observation. Do not claim it is trained. Model owners should import from data.schema rather than copy enum lists.
