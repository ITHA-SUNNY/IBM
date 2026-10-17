# M2 v2 data

Run `python data/generate.py`; verify `python data/verify_data.py`.

Canonical demo: `data/demo_stream.csv` (two same-actor benign baseline sessions + one attack + one legitimate look-alike). For live input use `demo_stream_events.csv`, which excludes ground truth.

Read [event_vocab.md](event_vocab.md) before integrating: v2 changes outcome/sensitivity/off_hours, ID format, HMAC key handling and adds operation. Retrain old models. rare_test.csv provides 3% malicious-session prevalence. manifest.json contains actual split statistics.
