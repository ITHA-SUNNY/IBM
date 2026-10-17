import csv
import tempfile
import unittest
from datetime import datetime,timezone
from pathlib import Path
from schema import COLUMNS, is_off_hours, normalize_event_type
from validate_events import validate_file


class SchemaTests(unittest.TestCase):
    def test_hour_boundaries(self):
        for hour,expected in [(5,1),(6,0),(19,0),(20,1)]:
            self.assertEqual(is_off_hours(f"2026-10-17T{hour:02d}:00:00Z"),expected)
    def test_legacy_mapping_does_not_guess(self):
        self.assertEqual(normalize_event_type("READ_DATASET"),"DATASET_READ")
        self.assertEqual(normalize_event_type("WRITE_DATASET"),"WRITE_DATASET")
    def test_rejects_extra_operation_column_and_unknown_event(self):
        row=dict(zip(COLUMNS,["e1","2026-10-17T20:00:00Z","SYS1","U_0123456789ab","s1","LOGON","SUCCESS","RACF","LOW","KNOWN_NET","1","BENIGN","benign"]))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.csv"
            def write(fields):
                with p.open("w",newline="") as f:
                    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerow(row)
            write(COLUMNS);self.assertEqual(validate_file(p),1)
            row["event_type"]="CRYPTO_OP";write(COLUMNS)
            with self.assertRaises(ValueError):validate_file(p)
            row["event_type"]="LOGON";row["operation"]="AUTHENTICATE";write(COLUMNS+["operation"])
            with self.assertRaises(ValueError):validate_file(p)


if __name__=="__main__":unittest.main()
