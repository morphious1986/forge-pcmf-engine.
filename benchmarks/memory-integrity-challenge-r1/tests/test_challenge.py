import json
import tempfile
import unittest
from pathlib import Path

from scorer import EVENTS, TASKS, GOLD, SubmissionError, load_fixture, read_jsonl, score_rows


class ChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.tasks = load_fixture()

    def test_question_file_does_not_expose_gold(self):
        for row in read_jsonl(TASKS):
            self.assertNotIn("gold",row)
            self.assertNotIn("value",row)
        self.assertEqual(12,len(read_jsonl(GOLD)))

    def test_data_sizes_and_unique_ids(self):
        self.assertEqual(25, len(self.events))
        self.assertEqual(12, len(self.tasks))
        self.assertEqual(12, len(set(self.tasks)))

    def test_oracle_example_is_perfect(self):
        rows = read_jsonl(TASKS.parent.parent / "examples" / "perfect_submissions.jsonl")
        output = score_rows(rows, self.tasks, self.events)
        self.assertEqual((60, 12), (output["score"], output["perfect_cases"]))

    def test_partial_submission_scoring(self):
        rows = read_jsonl(TASKS.parent.parent / "examples" / "minimal_submission.jsonl")
        output = score_rows(rows, self.tasks, self.events)
        self.assertEqual((15, 3, 12), (output["score"], output["submitted_cases"], output["total_cases"]))

    def test_empty_submission_scores_zero(self):
        self.assertEqual(0, score_rows([], self.tasks, self.events)["score"])

    def test_wrong_evidence_loses_only_evidence_point(self):
        rows = read_jsonl(TASKS.parent.parent / "examples" / "perfect_submissions.jsonl")
        rows[0]["evidence_ids"] = ["E001"]
        self.assertEqual(59, score_rows(rows, self.tasks, self.events)["score"])

    def test_wrong_decision_cannot_receive_value_points(self):
        rows = read_jsonl(TASKS.parent.parent / "examples" / "perfect_submissions.jsonl")
        rows[0].update(decision="ABSTAIN", value=None, evidence_ids=[])
        self.assertEqual(55, score_rows(rows, self.tasks, self.events)["score"])

    def test_duplicate_submission_rejected(self):
        rows = read_jsonl(TASKS.parent.parent / "examples" / "minimal_submission.jsonl")
        with self.assertRaises(SubmissionError):
            score_rows(rows + rows[:1], self.tasks, self.events)

    def test_unknown_case_rejected(self):
        with self.assertRaises(SubmissionError):
            score_rows([{"case_id":"UNLISTED","decision":"ABSTAIN","value":None,"evidence_ids":[]}],self.tasks,self.events)

    def test_cross_case_evidence_rejected(self):
        with self.assertRaises(SubmissionError):
            score_rows([{"case_id":"C01","decision":"ANSWER","value":"blue","evidence_ids":["E003"]}],self.tasks,self.events)

    def test_invalid_abstention_rejected(self):
        with self.assertRaises(SubmissionError):
            score_rows([{"case_id":"C04","decision":"ABSTAIN","value":"green","evidence_ids":[]}],self.tasks,self.events)

    def test_extra_fields_rejected(self):
        with self.assertRaises(SubmissionError):
            score_rows([{"case_id":"C04","decision":"ABSTAIN","value":None,"evidence_ids":[],"confidence":0.9}],self.tasks,self.events)

    def test_duplicate_evidence_id_rejected(self):
        with self.assertRaises(SubmissionError):
            score_rows([{"case_id":"C01","decision":"ANSWER","value":"blue","evidence_ids":["E002","E002"]}],self.tasks,self.events)

    def test_invalid_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"bad.jsonl"
            p.write_text("{oops}\n", encoding="utf-8")
            with self.assertRaises(SubmissionError):read_jsonl(p)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"duplicate.jsonl"
            p.write_text('{"case_id":"C01","case_id":"C04"}\n',encoding="utf-8")
            with self.assertRaises(SubmissionError): read_jsonl(p)

    def test_oversize_line_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"oversize.jsonl"
            p.write_text("X"*100001+"\n",encoding="utf-8")
            with self.assertRaises(SubmissionError): read_jsonl(p)

    def test_intentionally_naive_baseline_is_not_perfect(self):
        rows=read_jsonl(TASKS.parent.parent / "examples" / "naive_latest_timestamp.jsonl")
        result=score_rows(rows,self.tasks,self.events)
        self.assertLess(result["score"], 60)
        self.assertEqual(12,result["submitted_cases"])

    def test_untrusted_text_is_data_not_instruction(self):
        self.assertIn("Ignore the task", self.events["E013"]["note"])
        self.assertEqual("unverified", self.events["E013"]["authority"])
        self.assertEqual("bronze",self.tasks["C07"]["gold"]["value"])

    def test_no_private_host_material_in_fixtures(self):
        raw=EVENTS.read_text(encoding="utf-8")+TASKS.read_text(encoding="utf-8")
        for marker in ("PRIVATE_USER_HOME", "REAL_USER_DATA", "sk-proj-", "/home/", "/run/media", "api_key"):
            self.assertNotIn(marker,raw)


if __name__ == "__main__":
    unittest.main()
