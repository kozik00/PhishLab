from __future__ import annotations

from phishlab.training.library import (
    get_sample_by_id,
    get_sample_eml_path,
    list_sample_ids,
    load_training_samples,
)
from phishlab.training.quiz import calculate_quiz_score, evaluate_answer, run_quiz


class TestLoadTrainingSamples:
    def test_loads_all_samples(self):
        samples = load_training_samples()
        assert len(samples) == 7

    def test_each_sample_has_required_fields(self):
        for sample in load_training_samples():
            assert sample.id
            assert sample.title
            assert sample.eml_filename
            assert isinstance(sample.is_phishing, bool)
            assert sample.explanation
            assert len(sample.indicators) >= 1

    def test_contains_phishing_and_legit(self):
        samples = load_training_samples()
        phishing_count = sum(1 for s in samples if s.is_phishing)
        legit_count = sum(1 for s in samples if not s.is_phishing)
        assert phishing_count >= 4
        assert legit_count >= 2

    def test_sample_ids_are_unique(self):
        ids = list_sample_ids()
        assert len(ids) == len(set(ids))


class TestGetSampleById:
    def test_finds_existing_sample(self):
        sample = get_sample_by_id("fake-microsoft-alert")
        assert sample is not None
        assert sample.title == "Microsoft Account Security Alert"
        assert sample.is_phishing is True

    def test_returns_none_for_unknown_id(self):
        sample = get_sample_by_id("nonexistent-sample")
        assert sample is None

    def test_finds_benign_sample(self):
        sample = get_sample_by_id("benign-newsletter")
        assert sample is not None
        assert sample.is_phishing is False

    def test_finds_polish_sample(self):
        sample = get_sample_by_id("bank-phish-polish")
        assert sample is not None
        assert "polish" in sample.tags


class TestGetSampleEmlPath:
    def test_returns_valid_path(self):
        sample = get_sample_by_id("fake-microsoft-alert")
        assert sample is not None
        path = get_sample_eml_path(sample)
        assert path.exists()
        assert path.suffix == ".eml"

    def test_all_sample_emls_exist(self):
        for sample in load_training_samples():
            path = get_sample_eml_path(sample)
            assert path.exists(), f"Missing .eml for sample: {sample.id}"


class TestListSampleIds:
    def test_returns_seven_ids(self):
        ids = list_sample_ids()
        assert len(ids) == 7

    def test_contains_expected_ids(self):
        ids = list_sample_ids()
        assert "benign-newsletter" in ids
        assert "fake-microsoft-alert" in ids
        assert "invoice-phish" in ids
        assert "password-reset-legit" in ids
        assert "shipping-notification-phish" in ids
        assert "bank-phish-polish" in ids
        assert "gift-card-scam" in ids


class TestEvaluateAnswer:
    def test_correct_phishing_answer(self):
        result = evaluate_answer("fake-microsoft-alert", user_answer=True)
        assert result.correct is True
        assert result.explanation

    def test_incorrect_phishing_answer(self):
        result = evaluate_answer("fake-microsoft-alert", user_answer=False)
        assert result.correct is False

    def test_correct_legit_answer(self):
        result = evaluate_answer("benign-newsletter", user_answer=False)
        assert result.correct is True

    def test_incorrect_legit_answer(self):
        result = evaluate_answer("benign-newsletter", user_answer=True)
        assert result.correct is False

    def test_unknown_sample_returns_incorrect(self):
        result = evaluate_answer("nonexistent", user_answer=True)
        assert result.correct is False
        assert "Unknown" in result.explanation


class TestRunQuiz:
    def test_evaluates_all_answers(self):
        answers = {
            "fake-microsoft-alert": True,
            "benign-newsletter": False,
            "gift-card-scam": True,
        }
        results = run_quiz(answers)
        assert len(results) == 3
        assert all(r.correct for r in results)

    def test_mixed_results(self):
        answers = {
            "fake-microsoft-alert": True,
            "benign-newsletter": True,
        }
        results = run_quiz(answers)
        correct_count = sum(1 for r in results if r.correct)
        assert correct_count == 1


class TestCalculateQuizScore:
    def test_perfect_score(self):
        answers = {
            "fake-microsoft-alert": True,
            "benign-newsletter": False,
        }
        results = run_quiz(answers)
        score = calculate_quiz_score(results)
        assert score["total"] == 2
        assert score["correct"] == 2
        assert score["score_percent"] == 100.0

    def test_zero_score(self):
        answers = {
            "fake-microsoft-alert": False,
            "benign-newsletter": True,
        }
        results = run_quiz(answers)
        score = calculate_quiz_score(results)
        assert score["correct"] == 0
        assert score["score_percent"] == 0.0

    def test_partial_score(self):
        answers = {
            "fake-microsoft-alert": True,
            "benign-newsletter": True,
            "gift-card-scam": True,
        }
        results = run_quiz(answers)
        score = calculate_quiz_score(results)
        assert score["total"] == 3
        assert score["correct"] == 2
        assert score["incorrect"] == 1

    def test_empty_results(self):
        score = calculate_quiz_score([])
        assert score["total"] == 0
        assert score["score_percent"] == 0.0
