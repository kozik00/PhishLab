from __future__ import annotations

from pathlib import Path

from phishlab.models.training import QuizAnswer, TrainingSample
from phishlab.training.library import get_sample_by_id, load_training_samples


def evaluate_answer(
    sample_id: str,
    user_answer: bool,
    samples_dir: Path | None = None,
) -> QuizAnswer:
    sample = get_sample_by_id(sample_id, samples_dir)
    if sample is None:
        return QuizAnswer(
            sample_id=sample_id,
            user_answer=user_answer,
            correct=False,
            explanation=f"Unknown sample ID: {sample_id}",
        )

    correct = user_answer == sample.is_phishing
    return QuizAnswer(
        sample_id=sample_id,
        user_answer=user_answer,
        correct=correct,
        explanation=sample.explanation,
    )


def run_quiz(
    answers: dict[str, bool],
    samples_dir: Path | None = None,
) -> list[QuizAnswer]:
    results: list[QuizAnswer] = []
    for sample_id, user_answer in answers.items():
        results.append(evaluate_answer(sample_id, user_answer, samples_dir))
    return results


def calculate_quiz_score(results: list[QuizAnswer]) -> dict:
    total = len(results)
    correct = sum(1 for r in results if r.correct)
    return {
        "total": total,
        "correct": correct,
        "incorrect": total - correct,
        "score_percent": round(correct / total * 100, 1) if total > 0 else 0.0,
    }
