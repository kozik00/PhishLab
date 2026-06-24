from __future__ import annotations

from pathlib import Path

import yaml

from phishlab.models.training import TrainingSample

_DEFAULT_SAMPLES_DIR = Path(__file__).resolve().parents[4] / "examples" / "emails"


def load_training_samples(
    samples_dir: Path | None = None,
) -> list[TrainingSample]:
    samples_dir = samples_dir or _DEFAULT_SAMPLES_DIR
    manifest = samples_dir / "training_samples.yml"
    if not manifest.exists():
        return []

    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    samples: list[TrainingSample] = []
    for entry in data.get("samples", []):
        samples.append(TrainingSample(**entry))
    return samples


def get_sample_by_id(
    sample_id: str,
    samples_dir: Path | None = None,
) -> TrainingSample | None:
    for sample in load_training_samples(samples_dir):
        if sample.id == sample_id:
            return sample
    return None


def get_sample_eml_path(
    sample: TrainingSample,
    samples_dir: Path | None = None,
) -> Path:
    samples_dir = samples_dir or _DEFAULT_SAMPLES_DIR
    return samples_dir / sample.eml_filename


def list_sample_ids(
    samples_dir: Path | None = None,
) -> list[str]:
    return [s.id for s in load_training_samples(samples_dir)]
