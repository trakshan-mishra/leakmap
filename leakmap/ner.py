"""Optional model for names and addresses, which have no shape a regex can check.

    uv tool install 'leakmap[ner]'
    leakmap run --ner -- pytest

Uses GLiNER's PII model on the CPU. It is off by default: it adds torch to the
install and roughly 0.1-0.5 s per long text value, which suits a CI run, not
production traffic. Text never leaves the machine; the model is downloaded
once from Hugging Face, pinned to a commit.
"""

import re

MODEL = "urchade/gliner_multi_pii-v1"
REVISION = "1fcf13e85f4eef5394e1fcd406cf2ca9ea82351d"
# "organization" is asked for so company names are not forced into "person"; its spans are dropped.
LABELS = {"person": "person_name", "address": "address", "organization": None}
THRESHOLD = 0.5
CHUNK_WORDS = 250  # the model reads at most 384 tokens


class NER:
    def __init__(self, threshold: float = THRESHOLD):
        try:
            from gliner import GLiNER
        except ImportError as e:
            raise SystemExit("--ner needs the optional model: uv tool install 'leakmap[ner]'") from e
        self.model = GLiNER.from_pretrained(MODEL, revision=REVISION)
        self.threshold = threshold

    @staticmethod
    def chunks(text: str):
        """(offset, piece) windows of about CHUNK_WORDS words, cut at line ends where possible."""
        words = [m.start() for m in re.finditer(r"\S+", text)]
        start = 0
        while start < len(words):
            end = min(start + CHUNK_WORDS, len(words))
            stop = words[end] if end < len(words) else len(text)
            if end < len(words):
                nl = text.rfind("\n", words[start], stop)
                if nl > words[start]:
                    stop = nl
                    end = next((i for i in range(start, len(words)) if words[i] >= stop), end)
                    end = max(end, start + 1)
            yield words[start], text[words[start]:stop]
            start = end

    def predict_many(self, texts: list[str], batch_size: int = 8):
        """[(category, start, end, confidence)] per text."""
        jobs = [(i, off, piece) for i, t in enumerate(texts) for off, piece in self.chunks(t)]
        out = [[] for _ in texts]
        for b in range(0, len(jobs), batch_size):
            batch = jobs[b:b + batch_size]
            found = self.model.batch_predict_entities([p for _, _, p in batch], list(LABELS), threshold=self.threshold)
            for (i, off, _), entities in zip(batch, found):
                for e in entities:
                    cat = LABELS.get(e["label"])
                    if cat:
                        conf = "high" if e["score"] >= 0.8 else "medium"
                        out[i].append((cat, off + e["start"], off + e["end"], conf))
        return out

    def find(self, text: str):
        """[(category, matched_text, confidence)] for one value."""
        return [(c, text[s:e], conf) for c, s, e, conf in self.predict_many([text])[0]]
