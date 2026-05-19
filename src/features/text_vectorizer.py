from typing import Iterable, List


class TextVectorizer:
    """
    Module 6 placeholder.

    Module 7 is not implemented yet. This class only prepares request texts.
    Later it can be extended with TF-IDF character n-gram.
    """

    def build_text_corpus(self, records: Iterable[dict]) -> List[str]:
        return [record.get("normalized_request", "") or "" for record in records]
