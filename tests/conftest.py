import pytest
from secretgate.models import DiffLine


@pytest.fixture
def make_diff_line():
    def _make(content: str, file_path: str = "src/app.py", line_number: int = 1) -> DiffLine:
        return DiffLine(file_path=file_path, line_number=line_number, content=content)
    return _make
