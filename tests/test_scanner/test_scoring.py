from keygate.models import DiffLine, RuleMatch, Verdict
from keygate.scanner.context import ContextSignals
from keygate.scanner.scoring import aggregate


def make_line(content="secret", file_path="app.py"):
    return DiffLine(file_path=file_path, line_number=1, content=content)


def make_rule_match(score=90):
    return RuleMatch(
        rule_id="aws-access-key",
        matched_text="AKIAIOSFODNN7EXAMPLE",
        score=score,
        description="AWS Access Key detected",
        remediation=["Rotate credentials"],
        policy="must_block",
    )


def ctx(keyword_score=0, keyword_tier="", path_score=0, assignment_score=0):
    return ContextSignals(
        keyword_score=keyword_score,
        keyword_tier=keyword_tier,
        path_score=path_score,
        assignment_score=assignment_score,
    )


def test_block_verdict():
    result = aggregate(make_line(), [make_rule_match(90)], 0, ctx())
    assert result.verdict == Verdict.BLOCK
    assert result.total_score == 90


def test_warn_verdict():
    result = aggregate(make_line(), [make_rule_match(40)], 0, ctx())
    assert result.verdict == Verdict.WARN


def test_ignore_verdict():
    result = aggregate(make_line(), [], 0, ctx())
    assert result.verdict == Verdict.IGNORE
    assert result.total_score == 0


def test_only_top_rule_counted():
    matches = [make_rule_match(90), make_rule_match(80)]
    result = aggregate(make_line(), matches, 0, ctx())
    assert result.total_score == 90


def test_test_file_penalty():
    line = make_line(file_path="tests/test_app.py")
    result = aggregate(line, [make_rule_match(75)], 0, ctx())
    assert result.total_score == 65


def test_dummy_penalty():
    line = make_line(content="dummy key AKIAIOSFODNN7EXAMPLE")
    result = aggregate(line, [make_rule_match(75)], 0, ctx())
    assert result.total_score == 55


def test_placeholder_path_caps_strong_rule_to_warn():
    line = make_line(
        content='AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"  # example only',  # keygate: ignore reason="test fixture"
        file_path="README.md",
    )
    signals = ctx(assignment_score=15)
    result = aggregate(line, [make_rule_match(90)], 0, signals)
    assert result.verdict == Verdict.WARN
    assert result.total_score == 40
    assert result.score_breakdown["cap:placeholder_context"] == 40


def test_placeholder_comment_caps_openai_rule_to_warn():
    line = make_line(
        content='api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"  # dummy sample',  # keygate: ignore reason="test fixture"
        file_path="app.py",
    )
    match = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdefghijklmnopqrstuvwxyz123456",  # keygate: ignore reason="test fixture"
        score=85,
        description="OpenAI API Key detected",
        policy="must_block",
    )
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(line, [match], 20, signals)
    assert result.verdict == Verdict.WARN
    assert result.total_score == 40
    assert result.score_breakdown["cap:placeholder_context"] == 40


def test_dummy_word_alone_does_not_cap_real_secret():
    line = make_line(content='api_key = "sk-abcdefghijklmnopqrstuvwxyz123456" dummy')  # keygate: ignore reason="test fixture"
    match = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdefghijklmnopqrstuvwxyz123456",  # keygate: ignore reason="test fixture"
        score=85,
        description="OpenAI API Key detected",
        policy="must_block",
    )
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(line, [match], 20, signals)
    assert result.verdict == Verdict.BLOCK
    assert "cap:placeholder_context" not in result.score_breakdown


def test_score_never_negative():
    line = make_line(content="dummy example placeholder", file_path="tests/test_app.py")
    result = aggregate(line, [], 0, ctx())
    assert result.total_score == 0


def test_entropy_and_context_added():
    result = aggregate(make_line(), [], 20, ctx(keyword_score=15, keyword_tier="mid"))
    assert result.total_score == 20 + 15 + 15
    assert result.verdict == Verdict.WARN


def test_combo_keyword_plus_entropy_bonus():
    result = aggregate(
        make_line(content="token = 'x'"),
        [],
        20,
        ctx(keyword_score=15, keyword_tier="mid"),
    )
    assert "combo:keyword+entropy" in result.score_breakdown
    assert result.score_breakdown["combo:keyword+entropy"] == 15


def test_combo_high_entropy_assignment_triple_bonus():
    line = make_line(content='api_key = "xxx"')
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(line, [], 20, signals)
    assert "combo:high+entropy+assignment" in result.score_breakdown
    assert result.score_breakdown["combo:high+entropy+assignment"] == 15
    assert result.score_breakdown["combo:keyword+entropy"] == 15
    assert result.total_score == 25 + 15 + 20 + 15 + 15
    assert result.verdict == Verdict.BLOCK


def test_no_combo_when_rule_matches():
    line = make_line(content='api_key = "AKIA..."')
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(line, [make_rule_match(90)], 20, signals)
    assert "combo:keyword+entropy" not in result.score_breakdown
    assert "combo:high+entropy+assignment" not in result.score_breakdown


def test_no_combo_when_entropy_zero():
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(make_line(), [], 0, signals)
    assert "combo:keyword+entropy" not in result.score_breakdown


def test_tp12_api_key_reaches_block():
    line = DiffLine(
        file_path="app.py",
        line_number=1,
        content='api_key = "x8fa2dKq9Lm3Wn5Pqv7Zb4Cj6Hs0Ue"',  # keygate: ignore reason="TP12 test fixture"
    )
    signals = ctx(keyword_score=25, keyword_tier="high", assignment_score=15)
    result = aggregate(line, [], 20, signals)
    assert result.verdict == Verdict.BLOCK


def test_tp21_yaml_password_reaches_block():
    line = DiffLine(
        file_path="config.yaml",
        line_number=2,
        content='  password: "ProdDbSecret9Kx2Lq7MnZ"',  # keygate: ignore reason="TP21 test fixture"
    )
    signals = ctx(
        keyword_score=25, keyword_tier="high", assignment_score=15, path_score=15,
    )
    result = aggregate(line, [], 20, signals)
    assert result.verdict == Verdict.BLOCK


def test_tp22_settings_secret_key_reaches_block():
    line = DiffLine(
        file_path="settings.py",
        line_number=1,
        content='SECRET_KEY = "django-insecure-Kx9Lq2Mn7Vb5Wr8Cf4Hj0Ds6Ue3Zp"',  # keygate: ignore reason="TP22 test fixture"
    )
    signals = ctx(
        keyword_score=25, keyword_tier="high", assignment_score=15, path_score=15,
    )
    result = aggregate(line, [], 20, signals)
    assert result.verdict == Verdict.BLOCK


def test_breakdown_includes_context_parts():
    signals = ctx(
        keyword_score=25, keyword_tier="high", assignment_score=15, path_score=15,
    )
    result = aggregate(make_line(), [], 20, signals)
    assert result.score_breakdown["keyword:high"] == 25
    assert result.score_breakdown["assignment"] == 15
    assert result.score_breakdown["path"] == 15
    assert result.score_breakdown["entropy"] == 20
