"""Documented split between reveng.pipeline and reveng.pipelines (M5-PIPE)."""

from reveng import pipeline, pipelines


def test_pipeline_and_pipelines_remain_distinct_packages():
    assert pipeline.__name__ == "reveng.pipeline"
    assert pipelines.__name__ == "reveng.pipelines"
    assert "pipelines" in (pipeline.__doc__ or "")
    assert "pipeline" in (pipelines.__doc__ or "")
    assert hasattr(pipelines, "AutomatedAnalysisPipeline")
    assert hasattr(pipeline, "steps")
