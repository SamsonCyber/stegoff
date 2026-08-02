# Independent repro: offline unit suite (no Ollama, no cloud APIs).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
python -m pip install -e ".[dev]" -q
python -m pytest -q `
  tests/test_text_detectors.py `
  tests/test_prompt_injection.py `
  tests/test_pipeline_integration.py `
  tests/test_false_positives.py `
  tests/test_sanitizers.py `
  tests/test_html_sanitizer_redteam.py `
  tests/test_injection_redteam.py `
  tests/test_semantic_detectors.py `
  tests/test_ml_classifier.py `
  tests/test_orchestrator.py `
  tests/test_guard_decorator.py `
  tests/test_classifier_robustness.py `
  --ignore=tests/test_ollama_redteam.py
Write-Output "REPRO_OK stegoff offline suite"
