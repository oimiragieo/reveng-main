# Misc-2 Milestone: Codebase Patterns

## Lazy Imports (PEP 562) in Package `__init__.py` Files

`src/reveng/__init__.py` and `src/reveng/ml/__init__.py` now use PEP 562 lazy `__getattr__` imports instead of eager top-level imports. Public symbols are defined in a `_LAZY_IMPORTS` dict mapping names to their module paths. When adding new public exports, add entries to `_LAZY_IMPORTS` rather than adding direct import statements.

Example pattern:
```python
_LAZY_IMPORTS = {
    "REVENGAnalyzer": ".analyzer",
    "NewClass": ".new_module",
}

def __getattr__(name):
    if name in _LAZY_IMPORTS:
        module = importlib.import_module(_LAZY_IMPORTS[name], __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
```

## Singleton Model Cache in `forensics_anomaly_models.py`

`src/reveng/ml/forensics_anomaly_models.py` uses a thread-safe per-class singleton pattern (`_instances` ClassVar dict + `_instance_lock` + double-checked locking in `__new__`/`__init__`) to ensure Isolation Forest models are trained exactly once per process lifetime. To reset the cache in tests, use `ModelClass._instances.pop(ModelClass, None)`.
