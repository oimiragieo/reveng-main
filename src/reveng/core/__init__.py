"""REVENG core foundation layer.

Cross-cutting primitives depended on by every higher domain: exceptions,
error codes, validation, configuration, shared result/IR contracts, and the
shared AI data models. This layer must not import any higher-level domain
(enforced by the ``core-is-foundation`` import-linter contract).
"""
