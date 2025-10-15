#!/usr/bin/env python3
"""
NLP Code Analyzer
================

Natural Language Processing for code analysis and documentation generation.
Provides semantic analysis, code summarization, and automated documentation.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from collections import Counter, defaultdict
import math

try:
    from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.cluster import KMeans
    from sklearn.decomposition import LatentDirichletAllocation
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available - NLP features limited")

try:
    # Optional: Advanced NLP libraries
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.stem import PorterStemmer, WordNetLemmatizer
    from nltk.tag import pos_tag
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logging.info("NLTK not available - using basic NLP features")

try:
    from .ai_enhanced_data_models import (
        CodeSummary, SemanticAnalysis, DocumentationSuggestion,
        Evidence, EvidenceTracker
    )
except ImportError:
    from ai_enhanced_data_models import (
        CodeSummary, SemanticAnalysis, DocumentationSuggestion,
        Evidence, EvidenceTracker
    )


@dataclass
class CodeSemantics:
    """Semantic information extracted from code"""
    # Function analysis
    function_purposes: Dict[str, str] = None
    variable_meanings: Dict[str, str] = None
    class_descriptions: Dict[str, str] = None
    
    # Code patterns
    design_patterns: List[str] = None
    algorithms_detected: List[str] = None
    data_structures: List[str] = None
    
    # Quality metrics
    complexity_score: float = 0.0
    readability_score: float = 0.0
    maintainability_score: float = 0.0
    
    # Documentation quality
    comment_coverage: float = 0.0
    docstring_quality: float = 0.0
    naming_quality: float = 0.0
    
    def __post_init__(self):
        if self.function_purposes is None:
            self.function_purposes = {}
        if self.variable_meanings is None:
            self.variable_meanings = {}
        if self.class_descriptions is None:
            self.class_descriptions = {}
        if self.design_patterns is None:
            self.design_patterns = []
        if self.algorithms_detected is None:
            self.algorithms_detected = []
        if self.data_structures is None:
            self.data_structures = []


class CodeTokenizer:
    """Tokenize and preprocess code for NLP analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Programming language keywords to filter out
        self.keywords = {
            'c': ['int', 'char', 'float', 'double', 'void', 'if', 'else', 'for', 'while', 
                  'return', 'include', 'define', 'struct', 'typedef', 'static', 'extern'],
            'python': ['def', 'class', 'if', 'else', 'elif', 'for', 'while', 'try', 'except',
                      'import', 'from', 'return', 'yield', 'lambda', 'with', 'as'],
            'java': ['public', 'private', 'protected', 'static', 'final', 'class', 'interface',
                    'extends', 'implements', 'if', 'else', 'for', 'while', 'try', 'catch'],
            'javascript': ['function', 'var', 'let', 'const', 'if', 'else', 'for', 'while',
                          'try', 'catch', 'return', 'class', 'extends', 'import', 'export']
        }
        
        # Common code patterns
        self.code_patterns = {
            'camelCase': re.compile(r'[a-z]+([A-Z][a-z]*)+'),
            'snake_case': re.compile(r'[a-z]+(_[a-z]+)+'),
            'CONSTANT': re.compile(r'[A-Z]+(_[A-Z]+)*'),
            'function_call': re.compile(r'\w+\s*\([^)]*\)'),
            'variable_assignment': re.compile(r'\w+\s*=\s*[^;]+'),
        }
        
        # Initialize NLTK components if available
        if NLTK_AVAILABLE:
            try:
                self.stemmer = PorterStemmer()
                self.lemmatizer = WordNetLemmatizer()
                # Download required NLTK data
                nltk.download('punkt', quiet=True)
                nltk.download('stopwords', quiet=True)
                nltk.download('wordnet', quiet=True)
                nltk.download('averaged_perceptron_tagger', quiet=True)
                self.stop_words = set(stopwords.words('english'))
            except Exception as e:
                self.logger.warning(f"NLTK initialization failed: {e}")
                self.stemmer = None
                self.lemmatizer = None
                self.stop_words = set()
        else:
            self.stemmer = None
            self.lemmatizer = None
            self.stop_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])
    
    def tokenize_code(self, code: str, language: str = "c") -> List[str]:
        """Tokenize code into meaningful tokens"""
        tokens = []
        
        # Extract identifiers (variable names, function names, etc.)
        identifier_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
        identifiers = identifier_pattern.findall(code)
        
        # Filter out language keywords
        lang_keywords = self.keywords.get(language, [])
        filtered_identifiers = [
            token for token in identifiers 
            if token.lower() not in lang_keywords and len(token) > 1
        ]
        
        # Split camelCase and snake_case identifiers
        for identifier in filtered_identifiers:
            tokens.extend(self._split_identifier(identifier))
        
        # Extract string literals
        string_pattern = re.compile(r'"([^"]*)"')
        strings = string_pattern.findall(code)
        for string in strings:
            if len(string) > 2:  # Skip very short strings
                tokens.extend(self._tokenize_text(string))
        
        # Extract comments
        comment_patterns = [
            re.compile(r'//(.*)'),  # Single line comments
            re.compile(r'/\*(.*?)\*/', re.DOTALL),  # Multi-line comments
            re.compile(r'#(.*)'),  # Python/shell comments
        ]
        
        for pattern in comment_patterns:
            comments = pattern.findall(code)
            for comment in comments:
                if isinstance(comment, tuple):
                    comment = comment[0] if comment else ""
                tokens.extend(self._tokenize_text(comment))
        
        # Clean and filter tokens
        cleaned_tokens = []
        for token in tokens:
            token = token.lower().strip()
            if (len(token) > 2 and 
                token not in self.stop_words and 
                token.isalpha()):
                cleaned_tokens.append(token)
        
        return cleaned_tokens
    
    def _split_identifier(self, identifier: str) -> List[str]:
        """Split camelCase and snake_case identifiers into words"""
        words = []
        
        # Handle snake_case
        if '_' in identifier:
            words.extend(identifier.split('_'))
        
        # Handle camelCase
        elif re.match(self.code_patterns['camelCase'], identifier):
            # Split on capital letters
            parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)', identifier)
            words.extend(parts)
        
        else:
            words.append(identifier)
        
        # Filter out single characters and numbers
        return [word.lower() for word in words if len(word) > 1 and word.isalpha()]
    
    def _tokenize_text(self, text: str) -> List[str]:
        """Tokenize natural language text"""
        if NLTK_AVAILABLE and self.stemmer:
            try:
                tokens = word_tokenize(text.lower())
                # Remove punctuation and short words
                tokens = [token for token in tokens if token.isalpha() and len(token) > 2]
                # Remove stop words
                tokens = [token for token in tokens if token not in self.stop_words]
                # Stem words
                tokens = [self.stemmer.stem(token) for token in tokens]
                return tokens
            except Exception as e:
                self.logger.warning(f"NLTK tokenization failed: {e}")
        
        # Fallback to simple tokenization
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        return [word for word in words if word not in self.stop_words]


class SemanticAnalyzer:
    """Analyze semantic meaning of code using NLP techniques"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.tokenizer = CodeTokenizer()
        
        # Initialize vectorizers
        if SKLEARN_AVAILABLE:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 2),
                min_df=2
            )
            self.count_vectorizer = CountVectorizer(
                max_features=500,
                ngram_range=(1, 2)
            )
        
        # Semantic dictionaries
        self.algorithm_keywords = {
            'sorting': ['sort', 'bubble', 'quick', 'merge', 'heap', 'insertion', 'selection'],
            'searching': ['search', 'find', 'binary', 'linear', 'hash', 'lookup'],
            'graph': ['graph', 'node', 'edge', 'vertex', 'tree', 'traverse', 'dfs', 'bfs'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'cipher', 'key', 'crypto', 'aes', 'rsa'],
            'network': ['socket', 'connect', 'send', 'receive', 'http', 'tcp', 'udp'],
            'file': ['file', 'read', 'write', 'open', 'close', 'stream', 'buffer'],
            'memory': ['malloc', 'free', 'alloc', 'memory', 'buffer', 'pointer', 'heap'],
            'string': ['string', 'char', 'text', 'parse', 'format', 'concat', 'split']
        }
        
        self.design_patterns = {
            'singleton': ['singleton', 'instance', 'static', 'single'],
            'factory': ['factory', 'create', 'make', 'build', 'construct'],
            'observer': ['observer', 'notify', 'update', 'subscribe', 'event'],
            'strategy': ['strategy', 'algorithm', 'behavior', 'policy'],
            'decorator': ['decorator', 'wrap', 'enhance', 'extend'],
            'adapter': ['adapter', 'convert', 'translate', 'bridge'],
            'mvc': ['model', 'view', 'controller', 'mvc', 'mvp', 'mvvm']
        }
        
        self.data_structures = {
            'array': ['array', 'list', 'vector', 'sequence'],
            'linked_list': ['linked', 'list', 'node', 'next', 'prev'],
            'stack': ['stack', 'push', 'pop', 'lifo'],
            'queue': ['queue', 'enqueue', 'dequeue', 'fifo'],
            'tree': ['tree', 'root', 'leaf', 'branch', 'binary'],
            'hash_table': ['hash', 'table', 'map', 'dictionary', 'bucket'],
            'graph': ['graph', 'vertex', 'edge', 'adjacency']
        }
    
    def analyze_code_semantics(self, code: str, language: str = "c") -> CodeSemantics:
        """Perform comprehensive semantic analysis of code"""
        semantics = CodeSemantics()
        
        try:
            # Tokenize code
            tokens = self.tokenizer.tokenize_code(code, language)
            
            if not tokens:
                return semantics
            
            # Analyze algorithms and patterns
            semantics.algorithms_detected = self._detect_algorithms(tokens)
            semantics.design_patterns = self._detect_design_patterns(tokens)
            semantics.data_structures = self._detect_data_structures(tokens)
            
            # Analyze code structure
            semantics.function_purposes = self._analyze_functions(code, tokens)
            semantics.variable_meanings = self._analyze_variables(code, tokens)
            semantics.class_descriptions = self._analyze_classes(code, tokens)
            
            # Calculate quality metrics
            semantics.complexity_score = self._calculate_complexity(code)
            semantics.readability_score = self._calculate_readability(code, tokens)
            semantics.maintainability_score = self._calculate_maintainability(code, tokens)
            
            # Analyze documentation quality
            semantics.comment_coverage = self._calculate_comment_coverage(code)
            semantics.docstring_quality = self._analyze_docstring_quality(code)
            semantics.naming_quality = self._analyze_naming_quality(tokens)
            
            return semantics
            
        except Exception as e:
            self.logger.error(f"Error in semantic analysis: {e}")
            return semantics
    
    def _detect_algorithms(self, tokens: List[str]) -> List[str]:
        """Detect algorithms based on token analysis"""
        detected = []
        token_set = set(tokens)
        
        for algorithm, keywords in self.algorithm_keywords.items():
            # Calculate overlap between tokens and algorithm keywords
            overlap = len(token_set.intersection(set(keywords)))
            if overlap >= 2:  # Require at least 2 matching keywords
                detected.append(algorithm)
        
        return detected
    
    def _detect_design_patterns(self, tokens: List[str]) -> List[str]:
        """Detect design patterns based on token analysis"""
        detected = []
        token_set = set(tokens)
        
        for pattern, keywords in self.design_patterns.items():
            overlap = len(token_set.intersection(set(keywords)))
            if overlap >= 2:
                detected.append(pattern)
        
        return detected
    
    def _detect_data_structures(self, tokens: List[str]) -> List[str]:
        """Detect data structures based on token analysis"""
        detected = []
        token_set = set(tokens)
        
        for structure, keywords in self.data_structures.items():
            overlap = len(token_set.intersection(set(keywords)))
            if overlap >= 1:  # Data structures need fewer matches
                detected.append(structure)
        
        return detected
    
    def _analyze_functions(self, code: str, tokens: List[str]) -> Dict[str, str]:
        """Analyze function purposes based on names and content"""
        functions = {}
        
        # Extract function definitions
        function_patterns = [
            re.compile(r'(\w+)\s*\([^)]*\)\s*{', re.MULTILINE),  # C-style
            re.compile(r'def\s+(\w+)\s*\([^)]*\):', re.MULTILINE),  # Python
            re.compile(r'function\s+(\w+)\s*\([^)]*\)', re.MULTILINE),  # JavaScript
        ]
        
        for pattern in function_patterns:
            matches = pattern.findall(code)
            for func_name in matches:
                purpose = self._infer_function_purpose(func_name, tokens)
                if purpose:
                    functions[func_name] = purpose
        
        return functions
    
    def _infer_function_purpose(self, func_name: str, tokens: List[str]) -> str:
        """Infer function purpose from name and context"""
        name_parts = self.tokenizer._split_identifier(func_name)
        
        # Common function purpose patterns
        if any(part in ['init', 'initialize', 'setup'] for part in name_parts):
            return "Initialization function"
        elif any(part in ['create', 'make', 'build', 'construct'] for part in name_parts):
            return "Constructor/Factory function"
        elif any(part in ['destroy', 'cleanup', 'free', 'delete'] for part in name_parts):
            return "Destructor/Cleanup function"
        elif any(part in ['get', 'fetch', 'retrieve', 'find'] for part in name_parts):
            return "Getter/Accessor function"
        elif any(part in ['set', 'update', 'modify', 'change'] for part in name_parts):
            return "Setter/Mutator function"
        elif any(part in ['process', 'handle', 'execute', 'run'] for part in name_parts):
            return "Processing function"
        elif any(part in ['validate', 'check', 'verify', 'test'] for part in name_parts):
            return "Validation function"
        elif any(part in ['parse', 'decode', 'convert', 'transform'] for part in name_parts):
            return "Parsing/Conversion function"
        elif any(part in ['send', 'transmit', 'communicate'] for part in name_parts):
            return "Communication function"
        elif any(part in ['calculate', 'compute', 'solve'] for part in name_parts):
            return "Calculation function"
        else:
            return f"Function related to {', '.join(name_parts[:2])}"
    
    def _analyze_variables(self, code: str, tokens: List[str]) -> Dict[str, str]:
        """Analyze variable meanings based on names and usage"""
        variables = {}
        
        # Extract variable declarations
        var_patterns = [
            re.compile(r'(?:int|char|float|double|void\*?)\s+(\w+)', re.MULTILINE),  # C
            re.compile(r'(\w+)\s*=\s*[^;]+', re.MULTILINE),  # General assignment
        ]
        
        for pattern in var_patterns:
            matches = pattern.findall(code)
            for var_name in matches:
                if len(var_name) > 2:  # Skip very short names
                    meaning = self._infer_variable_meaning(var_name)
                    if meaning:
                        variables[var_name] = meaning
        
        return variables
    
    def _infer_variable_meaning(self, var_name: str) -> str:
        """Infer variable meaning from name"""
        name_parts = self.tokenizer._split_identifier(var_name)
        
        # Common variable patterns
        if any(part in ['count', 'num', 'number'] for part in name_parts):
            return "Counter or numeric value"
        elif any(part in ['index', 'idx', 'pos', 'position'] for part in name_parts):
            return "Index or position variable"
        elif any(part in ['size', 'length', 'len'] for part in name_parts):
            return "Size or length variable"
        elif any(part in ['buffer', 'buf', 'data'] for part in name_parts):
            return "Data buffer or storage"
        elif any(part in ['result', 'ret', 'return'] for part in name_parts):
            return "Return value or result"
        elif any(part in ['temp', 'tmp', 'temporary'] for part in name_parts):
            return "Temporary variable"
        elif any(part in ['flag', 'status', 'state'] for part in name_parts):
            return "Status or flag variable"
        elif any(part in ['ptr', 'pointer'] for part in name_parts):
            return "Pointer variable"
        else:
            return f"Variable for {', '.join(name_parts[:2])}"
    
    def _analyze_classes(self, code: str, tokens: List[str]) -> Dict[str, str]:
        """Analyze class purposes and descriptions"""
        classes = {}
        
        # Extract class definitions
        class_patterns = [
            re.compile(r'class\s+(\w+)', re.MULTILINE),  # C++/Java/Python
            re.compile(r'struct\s+(\w+)', re.MULTILINE),  # C struct
        ]
        
        for pattern in class_patterns:
            matches = pattern.findall(code)
            for class_name in matches:
                description = self._infer_class_purpose(class_name)
                if description:
                    classes[class_name] = description
        
        return classes
    
    def _infer_class_purpose(self, class_name: str) -> str:
        """Infer class purpose from name"""
        name_parts = self.tokenizer._split_identifier(class_name)
        
        # Common class patterns
        if any(part in ['manager', 'handler', 'controller'] for part in name_parts):
            return "Management or control class"
        elif any(part in ['factory', 'builder', 'creator'] for part in name_parts):
            return "Factory or builder class"
        elif any(part in ['parser', 'processor', 'analyzer'] for part in name_parts):
            return "Processing or analysis class"
        elif any(part in ['client', 'server', 'connection'] for part in name_parts):
            return "Network or communication class"
        elif any(part in ['model', 'data', 'entity'] for part in name_parts):
            return "Data model or entity class"
        elif any(part in ['view', 'ui', 'interface'] for part in name_parts):
            return "User interface class"
        elif any(part in ['util', 'helper', 'tool'] for part in name_parts):
            return "Utility or helper class"
        else:
            return f"Class for {', '.join(name_parts[:2])}"
    
    def _calculate_complexity(self, code: str) -> float:
        """Calculate code complexity score"""
        # Cyclomatic complexity approximation
        decision_points = len(re.findall(r'\b(if|else|while|for|switch|case|catch)\b', code))
        lines = len(code.split('\n'))
        
        if lines == 0:
            return 0.0
        
        # Normalize complexity (lower is better)
        complexity = decision_points / lines
        return min(complexity * 10, 10.0)  # Scale to 0-10
    
    def _calculate_readability(self, code: str, tokens: List[str]) -> float:
        """Calculate code readability score"""
        lines = code.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        if not non_empty_lines:
            return 0.0
        
        # Factors affecting readability
        avg_line_length = sum(len(line) for line in non_empty_lines) / len(non_empty_lines)
        comment_lines = len([line for line in lines if line.strip().startswith(('//','#','/*'))])
        comment_ratio = comment_lines / len(non_empty_lines) if non_empty_lines else 0
        
        # Readability score (0-10, higher is better)
        readability = 10.0
        
        # Penalize very long lines
        if avg_line_length > 100:
            readability -= 2.0
        elif avg_line_length > 80:
            readability -= 1.0
        
        # Reward good commenting
        if comment_ratio > 0.2:
            readability += 1.0
        elif comment_ratio < 0.05:
            readability -= 1.0
        
        return max(0.0, min(10.0, readability))
    
    def _calculate_maintainability(self, code: str, tokens: List[str]) -> float:
        """Calculate code maintainability score"""
        # Factors: function length, variable naming, complexity
        functions = len(re.findall(r'\b\w+\s*\([^)]*\)\s*{', code))
        lines = len(code.split('\n'))
        
        if functions == 0:
            avg_function_length = lines
        else:
            avg_function_length = lines / functions
        
        # Maintainability score (0-10, higher is better)
        maintainability = 10.0
        
        # Penalize very long functions
        if avg_function_length > 100:
            maintainability -= 3.0
        elif avg_function_length > 50:
            maintainability -= 1.5
        
        # Reward good naming (longer identifiers are generally better)
        if tokens:
            avg_token_length = sum(len(token) for token in tokens) / len(tokens)
            if avg_token_length > 8:
                maintainability += 1.0
            elif avg_token_length < 4:
                maintainability -= 1.0
        
        return max(0.0, min(10.0, maintainability))
    
    def _calculate_comment_coverage(self, code: str) -> float:
        """Calculate comment coverage percentage"""
        lines = code.split('\n')
        total_lines = len([line for line in lines if line.strip()])
        comment_lines = len([line for line in lines if line.strip().startswith(('//','#','/*'))])
        
        if total_lines == 0:
            return 0.0
        
        return (comment_lines / total_lines) * 100
    
    def _analyze_docstring_quality(self, code: str) -> float:
        """Analyze quality of docstrings and comments"""
        # Find docstrings and comments
        docstring_pattern = re.compile(r'"""(.*?)"""', re.DOTALL)
        comment_pattern = re.compile(r'//(.*)|\#(.*)|/\*(.*?)\*/', re.DOTALL)
        
        docstrings = docstring_pattern.findall(code)
        comments = comment_pattern.findall(code)
        
        total_docs = len(docstrings) + len(comments)
        if total_docs == 0:
            return 0.0
        
        # Analyze quality based on length and content
        quality_score = 0.0
        
        for docstring in docstrings:
            if len(docstring) > 50:  # Substantial documentation
                quality_score += 2.0
            elif len(docstring) > 20:
                quality_score += 1.0
        
        for comment_tuple in comments:
            comment = ''.join(filter(None, comment_tuple))
            if len(comment) > 30:
                quality_score += 1.0
            elif len(comment) > 10:
                quality_score += 0.5
        
        return min(10.0, quality_score)
    
    def _analyze_naming_quality(self, tokens: List[str]) -> float:
        """Analyze quality of variable and function naming"""
        if not tokens:
            return 0.0
        
        # Quality factors
        avg_length = sum(len(token) for token in tokens) / len(tokens)
        descriptive_names = len([token for token in tokens if len(token) > 5])
        
        # Naming quality score (0-10)
        quality = 5.0  # Base score
        
        # Reward longer, more descriptive names
        if avg_length > 8:
            quality += 2.0
        elif avg_length > 6:
            quality += 1.0
        elif avg_length < 3:
            quality -= 2.0
        
        # Reward high percentage of descriptive names
        descriptive_ratio = descriptive_names / len(tokens)
        if descriptive_ratio > 0.7:
            quality += 1.5
        elif descriptive_ratio < 0.3:
            quality -= 1.0
        
        return max(0.0, min(10.0, quality))


class DocumentationGenerator:
    """Generate automated documentation and suggestions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.semantic_analyzer = SemanticAnalyzer()
        self.evidence_tracker = EvidenceTracker()
    
    def generate_code_summary(self, code: str, language: str = "c") -> CodeSummary:
        """Generate comprehensive code summary"""
        try:
            # Perform semantic analysis
            semantics = self.semantic_analyzer.analyze_code_semantics(code, language)
            
            # Generate summary text
            summary_text = self._generate_summary_text(semantics, code)
            
            # Generate documentation suggestions
            suggestions = self._generate_documentation_suggestions(semantics, code)
            
            # Create evidence
            evidence = self.evidence_tracker.add_evidence(
                "nlp_code_analysis",
                "Generated code summary using NLP analysis",
                "natural_language_processing",
                0.8,
                {
                    "algorithms_detected": len(semantics.algorithms_detected),
                    "patterns_detected": len(semantics.design_patterns),
                    "functions_analyzed": len(semantics.function_purposes)
                }
            )
            
            summary = CodeSummary(
                overview=summary_text,
                key_functions=list(semantics.function_purposes.keys())[:5],
                algorithms_used=semantics.algorithms_detected,
                design_patterns=semantics.design_patterns,
                data_structures=semantics.data_structures,
                complexity_analysis={
                    "complexity_score": semantics.complexity_score,
                    "readability_score": semantics.readability_score,
                    "maintainability_score": semantics.maintainability_score
                },
                documentation_suggestions=suggestions,
                semantic_analysis=semantics,
                evidence=[evidence]
            )
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating code summary: {e}")
            return CodeSummary(
                overview="Error generating summary",
                key_functions=[],
                algorithms_used=[],
                design_patterns=[],
                data_structures=[],
                complexity_analysis={},
                documentation_suggestions=[],
                semantic_analysis=CodeSemantics()
            )
    
    def _generate_summary_text(self, semantics: CodeSemantics, code: str) -> str:
        """Generate natural language summary of code"""
        summary_parts = []
        
        # Basic code statistics
        lines = len(code.split('\n'))
        functions = len(semantics.function_purposes)
        
        summary_parts.append(f"This code contains {lines} lines with {functions} functions.")
        
        # Algorithms and patterns
        if semantics.algorithms_detected:
            algorithms_text = ", ".join(semantics.algorithms_detected)
            summary_parts.append(f"The code implements {algorithms_text} algorithms.")
        
        if semantics.design_patterns:
            patterns_text = ", ".join(semantics.design_patterns)
            summary_parts.append(f"It uses {patterns_text} design patterns.")
        
        if semantics.data_structures:
            structures_text = ", ".join(semantics.data_structures)
            summary_parts.append(f"The main data structures are {structures_text}.")
        
        # Quality assessment
        if semantics.complexity_score > 7:
            summary_parts.append("The code has high complexity and may be difficult to maintain.")
        elif semantics.complexity_score < 3:
            summary_parts.append("The code has low complexity and should be easy to understand.")
        
        if semantics.comment_coverage < 10:
            summary_parts.append("The code lacks sufficient documentation and comments.")
        elif semantics.comment_coverage > 30:
            summary_parts.append("The code is well-documented with good comment coverage.")
        
        # Function purposes
        if semantics.function_purposes:
            main_functions = list(semantics.function_purposes.items())[:3]
            func_descriptions = [f"{name} ({purpose})" for name, purpose in main_functions]
            summary_parts.append(f"Key functions include: {', '.join(func_descriptions)}.")
        
        return " ".join(summary_parts)
    
    def _generate_documentation_suggestions(self, semantics: CodeSemantics, code: str) -> List[DocumentationSuggestion]:
        """Generate suggestions for improving documentation"""
        suggestions = []
        
        # Comment coverage suggestions
        if semantics.comment_coverage < 15:
            suggestions.append(DocumentationSuggestion(
                type="comment_coverage",
                priority="high",
                description="Add more comments to explain complex logic and algorithms",
                suggestion="Aim for at least 20% comment coverage, focusing on non-obvious code sections",
                location="throughout_code"
            ))
        
        # Function documentation
        undocumented_functions = []
        for func_name in semantics.function_purposes.keys():
            if func_name not in code or f"/**" not in code:
                undocumented_functions.append(func_name)
        
        if undocumented_functions:
            suggestions.append(DocumentationSuggestion(
                type="function_documentation",
                priority="medium",
                description="Add function documentation for better maintainability",
                suggestion=f"Document functions: {', '.join(undocumented_functions[:5])}",
                location="function_definitions"
            ))
        
        # Naming improvements
        if semantics.naming_quality < 5:
            suggestions.append(DocumentationSuggestion(
                type="naming_quality",
                priority="medium",
                description="Improve variable and function naming for better readability",
                suggestion="Use more descriptive names that clearly indicate purpose",
                location="variable_declarations"
            ))
        
        # Complexity warnings
        if semantics.complexity_score > 7:
            suggestions.append(DocumentationSuggestion(
                type="complexity_reduction",
                priority="high",
                description="Consider refactoring to reduce code complexity",
                suggestion="Break down complex functions into smaller, more manageable pieces",
                location="complex_functions"
            ))
        
        # Algorithm documentation
        if semantics.algorithms_detected and semantics.comment_coverage < 20:
            suggestions.append(DocumentationSuggestion(
                type="algorithm_documentation",
                priority="medium",
                description="Document the algorithms used in the code",
                suggestion=f"Add explanations for {', '.join(semantics.algorithms_detected)} implementations",
                location="algorithm_sections"
            ))
        
        return suggestions


def main():
    """Main function for testing NLP code analyzer"""
    analyzer = DocumentationGenerator()
    
    # Test code
    test_code = """
    #include <stdio.h>
    #include <stdlib.h>
    
    // Bubble sort implementation
    void bubble_sort(int arr[], int n) {
        for (int i = 0; i < n-1; i++) {
            for (int j = 0; j < n-i-1; j++) {
                if (arr[j] > arr[j+1]) {
                    int temp = arr[j];
                    arr[j] = arr[j+1];
                    arr[j+1] = temp;
                }
            }
        }
    }
    
    int main() {
        int data[] = {64, 34, 25, 12, 22, 11, 90};
        int size = sizeof(data)/sizeof(data[0]);
        
        bubble_sort(data, size);
        
        printf("Sorted array: ");
        for (int i = 0; i < size; i++) {
            printf("%d ", data[i]);
        }
        return 0;
    }
    """
    
    print("Analyzing code with NLP...")
    summary = analyzer.generate_code_summary(test_code, "c")
    
    print(f"Overview: {summary.overview}")
    print(f"Algorithms: {summary.algorithms_used}")
    print(f"Key Functions: {summary.key_functions}")
    print(f"Complexity Score: {summary.complexity_analysis.get('complexity_score', 0):.2f}")
    print(f"Documentation Suggestions: {len(summary.documentation_suggestions)}")
    
    for suggestion in summary.documentation_suggestions:
        print(f"  - {suggestion.type}: {suggestion.description}")


if __name__ == "__main__":
    main()