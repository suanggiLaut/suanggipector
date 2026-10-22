#!/usr/bin/env python3
"""
suanggipector.modules.ast_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tree-sitter AST parser for JavaScript sink extraction.
Detects: fetch(), axios(), axios.get/post/put/delete(),
XMLHttpRequest.open(), and API route string literals.

Requires: tree-sitter >= 0.22.0, tree-sitter-javascript >= 0.23.0
(uses the modern Python API — Language.build() is NOT called).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from colorama import Fore

# ---------------------------------------------------------------------------
# API route patterns (extracted from string literals in AST)
# ---------------------------------------------------------------------------
_API_ROUTE_PATTERNS = [
    re.compile(r'^/api/v\d+/'),           # /api/v1/users
    re.compile(r'^/v\d+/'),               # /v1/accounts
    re.compile(r'^/api/'),                 # /api/auth/login
    re.compile(r'^/graphql'),             # /graphql
    re.compile(r'^/rest/'),               # /rest/endpoint
    re.compile(r'^/internal/'),           # /internal/admin
    re.compile(r'^/admin/'),              # /admin/settings
    re.compile(r'^/auth/'),               # /auth/callback
    re.compile(r'^/oauth/'),              # /oauth/token
    re.compile(r'^/webhook'),             # /webhook/stripe
]

# Sinks we want to find in call expressions
_SINK_FUNCTIONS = {'fetch', 'axios', 'XMLHttpRequest'}
_AXIOS_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request'}


@dataclass
class ASTFinding:
    """A single sink or route finding from AST analysis."""
    kind: str           # 'fetch_call', 'axios_call', 'xhr_open', 'api_route'
    value: str          # URL or route string
    line: int = 0
    column: int = 0


@dataclass
class ASTResult:
    """Aggregated AST analysis result for one JS file."""
    source_url: str
    sinks: list[ASTFinding] = field(default_factory=list)
    api_routes: list[ASTFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.sinks) + len(self.api_routes)

    def to_dict(self) -> dict:
        return {
            "source": self.source_url,
            "sinks": [
                {"kind": f.kind, "value": f.value, "line": f.line, "col": f.column}
                for f in self.sinks
            ],
            "api_routes": [
                {"kind": f.kind, "value": f.value, "line": f.line, "col": f.column}
                for f in self.api_routes
            ],
            "errors": self.errors,
        }


class ASTAnalyzer:
    """
    Tree-sitter based JavaScript AST analyzer.

    Uses the modern tree-sitter Python API (>= 0.22.x) where
    ``tree_sitter_javascript.language()`` returns the Language
    pointer directly.
    """

    def __init__(self):
        self._parser = None
        self._language = None
        self._available = None  # None = not checked yet

    # ------------------------------------------------------------------
    # Lazy init
    # ------------------------------------------------------------------
    def _ensure_parser(self) -> bool:
        """Initialize tree-sitter parser. Returns True if available."""
        if self._available is not None:
            return self._available

        try:
            import tree_sitter
            import tree_sitter_javascript

            self._language = tree_sitter.Language(
                tree_sitter_javascript.language()
            )
            self._parser = tree_sitter.Parser(self._language)
            self._available = True
        except ImportError as exc:
            print(
                Fore.YELLOW +
                f"[AST] tree-sitter not available: {exc}. "
                "Install with: pip install tree-sitter tree-sitter-javascript"
            )
            self._available = False
        except Exception as exc:
            print(Fore.RED + f"[AST] Failed to initialize parser: {exc}")
            self._available = False

        return self._available

    @property
    def available(self) -> bool:
        return self._ensure_parser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, source_url: str, js_content: str) -> ASTResult:
        """
        Parse JS content and extract sinks + API routes.
        Falls back to regex-only if tree-sitter is unavailable.
        """
        result = ASTResult(source_url=source_url)

        if not self._ensure_parser():
            # Fallback: regex-based route extraction only
            result.errors.append("tree-sitter unavailable; regex fallback only")
            self._extract_routes_regex(js_content, result)
            return result

        try:
            tree = self._parser.parse(js_content.encode('utf-8'))
            root = tree.root_node
            self._walk_node(root, js_content, result)
        except Exception as exc:
            result.errors.append(f"AST parse error: {exc}")
            self._extract_routes_regex(js_content, result)

        # Always supplement with regex-based route extraction
        self._extract_routes_regex(js_content, result)

        # Deduplicate
        result.sinks = self._deduplicate(result.sinks)
        result.api_routes = self._deduplicate(result.api_routes)

        return result

    # ------------------------------------------------------------------
    # AST walking
    # ------------------------------------------------------------------
    def _walk_node(self, node, source: str, result: ASTResult):
        """Recursively walk the AST tree looking for call expressions."""
        if node.type == 'call_expression':
            self._check_call(node, source, result)

        for child in node.children:
            self._walk_node(child, source, result)

    def _check_call(self, node, source: str, result: ASTResult):
        """Check if a call_expression is a known sink."""
        func_node = node.child_by_field_name('function')
        if func_node is None:
            return

        args_node = node.child_by_field_name('arguments')
        first_arg = self._get_first_string_arg(args_node) if args_node else None

        # --- fetch("url") ---
        if func_node.type == 'identifier' and func_node.text.decode() == 'fetch':
            value = first_arg or '<dynamic>'
            result.sinks.append(ASTFinding(
                kind='fetch_call',
                value=value,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
            ))

        # --- axios("url") or axios.get("url") ---
        elif func_node.type == 'identifier' and func_node.text.decode() == 'axios':
            value = first_arg or '<dynamic>'
            result.sinks.append(ASTFinding(
                kind='axios_call',
                value=value,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
            ))

        elif func_node.type == 'member_expression':
            obj = func_node.child_by_field_name('object')
            prop = func_node.child_by_field_name('property')
            if obj and prop:
                obj_name = obj.text.decode() if obj.type == 'identifier' else ''
                prop_name = prop.text.decode() if prop.type == 'property_identifier' else ''

                # axios.get / axios.post / etc.
                if obj_name == 'axios' and prop_name in _AXIOS_METHODS:
                    value = first_arg or '<dynamic>'
                    result.sinks.append(ASTFinding(
                        kind=f'axios_{prop_name}',
                        value=value,
                        line=node.start_point[0] + 1,
                        column=node.start_point[1],
                    ))

                # XMLHttpRequest.open("GET", "url")
                elif prop_name == 'open':
                    second_arg = self._get_nth_string_arg(args_node, 1) if args_node else None
                    if second_arg:
                        result.sinks.append(ASTFinding(
                            kind='xhr_open',
                            value=second_arg,
                            line=node.start_point[0] + 1,
                            column=node.start_point[1],
                        ))

    def _get_first_string_arg(self, args_node) -> Optional[str]:
        """Extract first string literal argument from an arguments node."""
        return self._get_nth_string_arg(args_node, 0)

    def _get_nth_string_arg(self, args_node, n: int) -> Optional[str]:
        """Extract the Nth string literal argument."""
        if args_node is None:
            return None
        idx = 0
        for child in args_node.children:
            if child.type in ('string', 'template_string'):
                if idx == n:
                    text = child.text.decode()
                    # Strip quotes
                    if len(text) >= 2 and text[0] in ('"', "'", '`'):
                        text = text[1:-1]
                    return text
                idx += 1
            elif child.type not in (',', '(', ')'):
                if idx == n:
                    return None
                idx += 1
        return None

    # ------------------------------------------------------------------
    # Regex-based route extraction (always runs as supplement)
    # ------------------------------------------------------------------
    def _extract_routes_regex(self, js_content: str, result: ASTResult):
        """Extract API route literals via regex patterns."""
        existing_routes = {f.value for f in result.api_routes}

        # Find string literals that look like API routes
        for match in re.finditer(r'''["'`](/[a-zA-Z0-9_/\-.:]+)["'`]''', js_content):
            route = match.group(1)
            if route in existing_routes:
                continue
            for pattern in _API_ROUTE_PATTERNS:
                if pattern.match(route):
                    line_num = js_content[:match.start()].count('\n') + 1
                    result.api_routes.append(ASTFinding(
                        kind='api_route',
                        value=route,
                        line=line_num,
                    ))
                    existing_routes.add(route)
                    break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _deduplicate(findings: list[ASTFinding]) -> list[ASTFinding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.kind, f.value)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
