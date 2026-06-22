# trie_re.py — build a prefix-trie regex from many literal strings.
#
# A flat alternation `a|b|c|...` makes Python's `re` try every alternative at
# every position (O(N) per position, lots of backtracking). Factoring the
# strings into a trie and emitting `(?:...)` groups + character classes lets the
# C regex engine dispatch on the next character, which is dramatically faster for
# large keyword sets — while matching exactly the same set of strings.

import re


def _pattern(node):
    # Leaf (only the end-marker): caller emits this branch as a bare character.
    if "" in node and len(node) == 1:
        return None

    alt = []
    cc = []
    optional = False
    for ch in sorted(k for k in node if k != ""):
        rec = _pattern(node[ch])
        if rec is None:
            cc.append(re.escape(ch))
        else:
            alt.append(re.escape(ch) + rec)
    if "" in node:
        optional = True

    if cc:
        alt.append(cc[0] if len(cc) == 1 else "[" + "".join(cc) + "]")

    result = alt[0] if len(alt) == 1 else "(?:" + "|".join(alt) + ")"
    if optional:
        result = "(?:" + result + ")?"
    return result


def build_trie_pattern(words):
    """Return a regex string matching exactly the given literal words."""
    root = {}
    for word in words:
        node = root
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = None
    if not root:
        return None
    return _pattern(root)
