# fastsub.py -- run a regex only where it can match.
#
# Python's `re` walks the text one position at a time unless the pattern
# starts with a plain literal, so a pattern like (?i)(?:password|token)...
# costs 10-50 MB/s whether or not the text holds a single secret. A plain
# substring search (str.find, str.count) runs at about 2 GB/s. This module
# reads a compiled pattern's parse tree once and derives, when it can:
#
#   first     literals one of which every match STARTS with
#   required  literals one of which every match CONTAINS
#   one_line  the pattern cannot consume a newline
#
# gsub() then gives exactly the result of pattern.sub(repl, text) while only
# running the pattern
#   - at the positions where a `first` literal occurs (any pattern), or
#   - on the lines that hold a `required` literal (one_line patterns),
# and not at all when no literal occurs. Whenever nothing can be derived, the
# literals are too frequent to pay off, or the text holds a character whose
# case folding is irregular, it falls back to pattern.sub. The pattern itself
# is never changed, so the result is the same by construction and the choice
# is only about speed.
#
# The parse tree comes from the private re parser; if that is missing or
# changes shape, every plan is simply "fall back".

import re

try:                                    # Python 3.11+
    from re import _parser as _sre_parse, _constants as _c
except ImportError:                     # Python 3.6 - 3.10
    import sre_parse as _sre_parse
    import sre_constants as _c

_MAX_SET = 64          # strings one exact set may hold while being built
_MAX_NEEDLES = 20      # literals worth a pass each over the text
# Non-ASCII characters that match an ASCII letter under re.IGNORECASE or that
# change length in lower(): with one of these in the text a lowercase copy
# is not a faithful index into it.
_IRREGULAR = ('\u0130', '\u0131', '\u017f', '\u212a')

_ZERO_WIDTH = {_c.AT, _c.ASSERT, _c.ASSERT_NOT}
_REPEATS = {_c.MAX_REPEAT, _c.MIN_REPEAT}
if hasattr(_c, 'POSSESSIVE_REPEAT'):
    _REPEATS.add(_c.POSSESSIVE_REPEAT)
_ATOMIC = getattr(_c, 'ATOMIC_GROUP', None)


if hasattr(str, 'isascii'):
    _is_ascii = str.isascii
else:                                    # Python 3.6
    def _is_ascii(s):
        try:
            s.encode('ascii')
        except UnicodeEncodeError:
            return False
        return True


def fold(text):
    """A lowercase copy of text with the same indices, or None when one
    cannot be relied on. The last result is remembered: a chain of passes
    that change nothing keeps handing the same object over."""
    if text is _fold_memo[0]:
        return _fold_memo[1]
    if len(text) < _MEMO_MIN:
        # a value handed over by a callback: not worth displacing the file
        return _fold(text)
    low = _fold(text)
    _fold_memo[0], _fold_memo[1], _fold_memo[2] = text, low, {}
    return low


def _fold(text):
    if _is_ascii(text):
        low = text.lower()
    elif any(ch in text for ch in _IRREGULAR):
        low = None
    else:
        # Block by block. lower() on a text with one non-ASCII character
        # goes character by character through a work buffer of 12 bytes per
        # character (a 32 MB segment: 128 MB touched); a block cut out of
        # it that holds none is plain ASCII again and takes the fast path.
        # A log with a few stray bytes is all but made of such blocks.
        low = ''.join([text[i:i + _FOLD_BLOCK].lower()
                       for i in range(0, len(text), _FOLD_BLOCK)])
        if len(low) != len(text):
            low = None
    return low


# text, its lowercase copy, {literal: occurrences in that copy}
_fold_memo = [None, None, {}]
_MEMO_MIN = 4096
_FOLD_BLOCK = 1 << 16


def forget():
    """Drop the remembered text (it can be tens of MB)."""
    _fold_memo[0] = _fold_memo[1] = None
    _fold_memo[2] = {}


# --- pattern analysis -------------------------------------------------------

def _sub_items(av):
    """The inner sequence of a SUBPATTERN node, across re versions."""
    return av[-1]


def _product(a, b):
    out = {x + y for x in a for y in b}
    return out if len(out) <= _MAX_SET else None


def _exact(op, av):
    """The finite set of lowercase strings a node can match, or None."""
    if op in _ZERO_WIDTH:
        return {''}
    if op is _c.LITERAL:
        return {chr(av).lower()} if av < 128 else None
    if op is _c.IN:
        out = set()
        for iop, iav in av:
            if iop is not _c.LITERAL or iav >= 128:
                return None
            out.add(chr(iav).lower())
        return out if len(out) <= 4 else None
    if op is _c.BRANCH:
        out = set()
        for alt in av[1]:
            s = _exact_seq(alt)
            if s is None:
                return None
            out |= s
        return out if len(out) <= _MAX_SET else None
    if op is _c.SUBPATTERN or op is _ATOMIC:
        return _exact_seq(_sub_items(av) if op is _c.SUBPATTERN else av)
    if op in _REPEATS:
        lo, hi, sub = av
        if (lo, hi) == (0, 1):
            s = _exact_seq(sub)
            return None if s is None else s | {''}
        if lo == hi == 1:
            return _exact_seq(sub)
    return None


def _exact_seq(seq):
    cur = {''}
    for op, av in seq:
        s = _exact(op, av)
        if s is None:
            return None
        cur = _product(cur, s)
        if cur is None:
            return None
    return cur


def _score(s):
    return (min(len(x) for x in s), -len(s))


def _runs(seq):
    """(index, set) for each maximal run of exact nodes in a sequence."""
    runs = []
    cur, start = None, 0
    for i, (op, av) in enumerate(seq):
        s = _exact(op, av)
        nxt = None if s is None else (_product(cur, s) if cur is not None else s)
        if nxt is None:
            if cur is not None:
                runs.append((start, cur))
            # an exact node that only overflowed the product starts a new run
            cur, start = (s, i) if s is not None else (None, i + 1)
        else:
            if cur is None:
                start = i
            cur = nxt
    if cur is not None:
        runs.append((start, cur))
    return runs


def _required(seq):
    """Literals one of which every match of seq contains, or None."""
    best = None
    for _i, s in _runs(seq):
        if '' in s:
            continue
        if best is None or _score(s) > _score(best):
            best = s
    for op, av in seq:
        s = None
        if op is _c.BRANCH:
            s = set()
            for alt in av[1]:
                r = _required(alt)
                if r is None:
                    s = None
                    break
                s |= r
        elif op is _c.SUBPATTERN:
            s = _required(_sub_items(av))
        elif op is _ATOMIC:
            s = _required(av)
        elif op in _REPEATS and av[0] >= 1:
            s = _required(av[2])
        if s and len(s) <= _MAX_SET and (best is None or _score(s) > _score(best)):
            best = s
    return best


def _first(seq):
    """Literals one of which every match of seq starts with, or None."""
    if not seq:
        return None
    runs = _runs(seq)
    if runs and runs[0][0] == 0 and '' not in runs[0][1]:
        return runs[0][1]
    # leading zero-width nodes, then one non-exact node we can look into
    i = 0
    while i < len(seq) and seq[i][0] in _ZERO_WIDTH:
        i += 1
    if i >= len(seq):
        return None
    op, av = seq[i]
    if op is _c.SUBPATTERN:
        return _first(list(_sub_items(av)))
    if op is _ATOMIC:
        return _first(list(av))
    if op is _c.BRANCH:
        out = set()
        for alt in av[1]:
            f = _first(list(alt))
            if f is None:
                return None
            out |= f
        return out if len(out) <= _MAX_SET else None
    if op in _REPEATS and av[0] >= 1:
        return _first(list(av[2]))
    return None


def _in_has_newline(items):
    negate = False
    hit = False
    for iop, iav in items:
        if iop is _c.NEGATE:
            negate = True
        elif iop is _c.LITERAL:
            hit = hit or iav == 10
        elif iop is _c.RANGE:
            hit = hit or iav[0] <= 10 <= iav[1]
        elif iop is _c.CATEGORY:
            if iav in (_c.CATEGORY_DIGIT, _c.CATEGORY_WORD, _c.CATEGORY_NOT_SPACE):
                pass
            else:                        # \s, \D, \W and anything unknown
                hit = True
        else:
            hit = True
    return hit != negate


def _crosses_lines(seq, flags, anchors_only=False):
    """True when a match of seq could consume a newline, or when matching it
    against one line alone could differ from matching it in the full text.
    anchors_only: seq sits in a lookaround that sees at most the newline
    ending the line, so only an end-of-text anchor can tell the two apart."""
    for op, av in seq:
        if op is _c.AT:
            if av is _c.AT_END_STRING:
                return True
            if av is _c.AT_END and not flags & re.MULTILINE:
                return True
        elif op is _c.BRANCH:
            if any(_crosses_lines(alt, flags, anchors_only) for alt in av[1]):
                return True
        elif op is _c.SUBPATTERN:
            f = flags
            if len(av) == 4:
                f = (flags | av[1]) & ~av[2]
            if _crosses_lines(_sub_items(av), f, anchors_only):
                return True
        elif op is _ATOMIC:
            if _crosses_lines(av, flags, anchors_only):
                return True
        elif op in _REPEATS:
            if _crosses_lines(av[2], flags, anchors_only):
                return True
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            direction, sub = av
            # A lookbehind sees the real text. A lookahead sees its line and
            # the newline that ends it: one character far it may match
            # anything, further it must stay on the line.
            narrow = direction < 0 or sub.getwidth()[1] <= 1
            if _crosses_lines(sub, flags, anchors_only or narrow):
                return True
        elif op is _c.GROUPREF_EXISTS:
            if any(b is not None and _crosses_lines(b, flags, anchors_only)
                   for b in av[1:]):
                return True
        elif anchors_only or op is _c.GROUPREF:
            pass
        elif op is _c.LITERAL:
            if av == 10:
                return True
        elif op is _c.NOT_LITERAL:
            if av != 10:
                return True
        elif op is _c.ANY:
            if flags & re.DOTALL:
                return True
        elif op is _c.IN:
            if _in_has_newline(av):
                return True
        else:
            return True
    return False


_STEM = 4


def _stems(needles):
    """Literals sharing their first _STEM characters, replaced by what they
    have in common: one pass over the text instead of one each. Whatever
    starts with or contains the longer literal does so with the shorter."""
    groups = {}
    for n in needles:
        groups.setdefault(n[:_STEM], []).append(n)
    out = set()
    for key, group in groups.items():
        if len(key) < _STEM or len(group) == 1:
            out.update(group)
            continue
        common = min(group)
        last = max(group)
        i = 0
        while i < len(common) and common[i] == last[i]:
            i += 1
        out.add(common[:i])
    return out


def _clean(needles, prefix_only):
    """Drop a literal another one already implies; None when not worth it."""
    if not needles or '' in needles:
        return None
    needles = _stems(needles)
    keep = []
    for n in sorted(needles, key=len):
        if prefix_only:
            implied = any(n.startswith(k) for k in keep)
        else:
            implied = any(k in n for k in keep)
        if not implied:
            keep.append(n)
    if len(keep) > _MAX_NEEDLES:
        return None
    return tuple(sorted(keep))


def literals(words):
    """Lowercase start literals for a pattern built from a word list, or
    None when they cannot serve (a non-ASCII word, an empty one, too many)."""
    words = {w.lower() for w in words}
    if not words or any(not w or any(ord(ch) > 127 for ch in w) for w in words):
        return None
    first = _clean(words, True)
    # A long list (hundreds of accounts) usually shares a few beginnings:
    # the longest ones that fit are still where every match starts.
    for k in (6, 5, 4, 3, 2):
        if first is not None:
            break
        if all(len(w) >= k for w in words):
            first = _clean({w[:k] for w in words}, True)
    return first


class Plan:
    __slots__ = ('first', 'required', 'one_line')

    def __init__(self, first=None, required=None, one_line=False):
        self.first = first
        self.required = required
        self.one_line = one_line


_NO_PLAN = Plan()
_plans = {}


def plan(rx):
    """The Plan for a compiled pattern (cached)."""
    p = _plans.get(rx)
    if p is None:
        try:
            p = _analyse(rx)
        except Exception:
            p = _NO_PLAN
        _plans[rx] = p
    return p


def _analyse(rx):
    if not isinstance(rx.pattern, str) or rx.flags & (re.LOCALE | re.VERBOSE):
        return _NO_PLAN
    tree = _sre_parse.parse(rx.pattern, rx.flags)
    state = getattr(tree, 'state', None) or getattr(tree, 'pattern')
    flags = state.flags
    seq = list(tree)
    if tree.getwidth()[0] < 1:
        return _NO_PLAN                 # could match the empty string
    first = _clean(_first(seq), True)
    required = _clean(_required(seq), False)
    return Plan(first, required, not _crosses_lines(seq, flags))


# --- substitution -----------------------------------------------------------

def _counts(low):
    """{literal: occurrences} for low; kept with the remembered text so the
    patterns of one pass, and passes that change nothing, count once."""
    return _fold_memo[2] if low is _fold_memo[1] else {}


def _count(low, needles, budget):
    """Occurrences of all needles, or -1 once they exceed budget."""
    total = 0
    seen = _counts(low)
    for n in needles:
        c = seen.get(n)
        if c is None:
            c = seen[n] = low.count(n)
        total += c
        if total > budget:
            return -1
    return total


def _positions(low, needles):
    """Where the needles occur, ascending. A position two needles share is
    listed twice; the walkers below pass over a repeat. (A set to drop them
    cost more memory than the text when a literal was on every line.)"""
    hits = []
    add = hits.append
    find = low.find
    seen = _counts(low)
    for n in needles:
        if seen.get(n) == 0:
            continue
        i = find(n)
        while i != -1:
            add(i)
            i = find(n, i + 1)
    hits.sort()
    return hits


def line_spans(text, positions):
    """(start, end) of each line holding one of the sorted positions; end is
    past the line's newline."""
    spans = []
    end = 0
    rfind, find, size = text.rfind, text.find, len(text)
    for p in positions:
        if p < end:
            continue
        start = rfind('\n', 0, p) + 1
        nl = find('\n', p)
        end = size if nl == -1 else nl + 1
        spans.append((start, end))
    return spans


def _apply(repl, m):
    return repl(m) if callable(repl) else m.expand(repl)


def _rebuild(text, edits):
    out = []
    pos = 0
    for start, end, new in edits:
        out.append(text[pos:start])
        out.append(new)
        pos = end
    out.append(text[pos:])
    return ''.join(out)


def _edited(text, edits):
    """text with the (start, end, replacement) edits applied; text itself
    when there are none.

    When text is the remembered one and holds non-ASCII characters, its
    lowercase copy is carried over by the same edits instead of being worked
    out again: lower() on such a text goes character by character, and a
    chain of passes that each replace something paid for it every time."""
    if not edits:
        return text
    new = _rebuild(text, edits)
    low = _fold_memo[1]
    if text is _fold_memo[0] and low is not None and not _is_ascii(text):
        low_edits = []
        for start, end, r in edits:
            if not _is_ascii(r):
                break
            low_edits.append((start, end, r.lower()))
        else:
            _fold_memo[0], _fold_memo[1], _fold_memo[2] = new, _rebuild(low, low_edits), {}
    return new


def sub_at(rx, repl, text, positions):
    """pattern.sub for a pattern whose matches can only start at one of the
    sorted positions."""
    edits = []
    pos = 0
    match = rx.match
    for p in positions:
        if p < pos:
            continue
        m = match(text, p)
        if m is None:
            pos = p + 1                  # also passes over a repeat of p
            continue
        pos = m.end()
        edits.append((p, pos, _apply(repl, m)))
    return _edited(text, edits)


def sub_spans(rx, repl, text, spans):
    """pattern.sub restricted to the given line spans, for a pattern that
    cannot match across a line end."""
    edits = []
    finditer = rx.finditer
    for start, end in spans:
        for m in finditer(text, start, end):
            edits.append((m.start(), m.end(), _apply(repl, m)))
    return _edited(text, edits)


def hint_spans(text, hints):
    """Line spans holding a match of one of the hint patterns, or None when
    there are so many that walking the whole text is cheaper. A hint is a
    cheap pattern (it starts with a literal) that every match of the real
    pattern contains."""
    budget = len(text) >> 7
    positions = []
    for h in hints:
        positions.extend(m.start() for m in h.finditer(text))
        if len(positions) > budget:
            return None
    positions.sort()
    return line_spans(text, positions)


def iter_spans(rx, text, spans):
    """pattern.finditer over the line spans (None: the whole text)."""
    if spans is None:
        return rx.finditer(text)
    return _iter_spans(rx, text, spans)


def _iter_spans(rx, text, spans):
    finditer = rx.finditer
    for start, end in spans:
        for m in finditer(text, start, end):
            yield m


def _route(rx, text, first, required, one_line):
    """How to walk text for rx: ('none',), ('at', positions),
    ('spans', spans) or ('all',)."""
    if first is None and required is None:
        return ('all',)
    low = fold(text)
    if low is None:
        return ('all',)
    size = len(text)
    if required is not None and required != first:
        n = _count(low, required, size >> 7)
        if n == 0:
            return ('none',)
        if n > 0 and first is None and one_line:
            return ('spans', line_spans(text, _positions(low, required)))
    else:
        n = None
    if first is not None:
        # One hit per 32 characters is where a position-by-position walk of
        # the whole text stops being the slower way.
        k = _count(low, first, size >> 5)
        if k == 0:
            return ('none',)
        if k > 0:
            return ('at', _positions(low, first))
        if n is not None and n > 0 and one_line:
            return ('spans', line_spans(text, _positions(low, required)))
    return ('all',)


ALNUM = frozenset('abcdefghijklmnopqrstuvwxyz0123456789')


def sub_folded(rx_low, behind, lookup, text, low):
    """Replace the words of a list, for a pattern of the shape
    (?<![behind])(?:words)(?!...) under IGNORECASE.

    rx_low is that pattern WITHOUT the lookbehind and without IGNORECASE,
    compiled for the lowercase copy `low` of text (see fold): it then starts
    with the words' first characters, and `re` skips every position that
    does not hold one of them instead of trying the pattern there. The
    lookbehind is applied here: a candidate behind one of `behind` is passed
    over and the search goes on one character further, which is what the
    lookbehind does inside the pattern. lookup maps a lowercase word to its
    replacement."""
    edits = []
    i = 0
    search = rx_low.search
    while True:
        m = search(low, i)
        if m is None:
            break
        s = m.start()
        if s and low[s - 1] in behind:
            i = s + 1
            continue
        i = m.end()
        edits.append((s, i, lookup[low[s:i]]))
    return _edited(text, edits)


def gsub(rx, repl, text, first=None):
    """pattern.sub(repl, text), skipping the parts of text rx cannot match.

    first: lowercase literals one of which every match starts with, for a
    pattern built at run time from a word list (the caller knows its words;
    a big alternation is not worth analysing)."""
    if first is not None:
        if len(first) > _MAX_NEEDLES:
            return rx.sub(repl, text)
        route = _route(rx, text, first, None, False)
    else:
        p = plan(rx)
        route = _route(rx, text, p.first, p.required, p.one_line)
    how = route[0]
    if how == 'none':
        return text
    if how == 'at':
        return sub_at(rx, repl, text, route[1])
    if how == 'spans':
        return sub_spans(rx, repl, text, route[1])
    return rx.sub(repl, text)


def giter(rx, text):
    """pattern.finditer(text), skipping the parts of text rx cannot match."""
    p = plan(rx)
    route = _route(rx, text, p.first, p.required, p.one_line)
    how = route[0]
    if how == 'none':
        return iter(())
    if how == 'at':
        return iter_at(rx, text, route[1])
    if how == 'spans':
        return _iter_spans(rx, text, route[1])
    return rx.finditer(text)


def iter_at(rx, text, positions):
    pos = 0
    match = rx.match
    for p in positions:
        if p < pos:
            continue
        m = match(text, p)
        if m is None:
            pos = p + 1                  # also passes over a repeat of p
        else:
            pos = m.end()
            yield m
