"""Regression checks for performance optimizations that must stay lossless."""


def test_encoding_cache_preserves_results():
    from modules.crypto import encodings

    sample = "ZHVjdGZ7cGVyZm9ybWFuY2VfY2FjaGV9"
    encodings._try_all_encodings_cached.cache_clear()
    cold = encodings._try_all_encodings_uncached(sample)
    first = encodings.try_all_encodings(sample)
    second = encodings.try_all_encodings(sample)
    # pmap returns completion order, so compare content rather than thread
    # scheduling order.
    assert set(first) == set(cold)
    assert set(second) == set(cold)
    assert encodings._try_all_encodings_cached.cache_info().hits >= 1


def test_analysis_cache_preserves_results():
    from modules.crypto import autodetect

    sample = "wkh txlfn eurzq ira mxpsv"
    autodetect._analyze_text_cached.cache_clear()
    first = autodetect.analyze_text(sample)
    second = autodetect.analyze_text(sample)
    assert second == first
    assert autodetect._analyze_text_cached.cache_info().hits >= 1


if __name__ == "__main__":
    test_encoding_cache_preserves_results()
    test_analysis_cache_preserves_results()
    print("performance regression: PASS")
