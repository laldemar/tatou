from app.mathops import is_even

def test_even():
    assert is_even(2)

def test_odd():
    assert not is_even(3)
