from pysymex import check_division_by_zero

def test_oracle_suite():
    # Known exact bugs
    def bug1(x):
        return 100 / (x - 42)
        
    def bug2(y):
        if y == 7:
            return 1 / (y - 7)
        return 0
        
    def bug3(z):
        if z < 0:
            return 5 / (z + 10)
        return 0
        
    def fp1_safe(z):
        if z != 0:
            return 1 / z
        return 0
        
    def fp2_safe(x):
        y = x * x + 1 # At least 1 (assuming x is an integer, x*x >= 0)
        return 50 / y

    # Test that ground truth vulnerabilities are discovered exactly
    iss1 = check_division_by_zero(bug1)
    assert len(iss1) == 1
    assert iss1[0].get_counterexample()["x"] == 42
    
    iss2 = check_division_by_zero(bug2)
    assert len(iss2) == 1
    assert iss2[0].get_counterexample()["y"] == 7
    
    iss3 = check_division_by_zero(bug3)
    assert len(iss3) == 1
    assert iss3[0].get_counterexample()["z"] == -10
    
    # Test that ground truth safe code yields no false positives
    assert len(check_division_by_zero(fp1_safe)) == 0
    assert len(check_division_by_zero(fp2_safe)) == 0
