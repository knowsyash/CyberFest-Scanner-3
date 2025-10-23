
def is_prime(n):
    """
    Checks if a number is prime.
    
    Args:
        n: Integer to check
    
    Returns:
        True if n is prime, False otherwise
    """
    if n <= 1:
        return False
    
    if n <= 3:
        return True
    
    # If n is divisible by 2 or 3, it's not prime
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    # Check for divisors up to sqrt(n)
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    
    return True


def find_primes_in_range(start, end):
    """
    Finds all prime numbers in a given range.
    
    Args:
        start: Starting number (inclusive)
        end: Ending number (inclusive)
    
    Returns:
        List of prime numbers in the range
    """
    primes = []
    for num in range(start, end + 1):
        if is_prime(num):
            primes.append(num)
    return primes


# Example usage
if __name__ == "__main__":
    # Test single numbers
    test_numbers = [2, 17, 20, 29, 50, 97]
    
    print("Prime Number Checker")
    print("=" * 40)
    
    for num in test_numbers:
        if is_prime(num):
            print(f"{num} is a prime number")
        else:
            print(f"{num} is not a prime number")
    
    # Find primes in a range
    print("\n" + "=" * 40)
    print("Prime numbers between 1 and 50:")
    primes = find_primes_in_range(1, 50)
    print(primes)
    print(f"\nTotal prime numbers found: {len(primes)}")

