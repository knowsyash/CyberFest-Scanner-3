"""
🔐 Password Strength Checker
Author: Open for Hacktoberfest Contributions
--------------------------------------------
Checks password strength based on length, variety, and common patterns.
"""

import re
import getpass

def check_strength(password: str) -> dict:
    score = 0
    feedback = []

    # Rule 1: Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password too short (min 8 chars).")

    # Rule 2: Character variety
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("❌ Add lowercase letters.")
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("❌ Add uppercase letters.")
    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("❌ Add digits.")
    if re.search(r"[^A-Za-z0-9]", password): score += 1
    else: feedback.append("❌ Add special characters (!,@,#, etc.)")

    # Rule 3: Common patterns
    common = ["password", "12345", "qwerty", "admin"]
    if any(word in password.lower() for word in common):
        feedback.append("⚠️ Avoid common passwords like 'password', '12345', etc.")
        score = max(0, score - 2)

    return {"score": score, "feedback": feedback}


def strength_label(score: int) -> str:
    if score >= 6:
        return "🟢 Strong"
    elif score >= 4:
        return "🟡 Medium"
    else:
        return "🔴 Weak"


def main():
    print("🔒 Password Strength Checker")
    print("-" * 35)
    password = getpass.getpass("Enter your password (hidden): ")

    result = check_strength(password)
    label = strength_label(result["score"])

    print("\n📊 Strength:", label)
    if result["feedback"]:
        print("\n💡 Suggestions:")
        for f in result["feedback"]:
            print(" -", f)
    else:
        print("✅ Great job! Your password looks strong.")

if __name__ == "__main__":
    main()
