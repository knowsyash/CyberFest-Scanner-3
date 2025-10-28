def main():
    dollars = dollars_to_float(input("How much was the meal? "))
    percent = percent_to_float(input("What percentage would you like to tip? "))
    tip = dollars * percent
    print(f"Leave ${tip:.2f}")


def dollars_to_float(d):
    d_beg = (d.startswith("$"))
    if d_beg == True:
        d = d[1:] #removes beg
    d = float(d)
    return (round(d, 1))


def percent_to_float(p):
    p_end = (p.endswith("%"))
    if p_end == True:
        p = p[:-1] #removes end
    p = float(p)
    p = p/100
    return (round(p, 2))

main()
