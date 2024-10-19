import sys

if __name__ == '__main__':
    a_list = sys.argv[1:]
    b_list = []

    for word in a_list:
        if word[0] == 'b':
            b_list.append(f"B{word[1:].lower()}")

    print(b_list)

