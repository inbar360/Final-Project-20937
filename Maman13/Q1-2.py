import sys

if __name__ == '__main__':
    b_list = [f"B{word[1:].lower()}" for word in sys.argv if word[0] == 'b']
    print(b_list)

