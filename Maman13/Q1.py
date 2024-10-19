import sys

if __name__ == '__main__':

    b_list = [f"B{word[1:].lower()}" for word in sys.argv if word[0] == 'b']
    line = input("Enter the sentence: ")
    words = [word.upper() for word in line.split() if 'o' in word]
    print(', '.join(words))
