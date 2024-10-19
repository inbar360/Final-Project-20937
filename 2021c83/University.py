import re

class University:
    def __init__(self, name: str, location: str, students: int):
        self.name = name
        self.location = location
        self.students = students


class OpenUniversity(University):
    def __init__(self, name, location, students, dic):
        super().__init__(name, location, students)
        self.dic = dic


def parse(filename):
    students = 0
    amt = 0
    file = open(filename)
    lines = file.readlines()
    unis = []
    print([l.strip() for l in lines])
    for line in lines:
        amt += 1
        splitted = re.split(', |\n', line.strip())

        print(splitted)
        if splitted[-1].endswith('courses:'):
            students += int(splitted[2].split()[0])

        else:
            students += int(splitted[2])
            unis.append(University(splitted[0], splitted[1], splitted[2]))


parse("randomfile.txt")
