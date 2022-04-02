# progress.py
import sys
import time
from rich.progress import track


def get_linecount(filename):
    with open(filename, "r") as infile:
        i = -1
        for i, _ in enumerate(infile):
            pass
        return i + 1


def process(line):
    time.sleep(1)
    

def main():
    try:
        filename = sys.argv[1]
    except IndexError:
        print("Please provide a filename")
        exit(1)
    linecount = get_linecount(filename)
    with open(filename, "r") as f:
        for line in track(f, description="Progress:", total=linecount):
            process(line)


if __name__ == "__main__":
    main()
