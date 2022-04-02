import time
import sys
for i in range(20):
        time.sleep(0.5)
        print(f"\rnumber{i}",end="")
        sys.stdout.flush()