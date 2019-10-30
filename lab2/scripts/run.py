import argparse

from os              import path
from pathlib         import Path
from multiprocessing import Queue
from math            import floor
from shutil          import copyfile, rmtree
from worker          import Worker

parser = argparse.ArgumentParser(description="Finding weak & semi-weak keys of SP-cyphering")
parser.add_argument("--keytype", "-k", type=str, required=True, help="Type of keys (weak or semi-weak)")
parser.add_argument("--threads", "-t", type=int, required=True, help="Amount of threads")
args = parser.parse_args()

# Path to plain text
GLOBAL_TEXT_PATH = Path("../text.txt")

KEY_SPACE       = (2**32 - 1)
# May be more, if KEY_SPACE not devided into full parts of THREAD_COUNT
THREAD_COUNT  = args.threads
# Folder with THREAD logs etc.
THREAD_FOLDER = Path("threads")

part_size = floor(KEY_SPACE / THREAD_COUNT)
remainder = KEY_SPACE - part_size * THREAD_COUNT

# Increase THREAD_COUNT if remainder exists
THREAD_COUNT += 1 if (remainder != 0) else 0

# Multiprocess queue
pqueue = Queue()

range_finish = 0
for i in range(0, THREAD_COUNT):

    # Calculate current range
    range_start, range_finish = range_finish + 1, range_finish + part_size

    # Put it on the proc. queue
    pqueue.put([range_start, range_finish])

    # Put the remainder on the top
    if ( i == THREAD_COUNT - 2):
        pqueue.put([range_finish + 1, range_finish + remainder])
        break


# Create threads and prepare environment
if (THREAD_FOLDER.exists()):
    rmtree(THREAD_FOLDER.absolute())
    
THREAD_FOLDER.mkdir(exist_ok=False)

thread_list = []
for pid in range(0, THREAD_COUNT):

    PID_DIR = THREAD_FOLDER / Path(str(pid))

    # Create folder for thread
    PID_DIR.mkdir(exist_ok=True)

    # Create files for encrypt. / decrypt. result
    ENCR_TEXT  = PID_DIR / "encr_text.txt"
    DECR_TEXT  = PID_DIR / "decr_text.txt"
    PLAIN_TEXT = PID_DIR / "plain_text.txt"
    KEYS_DIR   = PID_DIR / "keys"
    LOG_DIR    = PID_DIR / "log"

    # Create neccesary dirs
    LOG_DIR.mkdir()
    KEYS_DIR.mkdir()

    # Copy plain text into thread folder
    copyfile(GLOBAL_TEXT_PATH, PLAIN_TEXT)

    # Create thread and bind it to worker function
    t = Worker( pid=pid, 
                run_mode=args.keytype, 
                key_space=KEY_SPACE,
                queue=pqueue, 
                text_path = PLAIN_TEXT.absolute(), 
                encr_dest = ENCR_TEXT.absolute(), 
                decr_dest = DECR_TEXT.absolute(),
                keys_dir  = KEYS_DIR.absolute(),
                log_dir   = LOG_DIR.absolute())
            
    thread_list.append(t)

    # Start threads
    t.start()

for p in thread_list:
    p.join()