import threading
import subprocess
import filecmp

from pathlib         import Path
from multiprocessing import Queue
from math            import floor
from shutil          import copyfile, rmtree



# Path to plain text
GLOBAL_TEXT_PATH = Path("text.txt")

BINARY         = Path("bin/main")
UINT_MAX       = (2**32 - 1)
# May be more, if UINT_MAX not devided into full parts of THREAD_COUNT
THREAD_COUNT  = 50
# Folder with THREAD logs etc.
THREAD_FOLDER = Path("threads")

# Worker function. Running in separate threades
def worker( pid, queue : Queue, text_path : Path, encr_dest : Path, 
                                decr_dest : Path, key_file : Path, log_dir : Path ):
    print("Thread #{} started.".format(pid))

    range_list = queue.get()
    min_key, max_key = range_list[0], range_list[1]

    logerr_fd = open(log_dir/"stderr.txt", "a")

    i = min_key
    while i < max_key:
        key = bytearray([ (i & (0xff << shift*8)) >> shift*8 for shift in range(0,4) ])

        # Write key into file
        with open(key_file, "wb") as fd:
            fd.write(key)

        try:
            subprocess.run(args=[BINARY, "encrypt", text_path, key_file, encr_dest], 
                        stdout=subprocess.PIPE, 
                        stderr=logerr_fd,
                        check=True)

            subprocess.run(args=[BINARY, "encrypt", encr_dest, key_file, decr_dest], 
                        stdout=subprocess.PIPE, 
                        stderr=logerr_fd,
                        check=True)

            with open(log_dir/"stdout.txt", "a") as log_fd:
                per_proccessed = format(((i - min_key)/  (max_key - min_key)) * 100, "0.8f")
                log_fd.write("[{}%] Key {} checked. Weakness: {}\n".format(per_proccessed, i, filecmp.cmp(decr_dest, text_path)))

        except subprocess.CalledProcessError as proc_ex:
            print("Thread #{} failed.".format(pid))
            logerr_fd.close()
            exit(proc_ex.returncode)

        i += 1

    logerr_fd.close()
    print("Thread #{} finished.".format(pid))


part_size = floor(UINT_MAX / THREAD_COUNT)
remainder = UINT_MAX - part_size * THREAD_COUNT + 1

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
    KEY_FILE   = PID_DIR / "key.txt"
    LOG_DIR    = PID_DIR / "log"

    # Create log dir
    LOG_DIR.mkdir()

    # Copy plain text into thread folder
    copyfile(GLOBAL_TEXT_PATH, PLAIN_TEXT)

    # Create thread and bind it to worker function
    t = threading.Thread(
        target=worker, 
        args=(
            pid, 
            pqueue, 
            PLAIN_TEXT.absolute(), 
            ENCR_TEXT.absolute(), 
            DECR_TEXT.absolute(),
            KEY_FILE.absolute(),
            LOG_DIR.absolute()))
            
    thread_list.append(t)

    # Start threads
    t.start()

for p in thread_list:
    p.join()


# while i > 0:
#     key = bytearray([ (i & (0xff << x*8)) >> x*8 for x in range(0,4) ])

#     with open(KEY_FILE_PATH, "wb") as key_file:
#         key_file.write(key)

#     try:
#         subthread.run(
#             args=[BINARY, "encrypt", TEXT_FILE_PATH, KEY_FILE_PATH, ENCR_FILE_PATH], 
#             stdout=subthread.PIPE, 
#             check=True)
#     except subthread.CalledProcessError as proc_ex:
#         exit(proc_ex.returncode)

#     i -= 1
    