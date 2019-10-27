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

def bytearray_from_int(i : int) -> bytearray:
    return bytearray([ (i & (0xff << shift*8)) >> shift*8 for shift in range(0,4) ])

def thread_encrypt_file(text : Path, key : Path, dest : Path, logerr_fd):
    subprocess.run(args=[BINARY, "encrypt", text, key, dest], 
                    stdout=subprocess.PIPE, 
                    stderr=logerr_fd,
                    check=True)

# Worker function. Running in separate threades
def worker( pid, queue : Queue, text_path : Path, encr_dest : Path, 
                                decr_dest : Path, keys_dir: Path, log_dir : Path ):

    print("Thread #{} started.".format(pid))

    range_list       = queue.get()
    min_key, max_key = range_list[0], range_list[1]
    
    key_i_file, key_j_file = keys_dir/"key_i.txt", keys_dir/"key_j.txt"

    try:
        logerr_fd = open(log_dir/"stderr.txt", "a")

        i = min_key
        while i < max_key:
            # Write key into file
            with open(key_i_file, "wb") as fd:
                fd.write(bytearray_from_int(i))

            thread_encrypt_file(text_path, key_i_file, encr_dest, logerr_fd)

            j = 1
            while j < UINT_MAX:
                # Write keys into files
                with open(key_j_file, "wb") as fd:
                    fd.write(bytearray_from_int(j))

                thread_encrypt_file(encr_dest, key_j_file, decr_dest, logerr_fd)

                # Compare key_i and key_j results
                if filecmp.cmp(decr_dest, text_path) == True:
                    with open(log_dir/"semi-weak_keys.txt", "a") as fd:
                        fd.write("{},{}\n".format(i, j))              
                j += 1

            with open(log_dir/"stdout.txt", "w") as log_fd:
                per_proccessed = format(((i - min_key)/  (max_key - min_key)) * 100, "0.8f")
                log_fd.write("Processed [{}%]. Current keys: {},{}\n".format(per_proccessed, i, j))
            i += 1
    except:
        print("Thread #{} failed.".format(pid))
    else:
        print("Thread #{} finished.".format(pid))
    finally:
        logerr_fd.close()


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
    KEYS_DIR   = PID_DIR / "keys"
    LOG_DIR    = PID_DIR / "log"

    # Create neccesary dirs
    LOG_DIR.mkdir()
    KEYS_DIR.mkdir()

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
            KEYS_DIR.absolute(),
            LOG_DIR.absolute()))
            
    thread_list.append(t)

    # Start threads
    t.start()

for p in thread_list:
    p.join()