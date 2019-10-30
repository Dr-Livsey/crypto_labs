import threading
import random
import logging
import time
import subprocess

from multiprocessing import Queue
from pathlib         import Path
from os              import path

BINARY         = Path("bin/main")

def bytearray_from_int(i : int) -> bytearray:
    return bytearray([ (i & (0xff << shift*8)) >> shift*8 for shift in range(0,4) ])
    
# Compare first 'size' bytes of 'f1' file with 'f2' file 
def cmp_files(f1, f2, size : int) -> bool:
    f1_content = ""
    f2_content = ""
    with open(f1, "rb") as fd:
        f1_content = fd.read()
    with open(f2, "rb") as fd:
        f2_content = fd.read()
    return True if f1_content[:size] == f2_content[:size] else False

class Worker(threading.Thread):
    def __init__(self, 
                 pid,           # pid of thread 
                 run_mode,      # finding only weak keys or semi-weak keys too
                 key_space,     # size of key space
                 queue : Queue, # queue with range 
                 text_path : Path, encr_dest : Path, decr_dest : Path, 
                 keys_dir: Path, log_dir : Path):

        # Init base class
        threading.Thread.__init__(self)
        
        self._pid       = pid
        self._run_mode  = run_mode
        self._key_space = key_space
        self._queue     = queue
        self._text_path = text_path
        self._encr_dest = encr_dest
        self._decr_dest = decr_dest
        self._keys_dir  = keys_dir
        self._log_dir   = log_dir 

        # Set the logger
        log_handler = logging.FileHandler(log_dir/"log.txt")
        log_handler.setFormatter(logging.Formatter('%(levelname)-2s [%(asctime)s]: %(message)s'))
        log_handler.setLevel(logging.DEBUG)

        self._logger = logging.Logger("Thread logger", level=logging.DEBUG)
        self._logger.addHandler(log_handler)

    @staticmethod
    def encrypt_file(text : Path, key : Path, dest : Path, logerr_fd):
        subprocess.run(args=[BINARY, "encrypt", text, key, dest], 
                    stdout=subprocess.PIPE, 
                    stderr=logerr_fd,
                    check=True,
                    cwd=Path(".."))
    
    def run(self):        
        if self._run_mode == "weak-keys":
            self.weak_keys_finding()
        else:
            self.semi_weak_keys_finding()        

    def get_time(self) -> float:
        return time.clock_gettime_ns(time.CLOCK_THREAD_CPUTIME_ID)*(10**-9)

    # Finding weak keys
    def weak_keys_finding(self):

        print("Thread #{} started. Run mode = {}".format(self._pid, self._run_mode))

        ranges     = self._queue.get()
        key_i_file = self._keys_dir/"key_i.txt"
        # std error log file
        logerr_fd  = open(self._log_dir/"stderr.txt", "w")
        # for logging
        t_start = self.get_time()

        try:
            counter = 0
            key_range_s = (ranges[1] - ranges[0] + 1)
            while counter < key_range_s:
                i = random.randint(ranges[0], ranges[1])
                
                with open(self._keys_dir/"checked.txt", "a") as fd:
                    fd.write("{};".format(i))

                # Write key into file
                with open(key_i_file, "wb") as fd:
                    fd.write(bytearray_from_int(i))

                Worker.encrypt_file(self._text_path, key_i_file, self._encr_dest, logerr_fd)
                Worker.encrypt_file(self._encr_dest, key_i_file, self._decr_dest, logerr_fd)

                # Check results
                if cmp_files(self._text_path, self._decr_dest, path.getsize(self._text_path)) == True:
                    with open(self._keys_dir/"weak.txt", "a") as fd:
                        fd.write("{}\n".format(i))              

                # Logging
                if (self.get_time() - t_start)  >= 10.:
                    t_start = self.get_time()
                    per_proccessed = format((counter /  key_range_s) * 100, "0.8f")
                    self._logger.info("Processed [{}%]. Current key: {}\n".format(per_proccessed, i))

                counter += 1

        except Exception as default_ex:
            logerr_fd.write("Exception: {}".format(default_ex))
            print("Thread #{} failed.".format(self._pid))
        else:
            print("Thread #{} finished.".format(self._pid))
        finally:
            logerr_fd.close()
            
    def semi_weak_keys_finding(self):
        raise NotImplementedError
