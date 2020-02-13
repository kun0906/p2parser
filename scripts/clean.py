import os
import shutil
from os import path as pth
import time
from collections import OrderedDict


def convert_bytes(num):
    """
    this function will convert bytes to MB.... GB... etc
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def remove_files(input_dir, dur=7 * (24 * 60 * 60)):
    """remove files by time: please take it into consideration before using the remove function

        Note that once this operation is taken, the deleted files might not be recover.
    """
    try:
        i = 0
        file_sizes = OrderedDict()
        for (subdir_path, dirnames, filenames) in os.walk(input_dir):
            for file_name in [os.path.join(subdir_path, file) for file in filenames]:
                if os.stat(file_name).st_mtime < time.time() - dur:
                    if '.dat' in file_name or '.pdf' in file_name:  # don't remove label.csv and xxx.pcap
                        f_size = os.path.getsize(file_name)  # return file size in bytes
                        if file_name not in file_sizes.keys():
                            file_sizes[file_name] = f_size
                        os.remove(file_name)  # delete an old file
                        # shutil.move(file_name, pth.join(trash,subdir_path))
                        i += 1
                        print(
                            f'remove {file_name} (its size is {convert_bytes(f_size)}), '
                            f'because its time is more than {dur}s, ({int(dur / (24 * 3600))} days)')

        total_size = sum([v for v in file_sizes.values()])
        print(f'remove {i} old files in {input_dir}, total size is {convert_bytes(total_size)}')
        top_files = sorted(file_sizes.items(), key=lambda v: v[1], reverse=True)[:5]
        for i, (f_name, f_size) in enumerate(top_files):
            print(f'Top {i + 1} is {f_name}, {convert_bytes(f_size)} in size.')

    except Exception as e:
        print(f'Error: {e}')
        return -1

    return 0


def get_dir_sizes(input_dir='.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(input_dir):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)

    print(total_size, 'bytes')
    return total_size


input_dir = pth.join(pth.dirname(os.getcwd()), '.trash')
print(input_dir)
DAYS = 7
CAPACITY = 30 * 1024 * 1024 * 1024  # 30GB
while get_dir_sizes(input_dir) > CAPACITY and DAYS > 0:  # 30GB
    remove_files(input_dir=input_dir, dur=DAYS * (24 * 60 * 60))
    DAYS -= 1
