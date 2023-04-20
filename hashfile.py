import hashlib
import sys

from pathlib import Path
from tkinter import *
from tkinter import filedialog

# list of algorithms to use for hashing
hash_algorithms = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
# count of algorithms
hash_count = len(hash_algorithms)
# directories
bundle_dir = getattr(sys, '_MEIPASS', Path(__file__).parent.resolve())

def hashfile(filename=None):
    '''Prompts for file, and returns checksums'''
    # select file
    if filename is None:
        filename = filedialog.askopenfilename(
            title="Select file",
            filetypes=[("All Files", "*.*")]
        )
    # make sure valid file
    if Path(filename).is_file():

        # show filename on gui
        e1.config(state=NORMAL)
        e1.delete(0, END)
        e1.insert(END, str(Path(filename).resolve()))
        e1.config(state="readonly")

        # loop through hash_algorithms and calculate checksums
        for idx, ha in enumerate(hash_algorithms):
            if ha == "MD5":
                hash = hashlib.md5()
            elif ha == "SHA-1":
                hash = hashlib.sha1()
            elif ha == "SHA-256":
                hash = hashlib.sha256()
            else:
                hash = hashlib.sha512()

            with open(filename, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash.update(byte_block)

            # show checksum on gui
            entries[idx][1].config(state=NORMAL)
            entries[idx][1].delete(0, END)
            entries[idx][1].insert(END, hash.hexdigest())
            entries[idx][1].config(state="readonly")


def search_cb(var, index, mode):
    '''Callback function for the search box'''
    for entry in entries:
        # if search value mataches entry
        if s.get().strip() == entry[1].get().strip():
            entry[1].config(fg="blue")
        else:
            entry[1].config(fg="black")


if __name__ == "__main__":

    # create root window
    root = Tk()
    root.title("hashfile by NN")
    root.resizable(False, False)

    # icon
    icon = Path(bundle_dir, "icon/icon.png")
    p1 = PhotoImage(file=icon)
    root.iconphoto(True, p1)

    # frames
    top_frame = Frame(root)
    top_frame.grid(row=0,  column=0,  padx=10,  pady=5)
    bottom_frame = Frame(root)
    bottom_frame.grid(row=1,  column=0,  padx=10,  pady=5)

    # filename field
    l1 = Label(top_frame, text="File")
    e1 = Entry(top_frame, width=128)
    l1.grid(row=0, column=0, sticky=E, pady=2, padx=2)
    e1.grid(row=0, column=1, pady=2, padx=2)

    # checksum fields
    entries = []
    for idx, ha in enumerate(hash_algorithms):
        entries.append((
            Label(top_frame, text=ha),
            Entry(top_frame, width=128, fg="black")
        ))
        entries[idx][0].grid(row=idx+1, column=0, sticky=E, pady=2, padx=2)
        entries[idx][1].grid(row=idx+1, column=1, pady=2, padx=2)

    # search bar
    s = StringVar()
    s.trace_add(mode="write", callback=search_cb)
    l2 = Label(top_frame, text="Search")
    e2 = Entry(top_frame, width=128, textvariable=s)
    l2.grid(row=hash_count+1, column=0, sticky=E, pady=2, padx=2)
    e2.grid(row=hash_count+1, column=1, pady=2, padx=2)

    # buttons
    btn1 = Button(bottom_frame, text='Open File', command=hashfile)
    btn1.grid(row=0, column=0, pady=2, padx=2)
    btn2 = Button(bottom_frame, text='Exit', command=root.destroy)
    btn2.grid(row=0, column=1, pady=2, padx=2)

    # if filename is passed as argument
    if len(sys.argv) > 1:
        if Path(sys.argv[1]).is_file():
            hashfile(sys.argv[1])

    root.mainloop()
