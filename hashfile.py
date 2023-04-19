import hashlib
import os.path
import sys

from tkinter import *
from tkinter import filedialog

# list of algorithms to use for hashing
hash_algorithms = ["MD5", "SHA-1", "SHA-256", "SHA-512"]


def hashfile(filename=None):
    '''Prompts for file, and returns checksums'''

    # select file
    if filename is None:
        filename = filedialog.askopenfilename(
                        title="Select file",
                        filetypes=[("All Files","*.*")]
                    )

    # make sure valid file
    if os.path.isfile(filename):

        # show filename on gui
        e1.config(state=NORMAL)
        e1.delete(0, END)
        e1.insert(END, filename)
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
                for byte_block in iter(lambda: f.read(4096),b""):
                    hash.update(byte_block)
            
            # show checksum on gui
            entries[idx][1].config(state=NORMAL)
            entries[idx][1].delete(0, END)
            entries[idx][1].insert(END, hash.hexdigest())
            entries[idx][1].config(state="readonly")


if __name__ == "__main__":
        
    # create root window
    root = Tk()
    root.title("hashfile by NN")
    root.resizable(False, False)

    # filename field
    l1 = Label(root, text="File")
    e1 = Entry(root, width=128)

    l1.grid(row=0, column=0, sticky=E, pady=2, padx=2)
    e1.grid(row=0, column=1, pady=2, padx=2)

    # checksum fields
    entries = []
    for idx, ha in enumerate(hash_algorithms):
        entries.append(
            (Label(root, text=ha), Entry(root, width=128))
        )
        entries[idx][0].grid(row=idx+1, column=0, sticky=E, pady=2, padx=2)
        entries[idx][1].grid(row=idx+1, column=1, pady=2, padx=2)

    # open button
    open_button = Button(root, text='Open File', command=hashfile)
    open_button.grid(row=0, column=2, sticky=W, pady=2, padx=2)

    # if filename is passed as argument
    if len(sys.argv) > 1:
        if os.path.isfile(sys.argv[1]):
            hashfile(sys.argv[1])

    root.mainloop()
