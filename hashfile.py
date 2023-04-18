import hashlib
import os.path
import sys

from tkinter import *
from tkinter import filedialog


def hashfile(filename=None):
    '''Prompts for file, and returns checksums'''

    # select file
    if filename is None:
        while True: 
            filename = filedialog.askopenfilename(
                            title="Select file",
                            filetypes=[("All Files","*.*")]
                        )
            if os.path.isfile(filename):
                break

    # reset text box
    txt_output.config(state=NORMAL)
    txt_output.delete("1.0", END)
    txt_output.insert(END, f"{filename}\n\n\n")

    # list of algorithms to use for hashing
    hash_algorithms = [
        ("MD5", hashlib.md5()),
        ("SHA256", hashlib.sha256()),
        ("SHA512", hashlib.sha512())
    ]

    # loop through hash_algorithms and print checksum to textbox
    for ha in hash_algorithms:
        with open(filename, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                ha[1].update(byte_block)
        
        txt = f"{ha[0]}:\t{ha[1].hexdigest()}\n\n"
        txt_output.insert(END, txt)
    
    txt_output.config(state=DISABLED)


# create root window
root = Tk()
root.geometry("720x250")
root.title("hashfile by NN")

# open button
open_button = Button(root, text='Open File', command=hashfile)
open_button.pack(expand=True)

# for outputting checksums
txt_output = Text(root, height=10, width=80)
txt_output.pack(expand=True)

# if filename is passed as argument
if len(sys.argv) > 1:
    if os.path.isfile(sys.argv[1]):
        hashfile(sys.argv[1])

root.mainloop()
