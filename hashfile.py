import hashlib
import sys

from pathlib import Path
from tkinter import *
from tkinter import filedialog

# list of cryptographic hash functions to use
CHF = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
# count of algorithms
CHF_COUNT = len(CHF)
# directories
ROOTDIR = getattr(sys, '_MEIPASS', Path(__file__).parent.resolve())


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

        # show filename in gui
        e1.config(state=NORMAL)
        e1.delete(0, END)
        e1.insert(END, str(Path(filename).resolve()))
        e1.config(state="readonly")

        # loop through CHF's and calculate checksums
        for idx, hf in enumerate(CHF):
            if hf == "MD5":
                hash = hashlib.md5()
            elif hf == "SHA-1":
                hash = hashlib.sha1()
            elif hf == "SHA-256":
                hash = hashlib.sha256()
            else:
                hash = hashlib.sha512()

            with open(filename, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash.update(byte_block)

            # show checksum on gui
            entries[idx].config(state=NORMAL)
            entries[idx].delete(0, END)
            entries[idx].insert(END, hash.hexdigest())
            entries[idx].config(state="readonly")


def search_cb(var, index, mode):
    '''Callback function for the search box'''
    for entry in entries:
        # if search value mataches entry
        if s.get().strip() == entry.get().strip():
            entry.config(fg="blue")
        else:
            entry.config(fg="black")


def clear_search():
    '''Clear search box'''
    e2.delete(0, END)


if __name__ == "__main__":

    # create root window
    root = Tk()
    root.title("HashFile")
    root.resizable(False, False)

    # icon
    icon = Path(ROOTDIR, "icon/icon.png")
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
    for idx, hf in enumerate(CHF):
        l = Label(top_frame, text=hf)
        e = Entry(top_frame, width=128, fg="black")
        l.grid(row=idx+1, column=0, sticky=E, pady=2, padx=2)
        e.grid(row=idx+1, column=1, pady=2, padx=2)
        entries.append(e)

    # search bar
    s = StringVar()
    s.trace_add(mode="write", callback=search_cb)
    l2 = Label(top_frame, text="Search")
    e2 = Entry(top_frame, width=128, textvariable=s)
    l2.grid(row=CHF_COUNT+1, column=0, sticky=E, pady=2, padx=2)
    e2.grid(row=CHF_COUNT+1, column=1, pady=2, padx=2)

    # buttons
    btn1 = Button(bottom_frame, text='Open File', command=hashfile)
    btn1.grid(row=0, column=0, pady=2, padx=2)
    btn2 = Button(bottom_frame, text='Clear Search', command=clear_search)
    btn2.grid(row=0, column=1, pady=2, padx=2)
    btn3 = Button(bottom_frame, text='Exit', command=root.destroy)
    btn3.grid(row=0, column=2, pady=2, padx=2)

    # if filename is passed as argument
    if len(sys.argv) > 1:
        if Path(sys.argv[1]).is_file():
            hashfile(sys.argv[1])

    root.mainloop()
