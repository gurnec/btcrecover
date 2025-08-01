#!/usr/bin/env python

# btcrecover-gui.py -- A simple graphical frontend for btcrecover
# Copyright (C) 2024
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

from __future__ import print_function

import sys
import os
from btcrecover import btcrpass
import multiprocessing

try:
    import Tkinter as tk
    import ttk
    import tkFileDialog
    import tkMessageBox
    from ScrolledText import ScrolledText
except ImportError:
    # Python 3
    import tkinter as tk
    from tkinter import ttk
    from tkinter import filedialog as tkFileDialog
    from tkinter import messagebox as tkMessageBox
    from tkinter.scrolledtext import ScrolledText

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify='left',
                      background="#ffffe0", relief='solid', borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

class ConsoleRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete(1.0, tk.END)
        self.text_widget.config(state=tk.DISABLED)

    def write(self, message):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.update_idletasks()

    def flush(self):
        self.text_widget.update_idletasks()

class BTCRecoverGUI:
    def __init__(self, master):
        self.master = master
        master.title("BTCRecover GUI")

        menubar = tk.Menu(master)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.show_about)
        helpmenu.add_command(label="Usage", command=self.show_usage)
        menubar.add_cascade(label="Help", menu=helpmenu)
        master.config(menu=menubar)

        window_width = 500
        window_height = 400
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)
        master.geometry('{}x{}+{}+{}'.format(window_width, window_height, position_right, position_top))

        self.wallet_path = tk.StringVar()
        self.passwordlist_path = tk.StringVar()
        self.tokenlist_path = tk.StringVar()
        self.typos_count = tk.IntVar(value=0)
        self.typo_swap = tk.BooleanVar()
        self.typo_delete = tk.BooleanVar()
        self.typo_case = tk.BooleanVar()
        self.threads_count = tk.IntVar(value=btcrpass.cpus)

        file_frame = tk.Frame(master, padx=10, pady=10)
        file_frame.pack(fill=tk.X)

        wallet_label = tk.Label(file_frame, text="Wallet File:")
        wallet_label.grid(row=0, column=0, sticky=tk.W)
        Tooltip(wallet_label, "The encrypted wallet file you want to recover the password for.")
        tk.Entry(file_frame, textvariable=self.wallet_path, width=50, state='readonly').grid(row=0, column=1, padx=5)
        tk.Button(file_frame, text="Browse...", command=self.select_wallet).grid(row=0, column=2)

        passwordlist_label = tk.Label(file_frame, text="Password List:")
        passwordlist_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        Tooltip(passwordlist_label, "A file containing a list of passwords to try, one per line.\nSelect this if you have a list of complete passwords.")
        tk.Entry(file_frame, textvariable=self.passwordlist_path, width=50, state='readonly').grid(row=1, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="Browse...", command=self.select_passwordlist).grid(row=1, column=2, pady=5)

        tokenlist_label = tk.Label(file_frame, text="Token List:")
        tokenlist_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        Tooltip(tokenlist_label, "A file containing a list of password tokens (parts of the password).\nBTCRecover will try different combinations of these tokens.\nSelect this if you know parts of your password.")
        tk.Entry(file_frame, textvariable=self.tokenlist_path, width=50, state='readonly').grid(row=2, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="Browse...", command=self.select_tokenlist).grid(row=2, column=2, pady=5)

        options_frame = tk.Frame(master, padx=10, pady=10)
        options_frame.pack(fill=tk.X)

        typos_label = tk.Label(options_frame, text="Typos:")
        typos_label.grid(row=0, column=0, sticky=tk.W)
        Tooltip(typos_label, "The maximum number of typos to simulate in each password guess.\nA typo can be a swapped, deleted, or case-changed character.")
        tk.Spinbox(options_frame, from_=0, to=4, textvariable=self.typos_count, width=5).grid(row=0, column=1, sticky=tk.W, padx=5)

        typo_types_label = tk.Label(options_frame, text="Typo Types:")
        typo_types_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        Tooltip(typo_types_label, "Select the types of typos to simulate.\n'Swap' swaps adjacent characters, 'Delete' removes a character,\nand 'Case' changes the case of a letter.")
        tk.Checkbutton(options_frame, text="Swap", variable=self.typo_swap).grid(row=1, column=1, sticky=tk.W)
        tk.Checkbutton(options_frame, text="Delete", variable=self.typo_delete).grid(row=1, column=2, sticky=tk.W)
        tk.Checkbutton(options_frame, text="Case", variable=self.typo_case).grid(row=1, column=3, sticky=tk.W)

        threads_label = tk.Label(options_frame, text="Threads:")
        threads_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        Tooltip(threads_label, "The number of CPU threads to use for the recovery process.\nMore threads can be faster on multi-core CPUs.")
        tk.Spinbox(options_frame, from_=1, to=btcrpass.cpus, textvariable=self.threads_count, width=5).grid(row=2, column=1, sticky=tk.W, padx=5)

        run_frame = tk.Frame(master, padx=10, pady=10)
        run_frame.pack(fill=tk.BOTH, expand=True)

        self.start_button = tk.Button(run_frame, text="Start Recovery", command=self.run_recovery, font=("Helvetica", 12, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.cancel_button = tk.Button(run_frame, text="Cancel", command=self.cancel_recovery, font=("Helvetica", 12, "bold"), state=tk.DISABLED)
        self.cancel_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.progress = ttk.Progressbar(run_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        self.output_console = ScrolledText(run_frame, height=10)
        self.output_console.pack(fill=tk.BOTH, expand=True)
        self.output_console.config(state=tk.DISABLED)

    def show_about(self):
        tkMessageBox.showinfo("About BTCRecover GUI",
                              "BTCRecover GUI\n\n"
                              "A simple graphical frontend for the btcrecover password recovery tool.\n\n"
                              "Copyright (C) 2024")

    def show_usage(self):
        tkMessageBox.showinfo("How to Use",
                              "1. Select your encrypted wallet file.\n"
                              "2. Select a password list or a token list.\n"
                              "3. (Optional) Adjust the typo and thread settings.\n"
                              "4. Click 'Start Recovery' to begin.\n\n"
                              "For more detailed instructions, please see the btcrecover documentation.")

    def select_wallet(self):
        path = tkFileDialog.askopenfilename(title="Select your wallet file")
        if path:
            self.wallet_path.set(path)

    def select_passwordlist(self):
        path = tkFileDialog.askopenfilename(title="Select your password list file")
        if path:
            self.passwordlist_path.set(path)
            self.tokenlist_path.set("")

    def select_tokenlist(self):
        path = tkFileDialog.askopenfilename(title="Select your password tokenlist file")
        if path:
            self.tokenlist_path.set(path)
            self.passwordlist_path.set("")

    def progress_callback(self, recovered_so_far, total_to_recover):
        self.progress['value'] = (recovered_so_far / total_to_recover) * 100
        self.master.update_idletasks()

    def cancel_recovery(self):
        btcrpass.stop_all_threads = True

    def run_recovery(self):
        wallet = self.wallet_path.get()
        if not wallet:
            tkMessageBox.showerror("Error", "Please select a wallet file.")
            return

        passwordlist = self.passwordlist_path.get()
        tokenlist = self.tokenlist_path.get()

        if not passwordlist and not tokenlist:
            tkMessageBox.showerror("Error", "Please select a passwordlist or tokenlist file.")
            return

        argv = []
        argv.extend(["--wallet", wallet])

        if passwordlist:
            argv.extend(["--passwordlist", passwordlist])
        elif tokenlist:
            argv.extend(["--tokenlist", tokenlist])

        typos = self.typos_count.get()
        if typos > 0:
            argv.extend(["--typos", str(typos)])
            if self.typo_swap.get(): argv.append("--typos-swap")
            if self.typo_delete.get(): argv.append("--typos-delete")
            if self.typo_case.get(): argv.append("--typos-case")

        argv.extend(["--threads", str(self.threads_count.get())])

        self.start_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        self.progress['value'] = 0

        # Redirect stdout and stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = ConsoleRedirector(self.output_console)
        sys.stderr = sys.stdout

        try:
            btcrpass.parse_arguments(argv, progress_callback=self.progress_callback)
            (password_found, not_found_msg) = btcrpass.main()

            if isinstance(password_found, str):
                tkMessageBox.showinfo("Success!", "Password found: '{}'".format(password_found))
            elif not_found_msg:
                tkMessageBox.showinfo("Finished", not_found_msg)
            else:
                tkMessageBox.showerror("Error", "An unknown error occurred, or the recovery was cancelled.")

        except SystemExit as e:
            tkMessageBox.showerror("Error", "BTCRecover exited with an error: " + str(e))
        except Exception as e:
            tkMessageBox.showerror("Fatal Error", "A fatal error occurred: " + str(e))
        finally:
            # Restore stdout and stderr
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            self.start_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)
            self.progress['value'] = 0

def main():
    root = tk.Tk()
    gui = BTCRecoverGUI(root)
    root.mainloop()

if __name__ == "__main__":
    # This is required for multiprocessing to work correctly on Windows
    multiprocessing.freeze_support()
    main()
