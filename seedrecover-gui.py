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
# Add the directory containing btcrecover to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
from btcrecover import btcrpass, btcrseed
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

class SeedRecoverGUI:
    def __init__(self, master):
        self.master = master
        master.title("SeedRecover GUI")

        menubar = tk.Menu(master)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.show_about)
        helpmenu.add_command(label="Usage", command=self.show_usage)
        menubar.add_cascade(label="Help", menu=helpmenu)
        master.config(menu=menubar)

        window_width = 600
        window_height = 500
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)
        master.geometry('{}x{}+{}+{}'.format(window_width, window_height, position_right, position_top))

        self.wallet_type = tk.StringVar()
        self.wallet_path = tk.StringVar()
        self.mpk = tk.StringVar()
        self.addresses = tk.StringVar()
        self.addr_limit = tk.IntVar(value=10)
        self.mnemonic_guess = tk.StringVar()
        self.typos_count = tk.IntVar(value=1)
        self.threads_count = tk.IntVar(value=btcrpass.cpus)
        self.passphrase = tk.BooleanVar()

        main_frame = tk.Frame(master, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Wallet Type
        wallet_type_label = tk.Label(main_frame, text="Wallet Type:")
        wallet_type_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        Tooltip(wallet_type_label, "Select the type of wallet you are trying to recover.")

        btcrseed.register_autodetecting_wallets()
        wallet_types = [desc for cls, desc in btcrseed.selectable_wallet_classes]
        self.wallet_type.set(wallet_types[0])
        wallet_type_menu = tk.OptionMenu(main_frame, self.wallet_type, *wallet_types, command=self.update_wallet_options)
        wallet_type_menu.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5)

        # Wallet Options Frame
        self.wallet_options_frame = tk.Frame(main_frame)
        self.wallet_options_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)

        self.wallet_path_label = tk.Label(self.wallet_options_frame, text="Wallet File:")
        self.wallet_path_entry = tk.Entry(self.wallet_options_frame, textvariable=self.wallet_path, width=50, state='readonly')
        self.wallet_path_button = tk.Button(self.wallet_options_frame, text="Browse...", command=self.select_wallet)

        self.mpk_label = tk.Label(self.wallet_options_frame, text="Master Public Key:")
        self.mpk_entry = tk.Entry(self.wallet_options_frame, textvariable=self.mpk, width=50)

        self.addresses_label = tk.Label(self.wallet_options_frame, text="Addresses (space-separated):")
        self.addresses_entry = tk.Entry(self.wallet_options_frame, textvariable=self.addresses, width=50)

        self.addr_limit_label = tk.Label(self.wallet_options_frame, text="Address Limit:")
        self.addr_limit_spinbox = tk.Spinbox(self.wallet_options_frame, from_=1, to=1000, textvariable=self.addr_limit, width=8)

        # Mnemonic Guess
        mnemonic_label = tk.Label(main_frame, text="Mnemonic Guess:")
        mnemonic_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        Tooltip(mnemonic_label, "Enter your best guess for the mnemonic seed phrase.")
        tk.Entry(main_frame, textvariable=self.mnemonic_guess, width=70).grid(row=2, column=1, columnspan=2, padx=5)

        # Options
        options_frame = tk.Frame(main_frame)
        options_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=5)

        self.typo_strategy = tk.StringVar(value="Common")
        typo_strategy_label = tk.Label(options_frame, text="Typo Strategy:")
        typo_strategy_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        Tooltip(typo_strategy_label, "Select a typo generation strategy.")
        typo_strategy_menu = tk.OptionMenu(options_frame, self.typo_strategy, "None", "Common", "All")
        typo_strategy_menu.grid(row=0, column=1, sticky=tk.W, padx=5)

        threads_label = tk.Label(options_frame, text="Threads:")
        threads_label.grid(row=0, column=2, sticky=tk.W, padx=20)
        Tooltip(threads_label, "Number of CPU threads to use.")
        tk.Spinbox(options_frame, from_=1, to=btcrpass.cpus, textvariable=self.threads_count, width=5).grid(row=0, column=3, sticky=tk.W, padx=5)

        passphrase_check = tk.Checkbutton(options_frame, text="Use Passphrase", variable=self.passphrase)
        passphrase_check.grid(row=0, column=4, sticky=tk.W, padx=20)
        Tooltip(passphrase_check, "Check this if your mnemonic seed is protected by a passphrase.")

        # Run Frame
        run_frame = tk.Frame(main_frame, pady=10)
        run_frame.grid(row=4, column=0, columnspan=3, sticky="ew")

        self.start_button = tk.Button(run_frame, text="Start Recovery", command=self.run_recovery, font=("Helvetica", 12, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.cancel_button = tk.Button(run_frame, text="Cancel", command=self.cancel_recovery, font=("Helvetica", 12, "bold"), state=tk.DISABLED)
        self.cancel_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.progress = ttk.Progressbar(run_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # Output Console
        self.output_console = ScrolledText(main_frame, height=10)
        self.output_console.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=5)
        self.output_console.config(state=tk.DISABLED)
        main_frame.grid_rowconfigure(5, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        self.update_wallet_options()

    def show_about(self):
        tkMessageBox.showinfo("About SeedRecover GUI",
                              "SeedRecover GUI\n\n"
                              "A simple graphical frontend for the seedrecover tool.\n\n"
                              "Copyright (C) 2024")

    def show_usage(self):
        tkMessageBox.showinfo("How to Use",
                              "1. Select the wallet type.\n"
                              "2. Fill in the required information for the selected wallet type.\n"
                              "3. Enter your best guess for the mnemonic seed phrase.\n"
                              "4. (Optional) Adjust the typo and thread settings.\n"
                              "5. Click 'Start Recovery' to begin.\n\n"
                              "For more detailed instructions, please see the seedrecover documentation.")

    def update_wallet_options(self, *args):
        for widget in self.wallet_options_frame.winfo_children():
            widget.grid_forget()

        wallet_type_name = self.wallet_type.get()
        selected_cls = None
        for cls, desc in btcrseed.selectable_wallet_classes:
            if desc == wallet_type_name:
                selected_cls = cls
                break

        if selected_cls:
            row = 0
            if hasattr(selected_cls, "is_wallet_file"):
                self.wallet_path_label.grid(row=row, column=0, sticky=tk.W, pady=5)
                self.wallet_path_entry.grid(row=row, column=1, padx=5)
                self.wallet_path_button.grid(row=row, column=2)
                row += 1
            if "mpk" in selected_cls.create_from_params.__code__.co_varnames:
                self.mpk_label.grid(row=row, column=0, sticky=tk.W, pady=5)
                self.mpk_entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=5)
                row += 1
            if "addresses" in selected_cls.create_from_params.__code__.co_varnames:
                self.addresses_label.grid(row=row, column=0, sticky=tk.W, pady=5)
                self.addresses_entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=5)
                row += 1
            if "address_limit" in selected_cls.create_from_params.__code__.co_varnames:
                self.addr_limit_label.grid(row=row, column=0, sticky=tk.W, pady=5)
                self.addr_limit_spinbox.grid(row=row, column=1, sticky=tk.W, padx=5)
                row += 1

    def select_wallet(self):
        path = tkFileDialog.askopenfilename(title="Select your wallet file")
        if path:
            self.wallet_path.set(path)

    def progress_callback(self, recovered_so_far, total_to_recover):
        self.progress['value'] = (recovered_so_far / total_to_recover) * 100
        self.master.update_idletasks()

    def cancel_recovery(self):
        btcrpass.stop_all_threads = True

    def run_recovery(self):
        argv = []

        wallet_type_name = self.wallet_type.get()
        selected_cls = None
        for cls, desc in btcrseed.selectable_wallet_classes:
            if desc == wallet_type_name:
                selected_cls = cls
                break

        argv.extend(["--wallet-type", selected_cls.__name__.replace("Wallet", "", 1).lower()])

        if self.wallet_path.get() and hasattr(selected_cls, "is_wallet_file"):
            argv.extend(["--wallet", self.wallet_path.get()])
        elif self.mpk.get() and "mpk" in selected_cls.create_from_params.__code__.co_varnames:
            argv.extend(["--mpk", self.mpk.get()])
        elif self.addresses.get() and "addresses" in selected_cls.create_from_params.__code__.co_varnames:
            argv.extend(["--addrs"] + self.addresses.get().split())
            if "address_limit" in selected_cls.create_from_params.__code__.co_varnames:
                argv.extend(["--addr-limit", str(self.addr_limit.get())])

        mnemonic = self.mnemonic_guess.get()
        if not mnemonic:
            tkMessageBox.showerror("Error", "Please enter a mnemonic guess.")
            return

        # This is a bit of a hack to pass the mnemonic guess
        with open("temp_mnemonic.txt", "w") as f:
            f.write(mnemonic)
        argv.extend(["--mnemonic-prompt"]) # This will be intercepted

        strategy = self.typo_strategy.get()
        if strategy == "None":
            argv.extend(["--typos", "0"])
        elif strategy == "Common":
            argv.extend(["--typos", str(self.typos_count.get())])
        elif strategy == "All":
            argv.extend(["--typos", str(self.typos_count.get()), "--big-typos", str(self.typos_count.get())])

        argv.extend(["--threads", str(self.threads_count.get())])

        if self.passphrase.get():
            argv.append("--passphrase")

        self.start_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = ConsoleRedirector(self.output_console)
        sys.stderr = sys.stdout

        try:
            # Intercept mnemonic prompt
            def get_mnemonic(prompt):
                with open("temp_mnemonic.txt", "r") as f:
                    return f.read()

            try:
                import __builtin__
                original_raw_input = __builtin__.raw_input
                __builtin__.raw_input = get_mnemonic
            except ImportError:
                import builtins
                original_input = builtins.input
                builtins.input = get_mnemonic

            # In Python 3, it's input
            try:
                import builtins
                original_input = builtins.input
                builtins.input = get_mnemonic
            except (ImportError, AttributeError):
                pass

            mnemonic_found = btcrseed.main(argv, progress_callback=self.progress_callback)

            # Restore original functions
            try:
                import __builtin__
                __builtin__.raw_input = original_raw_input
            except ImportError:
                import builtins
                builtins.input = original_input

            if os.path.exists("temp_mnemonic.txt"):
                os.remove("temp_mnemonic.txt")


            if isinstance(mnemonic_found, str):
                tkMessageBox.showinfo("Success!", "Seed found: '{}'".format(mnemonic_found))
            elif mnemonic_found is False:
                tkMessageBox.showinfo("Finished", "Seed not found.")
            else:
                tkMessageBox.showerror("Error", "An unknown error occurred, or the recovery was cancelled.")

        except SystemExit as e:
            if e.code != 0:
                tkMessageBox.showerror("Error", "SeedRecover exited with an error: " + str(e))
        except Exception as e:
            tkMessageBox.showerror("Fatal Error", "A fatal error occurred: " + str(e))
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            self.start_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    gui = SeedRecoverGUI(root)
    root.mainloop()

class MockGUI:
    def __init__(self):
        self.wallet_type = ""
        self.wallet_path = ""
        self.mpk = ""
        self.addresses = ""
        self.addr_limit = 10
        self.mnemonic_guess = ""
        self.typos_count = 1
        self.threads_count = btcrpass.cpus
        self.passphrase = False

        class MockWidget:
            def config(self, *args, **kwargs):
                pass
            def delete(self, *args, **kwargs):
                pass
            def insert(self, *args, **kwargs):
                pass
            def see(self, *args, **kwargs):
                pass
            def update_idletasks(self, *args, **kwargs):
                pass
        self.output_console = MockWidget()
        self.start_button = MockWidget()

    def run_recovery(self):
        # Create a dummy object with a 'get' method for each variable
        class MockVar:
            def __init__(self, value):
                self._value = value
            def get(self):
                return self._value

        self.wallet_type = MockVar(self.wallet_type)
        self.wallet_path = MockVar(self.wallet_path)
        self.mpk = MockVar(self.mpk)
        self.addresses = MockVar(self.addresses)
        self.addr_limit = MockVar(self.addr_limit)
        self.mnemonic_guess = MockVar(self.mnemonic_guess)
        self.typos_count = MockVar(self.typos_count)
        self.threads_count = MockVar(self.threads_count)
        self.passphrase = MockVar(self.passphrase)

        SeedRecoverGUI.run_recovery(self)

def test_integration():
    gui = MockGUI()
    gui.wallet_type = 'Electrum 2.x ("standard" wallets initially created with 2.x)'
    gui.mnemonic_guess = " ".join("act" for i in range(12))
    gui.typos_count = 0
    gui.threads_count = 1
    gui.passphrase = False
    gui.run_recovery()

if __name__ == "__main__":
    # This is required for multiprocessing to work correctly on Windows
    multiprocessing.freeze_support()

    if "--test" in sys.argv:
        test_integration()
    else:
        main()
