import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import subprocess
import os
import sys
import threading
from typing import Optional

# --- Constants for UI theming and configuration ---
BG_COLOR = "#f0f0f0"
FG_COLOR = "#333333"
FONT_FAMILY = "Helvetica"
DEFAULT_FONT = (FONT_FAMILY, 10)
TITLE_FONT = (FONT_FAMILY, 12, "bold")
BUTTON_FONT = (FONT_FAMILY, 10, "bold")
OUTPUT_FONT = ("Courier", 10)
DEFAULT_AUTOSAVE_FILE = "btcrecover.autosave"


class BTCRecoverGUI(tk.Tk):
    """
    A graphical user interface for the btcrecover command-line tool.

    This GUI provides an intuitive way to construct and run btcrecover
    commands, allowing users to select wallet files, specify recovery
    methods (password or token lists), and configure common options.
    """

    def __init__(self) -> None:
        super().__init__()

        self.title("BTCRecover GUI")
        self.geometry("850x650")
        self.configure(bg=BG_COLOR)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # To hold the running subprocess
        self.process: Optional[subprocess.Popen] = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initializes and lays out all the UI components."""
        main_frame = tk.Frame(self, padx=15, pady=15, bg=BG_COLOR)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Configure grid weights
        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Create and pack frames
        self._create_file_widgets(main_frame).grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self._create_options_widgets(main_frame).grid(row=1, column=0, sticky="ew", pady=5)
        self._create_output_widgets(main_frame).grid(row=2, column=0, sticky="nsew", pady=5)
        self._create_control_widgets(main_frame).grid(row=3, column=0, sticky="ew", pady=(10, 0))

    def _create_file_widgets(self, parent: tk.Frame) -> tk.LabelFrame:
        """Creates the widgets for file selection."""
        frame = tk.LabelFrame(parent, text="File Selection", padx=10, pady=10, bg=BG_COLOR, fg=FG_COLOR, font=TITLE_FONT)

        # Wallet File
        tk.Label(frame, text="Wallet File:", bg=BG_COLOR, fg=FG_COLOR, font=DEFAULT_FONT).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.wallet_file_entry = tk.Entry(frame, width=70, font=DEFAULT_FONT)
        self.wallet_file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        tk.Button(frame, text="Browse...", command=self._browse_wallet_file, font=BUTTON_FONT).grid(row=0, column=2, padx=5)

        # Recovery Method Radio Buttons
        self.recovery_method = tk.StringVar(value="passwordlist")
        tk.Radiobutton(frame, text="Password List", variable=self.recovery_method, value="passwordlist", command=self._toggle_recovery_inputs, bg=BG_COLOR, font=DEFAULT_FONT).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        tk.Radiobutton(frame, text="Token List", variable=self.recovery_method, value="tokenlist", command=self._toggle_recovery_inputs, bg=BG_COLOR, font=DEFAULT_FONT).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)

        # Password List
        self.passwordlist_entry = tk.Entry(frame, font=DEFAULT_FONT)
        self.passwordlist_entry.grid(row=1, column=1, sticky="ew", padx=5)
        self.passwordlist_button = tk.Button(frame, text="Browse...", command=self._browse_passwordlist, font=BUTTON_FONT)
        self.passwordlist_button.grid(row=1, column=2, padx=5)

        # Token List
        self.tokenlist_entry = tk.Entry(frame, font=DEFAULT_FONT, state=tk.DISABLED)
        self.tokenlist_entry.grid(row=2, column=1, sticky="ew", padx=5)
        self.tokenlist_button = tk.Button(frame, text="Browse...", command=self._browse_tokenlist, font=BUTTON_FONT, state=tk.DISABLED)
        self.tokenlist_button.grid(row=2, column=2, padx=5)

        frame.columnconfigure(1, weight=1)
        return frame

    def _create_options_widgets(self, parent: tk.Frame) -> tk.LabelFrame:
        """Creates the widgets for additional options."""
        frame = tk.LabelFrame(parent, text="Options", padx=10, pady=10, bg=BG_COLOR, fg=FG_COLOR, font=TITLE_FONT)

        # Typos
        self.typos_var = tk.BooleanVar()
        tk.Checkbutton(frame, text="Enable Typos (1-10):", variable=self.typos_var, bg=BG_COLOR, font=DEFAULT_FONT).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.typos_spinbox = tk.Spinbox(frame, from_=1, to=10, width=5, font=DEFAULT_FONT)
        self.typos_spinbox.grid(row=0, column=1, sticky=tk.W, padx=5)

        # No Duplicate Checks
        self.no_dupchecks_var = tk.BooleanVar()
        tk.Checkbutton(frame, text="Disable Duplicate Checks", variable=self.no_dupchecks_var, bg=BG_COLOR, font=DEFAULT_FONT).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

        # Autosave
        self.autosave_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Autosave Progress File:", variable=self.autosave_var, bg=BG_COLOR, font=DEFAULT_FONT).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.autosave_entry = tk.Entry(frame, width=30, font=DEFAULT_FONT)
        self.autosave_entry.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.autosave_entry.insert(0, DEFAULT_AUTOSAVE_FILE)
        
        return frame

    def _create_output_widgets(self, parent: tk.Frame) -> tk.LabelFrame:
        """Creates the scrolled text widget for command output."""
        frame = tk.LabelFrame(parent, text="Output", padx=10, pady=10, bg=BG_COLOR, fg=FG_COLOR, font=TITLE_FONT)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg="#ffffff", fg=FG_COLOR, font=OUTPUT_FONT, bd=1, relief=tk.SOLID)
        self.output_text.grid(row=0, column=0, sticky="nsew")

        return frame

    def _create_control_widgets(self, parent: tk.Frame) -> tk.Frame:
        """Creates the main control buttons (Run, Stop)."""
        frame = tk.Frame(parent, bg=BG_COLOR)

        self.run_button = tk.Button(frame, text="Run BTCRecover", command=self._run_btcrecover, bg="#4CAF50", fg="white", font=TITLE_FONT, relief=tk.RAISED, width=20)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(frame, text="Stop", command=self._stop_btcrecover, bg="#f44336", fg="white", font=TITLE_FONT, relief=tk.RAISED, state=tk.DISABLED, width=20)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        return frame

    def _browse_file(self, entry_widget: tk.Entry, is_wallet: bool = False) -> None:
        """Generic file browser dialog."""
        filetypes = (("All files", "*.*"),) if is_wallet else (("Text files", "*.txt"), ("All files", "*.*"))
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def _browse_wallet_file(self) -> None:
        self._browse_file(self.wallet_file_entry, is_wallet=True)

    def _browse_passwordlist(self) -> None:
        self._browse_file(self.passwordlist_entry)

    def _browse_tokenlist(self) -> None:
        self._browse_file(self.tokenlist_entry)

    def _toggle_recovery_inputs(self) -> None:
        """Enables/disables input fields based on the selected recovery method."""
        is_passwordlist = self.recovery_method.get() == "passwordlist"
        password_state = tk.NORMAL if is_passwordlist else tk.DISABLED
        token_state = tk.DISABLED if is_passwordlist else tk.NORMAL

        self.passwordlist_entry.config(state=password_state)
        self.passwordlist_button.config(state=password_state)
        self.tokenlist_entry.config(state=token_state)
        self.tokenlist_button.config(state=token_state)

    def _run_btcrecover(self) -> None:
        """Constructs the command and runs btcrecover in a separate thread."""
        # Find the path to btcrecover.py relative to this script
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        btcrecover_path = os.path.join(script_dir, "btcrecover.py")

        if not os.path.exists(btcrecover_path):
            messagebox.showerror("Error", f"Could not find 'btcrecover.py' in the script directory:\n{script_dir}")
            return

        command = ["python", btcrecover_path]

        # Validate wallet file
        wallet_file = self.wallet_file_entry.get()
        if not wallet_file or not os.path.exists(wallet_file):
            messagebox.showerror("Error", "Please select a valid wallet file.")
            return
        command.extend(["--wallet", wallet_file])

        # Add password/token list
        if self.recovery_method.get() == "passwordlist":
            passwordlist = self.passwordlist_entry.get()
            if not passwordlist or not os.path.exists(passwordlist):
                messagebox.showerror("Error", "Please select a valid password list file.")
                return
            command.extend(["--passwordlist", passwordlist])
        else:
            tokenlist = self.tokenlist_entry.get()
            if not tokenlist or not os.path.exists(tokenlist):
                messagebox.showerror("Error", "Please select a valid token list file.")
                return
            command.extend(["--tokenlist", tokenlist])

        # Add optional arguments
        if self.typos_var.get():
            command.extend(["--typos", self.typos_spinbox.get()])
        if self.no_dupchecks_var.get():
            command.append("--no-dupchecks")
        if self.autosave_var.get() and self.autosave_entry.get():
            command.extend(["--autosave", self.autosave_entry.get()])

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Running command: {' '.join(command)}\n\n")
        self._set_ui_state(running=True)

        # Run the command in a thread to keep the GUI responsive
        thread = threading.Thread(target=self._execute_command, args=(command,), daemon=True)
        thread.start()

    def _execute_command(self, command: list[str]) -> None:
        """Executes the command and streams its output to the text area."""
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                bufsize=1,
            )
            # Stream output line by line
            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ''):
                    self.output_text.insert(tk.END, line)
                    self.output_text.see(tk.END)
            self.process.wait()

        except Exception as e:
            self.output_text.insert(tk.END, f"\n--- An error occurred ---\n{e}\n")
        finally:
            self.process = None
            self._set_ui_state(running=False)

    def _stop_btcrecover(self) -> None:
        """Stops the running btcrecover process if it exists."""
        if self.process:
            self.process.terminate()
            self.output_text.insert(tk.END, "\n\nProcess terminated by user.\n")
            self.output_text.see(tk.END)

    def _set_ui_state(self, running: bool) -> None:
        """Toggles the state of control buttons."""
        state = tk.DISABLED if running else tk.NORMAL
        self.run_button.config(state=state)
        self.stop_button.config(state=tk.NORMAL if running else tk.DISABLED)

    def _on_closing(self) -> None:
        """Handles the window closing event."""
        if self.process:
            if messagebox.askyesno("Exit", "A recovery process is running. Do you want to stop it and exit?"):
                self._stop_btcrecover()
                self.destroy()
        else:
            self.destroy()


if __name__ == "__main__":
    # It's recommended to run this GUI from the same directory where
    # the main btcrecover.py script is located.
    app = BTCRecoverGUI()
    app.mainloop()
