import sys
import os
import multiprocessing
try:
    import Tkinter as tk
except ImportError:
    # Python 3
    import tkinter as tk

class MainGUI:
    def __init__(self, master):
        self.master = master
        master.title("BTCRecover")

        window_width = 300
        window_height = 200
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)
        master.geometry('{}x{}+{}+{}'.format(window_width, window_height, position_right, position_top))

        main_frame = tk.Frame(master, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        password_button = tk.Button(main_frame, text="Recover Password", command=self.open_btcrecover_gui, font=("Helvetica", 12, "bold"))
        password_button.pack(pady=20)

        seed_button = tk.Button(main_frame, text="Recover Seed", command=self.open_seedrecover_gui, font=("Helvetica", 12, "bold"))
        seed_button.pack(pady=20)

    def open_btcrecover_gui(self):
        self.master.destroy()
        os.system("python3 btcrecover-gui.py")

    def open_seedrecover_gui(self):
        self.master.destroy()
        os.system("python3 seedrecover-gui.py")

def main():
    root = tk.Tk()
    gui = MainGUI(root)
    root.mainloop()

if __name__ == "__main__":
    # This is required for multiprocessing to work correctly on Windows
    multiprocessing.freeze_support()
    main()
