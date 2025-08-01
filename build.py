import PyInstaller.__main__
import os

def build_executable(script_name, executable_name):
    """
    Builds a single executable file from a Python script using PyInstaller.
    """
    print(f"Current working directory: {os.getcwd()}")
    dist_path = os.path.join(os.getcwd(), 'dist')
    print(f"Dist path: {dist_path}")

    pyinstaller_options = [
        '--windowed',
        '--name', executable_name,
        os.path.join(os.path.dirname(__file__), script_name),
    ]

    print(f"Building {executable_name}...")
    PyInstaller.__main__.run(pyinstaller_options)
    print(f"Finished building {executable_name}.")

    print(f"Contents of dist directory: {os.listdir(dist_path)}")

if __name__ == '__main__':
    build_executable('btcrecover-gui.py', 'btcrecover-gui')
    build_executable('seedrecover-gui.py', 'seedrecover-gui')
