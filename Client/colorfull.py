# Import needed libraries and modules
import colorama

# Colorama colourfull class
class Colourfull:
    # Initing class
    def __init__(self):
        colorama.just_fix_windows_console()
        colorama.init()

    # Printing different colours easily
    def print_red(self) -> None:
        print(colorama.Fore.RED, end="")
    def print_green(self) -> None:
        print(colorama.Fore.GREEN, end="")
    def print_yellow(self) -> None:
        print(colorama.Fore.YELLOW, end="")
    def print_cyan(self) -> None:
        print(colorama.Fore.CYAN, end="")
    def print_black(self) -> None:
        print(colorama.Fore.BLACK, end="")
    def print_magenta(self) -> None:
        print(colorama.Fore.MAGENTA, end="")
    def print_blue(self) -> None:
        print(colorama.Fore.BLUE, end="")

    # Printing colorfull patterns
    def print_client(self) -> None:
        self.print_magenta()
        print("[CLIENT] ", end="")
    def print_client_from(self, _from : str) -> None:
        self.print_magenta()
        print(f"[CLIENT from {_from}] ", end="")
        