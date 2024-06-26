"""
@author : Aymen Brahim Djelloul
version : 1.0
date : 02.09.2023
LICENSE : MIT

                                 _       ___               _
                  /\  /\__ _ ___| |__   / __\ __ __ _  ___| | __
                 / /_/ / _` / __| '_ \ / / | '__/ _` |/ __| |/ /
                / __  / (_| \__ \ | | / /__| | | (_| | (__|   <
                \/ /_/ \__,_|___/_| |_\____/_|  \__,_|\___|_|\_\

    // HashCrack is a simple and light-weight tool to crack a hash using wordlist


"""

# IMPORTS
import sys
import os.path
import hashlib
from time import perf_counter, sleep
from exceptions import *

# DEFINE VARIABLES
AUTHOR = "Aymen Brahim Djelloul"
VERSION = "1.0"
SUPPORTED_HASH_FUNCTIONS = ("md5", "sha1", "sha3", "sha256",
                            "sha224", "sha384", "sha512")

BANNER = f"""
                 _       ___               _    
  /\  /\__ _ ___| |__   / __\ __ __ _  ___| | __
 / /_/ / _` / __| '_ \ / / | '__/ _` |/ __| |-/
/ __  / (_| \__ \ | | / /__| | | (_| | (__|   < 
\/ /_/ \__,_|___/_| |_\____/_|  \__,_|\___|_|\_\\
                     V{VERSION}\n
=================================================
#                                               #
#  AUTHOR : {AUTHOR}               #
#  Protected Under MIT License Copyright 2023   #
#                                               #
================================================
                                                
"""

# Define colors variables
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
BLUE = "\033[34m"
PURPLE = "\033[95m"
BOLD_FONT = "\033[1m"
COLOR_RESET = "\033[0m"


# Define the platform OS to get the console clear command
CONSOLE_CLEAR = None

if sys.platform == "linux" or "darwin":
    CONSOLE_CLEAR = "clear"
elif sys.platform == "win32":
    CONSOLE_CLEAR = "cls"


class HashCrack:

    # DECLARE SOME VARIABLES
    __HASHES_LENGTH = {
        32: "md5",      # md5    : 128bit
        40: "sha1",     # sha1   : 160bit
        56: "sha224",   # sha224 : 224bit
        64: "sha256",   # sha256 : 256bit
        96: "sha384",   # sha384 : 384bit
        128: "sha512"    # sha512 : 512bit
    }

    # DEFINE HASH FUNCTIONS ON DICTIONARY
    __HASH_FUNCTIONS: dict = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512
    }

    # DEFINE EMPTY VARIABLE FOR ATTEMPTS PER SECOND
    ATTEMPTS_PER_SECOND: int = 0

    def __init__(self, _hash: str, wordlist: str, interface_mode: bool = True):

        # Get the hash function
        self.hashing_func = self.__get_hashing_function(_hash)
        self.__hash = _hash
        self.interface_mode = interface_mode

        # Define empty list for wordlist
        self.wordlist: list = []

        if self.__is_valid_wordlist(wordlist):
            # Load wordlist content
            self.__load_wordlist_pass(wordlist)
            # get the passwords wordlist hashed
            self.hashed_wordlist: list = self.__hash_wordlist()
            # print(self.hashed_wordlist)

        else:
            raise WordlistNotFound

    def crack(self):
        """ This method will crack the given hash by performing a wordlist attack"""

        # Define empty password variable
        word: str = ""

        # Get the start cracking time
        s_time: float = perf_counter()
        # Iterate through the given wordlist
        for hash in self.hashed_wordlist:

            # Compare the two hashes
            if self.__hash == hash:
                # Get the word compatible with the found hash
                word = self.wordlist[self.hashed_wordlist.index(hash)]

                # Check if the program is running on interface mode
                if self.interface_mode:
                    # Clear console
                    os.system(CONSOLE_CLEAR)
                    # Print out the result
                    print(f"{BANNER}\n"
                          f"{GREEN}{' ' * 10}Hash cracked successfully !{COLOR_RESET}\n"
                          f"Password : {BOLD_FONT}{word}{COLOR_RESET}{' ' * 30}Cracked in : {self.__friendly_time_format(perf_counter() - s_time)}")

                    # Clear memory
                    del self.wordlist, self.hashed_wordlist, s_time, hash, self.__hash

                    break

                else:
                    # Clear memory
                    del self.wordlist, self.hashed_wordlist, s_time, hash, self.__hash

                    # return the password only when it's not runs on interface
                    return word

        # return None when password not found
        # Check if the for loop terminated
        if self.wordlist.index(word) == len(self.wordlist):
            if self.interface_mode:
                # Clear console
                os.system(CONSOLE_CLEAR)
                # Print out the result
                print(f"{BANNER}\n{YELLOW}{' ' * 30} Password not found ! Please try another wordlist .{COLOR_RESET}\n")

                # Clear memory
                del self.wordlist, self.hashed_wordlist, word, s_time, hash, self.__hash

            else:
                # Clear memory
                del self.wordlist, self.hashed_wordlist, word, s_time, hash, self.__hash

                return None

    def __get_hashing_function(self, _hash: bytes) -> str:
        """ This method will return the hashing function name of the used hash"""

        # Get the hash length
        hash_length: int = len(_hash)
        for length in self.__HASHES_LENGTH.keys():

            # Compare the hash lengths
            if length == hash_length:
                # Clear memory
                del hash_length, _hash
                return self.__HASHES_LENGTH[length]

        # Clear memory
        del hash_length, _hash, length
        # Raise A Hash function cannot be detected
        raise HashFunctionCannotBeDetected

    def __get_pass_hash(self, password: bytes) -> bytes:
        """ This method will return a password hash using the determined hashing function"""
        return self.__HASH_FUNCTIONS[self.hashing_func](password.encode("UTF-8")).hexdigest()

    @staticmethod
    def __is_valid_wordlist(file_path: str) -> bool:
        """ This method will check if the wordlist file is valid"""
        return True if os.path.exists(f"{os.getcwd()}\\{file_path}") else False

    def __load_wordlist_pass(self, file_path: str):
        """ This method will load the wordlist"""

        # Read passwords from wordlist
        try:
            with open(f"{os.getcwd()}\\{file_path}", "r", encoding="UTF-8") as file:
                self.wordlist = file.read().split()

            # Clear memory
            del file_path, file

        # Handle exceptions
        except UnicodeDecodeError:
            raise WordlistCannotBeUsed

        except PermissionError:
            raise WordlistCannotBeUsed

    def get_remaining_time(self):
        """ This method will calculate the estimation of the time remaining for hash crack"""

        # Get the time taken of a single iter
        # Store the start time
        s_time: float = perf_counter()

        # make one iterate
        for i in self.wordlist:
            password_hash: str = self.__get_pass_hash(i)

            if self.__hash == password_hash:
                pass

            break

        # Store the end time
        end_time: float = perf_counter()

        # Calculate remaining time in seconds
        remaining_time: flaot = (end_time - s_time) * len(self.wordlist)

        # Calculate the attempts per seconds
        self.ATTEMPTS_PER_SECOND = 1 / (end_time - s_time)

        # Clear memory
        del s_time, i, password_hash, end_time
        # Get the friendly remaining time and return it
        return self.__friendly_time_format(remaining_time)

    def __hash_wordlist(self) -> list:
        """ This method will return a list contain hashes of given wordlist"""

        # Define empty list for hashes wordlist
        hashed_wordlist: list = []

        # Define the word hashing function
        hash_function: str = self.__HASH_FUNCTIONS[self.__get_hashing_function(self.__hash)]

        for word in self.wordlist:

            # Get the word hash
            hashed_wordlist.append(hash_function(word.encode("UTF-8")).hexdigest())

        # Clear memory
        del word
        # Return the hashes wordlist
        return hashed_wordlist

    @staticmethod
    def __friendly_time_format(seconds: float) -> str:
        """ This method will convert the seconds into friendly time format"""

        # Convert seconds parameter into int
        _seconds = int(seconds)

        # Calculate the hours, minutes, and seconds
        hours = _seconds // 3600
        minutes = (_seconds % 3600) // 60
        seconds = _seconds % 60
        milliseconds = (_seconds % 1) * 1000

        # Format the time string
        # handle hours and minutes
        time_str = ""
        if hours > 0:
            time_str += f"{hours} hours"
        if minutes > 0 or hours > 0:
            time_str += f" {minutes} minutes"

        # handle seconds
        if _seconds <= 60:
            time_str = f"{seconds} seconds"

        # handle milliseconds
        if seconds == 0:
            time_str += f"{int(milliseconds)} milliseconds"

        # Clear memory
        del _seconds, seconds, hours, minutes, milliseconds
        return time_str



def main():
    """ This function is the main to start Hash Crack"""

    print(f"{BOLD_FONT}{BANNER}{COLOR_RESET}\n")
    _hash = str(input(f"{PURPLE}Enter the HASH : {COLOR_RESET}"))
    wordlist_path = str(input(f"{PURPLE}Wordlist Path : {COLOR_RESET}"))

    # Create HashCrack object
    try:
        hash_crack_obj = HashCrack(_hash, wordlist_path)

    # Errors Handling
    except WordlistNotFound:
        print(f"{RED}Cannot get the wordlist. Please try Again!{COLOR_RESET}{YELLOW}\nExiting...{COLOR_RESET}")
        sleep(2)
        sys.exit()

    # Clear memory
    del _hash, wordlist_path

    # Print the detected hash function with the number of passwords to try
    # With the question if the user is ready!
    print(f"\n{BOLD_FONT}Hash Function used : {hash_crack_obj.hashing_func}"
          f"{' ' * 30}Count Passwords : {len(hash_crack_obj.wordlist)}\n")

    # Print the estimated remaining time
    print(f"{BOLD_FONT}Remaining time : {hash_crack_obj.get_remaining_time()}"
          f"{' ' * 30}Attempts per second : {int(hash_crack_obj.ATTEMPTS_PER_SECOND)}")

    # Ask the user
    answer = str(input("\nAre you ready to start ? [Y|N]")).lower()
    if answer.upper() == "Y":
        # Start the Cracking
        hash_crack_obj.crack()

    elif answer.upper() == "N":
        # otherwise clear the console and rerun the software
        os.system(CONSOLE_CLEAR)
        main()


if __name__ == "__main__":
    # LAUNCH THE APP
    main()
