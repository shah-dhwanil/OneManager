from psycopg import connect
from psycopg.errors import UniqueViolation, NoDataFound
from pyperclip import copy
from rich.box import DOUBLE_EDGE
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text
from sys import argv
from os import getenv
from one_manager.controller import Controller, DatabaseController
from one_manager.cryptography import Cryptography
from one_manager.utils import generate_master_key


class UI:
    """
    Command line Application
    """

    def __init__(self) -> None:
        self.console = Console(color_system='truecolor')
        host_addr = getenv("OneManager_DB_HOST", "localhost")
        port = getenv("OneManager_DB_PORT", "5432")
        db = getenv("OneManager_DB_NAME", "one_manager")
        username = getenv("OneManager_DB_USERNAME")
        password = getenv("OneManager_DB_PASSWORD")
        self.connection = connect(f"host={host_addr} port={port} dbname={db} user={username} password={password}",
                                  autocommit=True)
        self.__user_id__ = None
        self.__user_password__ = None
        self.render_banner()

    def render_banner(self):
        """
        Renders a banner on terminal
        :return: None
        """
        text = Text("""
         ▄██████▄  ███▄▄▄▄      ▄████████        ▄▄▄▄███▄▄▄▄      ▄████████ ███▄▄▄▄      ▄████████    ▄██████▄     ▄████████    ▄████████ 
        ███    ███ ███▀▀▀██▄   ███    ███      ▄██▀▀▀███▀▀▀██▄   ███    ███ ███▀▀▀██▄   ███    ███   ███    ███   ███    ███   ███    ███ 
        ███    ███ ███   ███   ███    █▀       ███   ███   ███   ███    ███ ███   ███   ███    ███   ███    █▀    ███    █▀    ███    ███ 
        ███    ███ ███   ███  ▄███▄▄▄          ███   ███   ███   ███    ███ ███   ███   ███    ███  ▄███         ▄███▄▄▄      ▄███▄▄▄▄██▀ 
        ███    ███ ███   ███ ▀▀███▀▀▀          ███   ███   ███ ▀███████████ ███   ███ ▀███████████ ▀▀███ ████▄  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
        ███    ███ ███   ███   ███    █▄       ███   ███   ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    █▄  ▀███████████ 
        ███    ███ ███   ███   ███    ███      ███   ███   ███   ███    ███ ███   ███   ███    ███   ███    ███   ███    ███   ███    ███ 
         ▀██████▀   ▀█   █▀    ██████████       ▀█   ███   █▀    ███    █▀   ▀█   █▀    ███    █▀    ████████▀    ██████████   ███    ███ 
                                                                                                                               ███    ███ 
        """)
        text.stylize("bold #2196F3")
        self.console.print(text)

    def show_identity_options(self):
        """
        Render a menu for signin ot signup
        :return: None
        """
        with self.console.screen() as screen:
            self.render_banner()
            self.console.print("1) [#29B6F6]Login[/]")
            self.console.print("2) [#29B6F6]Register[/]")
            value = Prompt.ask("[bold italic #64FFDA]Please select a choice[/]", choices=['1', '2'])
            if value == "1":
                self.renderer_login()
            else:
                self.render_register()
                self.renderer_login()
        self.render_main_screen_option()

    def render_main_screen_option(self):
        """
        Renders the main n=menu of the application
        :return: None
        """
        while True:
            table = Table(expand=True, box=DOUBLE_EDGE)
            table.add_column("[bold gold1]MENU                  [/]", justify="center", style="bold red")
            table.add_row("[blue] 1) [/] [rgb(249,38,114)]Store a secret           [/]")
            table.add_row("[blue] 2) [/] [rgb(249,38,114)]View a secret            [/]")
            table.add_row("[blue] 3) [/] [rgb(249,38,114)]Update a secret          [/]")
            table.add_row("[blue] 4) [/] [rgb(249,38,114)]Delete a secret          [/]")
            table.add_row("[blue] 5) [/] [rgb(249,38,114)]Generate random password [/]")
            table.add_row("[blue] 6) [/] [rgb(249,38,114)]Exit [/]")
            self.console.print(table)
            value = Prompt.ask("[bold italic #64FFDA]Please select a choice[/]", choices=['1', '2', '3', '4', '5', '6'])
            if value == '1':
                self.render_create_secret()
            elif value == '2':
                self.render_view_secret()
            elif value == '3':
                self.render_update_secret()
            elif value == '4':
                self.render_delete_secret()
            elif value == '5':
                self.render_generate_password()
            elif value == '6':
                self.render_exit(True)
                return

    def renderer_login(self):
        """
        Renders Login interface in the terminal & performs login operation
        :return: None
        """
        while True:
            username = Prompt.ask("[bold italic #64FFDA]Enter your Username[/]")
            password = Prompt.ask("[bold italic #64FFDA]Enter your Password", password=True)
            verify = Controller.verify_password(self.connection, username, password)
            try:
                if verify == False:
                    self.console.print(f"[#FF1744]No user with name {username} exists. [/]")
                else:
                    self.__user_id__ = verify
                    self.__user_password__ = password
                    self.console.print("[bold green1]Successfully logged in :thumbsup: [/]")
                    Prompt.ask()
                    return None
            except Exception as exception:
                self.console.print("[#FF1744] An error occurred [/]")

    def render_register(self):
        """"
        Render Register interface on the terminal and performs signup operation
        :return None
        """
        while True:
            username = Prompt.ask("[bold italic #64FFDA]Enter your Username[/]")
            password = Prompt.ask("[bold italic #64FFDA]Enter your Password[/]", password=True)
            re_password = Prompt.ask("[bold italic #64FFDA]Retype your Password[/]", password=True)
            if password != re_password:
                self.console.print("[#FF1744]Password does not match Please retype of your password [/]")
                continue
            try:
                Controller.create_user(self.connection, username, password)
                self.console.print("[bold green1]Successfully created user :thumbsup: [/]")
                self.console.input("[bold italic #64FFDA]Press any key to continue to login ... [/]")
                return
            except UniqueViolation as excpetion:
                self.console.print(
                    f"[#FF1744]Already user with name {username} exists. Please use a different username  [/]")
            except Exception as exception:
                self.console.print("[#FF1744] An error occurred [/]")

    def render_create_secret(self):
        """
        Renders Save a Secret interface on the terminal and stores the secret in the database
        :return: None
        """
        while True:
            try:
                name = Prompt.ask("[bold italic #64FFDA]Enter name of secret[/]")
                secret = Prompt.ask("[bold italic #64FFDA]Enter the secret[/]", password=True)
                Controller.create_secret(self.connection, self.__user_id__, self.__user_password__, name, secret)
                self.console.print("[bold green1]Successfully stored secret :thumbsup: [/]")
                return
            except UniqueViolation:
                self.console.print(f"[#FF1744]Already secret with name {name} exists. Please use a different name  [/]")
            except Exception:
                self.console.print("[#FF1744] An error occurred [/]")
                self.render_exit(wait=True)
                return

    def render_view_secret(self):
        """
        Renders View Secret interface and reads the secret from database
        :return: None
        """
        while True:
            try:
                name = Prompt.ask("[bold italic #64FFDA]Enter name of secret[/]")
                secret = Controller.get_secret(self.connection, self.__user_id__, name)
                self.console.print("1) [#29B6F6]Copy Secret[/]")
                self.console.print("2) [#29B6F6]Display Secret[/]")
                value = Prompt.ask("[bold italic #64FFDA]Please select a option[/]", choices=['1', '2'])
                if value == '1':
                    copy(secret)
                    self.console.print("[bold green1]Secret has been copied to clipboard. :thumbsup:[/]")
                else:
                    self.console.print(f"[bold italic #64FFDA]The secret is :-[/] [gold1]{secret}[/]")
                return
            except NoDataFound as exception:
                self.console.print(f"[#FF1744] No secret found with name {name}. Please enter a valid name [/]")
            except Exception as exception:
                print(type(exception), exception)
                self.console.print("[#FF1744] An error occurred [/]")
                self.render_exit(wait=True)
                return

    def render_update_secret(self):
        """
        Renders Update Secrets interface and updates the secrets
        :return: None
        """
        while True:
            try:
                name = Prompt.ask("[bold italic #64FFDA]Enter name of secret[/]")
                secret = Prompt.ask("[bold italic #64FFDA]Enter the secret[/]", password=True)
                Controller.update_secret(self.connection, self.__user_id__, self.__user_password__, name, secret)
                self.console.print("[bold green1]Successfully updated secret :thumbsup:[/]")
                break
            except NoDataFound as exception:
                self.console.print(f"[#FF1744] No secret found with name {name}. Please enter a valid name [/]")
            except Exception as exception:
                self.console.print("[#FF1744] An error occurred [/]")
                self.render_exit(wait=True)
                return

    def render_delete_secret(self):
        """
        Renders Delete Secret Interface and deletes the secret
        :return: None
        """
        while True:
            try:
                name = Prompt.ask("[bold italic #64FFDA]Enter name of secret[/]")
                Controller.delete_secret(self.connection, self.__user_id__, name)
                self.console.print("[bold green1]Successfully deleted secret :thumbsup:[/]")
                return
            except NoDataFound as exception:
                self.console.print(f"[#FF1744] No secret found with name {name}. Please enter a valid name [/]")
            except Exception as exception:
                print(type(exception), exception)
                self.console.print("[#FF1744] An error occurred [/]")
                self.render_exit(wait=True)
                return

    def render_generate_password(self):
        """
        Renders interface to generate random passwords and also store them or display it
        :return:
        """
        secret = Cryptography.generate_random_password(self.__user_password__)
        store = Confirm.ask("[bold italic #64FFDA]Do you want to store secret[/]")
        if store:
            while True:
                try:
                    name = Prompt.ask("[bold italic #64FFDA]Enter name of secret[/]")
                    Controller.create_secret(self.connection, self.__user_id__, self.__user_password__, name, secret)
                    self.console.print("[bold green1]Successfully stored secret :thumbsup: [/]")
                    break
                except UniqueViolation as excpetion:
                    self.console.print(
                        f"[#FF1744]Already secret with name {name} exists. Please use a different name  [/]")
                except Exception as exception:
                    self.console.print("[#FF1744] An error occurred [/]")
                    self.render_exit(wait=True)
                    break
        else:
            self.console.print("1) [#29B6F6]Copy Secret[/]")
            self.console.print("2) [#29B6F6]Display Secret[/]")
            value = Prompt.ask("[bold italic #64FFDA]Please select a option[/]", choices=['1', '2'])
            if value == '1':
                copy(secret)
                self.console.print("[bold green1]Secret has been copied to clipboard. :thumbsup:[/]")
            else:
                self.console.print(f"[bold italic #64FFDA]The secret is :-[/] [gold1]{secret}[/]")

    def render_exit(self, wait: bool = False):
        """
        Renders exist interface
        :param wait: If app need to wait before exiting
        :return: None
        """
        self.console.print("[bold italic cyan]Good bye :waving_hand:[/]")
        if wait:
            self.console.input("[bold italic #64FFDA]Press any key to exit ... [/]")
        self.connection.close()


if __name__ == "__main__":

    if "--setup" in argv:
        generate_master_key()
        host_addr = getenv("OneManager_DB_HOST", "localhost")
        port = getenv("OneManager_DB_PORT", "5432")
        db = getenv("OneManager_DB_NAME", "one_manager")
        username = getenv("OneManager_DB_USERNAME")
        password = getenv("OneManager_DB_PASSWORD")
        with connect(f"host={host_addr} port={port} dbname={db} user={username} password={password}",
                     autocommit=True) as connection:
            DatabaseController.setup(connection)
    else:
        ui = UI()
        ui.show_identity_options()
