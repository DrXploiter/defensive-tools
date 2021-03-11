#Open source - Password Generator v1.5 developed by DrXploiter
import random


print("""
     .--------.
    | .------. |
   | /        \ |
   | |        | |
  _| |________| |_
.' |_|        |_| '.
'._____ ____ _____.'
|     .'____'.     |
'.__.'.'    '.'.__.'
'.__  | Pass |  __.'
|   '.'.____.'.'   |
'.____'.____.'____.'
'.________________.'  
Password Generator v1.5 By DrXploiter                                                                                                                                     
""")

#pass var
password = ''
#possible pass chars
letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '00', '01', '02']
symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+', '@', ')', '^', '€', ';', '_', '~', '-', '/', '=', '|', '']
spaces = (' ')


def automatic():
    global password
    validInput = False
    while not (validInput == True):
        try:
            numOfpasses= int(input("How many passwords do you wish to generate\n"))

            for _ in range(numOfpasses):
                #randomly select how many letters, symbols, numbers and spaces there will be in the password's property
                num_letters = random.randint(0, 20)
                num_symbols = random.randint(0, 5)
                num_numbers = random.randint(0, 6)
                num_spaces = random.randint(0, 1)

                #iteratively append to password based on the amount of letters, symbols, ect selected
                for genLetters in range(num_letters):
                    i = (random.randrange(0, len(letters) -1))
                    password+=str(letters[i])

                for genSymbols in range(num_symbols):
                    x = (random.randrange(0, len(symbols) - 1))
                    password += str(symbols[x])

                for genNumbers in range(num_numbers):
                    y = (random.randrange(0, len(numbers) - 1))
                    password += str(numbers[y])

                for amountOfspaces in range(num_spaces):
                    password +=(spaces)

                shuffledpass = (''.join(random.sample(password, len(password))))

                print(f"Generated password:{shuffledpass}")
                # clear current password var so we don't use the same characters in the next iteration
                password = ''

            retry = input("Retry? 'Y' to go back to the main menu. 'N' to exit.")
            if(retry == 'y' or retry == 'Y'):
                mainMenu()
            else:
                validInput = True #exit
                break
        except:
            print('Error: Invalid input value entered.')

def custom():
    global password
    validInput = False
    while not (validInput == True):
        try:
            nr_letters= int(input("How many letters would you like in your password?\n"))
            nr_symbols = int(input(f"How many symbols would you like?\n"))
            nr_numbers = int(input(f"How many numbers would you like?\n"))
            nr_spaces = int(input(f"How many spaces would you like\n"))

            numOfpasses = int(input("How many passwords do you wish to generate\n"))

            for _ in range(numOfpasses):
                #iteratively append to password based on the amount of letters, symbols, ect selected
                for genLetters in range(nr_letters):
                    i = (random.randrange(0, len(letters) -1))
                    password+=str(letters[i])

                for genSymbols in range(nr_symbols):
                    x = (random.randrange(0, len(symbols) -1))
                    password+=str(symbols[x])

                for genNumbers in range(nr_numbers):
                    y = (random.randrange(0, len(numbers) -1))
                    password+=str(numbers[y])

                for amountOfspaces in range(nr_spaces):
                        password+=(spaces)

                shuffledpass = (''.join(random.sample(password,len(password))))

                print(f"Generated password:{shuffledpass}")
                # clear current password var so we don't use the same characters in the next iteration
                password = ''

            retry = input("Retry? 'Y' to go back to the main menu. 'N' to exit.")
            if (retry == 'y' or retry == 'Y'):
                mainMenu()
            else:
                validInput = True #exit
                break

        except:
            print('Error: Invalid input value entered.')

def mainMenu():
    validInput = False
    while not (validInput == True):
        print("Welcome to the pseudo-random password Generator!")
        option = input("""
        Options:
        1. Automatically Generate password
        2. Custom define password properties for generation \n> """)

        if option == '1':
            automatic()
            validInput = True
        elif option == '2':
            custom()
            validInput = True
        else:
            print("""Error. Invalid value entered.
        Please enter a numbered option (eg; 2)""")

mainMenu()





