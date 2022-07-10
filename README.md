# Keylogger
Keyloggers are a particularly insidious type of spyware that can record and steal the user's keystrokes on a device. They are Software that logs what you type on your keyboard.

# Sample overview

md5 : A7F21E412022554D187D6A876A3C08AC

sha1 : 70E39BDFCAA4BCF0021311E8298266E527CF7C97

sha256 : 9B683D2FDA7CA7ADCC043E4412271009A0E115CA55F9A718C385A3F46B57AE6B
### Virustotal
<img src="https://user-images.githubusercontent.com/84356407/178140235-94f78b7c-d6af-4a86-8975-8d7c35f68f69.png" width="600">

### Unpacked
This sample is unpacked. It was checked by DIE & EXEINFO & PEID

<img src="https://user-images.githubusercontent.com/84356407/178139617-b804e8bc-074d-428c-b6c2-3a4c09c9e44e.png" width="500">

### Strings
<img src="https://user-images.githubusercontent.com/84356407/178142954-278e5f6b-ff1f-4ab0-80c9-dd0d1a3b0c67.png" width="300">

# How it works?
By examining the main function for this sample we found that it calls the 'SetWindowsHookExA' that installs the hook which is the type of 'WH_KEYBOARD_LL' that is specific to keyboard events then it points to the Hooking Function 'Hooking_Keyboard_Fun' as shown in the following picture:-

<img src="https://user-images.githubusercontent.com/84356407/178153358-d46daa19-cb66-4381-8492-70199eca9801.png" width="400">
inside this function 'Hooking_Keyboard_Fun' we can find that calls 'KeyLogging_Fun' as shown in the following picture:-

<img src="https://user-images.githubusercontent.com/84356407/178153830-083069a9-06d3-4aa7-87af-5c638712db61.png" width="400">
By examining this function 'KeyLogging_Fun' we can find :-

First : it creates a file called 'practicalmalwareanalysis.log' by calling 'CreateFileA' function to recode everything that you write on the keyboard then  as shown in the following picture:-

<img src="https://user-images.githubusercontent.com/84356407/178156194-7c894054-9572-416c-a875-18a7f2e2d63a.png" width="400">
Inside this file 'practicalmalwareanalysis.log' it recodes the window name that you open by calling this fun 'GetForegroundWindow' as shown in the following picture:-

<img src="https://user-images.githubusercontent.com/84356407/178156200-f85c2643-7757-425e-81a0-bf0c13c43d09.png" width="400">
It recodes the window name as the folloing pattern " [Window:  New Tab - window name]" as shown in the following picture:-
<img src="https://user-images.githubusercontent.com/84356407/178156205-ce6acb23-acbd-4761-ab3c-ad4c697ef822.png" width="400">
<img src="https://user-images.githubusercontent.com/84356407/178156450-1c64ee3c-80b7-4788-b7a9-debee841d02e.png" width="500">

Then it recodes eveything that you write on the keyboard but it first make a comparission in some case by its switch cases to check if you cleck on 'BackSpace','Crtl' or numbers etc. Then it recodes these Keystrokes as shown in the following picture:-

<img src="https://user-images.githubusercontent.com/84356407/178156226-06d41da3-a783-48ff-a634-de052cf8b74d.png" width="500">
Then it close the Handle for the file 'practicalmalwareanalysis.log' by calling 'CloseHandle' funcion as shown in the following picture:-
<img src="https://user-images.githubusercontent.com/84356407/178156229-ee146033-8f11-45a0-b2d4-6b994c7d858e.png" width="500">

# IOCs

### Hashes

sha256 : 9B683D2FDA7CA7ADCC043E4412271009A0E115CA55F9A718C385A3F46B57AE6B

### Functions

WriteFile

GetForegroundWindow

SetWindowsHookExA

### Strings

practicalmalwareanalysis.log

[SHIFT]

[TAB]

[BACKSPACE]

[CAPS LOCK]

# Sumerization
This malware called 'Keylogger', creates a file called 'practicalmalwareanalysis.log' then it records everything that you write on the keyboard
and this is a picture that shows the functionality after running this malware
<img src="https://user-images.githubusercontent.com/84356407/178157096-6f599656-2aa4-4c40-a687-169987f8eeb9.png" width="500">






