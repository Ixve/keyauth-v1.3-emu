# Note
This emulator was made for a cheat named 'Hozinum' - you *will* need to modify the batch file and the script if you want to use this for other programs.

# Requirements
x64dbg (With ScyllaHide)<br>
Cheat Engine
Notepad (to write down all the values)

# Usage
Open the x64dbg folder and rename x64dbg.exe to anything else
Open x64dbg, go to Options -> Preferences and toggle the "Exit Breakpoint"<br>
Attach to your desired process<br>
Right click inside the disassembler -> Search for -> All modules -> String references<br>
Press the regex toggle on the bottom right<br>
Put in the following regex: `[a-zA-Z0-9]{64}`<br>
Find what seems to be your public key (e.g. "f7ab43f1cc6907bbb66d77bc0eadbfdbd0f108710d3a52b88750ad205158f64c")<br>
Right click -> Copy -> String , save it in your notepad.<br>

Put in the following regex: `[a-zA-Z0-9]{10}\"$`<br>(NOTE: If you cannot find the key using this, you can just type `keyauth.win`, press the first value, and erase the search text)<br>
Find what seems to be your KeyAuth owner id (e.g. "3mnye99Bp3") <br>
Right click -> Copy -> String, save it in your notepad.<br>
Erase your search text - look for a version number, save it in your notepad.<br>

Open your Cheat Engine (do not detach x64dbg yet)<br>
Attach to your process<br>
Select "Value Type" -> "String"<br>
Find the `ProcessName.exe+OFFSET` value<br>
Right click the address and press "Copy selected address" (e.g. `Hozinum.exe+2F3170`)<br>
Terminate the program via x64dbg and close both the debugger and Cheat Engine as we no longer need it.<br>
Start server.bat and put in the values (For offset you would want to do `0x2F3170`, make sure your pasted values do not have quotation marks)
